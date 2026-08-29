"""Indexer client: the only module that talks to the network.

The client is read-only by construction (CONTEXT.md, decision D2). Every
request passes :func:`assert_read_only` before it leaves the process, so a
future change that tries to write fails loudly instead of touching a customer's
cluster.

Nothing here logs credentials or request bodies.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from types import TracebackType

import httpx

from vulnfold.config import (
    MAX_REQUEST_ATTEMPTS,
    RETRY_BACKOFF_SECONDS,
    RETRYABLE_STATUS_CODES,
    ScanConfig,
)
from vulnfold.errors import (
    AggregationError,
    IndexerError,
    IndexNotReadableError,
    ReadOnlyViolationError,
)
from vulnfold.mapping import (
    build_composite_query,
    build_count_query,
    parse_composite_page,
    parse_count,
    parse_totals,
)
from vulnfold.models import FieldMapping, IndexerSnapshot, PackageBucket

READ_METHOD = "GET"
SEARCH_ENDPOINT = "_search"
COUNT_ENDPOINT = "_count"
SEARCH_METHOD = "POST"
ALLOWED_POST_ENDPOINTS: frozenset[str] = frozenset({SEARCH_ENDPOINT, COUNT_ENDPOINT})


def assert_read_only(method: str, path: str) -> None:
    """Reject any request that could modify the cluster.

    Args:
        method: HTTP method about to be used.
        path: Request path, without query string.

    Raises:
        ReadOnlyViolationError: The request is not a read.
    """
    if method == READ_METHOD:
        return
    endpoint = path.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if method == SEARCH_METHOD and endpoint in ALLOWED_POST_ENDPOINTS:
        return
    allowed = ", ".join(sorted(ALLOWED_POST_ENDPOINTS))
    raise ReadOnlyViolationError(
        f"Refusing {method} {path}: vulnfold is read-only. Only GET, and POST to "
        f"{allowed}, are permitted. This is a defect in vulnfold, not a "
        f"configuration problem."
    )


class IndexerClient:
    """Read-only HTTP access to a Wazuh indexer."""

    def __init__(self, config: ScanConfig, mapping: FieldMapping) -> None:
        """Open a client.

        Args:
            config: Connection settings for this scan.
            mapping: Field mapping used to build every query body.
        """
        self._config = config
        self._mapping = mapping
        self._client = httpx.Client(
            base_url=config.url,
            auth=(config.username, config.password),
            verify=config.verify_tls,
            timeout=config.timeout_seconds,
        )

    def __enter__(self) -> IndexerClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._client.close()

    def verify_readable(self) -> None:
        """Confirm the configured index pattern exists and can be read.

        Raises:
            IndexNotReadableError: The pattern matches nothing, or the
                credentials cannot read it.
        """
        pattern = self._config.index_pattern
        response = self._send(READ_METHOD, f"/{pattern}")
        if response.status_code in (401, 403):
            raise IndexNotReadableError(
                f"The supplied credentials cannot read {pattern!r} "
                f"(HTTP {response.status_code}). Read access to the index and to "
                f"the cluster's index metadata is required."
            )
        if response.status_code == 404:
            raise IndexNotReadableError(
                f"Index pattern {pattern!r} does not exist on {self._config.url}."
            )
        body = self._decode(response, f"GET /{pattern}")
        if not body:
            raise IndexNotReadableError(
                f"Index pattern {pattern!r} matched no indices on "
                f"{self._config.url}. Check the pattern and that vulnerability "
                f"detection has run at least once."
            )

    def count_findings(self) -> int:
        """Total the findings the scan is about to collapse.

        Returns:
            Documents matching the index pattern.

        Raises:
            IndexerError: The indexer refused the request or answered oddly.
        """
        response = self._send(
            SEARCH_METHOD,
            self._endpoint(COUNT_ENDPOINT),
            json_body=build_count_query(),
        )
        return parse_count(self._require_success(response, COUNT_ENDPOINT))

    def fetch_snapshot(self) -> IndexerSnapshot:
        """Read the fleet's vulnerability state in full.

        Walks the ``composite`` aggregation to exhaustion. A fixed-size
        aggregation would truncate silently on a real fleet and produce a
        confidently wrong plan.

        Returns:
            Every ``(package, version)`` bucket plus the fleet-wide totals.

        Raises:
            IndexerError: The indexer refused a request or answered oddly.
        """
        total_findings = self.count_findings()

        first = self._search(after_key=None)
        totals = parse_totals(first)
        page = parse_composite_page(first, self._mapping)
        buckets: list[PackageBucket] = list(page.buckets)
        after_key = page.after_key if page.buckets else None

        while after_key is not None:
            page = parse_composite_page(self._search(after_key=after_key), self._mapping)
            if not page.buckets:
                break
            if page.after_key == after_key:
                raise AggregationError(
                    "The indexer returned the same composite cursor twice. "
                    "Pagination cannot advance, so the scan was stopped rather "
                    "than loop forever."
                )
            buckets.extend(page.buckets)
            after_key = page.after_key

        return IndexerSnapshot(
            total_findings=total_findings,
            total_agents=totals.agents,
            total_distinct_cves=totals.distinct_cves,
            total_distinct_packages=totals.distinct_packages,
            buckets=buckets,
        )

    def _search(self, *, after_key: Mapping[str, str | None] | None) -> Mapping[str, object]:
        body = build_composite_query(
            self._mapping,
            page_size=self._config.page_size,
            after_key=after_key,
        )
        response = self._send(
            SEARCH_METHOD,
            self._endpoint(SEARCH_ENDPOINT),
            json_body=body,
        )
        return self._require_success(response, SEARCH_ENDPOINT)

    def _endpoint(self, name: str) -> str:
        return f"/{self._config.index_pattern}/{name}"

    def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, object] | None = None,
    ) -> httpx.Response:
        assert_read_only(method, path)
        response = self._attempt(method, path, json_body)
        delay = RETRY_BACKOFF_SECONDS
        for _ in range(MAX_REQUEST_ATTEMPTS - 1):
            if response.status_code not in RETRYABLE_STATUS_CODES:
                break
            time.sleep(delay)
            delay *= 2
            response = self._attempt(method, path, json_body)
        return response

    def _attempt(
        self,
        method: str,
        path: str,
        json_body: dict[str, object] | None,
    ) -> httpx.Response:
        try:
            return self._client.request(method, path, json=json_body)
        except httpx.HTTPError as exc:
            raise IndexerError(
                f"Cannot reach the indexer at {self._config.url}: {exc}. "
                f"Check the URL, network reachability and, for a self-signed "
                f"certificate, whether --insecure is needed."
            ) from exc

    def _require_success(self, response: httpx.Response, context: str) -> Mapping[str, object]:
        if response.status_code >= 400:
            raise IndexerError(
                f"The indexer answered HTTP {response.status_code} to {context} on "
                f"{self._config.index_pattern!r}. Verify the credentials have read "
                f"access and that the index pattern is correct."
            )
        return self._decode(response, context)

    def _decode(self, response: httpx.Response, context: str) -> Mapping[str, object]:
        try:
            body = response.json()
        except ValueError as exc:
            raise IndexerError(
                f"The indexer answered {context} with a body that is not JSON."
            ) from exc
        if not isinstance(body, dict):
            raise IndexerError(
                f"The indexer answered {context} with a "
                f"{type(body).__name__}, expected a JSON object."
            )
        return {str(key): value for key, value in body.items()}
