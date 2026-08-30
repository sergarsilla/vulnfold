"""The indexer client is read-only, retries, and pages to exhaustion."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from conftest import (
    INDEX_PATTERN,
    MEASURED_BUCKETS,
    MEASURED_FINDINGS,
    FakeIndexer,
)

from vulnfold.client import IndexerClient, assert_read_only
from vulnfold.config import MAX_REQUEST_ATTEMPTS, ScanConfig
from vulnfold.errors import (
    AggregationError,
    IndexerError,
    IndexNotReadableError,
    ReadOnlyViolationError,
)
from vulnfold.models import FieldMapping

SEARCH_PATH = f"/{INDEX_PATTERN}/_search"
COUNT_PATH = f"/{INDEX_PATTERN}/_count"


@pytest.fixture(autouse=True)
def no_backoff_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep retry tests instant; the delay itself is not what is under test."""
    monkeypatch.setattr("vulnfold.client.time.sleep", lambda _seconds: None)


def _is_read(request: httpx.Request) -> bool:
    endpoint = request.url.path.rsplit("/", 1)[-1]
    return request.method == "GET" or (
        request.method == "POST" and endpoint in {"_search", "_count"}
    )


# ---------------------------------------------------------------------------
# Read-only enforcement (SPEC-01 section 5.2, criterion 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [SEARCH_PATH, COUNT_PATH, "/", f"/{INDEX_PATTERN}"])
def test_read_only_guard_allows_any_get(path: str) -> None:
    assert_read_only("GET", path)


@pytest.mark.parametrize("path", [SEARCH_PATH, COUNT_PATH])
def test_read_only_guard_allows_post_to_search_and_count(path: str) -> None:
    assert_read_only("POST", path)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD"])
def test_read_only_guard_refuses_any_other_method(method: str) -> None:
    with pytest.raises(ReadOnlyViolationError, match="read-only"):
        assert_read_only(method, SEARCH_PATH)


@pytest.mark.parametrize(
    "path",
    [f"/{INDEX_PATTERN}/_delete_by_query", f"/{INDEX_PATTERN}/_doc", "/_bulk", "/_cluster/settings"],
)
def test_read_only_guard_refuses_a_post_anywhere_else(path: str) -> None:
    with pytest.raises(ReadOnlyViolationError, match="read-only"):
        assert_read_only("POST", path)


def test_read_only_guard_ignores_a_query_string() -> None:
    with pytest.raises(ReadOnlyViolationError):
        assert_read_only("POST", f"/{INDEX_PATTERN}/_bulk?refresh=true")


@respx.mock
def test_a_whole_scan_issues_nothing_but_reads(
    scan_config: ScanConfig,
    mapping: FieldMapping,
    composite_pages: list[dict[str, Any]],
) -> None:
    """SPEC-01 section 9, criterion 3."""
    indexer = FakeIndexer(composite_pages)
    respx.route().mock(side_effect=indexer)

    with IndexerClient(scan_config, mapping) as client:
        client.verify_readable()
        client.fetch_snapshot()

    assert indexer.requests
    assert all(_is_read(request) for request in indexer.requests)
    assert {request.method for request in indexer.requests} == {"GET", "POST"}


# ---------------------------------------------------------------------------
# Composite pagination (SPEC-01 section 5.1, criterion 4)
# ---------------------------------------------------------------------------


@respx.mock
def test_composite_pagination_walks_every_page(
    scan_config: ScanConfig,
    mapping: FieldMapping,
    composite_pages: list[dict[str, Any]],
) -> None:
    """SPEC-01 section 9, criterion 4, on the fleet the condition source fans out.

    Adding the condition as a third composite source nearly doubled the bucket
    count, so the recorded walk spans six pages plus the terminating empty one.
    Pagination is exercised by the real fleet now, not only in theory.
    """
    indexer = FakeIndexer(composite_pages)
    respx.route().mock(side_effect=indexer)

    with IndexerClient(scan_config, mapping) as client:
        snapshot = client.fetch_snapshot()

    assert len(snapshot.buckets) == MEASURED_BUCKETS
    assert len(indexer.search_bodies) == len(composite_pages)


@respx.mock
def test_pagination_sends_the_cursor_each_page_returned(
    scan_config: ScanConfig,
    mapping: FieldMapping,
    composite_pages: list[dict[str, Any]],
) -> None:
    indexer = FakeIndexer(composite_pages)
    respx.route().mock(side_effect=indexer)

    with IndexerClient(scan_config, mapping) as client:
        client.fetch_snapshot()

    sent = [body["aggs"]["actions"]["composite"].get("after") for body in indexer.search_bodies]
    expected = [None] + [
        page["aggregations"]["actions"]["after_key"] for page in composite_pages[:-1]
    ]

    assert sent == expected


@respx.mock
def test_fleet_totals_are_requested_only_on_the_first_page(
    scan_config: ScanConfig,
    mapping: FieldMapping,
    composite_pages: list[dict[str, Any]],
) -> None:
    indexer = FakeIndexer(composite_pages)
    respx.route().mock(side_effect=indexer)

    with IndexerClient(scan_config, mapping) as client:
        client.fetch_snapshot()

    carries_totals = ["total_agents" in body["aggs"] for body in indexer.search_bodies]

    assert carries_totals == [True] + [False] * (len(composite_pages) - 1)


@respx.mock
def test_snapshot_carries_the_count_and_the_fleet_totals(
    scan_config: ScanConfig,
    mapping: FieldMapping,
    composite_pages: list[dict[str, Any]],
) -> None:
    respx.route().mock(side_effect=FakeIndexer(composite_pages))

    with IndexerClient(scan_config, mapping) as client:
        snapshot = client.fetch_snapshot()

    assert snapshot.total_findings == MEASURED_FINDINGS
    assert (snapshot.total_agents, snapshot.total_distinct_cves) == (15, 5950)


@respx.mock
def test_a_cursor_that_never_advances_is_refused(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    """A server that keeps answering with the same cursor must not loop forever."""
    stuck = {
        "aggregations": {
            "actions": {
                "after_key": {"pkg": "openssl", "ver": "1"},
                "buckets": [
                    {
                        "key": {"pkg": "openssl", "ver": "1"},
                        "doc_count": 1,
                        "agents": {"buckets": [{"key": "001", "doc_count": 1}]},
                        "agent_cardinality": {"value": 1},
                        "severity": {"buckets": [{"key": "High", "doc_count": 1}]},
                        "cves": {"value": 1},
                    }
                ],
            },
            "total_agents": {"value": 1},
            "total_cves": {"value": 1},
            "total_packages": {"value": 1},
        }
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("_count"):
            return httpx.Response(200, json={"count": 1})
        return httpx.Response(200, json=stuck)

    respx.route().mock(side_effect=handler)

    with IndexerClient(scan_config, mapping) as client, pytest.raises(
        AggregationError, match="same composite cursor"
    ):
        client.fetch_snapshot()


# ---------------------------------------------------------------------------
# Retries (SPEC-01 section 5.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
@respx.mock
def test_a_retryable_answer_is_retried(
    status: int,
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    route = respx.route().mock(
        side_effect=[
            httpx.Response(status),
            httpx.Response(200, json={"count": MEASURED_FINDINGS}),
        ]
    )

    with IndexerClient(scan_config, mapping) as client:
        assert client.count_findings() == MEASURED_FINDINGS

    assert route.call_count == 2


@respx.mock
def test_retries_stop_after_three_attempts(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    route = respx.route().mock(return_value=httpx.Response(503))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(IndexerError, match="503"):
        client.count_findings()

    assert route.call_count == MAX_REQUEST_ATTEMPTS


@respx.mock
def test_a_client_error_is_not_retried(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    route = respx.route().mock(return_value=httpx.Response(400))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(IndexerError, match="400"):
        client.count_findings()

    assert route.call_count == 1


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------


@respx.mock
def test_verify_readable_accepts_a_pattern_with_indices(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    respx.route().mock(
        return_value=httpx.Response(200, json={"wazuh-states-vulnerabilities-2026.08.29": {}})
    )

    with IndexerClient(scan_config, mapping) as client:
        client.verify_readable()


@respx.mock
def test_verify_readable_refuses_a_pattern_that_matches_nothing(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    respx.route().mock(return_value=httpx.Response(200, json={}))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(
        IndexNotReadableError, match="matched no indices"
    ):
        client.verify_readable()


@pytest.mark.parametrize("status", [401, 403])
@respx.mock
def test_verify_readable_reports_missing_read_access(
    status: int,
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    respx.route().mock(return_value=httpx.Response(status, json={}))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(
        IndexNotReadableError, match="credentials"
    ):
        client.verify_readable()


@respx.mock
def test_verify_readable_reports_a_missing_index(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    respx.route().mock(return_value=httpx.Response(404, json={}))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(
        IndexNotReadableError, match="does not exist"
    ):
        client.verify_readable()


@respx.mock
def test_an_unreachable_indexer_says_what_to_check(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    respx.route().mock(side_effect=httpx.ConnectError("connection refused"))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(
        IndexerError, match="--insecure"
    ):
        client.count_findings()


@respx.mock
def test_an_answer_that_is_not_json_is_reported(
    scan_config: ScanConfig,
    mapping: FieldMapping,
) -> None:
    respx.route().mock(return_value=httpx.Response(200, text="<html>proxy error</html>"))

    with IndexerClient(scan_config, mapping) as client, pytest.raises(IndexerError, match="JSON"):
        client.count_findings()


def test_tls_verification_is_on_unless_it_is_disabled_explicitly() -> None:
    default = ScanConfig(url="https://x", username="u", password="p", index_pattern="i")

    assert default.verify_tls is True


def test_the_password_never_appears_in_a_repr() -> None:
    config = ScanConfig(
        url="https://x", username="u", password="hunter2", index_pattern="i"
    )

    assert "hunter2" not in repr(config)


@respx.mock
def test_the_password_is_never_written_into_a_request_body(
    scan_config: ScanConfig,
    mapping: FieldMapping,
    composite_pages: list[dict[str, Any]],
) -> None:
    indexer = FakeIndexer(composite_pages)
    respx.route().mock(side_effect=indexer)

    with IndexerClient(scan_config, mapping) as client:
        client.fetch_snapshot()

    bodies = [request.content.decode() for request in indexer.requests if request.content]

    assert bodies
    assert not any(scan_config.password in body for body in bodies)
    assert all(json.loads(body) for body in bodies)
