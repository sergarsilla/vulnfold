"""Shared fixtures and factories.

The measured constants below are the figures SPEC-01 section 9 accepts against,
taken from the recorded Wazuh 4.14.7 response in ``fixtures/wazuh_sample.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from vulnfold.config import ScanConfig
from vulnfold.mapping import load_mapping, parse_composite_page, parse_totals
from vulnfold.models import FieldMapping, Fixability, IndexerSnapshot, PackageBucket

FIXTURES = Path(__file__).resolve().parent / "fixtures"
COMPOSITE_FIXTURE = FIXTURES / "aggregation_response.json"

MEASURED_FINDINGS = 32_718
MEASURED_AGENTS = 15
MEASURED_DISTINCT_CVES = 5_950
MEASURED_DISTINCT_PACKAGES = 554
MEASURED_ACTIONS = 744
MEASURED_COLLAPSE_RATIO = 59.06
MEASURED_TOP_SEVEN_FINDINGS = 23_309
MEASURED_TOP_SEVEN_PERCENTAGE = 71.2

INDEXER_URL = "https://indexer.example.test:9200"
INDEX_PATTERN = "wazuh-states-vulnerabilities-*"

DEFAULT_AGENT = "001"

#: Fixability vocabulary as shipped, so a hand-built bucket is classified by
#: exactly the rules production uses and the marker strings stay in the YAML.
FIXABILITY_RULES = load_mapping("wazuh-4.x").fixability
DEFAULT_TARGET_VERSION = "3.0.2-2"
FIXABLE_CONDITION = f"{FIXABILITY_RULES.fixed_version_prefix}{DEFAULT_TARGET_VERSION}"
NO_FIX_CONDITION = FIXABILITY_RULES.no_fix_values[0]


@pytest.fixture(scope="session")
def composite_pages() -> list[dict[str, Any]]:
    """The recorded fleet, reshaped as the pages of a composite walk."""
    pages: list[dict[str, Any]] = json.loads(COMPOSITE_FIXTURE.read_text(encoding="utf-8"))
    return pages


@pytest.fixture
def mapping() -> FieldMapping:
    """The Wazuh 4.x field mapping as shipped."""
    return load_mapping("wazuh-4.x")


@pytest.fixture
def real_snapshot(composite_pages: list[dict[str, Any]], mapping: FieldMapping) -> IndexerSnapshot:
    """The whole recorded fleet, as the client would hand it to the domain."""
    totals = parse_totals(composite_pages[0])
    buckets = [
        bucket
        for page in composite_pages
        for bucket in parse_composite_page(page, mapping).buckets
    ]
    return IndexerSnapshot(
        total_findings=MEASURED_FINDINGS,
        total_agents=totals.agents,
        total_distinct_cves=totals.distinct_cves,
        total_distinct_packages=totals.distinct_packages,
        buckets=buckets,
    )


@pytest.fixture
def scan_config() -> ScanConfig:
    """Connection settings pointing at the fake indexer."""
    return ScanConfig(
        url=INDEXER_URL,
        username="reader",
        password="secret",
        index_pattern=INDEX_PATTERN,
    )


def make_bucket(
    *,
    package: str = "openssl",
    version: str = "3.0.2-1",
    findings: int = 10,
    agents: dict[str, int] | None = None,
    agent_cardinality: int | None = None,
    severity: dict[str, int] | None = None,
    cves: int | None = None,
    condition: str | None = FIXABLE_CONDITION,
) -> PackageBucket:
    """Build one bucket, defaulting every field a test does not care about.

    ``condition`` is classified by the shipped rules, exactly as the parser
    classifies a real one, so a test bucket can never carry a fixability its
    condition string does not imply.
    """
    agent_counts = agents if agents is not None else {DEFAULT_AGENT: findings}
    return PackageBucket(
        package_name=package,
        package_version=version,
        finding_count=findings,
        agent_counts=agent_counts,
        agent_cardinality=(
            agent_cardinality if agent_cardinality is not None else len(agent_counts)
        ),
        severity_counts=severity if severity is not None else {"High": findings},
        cve_count=cves if cves is not None else findings,
        fixability=FIXABILITY_RULES.classify(condition) if condition else Fixability.UNKNOWN,
        target_version=FIXABILITY_RULES.target_version(condition) if condition else None,
        scanner_condition=condition,
    )


def make_snapshot(
    buckets: list[PackageBucket],
    *,
    total_findings: int | None = None,
    total_agents: int | None = None,
    total_distinct_cves: int | None = None,
    total_distinct_packages: int | None = None,
) -> IndexerSnapshot:
    """Build a snapshot whose totals reconcile with its buckets unless overridden."""
    agents = {agent for bucket in buckets for agent in bucket.agent_counts}
    packages = {bucket.package_name for bucket in buckets}
    return IndexerSnapshot(
        total_findings=(
            total_findings
            if total_findings is not None
            else sum(bucket.finding_count for bucket in buckets)
        ),
        total_agents=total_agents if total_agents is not None else len(agents),
        total_distinct_cves=(
            total_distinct_cves
            if total_distinct_cves is not None
            else sum(bucket.cve_count for bucket in buckets)
        ),
        total_distinct_packages=(
            total_distinct_packages if total_distinct_packages is not None else len(packages)
        ),
        buckets=buckets,
    )


class FakeIndexer:
    """A recording stand-in for the indexer.

    Dispatches ``_search`` by the cursor the client sent, so a test that asserts
    on the collected buckets is also asserting that the walk followed the right
    ``after_key`` at every step.
    """

    def __init__(
        self,
        pages: list[dict[str, Any]],
        *,
        total_findings: int = MEASURED_FINDINGS,
    ) -> None:
        self.pages = pages
        self.total_findings = total_findings
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        endpoint = request.url.path.rsplit("/", 1)[-1]
        if endpoint == "_count":
            return httpx.Response(200, json={"count": self.total_findings})
        if endpoint == "_search":
            return httpx.Response(200, json=self._page_for(request))
        return httpx.Response(200, json={INDEX_PATTERN.replace("*", "2026.08.29"): {}})

    @property
    def search_bodies(self) -> list[dict[str, Any]]:
        """Every ``_search`` body the client sent, in order."""
        return [
            json.loads(request.content)
            for request in self.requests
            if request.url.path.endswith("_search")
        ]

    def _page_for(self, request: httpx.Request) -> dict[str, Any]:
        body = json.loads(request.content)
        after = body["aggs"]["actions"]["composite"].get("after")
        if after is None:
            return self.pages[0]
        for position, page in enumerate(self.pages):
            if page["aggregations"]["actions"].get("after_key") == after:
                return self.pages[position + 1]
        raise AssertionError(f"The client sent a cursor no page produced: {after!r}")
