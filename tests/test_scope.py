"""Agent freshness and superseded indices (SPEC-06)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from conftest import INDEXER_URL, NO_FIX_CONDITION, FakeIndexer, make_bucket, make_snapshot
from typer.testing import CliRunner

from vulnfold.cli import app
from vulnfold.client import IndexerClient
from vulnfold.collapse import build_patch_plan
from vulnfold.config import DEFAULT_PASSWORD_ENV_VAR, ScanConfig
from vulnfold.mapping import (
    build_document_filter,
    parse_inventory,
    parse_latest_snapshot,
    parse_liveness,
)
from vulnfold.models import (
    AgentLiveness,
    AgentStatus,
    FieldMapping,
    IndexInventory,
    LivenessSnapshot,
    WarningCode,
)
from vulnfold.render import render_markdown
from vulnfold.scope import (
    agents_in_plan,
    build_agent_scopes,
    build_fleet_scope,
    classify_agents,
    count_superseded_findings,
    find_superseded_indices,
    scope_warnings,
)

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
runner = CliRunner()


def _liveness(**last_seen: datetime | None) -> LivenessSnapshot:
    return LivenessSnapshot(
        snapshot_time=NOW,
        agents={
            agent: AgentLiveness(agent_id=agent, name=f"host-{agent}", last_seen=seen)
            for agent, seen in last_seen.items()
        },
    )


def _millis(moment: datetime) -> float:
    return moment.timestamp() * 1000


# ---------------------------------------------------------------------------
# Superseded indices
# ---------------------------------------------------------------------------


def test_an_agent_in_two_indices_is_current_only_in_the_newest() -> None:
    inventory = IndexInventory(
        newest_detection={
            "001": {"states-old": "2026-05-30T14:19:53Z", "states-new": "2026-11-08T23:37:39Z"},
            "002": {"states-new": "2026-11-08T10:00:00Z"},
        },
        findings={"001": {"states-old": 198, "states-new": 319}, "002": {"states-new": 41}},
    )

    superseded = find_superseded_indices(inventory)

    assert superseded == {"states-old": ["001"]}
    assert count_superseded_findings(inventory, superseded) == 198


def test_without_detection_times_no_copy_is_discarded() -> None:
    inventory = IndexInventory(
        newest_detection={"001": {"states-old": None, "states-new": "2026-11-08T23:37:39Z"}},
        findings={"001": {"states-old": 5, "states-new": 9}},
    )

    assert find_superseded_indices(inventory) == {}


# ---------------------------------------------------------------------------
# Agent status
# ---------------------------------------------------------------------------


def test_agents_are_classified_by_when_they_were_last_seen() -> None:
    liveness = _liveness(
        **{
            "001": NOW - timedelta(hours=14),
            "002": NOW - timedelta(days=90),
            "003": None,
        }
    )

    statuses = classify_agents(
        ["001", "002", "003", "004"], liveness, now=NOW, stale_after_days=7
    )

    assert statuses == {
        "001": AgentStatus.ACTIVE,
        "002": AgentStatus.STALE,
        "003": AgentStatus.STALE,
        "004": AgentStatus.UNREGISTERED,
    }


def test_without_liveness_every_agent_is_unknown_and_stays_in_the_plan() -> None:
    statuses = classify_agents(["001", "002"], None, now=NOW, stale_after_days=7)

    assert set(statuses.values()) == {AgentStatus.UNKNOWN}
    assert agents_in_plan(statuses) == ["001", "002"]


def test_excluded_agents_lead_the_list_with_their_findings() -> None:
    fleet = make_snapshot(
        [
            make_bucket(package="openssl", agents={"001": 4, "002": 30}, findings=34),
            make_bucket(package="zlib", agents={"002": 6}, findings=6, condition=NO_FIX_CONDITION),
        ]
    )
    statuses = {"001": AgentStatus.ACTIVE, "002": AgentStatus.STALE}

    scopes = build_agent_scopes(fleet, statuses, _liveness(**{"001": NOW, "002": NOW}))

    assert [scope.agent_id for scope in scopes] == ["002", "001"]
    assert (scopes[0].findings, scopes[0].fixable_findings) == (36, 30)


# ---------------------------------------------------------------------------
# Queries and parsing
# ---------------------------------------------------------------------------


def test_document_filter_drops_superseded_copies_and_out_of_scope_agents(
    mapping: FieldMapping,
) -> None:
    query = build_document_filter(mapping, superseded={"states-old": ["001"]}, agents=["001", "003"])

    assert query == {
        "bool": {
            "must_not": [
                {"bool": {"filter": [{"term": {"_index": "states-old"}},
                                     {"terms": {"agent.id": ["001"]}}]}}
            ],
            "filter": [{"terms": {"agent.id": ["001", "003"]}}],
        }
    }


def test_nothing_to_filter_builds_no_query(mapping: FieldMapping) -> None:
    assert build_document_filter(mapping, superseded={}, agents=None) is None


def test_parse_inventory_reads_findings_and_newest_detection_per_index() -> None:
    response = {"aggregations": {"inventory": {"buckets": [
        {"key": "004", "indices": {"buckets": [
            {"key": "states-a", "doc_count": 198,
             "newest": {"value": 1.78e12, "value_as_string": "2026-05-30T14:19:53.686Z"}},
        ]}},
    ]}}}

    inventory = parse_inventory(response)

    assert inventory.findings == {"004": {"states-a": 198}}
    assert inventory.newest_detection == {"004": {"states-a": "2026-05-30T14:19:53.686Z"}}


def test_parse_liveness_tolerates_malformed_entries() -> None:
    response = {"aggregations": {"liveness": {"buckets": [
        {"key": "004", "last_seen": {"value": _millis(NOW)}, "name": {"buckets": [{"key": "laptop"}]}},
        {"no_key": True},
        {"key": "005", "last_seen": {"value": None}, "name": {"buckets": []}},
    ]}}}

    snapshot = parse_liveness(response, snapshot_time=NOW)

    assert snapshot.agents["004"].name == "laptop"
    assert snapshot.agents["004"].last_seen == NOW
    assert snapshot.agents["005"].last_seen is None
    assert parse_latest_snapshot({"aggregations": {"latest": {"value": None}}}) is None


@pytest.mark.parametrize("status", [403, 404])
@respx.mock
def test_unreadable_liveness_yields_none_instead_of_failing(
    status: int, scan_config: ScanConfig, mapping: FieldMapping
) -> None:
    respx.route().mock(return_value=httpx.Response(status))

    with IndexerClient(scan_config, mapping) as client:
        assert client.fetch_liveness() is None


# ---------------------------------------------------------------------------
# Warnings and rendering
# ---------------------------------------------------------------------------


def test_missing_liveness_and_superseded_copies_are_both_reported() -> None:
    warnings = scope_warnings(
        liveness_configured=True, liveness=None, superseded_findings=222, superseded_indices=["old"]
    )

    assert [w.code for w in warnings] == [
        WarningCode.LIVENESS_UNAVAILABLE,
        WarningCode.SUPERSEDED_INDEX_FINDINGS,
    ]
    assert "222" in warnings[1].message and "old" in warnings[1].message


def test_markdown_states_the_scope_and_lists_excluded_agents(mapping: FieldMapping) -> None:
    fleet = make_snapshot(
        [make_bucket(package="openssl", agents={"001": 4, "002": 30}, findings=34,
                     severity={"Critical": 34})]
    )
    active = make_snapshot(
        [make_bucket(package="openssl", agents={"001": 4}, findings=4, severity={"Critical": 4})]
    )
    statuses = {"001": AgentStatus.ACTIVE, "002": AgentStatus.STALE}
    liveness = _liveness(**{"001": NOW, "002": NOW - timedelta(days=100)})
    active_plan = build_patch_plan(active, mapping)
    scope = build_fleet_scope(
        active_plan=active_plan, fleet_plan=build_patch_plan(fleet, mapping), fleet=fleet,
        statuses=statuses, liveness=liveness, stale_after_days=7, superseded_findings=0,
        superseded_indices=[],
    )

    text = render_markdown(active_plan.model_copy(update={"scope": scope}), top=10)

    assert "Plan covers 1 of 2 agents" in text
    assert "34 fixable criticals, 30 of them on 1 agents" in text
    assert "## Agents not in this plan" in text
    assert "host-002 (002) | stale | 2026-08-01" in text


# ---------------------------------------------------------------------------
# End to end (SPEC-06 section 4)
# ---------------------------------------------------------------------------


def _fleet_with_liveness(composite_pages: list[dict[str, Any]]) -> FakeIndexer:
    agents = sorted(
        {agent["key"] for page in composite_pages
         for bucket in page["aggregations"]["actions"]["buckets"]
         for agent in bucket["agents"]["buckets"]}
    )
    stale, active = agents[0], agents[1:]
    inventory = {"aggregations": {"inventory": {"buckets": [
        {"key": agent, "indices": {"buckets": [
            {"key": "states-new", "doc_count": 10, "newest": {"value_as_string": "2026-11-08T00:00:00Z"}},
            *([{"key": "states-old", "doc_count": 7, "newest": {"value_as_string": "2026-05-30T00:00:00Z"}}]
              if agent == active[0] else []),
        ]}} for agent in agents
    ]}}}
    now = datetime.now(timezone.utc)
    latest = {"aggregations": {"latest": {"value": _millis(now)}}}
    seen = {"aggregations": {"liveness": {"buckets": [
        {"key": agent, "name": {"buckets": [{"key": f"host-{agent}"}]},
         "last_seen": {"value": _millis(now - timedelta(days=200 if agent == stale else 0))}}
        for agent in agents
    ]}}}
    return FakeIndexer(composite_pages, inventory=inventory, liveness=(latest, seen))


@respx.mock
def test_a_scoped_run_restricts_the_plan_and_keeps_the_fleet_in_evidence(
    composite_pages: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV_VAR, "s3cret")
    indexer = _fleet_with_liveness(composite_pages)
    respx.route().mock(side_effect=indexer)
    evidence = tmp_path / "evidence.json"
    metrics = tmp_path / "vulnfold.prom"

    result = runner.invoke(
        app,
        ["scan", "--url", INDEXER_URL, "--user", "reader", "--format", "json",
         "--evidence", str(evidence), "--metrics", str(metrics)],
        env={"COLUMNS": "200"},
    )

    assert result.exit_code == 0, result.stderr
    plan = json.loads(result.stdout)
    statuses = {agent["agent_id"]: agent["status"] for agent in plan["scope"]["agents"]}
    assert list(statuses.values()).count("stale") == 1
    scoped_bodies = [body for body in indexer.search_bodies if "query" in body]
    assert any("filter" in body["query"]["bool"] for body in scoped_bodies)
    assert all(
        clause["bool"]["filter"][0] == {"term": {"_index": "states-old"}}
        for body in scoped_bodies for clause in body["query"]["bool"].get("must_not", [])
    )
    assert "superseded_index_findings" in [w["code"] for w in plan["warnings"]]
    record = json.loads(evidence.read_text())
    assert record["scope"]["superseded_findings"] == 7
    assert record["scope"]["fleet"]["agents"] == len(statuses)
    assert 'status="stale"' in metrics.read_text()


@respx.mock
def test_without_liveness_the_run_matches_spec_05_plus_one_warning(
    composite_pages: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV_VAR, "s3cret")
    respx.route().mock(side_effect=FakeIndexer(composite_pages))

    result = runner.invoke(
        app, ["scan", "--url", INDEXER_URL, "--user", "reader", "--format", "json"],
        env={"COLUMNS": "200"},
    )

    plan = json.loads(result.stdout)
    assert [w["code"] for w in plan["warnings"]].count("liveness_unavailable") == 1
    assert {agent["status"] for agent in plan["scope"]["agents"]} <= {"unknown"}
