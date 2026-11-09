"""Prometheus export (SPEC-05)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import respx
from conftest import INDEXER_URL, MEASURED_ACTIONS, FakeIndexer
from typer.testing import CliRunner

from vulnfold.cli import app
from vulnfold.config import DEFAULT_PASSWORD_ENV_VAR, METRICS_HOSTS_IN_LABEL
from vulnfold.metrics import escape_label_value, hosts_label, render_prometheus
from vulnfold.models import CollapseSources, PatchPlan, RankBy, RemediationAction

GENERATED_AT = datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc)
SAMPLE_LINE = re.compile(r'^[a-z_]+(\{([a-z_]+="([^"\\]|\\.)*",?)*\})? -?[0-9.e+]+$')
runner = CliRunner()


def _action(package: str, agents: list[str]) -> RemediationAction:
    return RemediationAction(
        package_name=package,
        current_version="1.0",
        target_version="1.1",
        affected_agents=agents,
        agent_count=len(agents),
        finding_count=10,
        cve_count=4,
        severity_breakdown={"Critical": 2},
        critical_count=2,
        high_count=0,
        unknown_severity_count=0,
        is_kernel=False,
    )


def _plan(actions: list[RemediationAction], agent_names: dict[str, str]) -> PatchPlan:
    return PatchPlan(
        total_findings=100, total_criticals=10, total_agents=3, total_distinct_cves=50,
        total_distinct_packages=20, fixable_findings=60, fixable_criticals=6,
        fixable_distinct_packages=5, no_fix_findings=40, no_fix_criticals=4,
        unknown_fixability_findings=0, actions=actions, unfixable=[], collapse_ratio=12.0,
        collapse_sources=CollapseSources(findings_per_action=1, cves_per_action=1, hosts_per_action=1),
        rank_by=RankBy.CRITICALS, coverage_curve=[], coverage_by_findings=[],
        coverage_by_criticals=[], agent_names=agent_names,
    )


def test_every_sample_line_parses_as_exposition_text() -> None:
    plan = _plan([_action('we"ird\\pkg\nname', ["001"])], {"001": "web-01"})

    text = render_prometheus(plan, generated_at=GENERATED_AT, rows=50)

    samples = [line for line in text.splitlines() if not line.startswith("#")]
    assert samples
    assert all(SAMPLE_LINE.match(line) for line in samples), samples


def test_label_values_escape_quotes_backslashes_and_newlines() -> None:
    assert escape_label_value('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


def test_row_metrics_never_exceed_the_row_limit() -> None:
    plan = _plan([_action(f"pkg{i}", ["001"]) for i in range(80)], {})

    text = render_prometheus(plan, generated_at=GENERATED_AT, rows=50)

    assert text.count("vulnfold_action_findings{") == 50


def test_actions_carry_the_names_of_their_hosts() -> None:
    plan = _plan([_action("openssl", ["001", "002"])], {"001": "web-01"})

    text = render_prometheus(plan, generated_at=GENERATED_AT, rows=50)

    assert 'hosts="web-01 (001), 002"' in text
    assert 'rank="001"' in text


def test_hosts_label_counts_agents_beyond_the_limit() -> None:
    agents = [f"{i:03d}" for i in range(METRICS_HOSTS_IN_LABEL + 5)]

    label = hosts_label(agents, {})

    assert label.endswith(", +5 more")
    assert label.count(",") == METRICS_HOSTS_IN_LABEL


def test_totals_are_split_by_fixability_class() -> None:
    text = render_prometheus(_plan([], {}), generated_at=GENERATED_AT, rows=50)

    assert 'vulnfold_findings{class="fixable"} 60' in text
    assert 'vulnfold_findings{class="no_fix"} 40' in text
    assert f"vulnfold_last_scan_timestamp_seconds {int(GENERATED_AT.timestamp())}" in text


@respx.mock
def test_the_cli_writes_the_complete_plan_whatever_the_display_filter(
    composite_pages: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV_VAR, "s3cret")
    respx.route().mock(side_effect=FakeIndexer(composite_pages))
    destination = tmp_path / "vulnfold.prom"

    result = runner.invoke(
        app,
        ["scan", "--url", INDEXER_URL, "--user", "reader", "--min-severity", "Critical",
         "--metrics", str(destination), "--metrics-rows", str(MEASURED_ACTIONS + 1)],
        env={"COLUMNS": "200"},
    )

    assert result.exit_code == 0
    assert destination.read_text().count("vulnfold_action_findings{") == MEASURED_ACTIONS


@respx.mock
def test_an_unwritable_metrics_path_exits_nonzero(
    composite_pages: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV_VAR, "s3cret")
    respx.route().mock(side_effect=FakeIndexer(composite_pages))

    result = runner.invoke(
        app,
        ["scan", "--url", INDEXER_URL, "--user", "reader",
         "--metrics", str(tmp_path / "missing" / "vulnfold.prom")],
        env={"COLUMNS": "200"},
    )

    assert result.exit_code == 1
    assert "metrics file" in result.stderr
