"""The command line: credentials from the environment, machine-readable output."""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from conftest import (
    INDEXER_URL,
    MEASURED_ACTIONS,
    MEASURED_FINDINGS,
    MEASURED_UNFIXABLE_ENTRIES,
    FakeIndexer,
)
from typer.testing import CliRunner

from vulnfold.cli import app
from vulnfold.config import DEFAULT_PASSWORD_ENV_VAR
from vulnfold.models import EvidenceRecord

runner = CliRunner()

BASE_ARGUMENTS = ["scan", "--url", INDEXER_URL, "--user", "reader"]
WIDE_TERMINAL = {"COLUMNS": "200"}


@pytest.fixture
def indexer_password(monkeypatch: pytest.MonkeyPatch) -> str:
    password = "s3cret"
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV_VAR, password)
    return password


@pytest.fixture
def fake_indexer(composite_pages: list[dict[str, Any]]) -> FakeIndexer:
    return FakeIndexer(composite_pages)


# ---------------------------------------------------------------------------
# Machine-readable output (SPEC-01 section 9, criterion 7)
# ---------------------------------------------------------------------------


@respx.mock
def test_json_output_is_the_only_thing_on_stdout(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--format", "json"], env=WIDE_TERMINAL)

    assert result.exit_code == 0
    assert json.loads(result.stdout)["collapse_ratio"] == 30.15


@respx.mock
def test_json_output_can_be_piped_through_jq(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    """SPEC-01 section 9, criterion 7, run literally."""
    if shutil.which("jq") is None:
        pytest.skip("jq is not installed")

    respx.route().mock(side_effect=fake_indexer)
    result = runner.invoke(app, [*BASE_ARGUMENTS, "--format", "json"], env=WIDE_TERMINAL)

    piped = subprocess.run(
        ["jq", ".collapse_ratio"],
        input=result.stdout,
        capture_output=True,
        text=True,
        check=True,
    )

    assert piped.stdout.strip() == "30.15"


@respx.mock
def test_markdown_output_opens_with_the_impact_line(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--format", "markdown", "--top", "7"], env=WIDE_TERMINAL
    )

    assert result.exit_code == 0
    assert "# vulnfold patch plan" in result.stdout
    assert (
        "First 7 by findings: 7,727 of the 13,659 fixable findings (56.6%), on 7 hosts."
        in result.stdout
    )


@respx.mock
def test_table_is_the_default_format(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--top", "7"], env=WIDE_TERMINAL)

    assert result.exit_code == 0
    assert "32,718 findings → 13,659 fixable (41.7%)" in result.stdout
    assert (
        "13,659 fixable findings → 560 actions across 453 packages (ratio 30:1)"
        in result.stdout
    )
    assert "linux-image-6.14.0-37-generic" in result.stdout


@respx.mock
def test_top_limits_the_listed_actions(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--top", "3"], env=WIDE_TERMINAL)
    plan_section = result.stdout.split("No vendor fix available")[0]

    assert "linux-image-cloud-amd64" in plan_section
    # It has no published fix, so it is in the register, never in the plan.
    assert "linux-oracle" not in plan_section
    assert "linux-oracle" in result.stdout


@respx.mock
def test_group_kernels_reduces_the_action_count(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    plain = runner.invoke(app, [*BASE_ARGUMENTS, "--format", "json"], env=WIDE_TERMINAL)
    grouped = runner.invoke(
        app, [*BASE_ARGUMENTS, "--format", "json", "--group-kernels"], env=WIDE_TERMINAL
    )

    assert len(json.loads(grouped.stdout)["actions"]) < len(json.loads(plain.stdout)["actions"])


@respx.mock
def test_min_severity_shortens_the_listed_actions(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--format", "json", "--min-severity", "Critical"], env=WIDE_TERMINAL
    )
    plan = json.loads(result.stdout)

    assert result.exit_code == 0
    assert len(plan["actions"]) < MEASURED_ACTIONS
    assert plan["total_findings"] == 32_718


@respx.mock
def test_an_unknown_severity_is_rejected(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--min-severity", "Catastrophic"], env=WIDE_TERMINAL
    )

    assert result.exit_code == 1
    assert "Catastrophic" in result.stderr


# ---------------------------------------------------------------------------
# Credentials (SPEC-01 section 8)
# ---------------------------------------------------------------------------


@respx.mock
def test_the_password_comes_from_the_environment(
    fake_indexer: FakeIndexer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CUSTOM_INDEXER_PASSWORD", "from-the-environment")
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app,
        [*BASE_ARGUMENTS, "--password-env", "CUSTOM_INDEXER_PASSWORD", "--format", "json"],
        env=WIDE_TERMINAL,
    )

    assert result.exit_code == 0


def test_a_missing_password_variable_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DEFAULT_PASSWORD_ENV_VAR, raising=False)

    result = runner.invoke(app, BASE_ARGUMENTS, env=WIDE_TERMINAL)

    assert result.exit_code == 1
    assert DEFAULT_PASSWORD_ENV_VAR in result.stderr


@respx.mock
def test_a_password_argument_warns_but_still_runs(
    fake_indexer: FakeIndexer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(DEFAULT_PASSWORD_ENV_VAR, raising=False)
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--password", "on-the-command-line", "--format", "json"],
        env=WIDE_TERMINAL,
    )

    assert result.exit_code == 0
    assert "shell history" in result.stderr
    assert json.loads(result.stdout)["total_findings"] == 32_718


@respx.mock
def test_the_password_is_never_echoed_back(
    fake_indexer: FakeIndexer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(DEFAULT_PASSWORD_ENV_VAR, raising=False)
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--password", "hunter2", "--format", "json"], env=WIDE_TERMINAL
    )

    assert "hunter2" not in result.stdout
    assert "hunter2" not in result.stderr


# ---------------------------------------------------------------------------
# TLS and failures (SPEC-01 section 5.2)
# ---------------------------------------------------------------------------


@respx.mock
def test_disabling_tls_verification_warns(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--insecure", "--format", "json"], env=WIDE_TERMINAL
    )

    assert result.exit_code == 0
    assert "TLS certificate verification is disabled" in result.stderr


@respx.mock
def test_a_verified_run_says_nothing_about_tls(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--format", "json"], env=WIDE_TERMINAL)

    assert "TLS" not in result.stderr


@respx.mock
def test_an_unreachable_indexer_exits_nonzero_with_a_message(
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=Exception("boom"))

    result = runner.invoke(app, BASE_ARGUMENTS, env=WIDE_TERMINAL)

    assert result.exit_code != 0


@respx.mock
def test_an_index_that_matches_nothing_exits_nonzero_with_a_message(
    indexer_password: str,
) -> None:
    import httpx

    respx.route().mock(return_value=httpx.Response(200, json={}))

    result = runner.invoke(app, BASE_ARGUMENTS, env=WIDE_TERMINAL)

    assert result.exit_code == 1
    assert "matched no indices" in result.stderr


def test_an_unknown_mapping_exits_nonzero_with_a_message(indexer_password: str) -> None:
    result = runner.invoke(app, [*BASE_ARGUMENTS, "--mapping", "wazuh-9.x"], env=WIDE_TERMINAL)

    assert result.exit_code == 1
    assert "wazuh-9.x" in result.stderr


# ---------------------------------------------------------------------------
# Ranking mode (--rank-by)
# ---------------------------------------------------------------------------


@respx.mock
def test_rank_by_defaults_to_criticals(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--format", "json"], env=WIDE_TERMINAL)

    assert json.loads(result.stdout)["rank_by"] == "criticals"


@respx.mock
def test_rank_by_findings_reorders_the_plan(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--format", "json", "--rank-by", "findings"], env=WIDE_TERMINAL
    )
    plan = json.loads(result.stdout)

    assert result.exit_code == 0
    assert plan["rank_by"] == "findings"
    assert plan["coverage_curve"] == plan["coverage_by_findings"]


@respx.mock
def test_an_unknown_ranking_is_rejected(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--rank-by", "alphabetical"], env=WIDE_TERMINAL)

    assert result.exit_code != 0


@respx.mock
def test_both_headline_claims_appear_under_either_ranking(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    for ranking in ("criticals", "findings"):
        result = runner.invoke(
            app, [*BASE_ARGUMENTS, "--top", "7", "--rank-by", ranking], env=WIDE_TERMINAL
        )

        assert "First 7 by findings:" in result.stdout
        assert "First 7 by criticals:" in result.stdout


# ---------------------------------------------------------------------------
# Evidence file (--evidence)
# ---------------------------------------------------------------------------


@respx.mock
def test_evidence_records_the_run(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--format", "json", "--evidence", str(destination)],
        env=WIDE_TERMINAL,
    )
    record = json.loads(destination.read_text())

    assert result.exit_code == 0
    assert record["schema_version"] == "2"
    assert record["indexer_url"] == INDEXER_URL
    assert record["index_pattern"] == "wazuh-states-vulnerabilities-*"
    assert record["mapping_version"] == "4.x"
    assert record["total_findings"] == 32_718
    assert len(record["actions"]) == MEASURED_ACTIONS


@respx.mock
def test_evidence_carries_a_utc_timestamp(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    runner.invoke(app, [*BASE_ARGUMENTS, "--evidence", str(destination)], env=WIDE_TERMINAL)
    stamped = datetime.fromisoformat(json.loads(destination.read_text())["generated_at"])

    assert stamped.tzinfo is not None
    assert stamped.utcoffset() == timedelta(0)


@respx.mock
def test_evidence_is_never_shortened_by_a_display_filter(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    """--min-severity chooses what is listed; an audit artefact keeps everything."""
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    result = runner.invoke(
        app,
        [*BASE_ARGUMENTS, "--format", "json", "--min-severity", "Critical",
         "--evidence", str(destination)],
        env=WIDE_TERMINAL,
    )
    record = json.loads(destination.read_text())

    assert len(json.loads(result.stdout)["actions"]) < MEASURED_ACTIONS
    assert len(record["actions"]) == MEASURED_ACTIONS
    assert record["min_severity"] == "Critical"


@respx.mock
def test_evidence_never_writes_credentials_from_the_url(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    runner.invoke(
        app,
        ["scan", "--url", "https://reader:hunter2@indexer.example.test:9200",
         "--user", "reader", "--evidence", str(destination)],
        env=WIDE_TERMINAL,
    )
    written = destination.read_text()

    assert "hunter2" not in written
    assert json.loads(written)["indexer_url"] == "https://indexer.example.test:9200"


@respx.mock
def test_an_unwritable_evidence_path_exits_nonzero(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--evidence", str(tmp_path / "missing" / "e.json")],
        env=WIDE_TERMINAL,
    )

    assert result.exit_code == 1
    assert "evidence file" in result.stderr


@respx.mock
def test_the_written_evidence_file_validates_against_the_schema(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    """SPEC-04 section 5, criterion 3: the file reads back as a complete record."""
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "scan-2026-08-31.json"

    runner.invoke(app, [*BASE_ARGUMENTS, "--evidence", str(destination)], env=WIDE_TERMINAL)
    record = EvidenceRecord.model_validate_json(destination.read_text(encoding="utf-8"))

    assert record.total_findings == MEASURED_FINDINGS
    assert len(record.actions) == MEASURED_ACTIONS
    assert len(record.unfixable) == MEASURED_UNFIXABLE_ENTRIES


@respx.mock
def test_a_failed_scan_writes_no_evidence_file_at_all(
    indexer_password: str,
    tmp_path: Path,
) -> None:
    """SPEC-04 section 5, criterion 4, with the cheapest failure: bad credentials."""
    respx.route().mock(return_value=httpx.Response(401, json={}))
    destination = tmp_path / "scan-2026-08-31.json"

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--evidence", str(destination)], env=WIDE_TERMINAL
    )

    assert result.exit_code == 1
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


@respx.mock
def test_a_write_that_fails_partway_leaves_no_partial_evidence_file(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SPEC-04 section 4: what the atomic rename buys.

    A full disk is the realistic partway failure, and on a filesystem that
    allocates lazily it surfaces when the buffer reaches the disk rather than
    at the write() call.
    """
    respx.route().mock(side_effect=fake_indexer)
    yesterday = tmp_path / "scan-2026-08-30.json"
    yesterday.write_text('{"schema_version": "2"}', encoding="utf-8")
    today = tmp_path / "scan-2026-08-31.json"

    def out_of_space(descriptor: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", out_of_space)
    result = runner.invoke(app, [*BASE_ARGUMENTS, "--evidence", str(today)], env=WIDE_TERMINAL)

    assert result.exit_code == 1
    assert "No space left on device" in result.stderr
    assert not today.exists()
    assert yesterday.read_text(encoding="utf-8") == '{"schema_version": "2"}'
    assert list(tmp_path.iterdir()) == [yesterday]


@respx.mock
def test_the_evidence_file_stays_readable_to_an_auditor(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    """The temporary file the atomic write goes through is private; this is not."""
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    runner.invoke(app, [*BASE_ARGUMENTS, "--evidence", str(destination)], env=WIDE_TERMINAL)

    assert destination.stat().st_mode & stat.S_IRGRP
    assert destination.stat().st_mode & stat.S_IROTH


@respx.mock
def test_no_evidence_file_is_written_unless_asked(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    runner.invoke(app, [*BASE_ARGUMENTS, "--format", "json"], env=WIDE_TERMINAL)

    assert list(tmp_path.iterdir()) == []


@respx.mock
def test_the_register_is_shown_by_default(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--top", "3"], env=WIDE_TERMINAL)

    assert result.exit_code == 0
    assert "No vendor fix available" in result.stdout


@respx.mock
def test_no_unfixable_suppresses_the_register(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--top", "3", "--no-unfixable"], env=WIDE_TERMINAL
    )

    assert result.exit_code == 0
    assert "No vendor fix available" not in result.stdout
    assert "linux-oracle" not in result.stdout


@respx.mock
def test_no_unfixable_never_shortens_the_json_contract(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app,
        [*BASE_ARGUMENTS, "--format", "json", "--no-unfixable"],
        env=WIDE_TERMINAL,
    )

    assert json.loads(result.stdout)["unfixable"] != []


@respx.mock
def test_min_severity_filters_both_tables(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    """SPEC-02 section 8: it stays a display filter, in the register too."""
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(
        app, [*BASE_ARGUMENTS, "--format", "json", "--min-severity", "Critical"],
        env=WIDE_TERMINAL,
    )
    plan = json.loads(result.stdout)

    assert result.exit_code == 0
    assert 0 < len(plan["unfixable"]) < 362


@respx.mock
def test_evidence_records_the_fixability_partition(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    """SPEC-02 section 9: the register is the part an auditor reads."""
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    runner.invoke(
        app,
        [*BASE_ARGUMENTS, "--format", "json", "--evidence", str(destination)],
        env=WIDE_TERMINAL,
    )
    record = json.loads(destination.read_text())

    assert record["fixable_findings"] == 13_659
    assert record["fixable_criticals"] == 1_322
    assert record["no_fix_findings"] == 19_059
    assert record["no_fix_criticals"] == 1_170
    assert record["unknown_fixability_findings"] == 0
    assert record["total_criticals"] == 2_492
    assert record["fixable_distinct_packages"] == 453
    assert len(record["unfixable"]) == 362


@respx.mock
def test_evidence_keeps_the_register_when_the_display_hides_it(
    fake_indexer: FakeIndexer,
    indexer_password: str,
    tmp_path: Path,
) -> None:
    respx.route().mock(side_effect=fake_indexer)
    destination = tmp_path / "evidence.json"

    runner.invoke(
        app,
        [*BASE_ARGUMENTS, "--no-unfixable", "--evidence", str(destination)],
        env=WIDE_TERMINAL,
    )
    record = json.loads(destination.read_text())

    assert len(record["unfixable"]) == 362
