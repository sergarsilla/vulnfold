"""The command line: credentials from the environment, machine-readable output."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import pytest
import respx
from conftest import INDEXER_URL, FakeIndexer
from typer.testing import CliRunner

from vulnfold.cli import app
from vulnfold.config import DEFAULT_PASSWORD_ENV_VAR

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
    assert json.loads(result.stdout)["collapse_ratio"] == 59.06


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

    assert piped.stdout.strip() == "59.06"


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
    assert "The first 7 eliminate 23,309 findings (71.2%)" in result.stdout


@respx.mock
def test_table_is_the_default_format(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--top", "7"], env=WIDE_TERMINAL)

    assert result.exit_code == 0
    assert "32,718 findings → 744 actions across 554 packages (ratio 59:1)" in result.stdout
    assert "linux-image-6.14.0-37-generic" in result.stdout


@respx.mock
def test_top_limits_the_listed_actions(
    fake_indexer: FakeIndexer,
    indexer_password: str,
) -> None:
    respx.route().mock(side_effect=fake_indexer)

    result = runner.invoke(app, [*BASE_ARGUMENTS, "--top", "3"], env=WIDE_TERMINAL)

    assert "linux-image-cloud-amd64" in result.stdout
    assert "linux-oracle" not in result.stdout


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
    assert len(plan["actions"]) < 744
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
