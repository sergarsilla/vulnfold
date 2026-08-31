"""The scheduled scan hook and its units: SPEC-04 sections 3 to 5.

The script is exercised with a stand-in for the Docker CLI, so retention is
asserted against real files without a daemon, an image, credentials, or a wait
of ninety-one days.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_ROOT = PROJECT_ROOT / "deploy"
SCAN_SCRIPT = DEPLOY_ROOT / "vulnfold-scan.sh"
SERVICE_UNIT = DEPLOY_ROOT / "vulnfold-scan.service"
TIMER_UNIT = DEPLOY_ROOT / "vulnfold-scan.timer"

#: Where the script is installed, and therefore what the service must start.
INSTALLED_SCAN_PATH = "/usr/local/sbin/vulnfold-scan"

RETENTION_DAYS = 90
EVIDENCE_CONTENT = '{"schema_version": "2"}'

#: Stands in for the Docker CLI: writes the file the container would write, or
#: fails the way a scan against a refused login fails.
DOCKER_STUB = """#!/bin/sh
set -eu
if [ "${VULNFOLD_STUB_FAILS:-0}" = "1" ]; then
    echo "stub: the scan failed" >&2
    exit 1
fi
printf '%s' '""" + EVIDENCE_CONTENT + """' > "${VULNFOLD_EVIDENCE_ARG#--evidence=}"
"""


@pytest.fixture
def app_dir(tmp_path: Path) -> Path:
    """A stand-in for /opt/vulnfold, holding the evidence bind mount."""
    (tmp_path / "evidence").mkdir()
    return tmp_path


@pytest.fixture
def stub_path_entry(tmp_path: Path) -> Path:
    """A PATH entry whose only occupant is the fake ``docker``."""
    directory = tmp_path / "stub-bin"
    directory.mkdir()
    stub = directory / "docker"
    stub.write_text(DOCKER_STUB, encoding="utf-8")
    stub.chmod(0o755)
    return directory


def run_scan(
    app_dir: Path,
    stub_path_entry: Path,
    *,
    scan_fails: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the installed script against the stand-in Docker CLI."""
    environment = {
        "PATH": f"{stub_path_entry}{os.pathsep}{os.environ['PATH']}",
        "VULNFOLD_APP_DIR": str(app_dir),
        "VULNFOLD_STUB_FAILS": "1" if scan_fails else "0",
    }
    return subprocess.run(
        [str(SCAN_SCRIPT)], capture_output=True, text=True, env=environment
    )


def evidence_named_and_stamped(directory: Path, *, days_ago: int) -> Path:
    """Create an evidence file named and timestamped ``days_ago`` in the past."""
    stamp = datetime.now(timezone.utc) - timedelta(days=days_ago)
    path = directory / f"scan-{stamp:%Y-%m-%d}.json"
    path.write_text(EVIDENCE_CONTENT, encoding="utf-8")
    os.utime(path, (stamp.timestamp(), stamp.timestamp()))
    return path


def todays_evidence(directory: Path) -> Path:
    return directory / f"scan-{datetime.now(timezone.utc):%Y-%m-%d}.json"


# ---------------------------------------------------------------------------
# The scan itself (SPEC-04 section 3)
# ---------------------------------------------------------------------------


def test_the_script_writes_evidence_for_todays_date(
    app_dir: Path,
    stub_path_entry: Path,
) -> None:
    result = run_scan(app_dir, stub_path_entry)

    assert result.returncode == 0, result.stderr
    assert todays_evidence(app_dir / "evidence").read_text(encoding="utf-8") == EVIDENCE_CONTENT


def test_a_second_run_on_the_same_day_overwrites_rather_than_accumulating(
    app_dir: Path,
    stub_path_entry: Path,
) -> None:
    """The file is the day's state, not an append log."""
    run_scan(app_dir, stub_path_entry)
    run_scan(app_dir, stub_path_entry)

    assert list((app_dir / "evidence").iterdir()) == [todays_evidence(app_dir / "evidence")]


# ---------------------------------------------------------------------------
# Retention (SPEC-04 section 5, criteria 5 and 6)
# ---------------------------------------------------------------------------


def test_retention_deletes_evidence_older_than_the_window(
    app_dir: Path,
    stub_path_entry: Path,
) -> None:
    evidence = app_dir / "evidence"
    stale = evidence_named_and_stamped(evidence, days_ago=RETENTION_DAYS + 1)

    result = run_scan(app_dir, stub_path_entry)

    assert result.returncode == 0, result.stderr
    assert not stale.exists()


def test_retention_keeps_evidence_inside_the_window(
    app_dir: Path,
    stub_path_entry: Path,
) -> None:
    evidence = app_dir / "evidence"
    fresh = evidence_named_and_stamped(evidence, days_ago=RETENTION_DAYS - 1)

    result = run_scan(app_dir, stub_path_entry)

    assert result.returncode == 0, result.stderr
    assert fresh.read_text(encoding="utf-8") == EVIDENCE_CONTENT


def test_a_failed_scan_deletes_no_history_and_writes_no_evidence(
    app_dir: Path,
    stub_path_entry: Path,
) -> None:
    """SPEC-04 section 5, criterion 6: retention never runs before a good scan."""
    evidence = app_dir / "evidence"
    stale = evidence_named_and_stamped(evidence, days_ago=RETENTION_DAYS + 1)

    result = run_scan(app_dir, stub_path_entry, scan_fails=True)

    assert result.returncode != 0
    assert stale.exists()
    assert not todays_evidence(evidence).exists()


# ---------------------------------------------------------------------------
# The units (SPEC-04 section 5, criteria 1 and 2)
# ---------------------------------------------------------------------------


def test_the_service_starts_the_command_the_script_documents_installing() -> None:
    """A rename reaching only one of the two files would break the timer."""
    script = SCAN_SCRIPT.read_text(encoding="utf-8")
    service = SERVICE_UNIT.read_text(encoding="utf-8")

    assert INSTALLED_SCAN_PATH in script
    assert f"ExecStart={INSTALLED_SCAN_PATH}\n" in service


def test_the_units_pass_systemd_analyze_verify(tmp_path: Path) -> None:
    """SPEC-04 section 5, criterion 2.

    ExecStart is repointed at a copy of the script, because verify requires the
    command to exist and the real one is installed by hand on the deployment
    host, never here. Every other line is the shipped one.
    """
    if shutil.which("systemd-analyze") is None:
        pytest.skip("systemd-analyze is not installed")

    installed = tmp_path / "vulnfold-scan"
    installed.write_text(SCAN_SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    installed.chmod(0o755)
    service = tmp_path / SERVICE_UNIT.name
    service.write_text(
        SERVICE_UNIT.read_text(encoding="utf-8").replace(INSTALLED_SCAN_PATH, str(installed)),
        encoding="utf-8",
    )
    timer = tmp_path / TIMER_UNIT.name
    timer.write_text(TIMER_UNIT.read_text(encoding="utf-8"), encoding="utf-8")

    result = subprocess.run(
        ["systemd-analyze", "verify", str(service), str(timer)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
