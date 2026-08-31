"""Command line entry point."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vulnfold import __version__
from vulnfold.client import IndexerClient
from vulnfold.collapse import build_patch_plan
from vulnfold.config import (
    DEFAULT_MAPPING_NAME,
    DEFAULT_PASSWORD_ENV_VAR,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOP_ACTIONS,
    EVIDENCE_FILE_MODE,
    ScanConfig,
)
from vulnfold.errors import ConfigurationError, VulnfoldError
from vulnfold.mapping import load_mapping
from vulnfold.models import FieldMapping, IndexerSnapshot, PatchPlan, RankBy
from vulnfold.render import (
    OutputFormat,
    build_evidence_record,
    build_table_view,
    render_evidence,
    render_json,
    render_markdown,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Collapse Wazuh vulnerability findings into a ranked patch plan.",
)

_stdout = Console()
_stderr = Console(stderr=True)


@app.callback()
def main() -> None:
    """Keep ``scan`` a subcommand; typer collapses a lone command into the app."""


@app.command()
def scan(
    url: Annotated[str, typer.Option("--url", help="Indexer base URL.")],
    user: Annotated[str, typer.Option("--user", help="Indexer account with read access.")],
    password_env: Annotated[
        str,
        typer.Option("--password-env", help="Environment variable holding the password."),
    ] = DEFAULT_PASSWORD_ENV_VAR,
    password: Annotated[
        str | None,
        typer.Option("--password", help="Discouraged: passwords leak into shell history."),
    ] = None,
    index_pattern: Annotated[
        str | None,
        typer.Option("--index-pattern", help="Override the mapping's index pattern."),
    ] = None,
    mapping_name: Annotated[
        str,
        typer.Option("--mapping", help="Field mapping name, or path to a mapping file."),
    ] = DEFAULT_MAPPING_NAME,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
    top: Annotated[
        int, typer.Option("--top", min=1, help="Rows listed per table in table and markdown.")
    ] = DEFAULT_TOP_ACTIONS,
    rank_by: Annotated[
        RankBy, typer.Option("--rank-by", help="Order actions by criticals or by findings.")
    ] = RankBy.CRITICALS,
    group_kernels: Annotated[
        bool,
        typer.Option("--group-kernels", help="Merge each kernel package's versions."),
    ] = False,
    evidence: Annotated[
        Path | None,
        typer.Option("--evidence", help="Write the complete run to this JSON file."),
    ] = None,
    min_severity: Annotated[
        str | None,
        typer.Option("--min-severity", help="List only rows relevant at this severity or above."),
    ] = None,
    no_unfixable: Annotated[
        bool,
        typer.Option("--no-unfixable", help="Suppress the register of findings with no fix."),
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", min=0.1, help="Per-request timeout in seconds.")
    ] = DEFAULT_TIMEOUT_SECONDS,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Disable TLS certificate verification.")
    ] = False,
) -> None:
    """Read a Wazuh indexer and print the patch plan it implies."""
    try:
        mapping = load_mapping(mapping_name)
        snapshot = _read_fleet(
            url=url,
            user=user,
            password=_resolve_password(password_env, password),
            index_pattern=index_pattern,
            mapping=mapping,
            timeout=timeout,
            insecure=insecure,
        )
        plan = build_patch_plan(
            snapshot,
            mapping,
            rank_by=rank_by,
            group_kernels=group_kernels,
            min_severity=min_severity,
        )
        if evidence is not None:
            _write_evidence(
                snapshot,
                mapping,
                path=evidence,
                url=url,
                index_pattern=index_pattern or mapping.index_pattern,
                rank_by=rank_by,
                group_kernels=group_kernels,
                min_severity=min_severity,
            )
    except VulnfoldError as exc:
        _stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _write(plan, output_format, top, show_unfixable=not no_unfixable)


def _read_fleet(
    *,
    url: str,
    user: str,
    password: str,
    index_pattern: str | None,
    mapping: FieldMapping,
    timeout: float,
    insecure: bool,
) -> IndexerSnapshot:
    """Open a read-only connection and take one snapshot of the fleet."""
    if insecure:
        _stderr.print(
            "[yellow]warning[/yellow] TLS certificate verification is disabled. "
            "The connection to the indexer is not authenticated."
        )

    config = ScanConfig(
        url=url,
        username=user,
        password=password,
        index_pattern=index_pattern or mapping.index_pattern,
        verify_tls=not insecure,
        timeout_seconds=timeout,
    )

    with IndexerClient(config, mapping) as client:
        client.verify_readable()
        return client.fetch_snapshot()


def _write_evidence(
    snapshot: IndexerSnapshot,
    mapping: FieldMapping,
    *,
    path: Path,
    url: str,
    index_pattern: str,
    rank_by: RankBy,
    group_kernels: bool,
    min_severity: str | None,
) -> None:
    """Write the audit record for this run.

    The record is built from the unfiltered plan: --min-severity chooses what
    is listed on screen, and must never shorten an audit artefact.
    """
    complete = build_patch_plan(snapshot, mapping, rank_by=rank_by, group_kernels=group_kernels)
    record = build_evidence_record(
        complete,
        generated_at=datetime.now(timezone.utc),
        tool_version=__version__,
        indexer_url=url,
        index_pattern=index_pattern,
        mapping_version=mapping.version,
        group_kernels=group_kernels,
        min_severity=min_severity,
    )
    try:
        _replace_atomically(path, render_evidence(record))
    except OSError as exc:
        raise ConfigurationError(f"Cannot write the evidence file {path}: {exc}") from exc
    _stderr.print(f"evidence written to {path}")


def _replace_atomically(path: Path, payload: str) -> None:
    """Put ``payload`` at ``path`` in one step, or leave ``path`` as it was.

    Writing in place truncates first, so an I/O failure partway through — a
    full disk is the realistic one — would leave a truncated file carrying the
    day's name. A reader under audit pressure takes an empty or half-written
    ``scan-<date>.json`` for "we scanned and found nothing", which is the worst
    way for this artefact to fail.

    Args:
        path: Destination file, replaced only once the payload is on disk.
        payload: Complete file contents.

    Raises:
        OSError: If the payload could not be written or the file not replaced.
            The destination is untouched and no temporary file is left behind.
    """
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(EVIDENCE_FILE_MODE)
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def _resolve_password(password_env: str, password: str | None) -> str:
    if password is not None:
        _stderr.print(
            "[yellow]warning[/yellow] --password was supplied on the command line, "
            "where it is visible in shell history and in the process list. Use "
            "--password-env instead."
        )
        return password

    value = os.environ.get(password_env)
    if not value:
        raise ConfigurationError(
            f"Environment variable {password_env} is unset or empty. Export the "
            f"indexer password there, or name a different variable with "
            f"--password-env."
        )
    return value


def _write(
    plan: PatchPlan,
    output_format: OutputFormat,
    top: int,
    *,
    show_unfixable: bool,
) -> None:
    """Write the plan, keeping machine formats free of terminal decoration.

    ``--no-unfixable`` is a display choice, so it shortens the two reports a
    human reads and never the JSON contract, which always carries both lists.
    """
    if output_format is OutputFormat.JSON:
        typer.echo(render_json(plan))
    elif output_format is OutputFormat.MARKDOWN:
        typer.echo(render_markdown(plan, top, show_unfixable=show_unfixable))
    else:
        _stdout.print(build_table_view(plan, top, show_unfixable=show_unfixable))
