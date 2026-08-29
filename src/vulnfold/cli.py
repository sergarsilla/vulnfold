"""Command line entry point."""

from __future__ import annotations

import os
from typing import Annotated

import typer
from rich.console import Console

from vulnfold.client import IndexerClient
from vulnfold.collapse import build_patch_plan
from vulnfold.config import (
    DEFAULT_MAPPING_NAME,
    DEFAULT_PASSWORD_ENV_VAR,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOP_ACTIONS,
    ScanConfig,
)
from vulnfold.errors import ConfigurationError, VulnfoldError
from vulnfold.mapping import load_mapping
from vulnfold.models import PatchPlan
from vulnfold.render import OutputFormat, build_table_view, render_json, render_markdown

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
        int, typer.Option("--top", min=1, help="Actions listed in table and markdown.")
    ] = DEFAULT_TOP_ACTIONS,
    group_kernels: Annotated[
        bool,
        typer.Option("--group-kernels", help="Merge each kernel package's versions."),
    ] = False,
    min_severity: Annotated[
        str | None,
        typer.Option("--min-severity", help="List only actions relevant at this severity or above."),
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", min=0.1, help="Per-request timeout in seconds.")
    ] = DEFAULT_TIMEOUT_SECONDS,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Disable TLS certificate verification.")
    ] = False,
) -> None:
    """Read a Wazuh indexer and print the patch plan it implies."""
    try:
        plan = _scan(
            url=url,
            user=user,
            password=_resolve_password(password_env, password),
            index_pattern=index_pattern,
            mapping_name=mapping_name,
            group_kernels=group_kernels,
            min_severity=min_severity,
            timeout=timeout,
            insecure=insecure,
        )
    except VulnfoldError as exc:
        _stderr.print(f"[red]error[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _write(plan, output_format, top)


def _scan(
    *,
    url: str,
    user: str,
    password: str,
    index_pattern: str | None,
    mapping_name: str,
    group_kernels: bool,
    min_severity: str | None,
    timeout: float,
    insecure: bool,
) -> PatchPlan:
    mapping = load_mapping(mapping_name)
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
        snapshot = client.fetch_snapshot()

    return build_patch_plan(
        snapshot,
        mapping,
        group_kernels=group_kernels,
        min_severity=min_severity,
    )


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


def _write(plan: PatchPlan, output_format: OutputFormat, top: int) -> None:
    """Write the plan, keeping machine formats free of terminal decoration."""
    if output_format is OutputFormat.JSON:
        typer.echo(render_json(plan))
    elif output_format is OutputFormat.MARKDOWN:
        typer.echo(render_markdown(plan, top))
    else:
        _stdout.print(build_table_view(plan, top))
