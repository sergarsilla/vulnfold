"""Output formats.

Every format opens with the same impact line, because that line is the product:
it states how much of the noise a handful of upgrades removes.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from urllib.parse import urlsplit, urlunsplit

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from vulnfold.config import UNKNOWN_SEVERITY
from vulnfold.models import EvidenceRecord, PatchPlan, RemediationAction

NOTHING_TO_REMEDIATE = "Nothing to remediate."
KERNEL_MARK = "yes"

#: Package is the column a reader acts on, so it keeps its full width and
#: Version gives way. A truncated package name is unusable — "linux-..." names
#: no upgrade — while a truncated version still identifies which upgrade is
#: meant, and the untruncated string is always in the JSON and Markdown output.
VERSION_MAX_WIDTH = 14
_LEFT_ALIGNED = ("Package", "Version")

_ACTION_COLUMNS = (
    "#",
    "Package",
    "Version",
    "Hosts",
    "Findings",
    "% total",
    "CVEs",
    "Critical",
    "High",
    "Unrated",
    "Kernel",
)


class OutputFormat(str, Enum):
    """Formats a plan can be written in."""

    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"


def impact_lines(plan: PatchPlan, top: int) -> list[str]:
    """Build the headline that opens the table and markdown reports.

    Args:
        plan: Plan to summarise.
        top: How many leading actions the report is about to show.

    Returns:
        The collapse, where that collapse comes from, and both product claims:
        what the leading actions remove ordered by findings, and ordered by
        criticals. Both are always shown, whichever ordering is active, because
        each is a claim the tool makes and they need not agree.
    """
    action_count = len(plan.coverage_curve)
    headline = (
        f"{plan.total_findings:,} findings → {action_count:,} actions "
        f"across {plan.total_distinct_packages:,} packages "
        f"(ratio {plan.collapse_ratio:.0f}:1)"
    )
    if not plan.coverage_curve:
        return [headline, NOTHING_TO_REMEDIATE]

    sources = plan.collapse_sources
    leading = min(top, action_count)
    by_findings = plan.coverage_by_findings[leading - 1]
    by_criticals = plan.coverage_by_criticals[leading - 1]

    return [
        headline,
        f"Each action clears {sources.findings_per_action:.1f} findings: "
        f"{sources.cves_per_action:.1f} CVEs per package version "
        f"× {sources.hosts_per_action:.2f} hosts carrying it.",
        f"First {leading} by findings: {by_findings.cumulative_findings:,} findings "
        f"({by_findings.findings_percentage:.1f}%), on {_hosts(by_findings.cumulative_agents)}.",
        f"First {leading} by criticals: {by_criticals.cumulative_criticals:,} criticals "
        f"({by_criticals.criticals_percentage:.1f}%), on {_hosts(by_criticals.cumulative_agents)}.",
    ]


def _hosts(count: int) -> str:
    return f"{count:,} host" if count == 1 else f"{count:,} hosts"


def build_evidence_record(
    plan: PatchPlan,
    *,
    generated_at: datetime,
    tool_version: str,
    indexer_url: str,
    index_pattern: str,
    mapping_version: str,
    group_kernels: bool,
    min_severity: str | None,
) -> EvidenceRecord:
    """Assemble the audit record for one scan.

    Args:
        plan: The complete plan, unshortened by any display filter.
        generated_at: When the scan ran. Passed in so the record stays pure.
        tool_version: Version of vulnfold that produced it.
        indexer_url: Indexer the scan read. Credentials are stripped.
        index_pattern: Index pattern the scan read.
        mapping_version: Version of the field mapping in force.
        group_kernels: Whether kernel versions were merged.
        min_severity: Display filter recorded for reproducibility.

    Returns:
        A record conforming to ``docs/evidence-schema.md``.
    """
    return EvidenceRecord(
        generated_at=generated_at,
        tool_version=tool_version,
        indexer_url=_without_credentials(indexer_url),
        index_pattern=index_pattern,
        mapping_version=mapping_version,
        rank_by=plan.rank_by,
        group_kernels=group_kernels,
        min_severity=min_severity,
        total_findings=plan.total_findings,
        total_agents=plan.total_agents,
        total_distinct_cves=plan.total_distinct_cves,
        total_distinct_packages=plan.total_distinct_packages,
        collapse_ratio=plan.collapse_ratio,
        collapse_sources=plan.collapse_sources,
        actions=plan.actions,
        coverage_by_findings=plan.coverage_by_findings,
        coverage_by_criticals=plan.coverage_by_criticals,
        warnings=plan.warnings,
    )


def _without_credentials(url: str) -> str:
    """Strip any user:password embedded in a URL before it is written to disk."""
    parsed = urlsplit(url)
    if parsed.username is None and parsed.password is None:
        return url
    authority = parsed.hostname or ""
    if parsed.port is not None:
        authority = f"{authority}:{parsed.port}"
    return urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, parsed.fragment))


def render_evidence(record: EvidenceRecord) -> str:
    """Serialize an evidence record.

    Args:
        record: The record to serialize.

    Returns:
        Indented JSON, the stable contract documented in
        ``docs/evidence-schema.md``.
    """
    return record.model_dump_json(indent=2)


def render_json(plan: PatchPlan) -> str:
    """Serialize the whole plan.

    Args:
        plan: Plan to serialize.

    Returns:
        Indented JSON. This is the stable machine contract.
    """
    return plan.model_dump_json(indent=2)


def render_markdown(plan: PatchPlan, top: int) -> str:
    """Write the plan as a report that can be pasted into a ticket.

    Args:
        plan: Plan to render.
        top: Maximum number of actions to list.

    Returns:
        A Markdown document.
    """
    listed = plan.actions[:top]
    lines = ["# vulnfold patch plan", ""]
    lines += [f"**{line}**" for line in impact_lines(plan, top)]
    lines += [
        "",
        f"{plan.total_agents:,} agents · {plan.total_distinct_cves:,} distinct CVEs "
        f"· {plan.total_distinct_packages:,} distinct packages",
        "",
        f"## Top {len(listed):,} actions" if listed else "## Actions",
    ]

    if not listed:
        lines += ["", NOTHING_TO_REMEDIATE]
    else:
        lines += [
            "",
            "| " + " | ".join(_ACTION_COLUMNS) + " |",
            "|" + "|".join("---" for _ in _ACTION_COLUMNS) + "|",
        ]
        lines += [
            "| " + " | ".join(_action_cells(action, rank, plan.total_findings)) + " |"
            for rank, action in enumerate(listed, start=1)
        ]

    if plan.warnings:
        lines += ["", "## Warnings", ""]
        lines += [f"- `{warning.code.value}` {warning.message}" for warning in plan.warnings]

    return "\n".join(lines) + "\n"


def build_table_view(plan: PatchPlan, top: int) -> RenderableType:
    """Build the terminal view of the plan.

    Args:
        plan: Plan to render.
        top: Maximum number of actions to list.

    Returns:
        A rich renderable: the impact lines, the action table, then warnings.
    """
    listed = plan.actions[:top]
    header = Text("\n".join(impact_lines(plan, top)), style="bold")

    # Pin Package to the width its content actually needs: rich shrinks the
    # widest flexible column first, which would otherwise make the one column
    # a reader has to act on the first to lose characters.
    package_width = max((len(action.package_name) for action in listed), default=0)

    table = Table(title=None, header_style="bold", expand=False)
    for column in _ACTION_COLUMNS:
        table.add_column(
            column,
            justify="left" if column in _LEFT_ALIGNED else "right",
            no_wrap=True,
            overflow="ellipsis",
            min_width=package_width if column == "Package" else None,
            max_width=VERSION_MAX_WIDTH if column == "Version" else None,
        )
    for rank, action in enumerate(listed, start=1):
        table.add_row(*_action_cells(action, rank, plan.total_findings))

    parts: list[RenderableType] = [header, ""]
    parts.append(table if listed else Text(NOTHING_TO_REMEDIATE))
    if plan.warnings:
        parts.append("")
        parts.append(
            Text.from_markup(
                "\n".join(
                    f"[yellow]warning[/yellow] ({warning.code.value}) {warning.message}"
                    for warning in plan.warnings
                )
            )
        )
    return Group(*parts)


def _action_cells(action: RemediationAction, rank: int, total_findings: int) -> list[str]:
    return [
        str(rank),
        action.package_name,
        action.current_version,
        f"{action.agent_count:,}",
        f"{action.finding_count:,}",
        f"{_share(action.finding_count, total_findings):.1f}%",
        f"{action.cve_count:,}",
        f"{action.critical_count:,}",
        f"{action.high_count:,}",
        f"{action.severity_breakdown.get(UNKNOWN_SEVERITY, 0):,}",
        KERNEL_MARK if action.is_kernel else "",
    ]


def _share(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return 100.0 * part / whole
