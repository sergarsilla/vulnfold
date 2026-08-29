"""Output formats.

Every format opens with the same impact line, because that line is the product:
it states how much of the noise a handful of upgrades removes.
"""

from __future__ import annotations

from enum import Enum

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from vulnfold.config import UNKNOWN_SEVERITY
from vulnfold.models import PatchPlan, RemediationAction

NOTHING_TO_REMEDIATE = "Nothing to remediate."
KERNEL_MARK = "yes"

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
        One or two lines: the collapse, then what the leading actions remove.
    """
    action_count = len(plan.coverage_curve)
    headline = (
        f"{plan.total_findings:,} findings → {action_count:,} actions "
        f"across {plan.total_distinct_packages:,} packages "
        f"(ratio {plan.collapse_ratio:.0f}:1)"
    )
    if not plan.coverage_curve:
        return [headline, NOTHING_TO_REMEDIATE]

    leading = min(top, action_count)
    point = plan.coverage_curve[leading - 1]
    return [
        headline,
        f"The first {leading} eliminate {point.cumulative_findings:,} findings "
        f"({point.findings_percentage:.1f}%) and "
        f"{point.cumulative_criticals:,} criticals.",
    ]


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

    table = Table(title=None, header_style="bold", expand=False)
    for column in _ACTION_COLUMNS:
        table.add_column(column, justify="right" if column not in ("Package", "Version") else "left")
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
