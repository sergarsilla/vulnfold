"""Prometheus exposition of one scan (SPEC-05).

The output is a node-exporter textfile: one snapshot, written atomically by the
caller. vulnfold keeps no history; the monitoring stack that scrapes this file
does (CONTEXT.md, D4 as revised in 3.1).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime

from vulnfold.config import METRICS_HOSTS_IN_LABEL
from vulnfold.models import PatchPlan, RemediationAction, UnfixableEntry
from vulnfold.scope import IN_PLAN_STATUSES

METRIC_PREFIX = "vulnfold_"

Labels = dict[str, str]
Sample = tuple[Labels, float]


def escape_label_value(value: str) -> str:
    """Escape a label value as the exposition format requires.

    Args:
        value: Raw label value.

    Returns:
        The value with backslash, double quote and newline escaped.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def hosts_label(agent_ids: Sequence[str], agent_names: dict[str, str]) -> str:
    """Name the agents an entry touches, bounded in length.

    Args:
        agent_ids: Agent ids, in the order they should be listed.
        agent_names: Known names by agent id.

    Returns:
        ``name (id)`` for each listed agent, the bare id when no name is known,
        and a count of the agents beyond :data:`METRICS_HOSTS_IN_LABEL`.
    """
    shown = [
        f"{agent_names[agent]} ({agent})" if agent_names.get(agent) else agent
        for agent in agent_ids[:METRICS_HOSTS_IN_LABEL]
    ]
    hidden = len(agent_ids) - len(shown)
    if hidden > 0:
        shown.append(f"+{hidden} more")
    return ", ".join(shown)


def render_prometheus(plan: PatchPlan, *, generated_at: datetime, rows: int) -> str:
    """Render the complete plan as Prometheus exposition text.

    Args:
        plan: The complete plan, unshortened by any display filter.
        generated_at: When the scan ran.
        rows: Actions and register entries exported as row series.

    Returns:
        Exposition text ending in a newline.
    """
    actions = plan.actions[:rows]
    register = plan.unfixable[:rows]
    action_labels = [_action_labels(rank, a, plan.agent_names) for rank, a in enumerate(actions, 1)]
    entry_labels = [_entry_labels(rank, e, plan.agent_names) for rank, e in enumerate(register, 1)]
    curve = plan.coverage_curve[:rows]
    warning_counts = Counter(warning.code.value for warning in plan.warnings)

    families: list[tuple[str, str, list[Sample]]] = [
        ("last_scan_timestamp_seconds", "Unix time the scan ran.",
         [({}, generated_at.timestamp())]),
        ("findings", "Findings by fixability class.", [
            ({"class": "fixable"}, plan.fixable_findings),
            ({"class": "no_fix"}, plan.no_fix_findings),
            ({"class": "unknown"}, plan.unknown_fixability_findings),
        ]),
        ("criticals", "Critical findings by fixability class.", [
            ({"class": "fixable"}, plan.fixable_criticals),
            ({"class": "no_fix"}, plan.no_fix_criticals),
        ]),
        ("agents", "Distinct agents in the index.", [({}, plan.total_agents)]),
        ("fixable_packages", "Distinct packages with a published fix.",
         [({}, plan.fixable_distinct_packages)]),
        ("collapse_ratio", "Fixable findings per fixable package.", [({}, plan.collapse_ratio)]),
        ("action_findings", "Findings an action clears.",
         _rows(action_labels, (a.finding_count for a in actions))),
        ("action_criticals", "Critical findings an action clears.",
         _rows(action_labels, (a.critical_count for a in actions))),
        ("action_cves", "Distinct CVEs an action clears.",
         _rows(action_labels, (a.cve_count for a in actions))),
        ("action_agents", "Agents an action touches.",
         _rows(action_labels, (a.agent_count for a in actions))),
        ("unfixable_findings", "Findings with no published fix, per package version.",
         _rows(entry_labels, (e.finding_count for e in register))),
        ("unfixable_criticals", "Critical findings with no published fix, per package version.",
         _rows(entry_labels, (e.critical_count for e in register))),
        ("coverage_percent", "Share of fixable findings or criticals the first N actions clear.", [
            *(({"measure": "findings", "actions": str(p.action_count)}, p.findings_percentage)
              for p in curve),
            *(({"measure": "criticals", "actions": str(p.action_count)}, p.criticals_percentage)
              for p in curve),
        ]),
        ("warnings", "Warnings raised by the scan, by code.",
         [({"code": code}, count) for code, count in sorted(warning_counts.items())]),
    ]
    families += _scope_families(plan)

    lines: list[str] = []
    for name, help_text, samples in families:
        metric = f"{METRIC_PREFIX}{name}"
        lines.append(f"# HELP {metric} {help_text}")
        lines.append(f"# TYPE {metric} gauge")
        lines.extend(f"{metric}{_format_labels(labels)} {_format_value(value)}"
                     for labels, value in samples)
    return "\n".join(lines) + "\n"


def _scope_families(plan: PatchPlan) -> list[tuple[str, str, list[Sample]]]:
    """Fleet-wide counters and the agents the plan leaves out (SPEC-06)."""
    scope = plan.scope
    if scope is None:
        return []
    fleet = scope.fleet
    statuses = Counter(agent.status.value for agent in scope.agents)
    excluded = [agent for agent in scope.agents if agent.status not in IN_PLAN_STATUSES]
    labels = [
        {
            "agent": f"{agent.name} ({agent.agent_id})" if agent.name else agent.agent_id,
            "status": agent.status.value,
            "last_seen": agent.last_seen.date().isoformat() if agent.last_seen else "never",
        }
        for agent in excluded
    ]
    return [
        ("fleet_findings", "Findings by fixability class across every agent, in scope or not.", [
            ({"class": "fixable"}, fleet.fixable_findings),
            ({"class": "no_fix"}, fleet.no_fix_findings),
        ]),
        ("fleet_criticals", "Critical findings by fixability class across every agent.", [
            ({"class": "fixable"}, fleet.fixable_criticals),
            ({"class": "no_fix"}, fleet.no_fix_criticals),
        ]),
        ("agents_by_status", "Agents with findings, by liveness status.",
         [({"status": status}, count) for status, count in sorted(statuses.items())]),
        ("excluded_agent_findings", "Findings on an agent left out of the plan.",
         _rows(labels, (agent.findings for agent in excluded))),
        ("excluded_agent_fixable_findings", "Fixable findings on an agent left out of the plan.",
         _rows(labels, (agent.fixable_findings for agent in excluded))),
        ("superseded_findings", "Findings excluded as stale copies in a superseded state index.",
         [({}, scope.superseded_findings)]),
    ]


def _action_labels(rank: int, action: RemediationAction, agent_names: dict[str, str]) -> Labels:
    return {
        "rank": f"{rank:03d}",
        "package": action.package_name,
        "current_version": action.current_version,
        "target_version": action.target_version,
        "kernel": "true" if action.is_kernel else "false",
        "hosts": hosts_label(action.affected_agents, agent_names),
    }


def _entry_labels(rank: int, entry: UnfixableEntry, agent_names: dict[str, str]) -> Labels:
    return {
        "rank": f"{rank:03d}",
        "package": entry.package_name,
        "current_version": entry.current_version,
        "kernel": "true" if entry.is_kernel else "false",
        "hosts": hosts_label(entry.affected_agents, agent_names),
    }


def _rows(labels: Sequence[Labels], values: Iterable[float]) -> list[Sample]:
    return list(zip(labels, values))


def _format_labels(labels: Labels) -> str:
    if not labels:
        return ""
    body = ",".join(f'{key}="{escape_label_value(value)}"' for key, value in labels.items())
    return "{" + body + "}"


def _format_value(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))
