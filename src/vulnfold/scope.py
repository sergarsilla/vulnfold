"""Which agents a plan covers, and what it leaves out (SPEC-06).

Pure functions over data the client fetched: no I/O, so the rules that decide
what an operator is told to patch are testable without an indexer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta

from vulnfold.models import (
    AgentScope,
    ScanWarning,
    WarningCode,
    AgentStatus,
    FleetScope,
    Fixability,
    IndexerSnapshot,
    IndexInventory,
    LivenessSnapshot,
    PatchPlan,
    ScopeTotals,
)

#: Statuses whose findings the displayed plan covers.
IN_PLAN_STATUSES: frozenset[AgentStatus] = frozenset({AgentStatus.ACTIVE, AgentStatus.UNKNOWN})


def find_superseded_indices(inventory: IndexInventory) -> dict[str, list[str]]:
    """Name, per state index, the agents whose documents there are stale copies.

    An agent spread over several indices is current only in the one holding its
    newest detection. When any of those indices carries no detection time the
    newest cannot be told, and every copy is kept.

    Args:
        inventory: Which indices hold each agent.

    Returns:
        Index name to the agents superseded in it, sorted for stable queries.
    """
    superseded: dict[str, list[str]] = {}
    for agent, newest_by_index in inventory.newest_detection.items():
        if len(newest_by_index) < 2 or any(stamp is None for stamp in newest_by_index.values()):
            continue
        parsed = {index: _parse_time(stamp) for index, stamp in newest_by_index.items()}
        freshest = max(parsed, key=lambda index: parsed[index])
        for index in parsed:
            if index != freshest:
                superseded.setdefault(index, []).append(agent)
    return {index: sorted(agents) for index, agents in sorted(superseded.items())}


def count_superseded_findings(
    inventory: IndexInventory, superseded: Mapping[str, Iterable[str]]
) -> int:
    """Total the documents a superseded-index exclusion removes."""
    return sum(
        inventory.findings.get(agent, {}).get(index, 0)
        for index, agents in superseded.items()
        for agent in agents
    )


def classify_agents(
    agent_ids: Iterable[str],
    liveness: LivenessSnapshot | None,
    *,
    now: datetime,
    stale_after_days: int,
) -> dict[str, AgentStatus]:
    """Decide, for every agent with findings, whether its findings are current.

    Args:
        agent_ids: Agents that carry findings.
        liveness: Newest monitoring snapshots, or ``None`` when unavailable.
        now: The reference time, passed in so the rule stays pure.
        stale_after_days: Age beyond which a last-seen time is stale.

    Returns:
        Agent id to status. Without liveness every agent is ``UNKNOWN``.
    """
    if liveness is None:
        return {agent: AgentStatus.UNKNOWN for agent in agent_ids}
    cutoff = now - timedelta(days=stale_after_days)
    statuses: dict[str, AgentStatus] = {}
    for agent in agent_ids:
        seen = liveness.agents.get(agent)
        if seen is None:
            statuses[agent] = AgentStatus.UNREGISTERED
        elif seen.last_seen is not None and seen.last_seen >= cutoff:
            statuses[agent] = AgentStatus.ACTIVE
        else:
            statuses[agent] = AgentStatus.STALE
    return statuses


def agents_in_plan(statuses: Mapping[str, AgentStatus]) -> list[str]:
    """Return the agents whose findings the displayed plan covers, sorted."""
    return sorted(agent for agent, status in statuses.items() if status in IN_PLAN_STATUSES)


def scope_totals(plan: PatchPlan, agents: int) -> ScopeTotals:
    """Summarise a plan's headline counters for one set of agents."""
    return ScopeTotals(
        agents=agents,
        findings=plan.total_findings,
        criticals=plan.total_criticals,
        fixable_findings=plan.fixable_findings,
        fixable_criticals=plan.fixable_criticals,
        no_fix_findings=plan.no_fix_findings,
        no_fix_criticals=plan.no_fix_criticals,
    )


def build_agent_scopes(
    fleet: IndexerSnapshot,
    statuses: Mapping[str, AgentStatus],
    liveness: LivenessSnapshot | None,
) -> list[AgentScope]:
    """List every agent with its status and the findings it carries.

    Ordered by status (out-of-plan first), then by findings, largest first,
    so the agents most distorting an unscoped report lead the list.
    """
    findings: dict[str, int] = {agent: 0 for agent in statuses}
    fixable: dict[str, int] = {agent: 0 for agent in statuses}
    for bucket in fleet.buckets:
        for agent, count in bucket.agent_counts.items():
            findings[agent] = findings.get(agent, 0) + count
            if bucket.fixability is Fixability.FIXABLE:
                fixable[agent] = fixable.get(agent, 0) + count
    scopes = []
    for agent, status in statuses.items():
        seen = liveness.agents.get(agent) if liveness is not None else None
        scopes.append(
            AgentScope(
                agent_id=agent,
                name=(seen.name if seen is not None else None) or fleet.agent_names.get(agent),
                status=status,
                last_seen=seen.last_seen if seen is not None else None,
                findings=findings.get(agent, 0),
                fixable_findings=fixable.get(agent, 0),
            )
        )
    scopes.sort(key=lambda scope: (scope.status in IN_PLAN_STATUSES, -scope.findings, scope.agent_id))
    return scopes


def build_fleet_scope(
    *,
    active_plan: PatchPlan,
    fleet_plan: PatchPlan,
    fleet: IndexerSnapshot,
    statuses: Mapping[str, AgentStatus],
    liveness: LivenessSnapshot | None,
    stale_after_days: int,
    superseded_findings: int,
    superseded_indices: Iterable[str],
) -> FleetScope:
    """Assemble what a scoped run covers and leaves out.

    Args:
        active_plan: Plan over the agents in scope, unshortened by any filter.
        fleet_plan: Plan over every agent, superseded copies excluded.
        fleet: The snapshot ``fleet_plan`` was built from.
        statuses: Every agent's status.
        liveness: Newest monitoring snapshots, or ``None``.
        stale_after_days: The staleness threshold in force.
        superseded_findings: Documents excluded as superseded copies.
        superseded_indices: Indices holding those copies.

    Returns:
        The scope record attached to plans and evidence.
    """
    return FleetScope(
        stale_after_days=stale_after_days,
        liveness_available=liveness is not None,
        liveness_snapshot_time=liveness.snapshot_time if liveness is not None else None,
        active=scope_totals(active_plan, len(agents_in_plan(statuses))),
        fleet=scope_totals(fleet_plan, len(statuses)),
        agents=build_agent_scopes(fleet, statuses, liveness),
        superseded_findings=superseded_findings,
        superseded_indices=sorted(superseded_indices),
    )


def scope_warnings(
    *,
    liveness_configured: bool,
    liveness: LivenessSnapshot | None,
    superseded_findings: int,
    superseded_indices: Iterable[str],
) -> list[ScanWarning]:
    """Report what scoping could not do, or what it removed.

    Args:
        liveness_configured: Whether the mapping names a liveness source.
        liveness: What that source returned, or ``None``.
        superseded_findings: Documents excluded as superseded copies.
        superseded_indices: Indices holding those copies.

    Returns:
        Zero, one or two warnings.
    """
    warnings: list[ScanWarning] = []
    if liveness_configured and liveness is None:
        warnings.append(
            ScanWarning(
                code=WarningCode.LIVENESS_UNAVAILABLE,
                message=(
                    "Agent liveness could not be read, so every agent counts as active "
                    "and machines that stopped reporting stay in the plan. Check that "
                    "the monitoring index exists and that this account can read it."
                ),
            )
        )
    indices = sorted(superseded_indices)
    if superseded_findings:
        warnings.append(
            ScanWarning(
                code=WarningCode.SUPERSEDED_INDEX_FINDINGS,
                message=(
                    f"{superseded_findings} findings were excluded as stale copies: their "
                    f"agents have newer findings in another state index. Indices holding "
                    f"them: {', '.join(indices)}."
                ),
                detail={"findings": superseded_findings, "indices": ", ".join(indices)},
            )
        )
    return warnings


def _parse_time(stamp: str | None) -> datetime:
    return datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
