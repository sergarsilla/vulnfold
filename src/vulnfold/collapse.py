"""Collapse engine: findings in, ranked patch plan out.

Pure domain logic. Nothing here performs I/O, reads configuration from the
environment or imports the indexer client; everything it needs arrives as an
:class:`IndexerSnapshot`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from fnmatch import fnmatch

from vulnfold.config import KERNEL_PACKAGE_PATTERNS, UNKNOWN_SEVERITY
from vulnfold.errors import ConfigurationError
from vulnfold.models import (
    CoveragePoint,
    FieldMapping,
    IndexerSnapshot,
    PackageBucket,
    PatchPlan,
    RemediationAction,
    ScanWarning,
    WarningCode,
)

GROUPED_VERSION_SEPARATOR = ", "


def is_kernel_package(package_name: str) -> bool:
    """Report whether a package name denotes a kernel.

    Args:
        package_name: Package name as the indexer stores it.

    Returns:
        ``True`` when the name matches any pattern in
        :data:`~vulnfold.config.KERNEL_PACKAGE_PATTERNS`.
    """
    return any(fnmatch(package_name, pattern) for pattern in KERNEL_PACKAGE_PATTERNS)


def collapse_findings_to_actions(
    snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> list[RemediationAction]:
    """Turn every ``(package, version)`` bucket into one remediation action.

    Args:
        snapshot: Read-only view of the fleet's vulnerability state.
        mapping: Mapping supplying the severity vocabulary.

    Returns:
        One action per bucket, in the order the buckets arrived.
    """
    return [_action_from_bucket(bucket, mapping) for bucket in snapshot.buckets]


def rank_actions(actions: Sequence[RemediationAction]) -> list[RemediationAction]:
    """Order actions by remediation impact.

    Criticals first, then highs, then raw finding count. Ties break
    alphabetically so the same input always renders the same output.

    Args:
        actions: Actions to order.

    Returns:
        A new list, ordered by impact.
    """
    return sorted(
        actions,
        key=lambda action: (
            -action.critical_count,
            -action.high_count,
            -action.finding_count,
            action.package_name,
            action.current_version,
        ),
    )


def group_kernel_actions(actions: Sequence[RemediationAction]) -> list[RemediationAction]:
    """Merge the versions of each kernel package into a single action.

    A kernel is remediated once per host regardless of how many versions of the
    package the fleet carries, so presenting each version separately overstates
    the work. Non-kernel actions pass through untouched.

    Args:
        actions: Actions to group.

    Returns:
        A new list in which kernel actions sharing a package name are merged.
    """
    grouped: dict[str, list[RemediationAction]] = {}
    passthrough: list[RemediationAction] = []
    for action in actions:
        if action.is_kernel:
            grouped.setdefault(action.package_name, []).append(action)
        else:
            passthrough.append(action)

    merged = [_merge_actions(group) for group in grouped.values()]
    return merged + passthrough


def filter_by_min_severity(
    actions: Sequence[RemediationAction],
    min_severity: str,
    mapping: FieldMapping,
) -> list[RemediationAction]:
    """Keep the actions worth showing at a severity threshold.

    An action survives when it carries at least one finding at or above the
    threshold, or any finding whose severity is unknown. Unrated findings are
    22% of real data and are never hidden by a severity filter, because hiding
    them would silently shrink the fleet's reported exposure.

    Args:
        actions: Actions to filter.
        min_severity: Threshold, named as the mapping names severities.
        mapping: Mapping supplying the severity ordering.

    Returns:
        The surviving actions, in the order given.

    Raises:
        ConfigurationError: ``min_severity`` is not a severity the mapping knows.
    """
    canonical = mapping.canonical_severity(min_severity)
    if canonical is None:
        known = ", ".join(mapping.severity_order)
        raise ConfigurationError(
            f"Unknown severity {min_severity!r}. Mapping {mapping.version!r} "
            f"declares: {known}."
        )

    threshold = mapping.severity_order.index(canonical)
    at_or_above = mapping.severity_order[: threshold + 1]
    return [
        action
        for action in actions
        if action.unknown_severity_count > 0
        or any(action.severity_breakdown.get(severity, 0) > 0 for severity in at_or_above)
    ]


def build_coverage_curve(
    ranked_actions: Sequence[RemediationAction],
    total_findings: int,
) -> list[CoveragePoint]:
    """Compute what the first N actions of a plan eliminate, for every N.

    Args:
        ranked_actions: Actions in the order they would be applied.
        total_findings: Fleet-wide finding total the percentages are taken over.

    Returns:
        One cumulative point per action.
    """
    total_criticals = sum(action.critical_count for action in ranked_actions)
    curve: list[CoveragePoint] = []
    findings_so_far = 0
    criticals_so_far = 0
    for position, action in enumerate(ranked_actions, start=1):
        findings_so_far += action.finding_count
        criticals_so_far += action.critical_count
        curve.append(
            CoveragePoint(
                action_count=position,
                cumulative_findings=findings_so_far,
                findings_percentage=_percentage(findings_so_far, total_findings),
                cumulative_criticals=criticals_so_far,
                criticals_percentage=_percentage(criticals_so_far, total_criticals),
            )
        )
    return curve


def build_patch_plan(
    snapshot: IndexerSnapshot,
    mapping: FieldMapping,
    *,
    group_kernels: bool = False,
    min_severity: str | None = None,
) -> PatchPlan:
    """Assemble the ranked patch plan for one snapshot.

    ``collapse_ratio`` is findings per distinct package, the compression a
    reader experiences when a finding list becomes a package list. It is
    deliberately not findings per action: a package carrying several versions
    yields several actions, and the ratio would then flatter the tool.

    ``coverage_curve`` always describes the complete ranked plan, even when
    ``min_severity`` shortens the action list, so "the first N actions" keeps
    one meaning across invocations.

    Args:
        snapshot: Read-only view of the fleet's vulnerability state.
        mapping: Field mapping in force.
        group_kernels: Merge each kernel package's versions into one action.
        min_severity: Only list actions relevant at this severity or above.

    Returns:
        The plan, including any warnings the snapshot warranted.

    Raises:
        ConfigurationError: ``min_severity`` is not a severity the mapping knows.
    """
    warnings = _inspect_snapshot(snapshot, mapping)

    actions = collapse_findings_to_actions(snapshot, mapping)
    if group_kernels:
        grouped = group_kernel_actions(actions)
        if len(grouped) < len(actions):
            warnings.append(_grouped_cve_count_warning(len(actions) - len(grouped)))
        actions = grouped

    ranked = rank_actions(actions)
    curve = build_coverage_curve(ranked, snapshot.total_findings)
    listed = filter_by_min_severity(ranked, min_severity, mapping) if min_severity else ranked

    return PatchPlan(
        total_findings=snapshot.total_findings,
        total_agents=snapshot.total_agents,
        total_distinct_cves=snapshot.total_distinct_cves,
        total_distinct_packages=snapshot.total_distinct_packages,
        actions=listed,
        collapse_ratio=_collapse_ratio(
            snapshot.total_findings, snapshot.total_distinct_packages
        ),
        coverage_curve=curve,
        warnings=warnings,
    )


def _action_from_bucket(bucket: PackageBucket, mapping: FieldMapping) -> RemediationAction:
    breakdown = _severity_breakdown(bucket, mapping)
    return RemediationAction(
        package_name=bucket.package_name,
        current_version=bucket.package_version,
        affected_agents=sorted(bucket.agent_counts),
        agent_count=len(bucket.agent_counts),
        finding_count=bucket.finding_count,
        cve_count=bucket.cve_count,
        severity_breakdown=breakdown,
        critical_count=_severity_at(breakdown, mapping, rank=0),
        high_count=_severity_at(breakdown, mapping, rank=1),
        unknown_severity_count=breakdown[UNKNOWN_SEVERITY],
        is_kernel=is_kernel_package(bucket.package_name),
    )


def _severity_breakdown(bucket: PackageBucket, mapping: FieldMapping) -> dict[str, int]:
    breakdown = {severity: 0 for severity in mapping.severity_order}
    recognized = 0
    for raw, count in bucket.severity_counts.items():
        canonical = mapping.canonical_severity(raw)
        if canonical is not None:
            breakdown[canonical] += count
            recognized += count
    # Everything the mapping does not recognise as a severity is unknown:
    # the placeholders, unrecognised strings, and documents carrying no
    # severity field at all, which a terms aggregation never reports.
    breakdown[UNKNOWN_SEVERITY] = max(0, bucket.finding_count - recognized)
    return breakdown


def _severity_at(breakdown: dict[str, int], mapping: FieldMapping, *, rank: int) -> int:
    """Count findings at the ``rank``-th most severe level the mapping declares."""
    if rank >= len(mapping.severity_order):
        return 0
    return breakdown[mapping.severity_order[rank]]


def _merge_actions(group: Sequence[RemediationAction]) -> RemediationAction:
    if len(group) == 1:
        return group[0]

    agents = sorted({agent for action in group for agent in action.affected_agents})
    versions = sorted({action.current_version for action in group})
    breakdown: dict[str, int] = {}
    for action in group:
        for severity, count in action.severity_breakdown.items():
            breakdown[severity] = breakdown.get(severity, 0) + count

    return RemediationAction(
        package_name=group[0].package_name,
        current_version=GROUPED_VERSION_SEPARATOR.join(versions),
        affected_agents=agents,
        agent_count=len(agents),
        finding_count=sum(action.finding_count for action in group),
        # A union cardinality cannot be recovered from per-bucket cardinalities.
        # Versions of one package share most of their CVEs, so the largest
        # constituent count is the honest lower bound; summing would double-count.
        cve_count=max(action.cve_count for action in group),
        severity_breakdown=breakdown,
        critical_count=sum(action.critical_count for action in group),
        high_count=sum(action.high_count for action in group),
        unknown_severity_count=sum(action.unknown_severity_count for action in group),
        is_kernel=True,
    )


def _inspect_snapshot(snapshot: IndexerSnapshot, mapping: FieldMapping) -> list[ScanWarning]:
    warnings: list[ScanWarning] = []
    if not snapshot.buckets:
        warnings.append(_empty_index_warning(snapshot.total_findings))
        return warnings

    reconciliation = _reconciliation_warning(snapshot)
    if reconciliation is not None:
        warnings.append(reconciliation)

    truncation = _truncation_warning(snapshot.buckets)
    if truncation is not None:
        warnings.append(truncation)

    unrecognized = _unrecognized_severity_warning(snapshot.buckets, mapping)
    if unrecognized is not None:
        warnings.append(unrecognized)

    return warnings


def _empty_index_warning(total_findings: int) -> ScanWarning:
    return ScanWarning(
        code=WarningCode.EMPTY_INDEX,
        message=(
            "No vulnerability findings were returned. The index pattern matched "
            "no documents, so there is nothing to remediate."
        ),
        detail={"total_findings": total_findings},
    )


def _reconciliation_warning(snapshot: IndexerSnapshot) -> ScanWarning | None:
    bucket_total = sum(bucket.finding_count for bucket in snapshot.buckets)
    delta = snapshot.total_findings - bucket_total
    if delta == 0:
        return None
    return ScanWarning(
        code=WarningCode.BUCKET_SUM_MISMATCH,
        message=(
            f"Aggregated buckets account for {bucket_total:,} findings but the "
            f"index reports {snapshot.total_findings:,}. {abs(delta):,} findings "
            f"are {'unaccounted for' if delta > 0 else 'counted twice'}; the plan "
            f"below covers only what the buckets contain."
        ),
        detail={
            "bucket_total": bucket_total,
            "reported_total": snapshot.total_findings,
            "delta": delta,
        },
    )


def _truncation_warning(buckets: Sequence[PackageBucket]) -> ScanWarning | None:
    truncated = [
        bucket for bucket in buckets if bucket.agent_cardinality > len(bucket.agent_counts)
    ]
    if not truncated:
        return None
    worst = max(truncated, key=lambda bucket: bucket.agent_cardinality)
    return ScanWarning(
        code=WarningCode.AGENT_TERMS_TRUNCATED,
        message=(
            f"{len(truncated)} action(s) affect more agents than the indexer "
            f"listed, so their agent lists are incomplete. Worst case: "
            f"{worst.package_name} affects {worst.agent_cardinality:,} agents, "
            f"{len(worst.agent_counts):,} listed."
        ),
        detail={
            "affected_actions": len(truncated),
            "example_package": worst.package_name,
            "agents_reported": worst.agent_cardinality,
            "agents_listed": len(worst.agent_counts),
        },
    )


def _unrecognized_severity_warning(
    buckets: Iterable[PackageBucket],
    mapping: FieldMapping,
) -> ScanWarning | None:
    unrecognized = sorted(
        {
            raw
            for bucket in buckets
            for raw in bucket.severity_counts
            if mapping.canonical_severity(raw) is None and not mapping.is_explicitly_unknown(raw)
        }
    )
    if not unrecognized:
        return None
    return ScanWarning(
        code=WarningCode.UNRECOGNIZED_SEVERITY,
        message=(
            f"Mapping {mapping.version!r} does not declare the severity value(s) "
            f"{', '.join(repr(value) for value in unrecognized)}. Findings "
            f"carrying them are counted as unknown severity, never as Low."
        ),
        detail={"values": ", ".join(unrecognized)},
    )


def _grouped_cve_count_warning(merged_count: int) -> ScanWarning:
    return ScanWarning(
        code=WarningCode.GROUPED_CVE_COUNT_IS_LOWER_BOUND,
        message=(
            f"{merged_count} kernel action(s) were merged across package "
            f"versions. Their CVE counts are lower bounds: the indexer reports a "
            f"cardinality per version, and those sets overlap."
        ),
        detail={"merged_actions": merged_count},
    )


def _percentage(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round(100.0 * part / whole, 2)


def _collapse_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 2)
