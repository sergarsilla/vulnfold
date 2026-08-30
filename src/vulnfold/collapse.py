"""Collapse engine: findings in, ranked patch plan out.

Pure domain logic. Nothing here performs I/O, reads configuration from the
environment or imports the indexer client; everything it needs arrives as an
:class:`IndexerSnapshot`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from fnmatch import fnmatch
from typing import Protocol, TypeVar

from vulnfold.config import (
    KERNEL_PACKAGE_PATTERNS,
    UNKNOWN_FIXABILITY_EXAMPLES,
    UNKNOWN_SEVERITY,
)
from vulnfold.errors import ConfigurationError
from vulnfold.models import (
    CollapseSources,
    CoveragePoint,
    FieldMapping,
    Fixability,
    IndexerSnapshot,
    PackageBucket,
    PatchPlan,
    RankBy,
    RemediationAction,
    ScanWarning,
    UnfixableEntry,
    WarningCode,
)
from vulnfold.versions import max_target_version

GROUPED_VERSION_SEPARATOR = ", "


class SeverityRated(Protocol):
    """Anything the severity filter can judge: an action or a register entry."""

    @property
    def severity_breakdown(self) -> dict[str, int]:
        """Count of findings per severity, including the unknown bucket."""

    @property
    def unknown_severity_count(self) -> int:
        """Findings carrying no usable severity."""


SeverityRatedT = TypeVar("SeverityRatedT", bound=SeverityRated)


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
    """Turn the fixable findings into the upgrades that clear them.

    Only findings whose vendor has published a fixed version become actions.
    One ``(package, version)`` fans out into one bucket per condition, and a
    package with several outstanding fixes carries several; they are merged back
    together here, and the action targets the highest of their versions, because
    that one upgrade clears all of them.

    Args:
        snapshot: Read-only view of the fleet's vulnerability state.
        mapping: Mapping supplying the severity vocabulary.

    Returns:
        One action per fixable ``(package, version)``, in the order the buckets
        arrived.
    """
    return [
        _action_from_group(group, mapping)
        for group in _group_by_package_version(snapshot.buckets, Fixability.FIXABLE)
    ]


def collapse_findings_to_unfixable(
    snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> list[UnfixableEntry]:
    """Turn the findings with no published fix into a register.

    Args:
        snapshot: Read-only view of the fleet's vulnerability state.
        mapping: Mapping supplying the severity vocabulary.

    Returns:
        One entry per confirmed-affected ``(package, version)`` the vendor has
        published no fix for, in the order the buckets arrived.
    """
    return [
        _entry_from_group(group, mapping)
        for group in _group_by_package_version(snapshot.buckets, Fixability.NO_FIX)
    ]


def rank_actions(
    actions: Sequence[RemediationAction],
    rank_by: RankBy = RankBy.CRITICALS,
) -> list[RemediationAction]:
    """Order actions by remediation impact.

    Criticals-first sorts on criticals, then highs, then raw finding count.
    Findings-first sorts on finding count, then criticals, then highs. Ties
    break alphabetically so the same input always renders the same output.

    Args:
        actions: Actions to order.
        rank_by: Which impact the ordering optimises for.

    Returns:
        A new list, ordered by impact.
    """
    return sorted(actions, key=lambda action: _rank_key(action, rank_by))


def _rank_key(action: RemediationAction, rank_by: RankBy) -> tuple[int, int, int, str, str]:
    if rank_by is RankBy.FINDINGS:
        return (
            -action.finding_count,
            -action.critical_count,
            -action.high_count,
            action.package_name,
            action.current_version,
        )
    return (
        -action.critical_count,
        -action.high_count,
        -action.finding_count,
        action.package_name,
        action.current_version,
    )


def rank_unfixable(entries: Sequence[UnfixableEntry]) -> list[UnfixableEntry]:
    """Order the register by the exposure each entry represents.

    Criticals first, then findings. The register is not ranked by ``--rank-by``:
    that flag chooses how to spend remediation effort, and there is no effort to
    spend here. What a reader needs is the worst unpatched exposure first.

    Args:
        entries: Entries to order.

    Returns:
        A new list, ordered by exposure.
    """
    return sorted(
        entries,
        key=lambda entry: (
            -entry.critical_count,
            -entry.high_count,
            -entry.finding_count,
            entry.package_name,
            entry.current_version,
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


def group_kernel_entries(entries: Sequence[UnfixableEntry]) -> list[UnfixableEntry]:
    """Merge the versions of each kernel package into a single register entry.

    Kernel grouping applies within each fixability class separately: a kernel
    the vendor has fixed and a kernel it has not are different situations and
    are never merged into one row.

    Args:
        entries: Entries to group.

    Returns:
        A new list in which kernel entries sharing a package name are merged.
    """
    grouped: dict[str, list[UnfixableEntry]] = {}
    passthrough: list[UnfixableEntry] = []
    for entry in entries:
        if entry.is_kernel:
            grouped.setdefault(entry.package_name, []).append(entry)
        else:
            passthrough.append(entry)

    merged = [_merge_entries(group) for group in grouped.values()]
    return merged + passthrough


def filter_by_min_severity(
    items: Sequence[SeverityRatedT],
    min_severity: str,
    mapping: FieldMapping,
) -> list[SeverityRatedT]:
    """Keep the rows worth showing at a severity threshold.

    A row survives when it carries at least one finding at or above the
    threshold, or any finding whose severity is unknown. Unrated findings are
    22% of real data and are never hidden by a severity filter, because hiding
    them would silently shrink the fleet's reported exposure.

    Args:
        items: Actions or register entries to filter.
        min_severity: Threshold, named as the mapping names severities.
        mapping: Mapping supplying the severity ordering.

    Returns:
        The surviving rows, in the order given.

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
        item
        for item in items
        if item.unknown_severity_count > 0
        or any(item.severity_breakdown.get(severity, 0) > 0 for severity in at_or_above)
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
    agents_so_far: set[str] = set()
    for position, action in enumerate(ranked_actions, start=1):
        findings_so_far += action.finding_count
        criticals_so_far += action.critical_count
        agents_so_far.update(action.affected_agents)
        curve.append(
            CoveragePoint(
                action_count=position,
                cumulative_findings=findings_so_far,
                findings_percentage=_percentage(findings_so_far, total_findings),
                cumulative_criticals=criticals_so_far,
                criticals_percentage=_percentage(criticals_so_far, total_criticals),
                cumulative_agents=len(agents_so_far),
            )
        )
    return curve


def build_collapse_sources(actions: Sequence[RemediationAction]) -> CollapseSources:
    """Separate the two effects that compress a fleet's findings.

    One package version carrying thousands of CVEs on a single host compresses
    just as hard as one package repeated across a thousand hosts, and the
    remediation effort is nothing alike. The identity
    ``findings = cves * hosts`` holds per action, so the fleet-wide averages
    factor the same way.

    Args:
        actions: The plan's actions.

    Returns:
        Findings per action, and its decomposition into CVE depth and host
        spread. All three are zero for an empty plan.
    """
    action_count = len(actions)
    covered_findings = sum(action.finding_count for action in actions)
    covered_cves = sum(action.cve_count for action in actions)
    return CollapseSources(
        findings_per_action=_ratio(covered_findings, action_count),
        cves_per_action=_ratio(covered_cves, action_count),
        hosts_per_action=_ratio(covered_findings, covered_cves),
    )


def build_patch_plan(
    snapshot: IndexerSnapshot,
    mapping: FieldMapping,
    *,
    rank_by: RankBy = RankBy.CRITICALS,
    group_kernels: bool = False,
    min_severity: str | None = None,
) -> PatchPlan:
    """Assemble the ranked patch plan for one snapshot.

    The snapshot is partitioned on fixability before anything is ranked. Only
    findings the vendor has published a fix for can become actions; the
    confirmed-affected remainder becomes the register, and findings whose
    condition the mapping did not recognise are excluded from both and warned
    about. A plan that ranked all three together would recommend upgrades that
    do not exist, which is the defect this partition removes.

    ``collapse_ratio`` is fixable findings per distinct fixable package, the
    compression a reader experiences when a finding list becomes a package list.
    It is deliberately not findings per action: a package carrying several
    versions yields several actions, and the ratio would then flatter the tool.

    ``coverage_curve`` always describes the complete ranked plan, even when
    ``min_severity`` shortens the action list, so "the first N actions" keeps
    one meaning across invocations. Both the findings-ordered and the
    criticals-ordered curve are always computed, whichever ordering is active:
    each is a claim the tool makes, and they need not agree. Every percentage in
    them is taken over the fixable findings, never over the fleet total.

    Args:
        snapshot: Read-only view of the fleet's vulnerability state.
        mapping: Field mapping in force.
        rank_by: Which impact the listed ordering optimises for.
        group_kernels: Merge each kernel package's versions into one row, within
            each fixability class separately.
        min_severity: Only list rows relevant at this severity or above.

    Returns:
        The plan, its register, and any warnings the snapshot warranted.

    Raises:
        ConfigurationError: ``min_severity`` is not a severity the mapping knows.
    """
    warnings = _inspect_snapshot(snapshot, mapping)

    fixable = _buckets_of(snapshot.buckets, Fixability.FIXABLE)
    no_fix = _buckets_of(snapshot.buckets, Fixability.NO_FIX)
    unknown = _buckets_of(snapshot.buckets, Fixability.UNKNOWN)
    if unknown:
        warnings.append(_unrecognized_fixability_warning(unknown))

    actions = collapse_findings_to_actions(snapshot, mapping)
    unfixable = collapse_findings_to_unfixable(snapshot, mapping)
    merged_conditions = (len(fixable) - len(actions)) + (len(no_fix) - len(unfixable))
    if merged_conditions > 0:
        warnings.append(_merged_condition_warning(merged_conditions))

    if group_kernels:
        grouped_actions = group_kernel_actions(actions)
        grouped_unfixable = group_kernel_entries(unfixable)
        merged_versions = (len(actions) - len(grouped_actions)) + (
            len(unfixable) - len(grouped_unfixable)
        )
        if merged_versions > 0:
            warnings.append(_grouped_cve_count_warning(merged_versions))
        actions, unfixable = grouped_actions, grouped_unfixable

    fixable_findings, fixable_criticals = _class_totals(fixable, mapping)
    no_fix_findings, no_fix_criticals = _class_totals(no_fix, mapping)
    unknown_findings, _ = _class_totals(unknown, mapping)
    total_findings, total_criticals = _class_totals(snapshot.buckets, mapping)

    by_findings = build_coverage_curve(rank_actions(actions, RankBy.FINDINGS), fixable_findings)
    by_criticals = build_coverage_curve(rank_actions(actions, RankBy.CRITICALS), fixable_findings)

    ranked = rank_actions(actions, rank_by)
    curve = by_findings if rank_by is RankBy.FINDINGS else by_criticals
    listed = filter_by_min_severity(ranked, min_severity, mapping) if min_severity else ranked
    register = rank_unfixable(unfixable)
    if min_severity:
        register = filter_by_min_severity(register, min_severity, mapping)

    return PatchPlan(
        total_findings=snapshot.total_findings,
        # Counted from the buckets, not from _count: it must reconcile with the
        # two halves of the split it heads, and a bucket sum mismatch is already
        # reported separately.
        total_criticals=total_criticals,
        total_agents=snapshot.total_agents,
        total_distinct_cves=snapshot.total_distinct_cves,
        total_distinct_packages=snapshot.total_distinct_packages,
        fixable_findings=fixable_findings,
        fixable_criticals=fixable_criticals,
        fixable_distinct_packages=len({bucket.package_name for bucket in fixable}),
        no_fix_findings=no_fix_findings,
        no_fix_criticals=no_fix_criticals,
        unknown_fixability_findings=unknown_findings,
        actions=listed,
        unfixable=register,
        collapse_ratio=_ratio(fixable_findings, len({bucket.package_name for bucket in fixable})),
        collapse_sources=build_collapse_sources(actions),
        rank_by=rank_by,
        coverage_curve=curve,
        coverage_by_findings=by_findings,
        coverage_by_criticals=by_criticals,
        warnings=warnings,
    )


def _buckets_of(
    buckets: Sequence[PackageBucket],
    fixability: Fixability,
) -> list[PackageBucket]:
    return [bucket for bucket in buckets if bucket.fixability is fixability]


def _group_by_package_version(
    buckets: Sequence[PackageBucket],
    fixability: Fixability,
) -> list[list[PackageBucket]]:
    """Gather one class's buckets by the installed version they describe.

    Adding the condition as a composite source fanned each ``(package,
    version)`` out into one bucket per distinct condition string. A reader
    upgrades a package once, so those go back together before anything is
    ranked.
    """
    groups: dict[tuple[str, str], list[PackageBucket]] = {}
    for bucket in _buckets_of(buckets, fixability):
        groups.setdefault((bucket.package_name, bucket.package_version), []).append(bucket)
    return list(groups.values())


def _class_totals(buckets: Sequence[PackageBucket], mapping: FieldMapping) -> tuple[int, int]:
    """Total the findings and the criticals a set of buckets carries."""
    findings = sum(bucket.finding_count for bucket in buckets)
    criticals = sum(
        _severity_at(_severity_breakdown(bucket, mapping), mapping, rank=0) for bucket in buckets
    )
    return findings, criticals


def _action_from_group(
    group: Sequence[PackageBucket],
    mapping: FieldMapping,
) -> RemediationAction:
    # Every fixable bucket names a version, so the list is never empty and the
    # action's target_version is a str by construction, as the model requires.
    targets = [bucket.target_version for bucket in group if bucket.target_version]
    bucket = _merge_buckets(group)
    breakdown = _severity_breakdown(bucket, mapping)
    return RemediationAction(
        package_name=bucket.package_name,
        current_version=bucket.package_version,
        target_version=max_target_version(targets),
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


def _entry_from_group(group: Sequence[PackageBucket], mapping: FieldMapping) -> UnfixableEntry:
    bucket = _merge_buckets(group)
    breakdown = _severity_breakdown(bucket, mapping)
    return UnfixableEntry(
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


def _merge_buckets(group: Sequence[PackageBucket]) -> PackageBucket:
    """Sum the buckets one ``(package, version)`` fans out into by condition."""
    if len(group) == 1:
        return group[0]

    agent_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for bucket in group:
        for agent, count in bucket.agent_counts.items():
            agent_counts[agent] = agent_counts.get(agent, 0) + count
        for severity, count in bucket.severity_counts.items():
            severity_counts[severity] = severity_counts.get(severity, 0) + count

    targets = [bucket.target_version for bucket in group if bucket.target_version]
    return PackageBucket(
        package_name=group[0].package_name,
        package_version=group[0].package_version,
        finding_count=sum(bucket.finding_count for bucket in group),
        agent_counts=agent_counts,
        agent_cardinality=max(
            len(agent_counts), max(bucket.agent_cardinality for bucket in group)
        ),
        severity_counts=severity_counts,
        # A cardinality is not additive. Each condition names a different fixed
        # version and so covers a different set of CVEs, which makes the sum the
        # closest answer available from per-bucket cardinalities; the plan warns
        # that the result is no longer an exact count.
        cve_count=sum(bucket.cve_count for bucket in group),
        fixability=group[0].fixability,
        target_version=max_target_version(targets) if targets else None,
        scanner_condition=group[0].scanner_condition,
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
        # One upgrade replaces every version the fleet carries, so the merged
        # action targets the highest of their targets.
        target_version=max_target_version([action.target_version for action in group]),
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


def _merge_entries(group: Sequence[UnfixableEntry]) -> UnfixableEntry:
    if len(group) == 1:
        return group[0]

    agents = sorted({agent for entry in group for agent in entry.affected_agents})
    versions = sorted({entry.current_version for entry in group})
    breakdown: dict[str, int] = {}
    for entry in group:
        for severity, count in entry.severity_breakdown.items():
            breakdown[severity] = breakdown.get(severity, 0) + count

    return UnfixableEntry(
        package_name=group[0].package_name,
        current_version=GROUPED_VERSION_SEPARATOR.join(versions),
        affected_agents=agents,
        agent_count=len(agents),
        finding_count=sum(entry.finding_count for entry in group),
        # Same reasoning as the merged action: versions of one package share
        # most of their CVEs, so the largest constituent is the honest bound.
        cve_count=max(entry.cve_count for entry in group),
        severity_breakdown=breakdown,
        critical_count=sum(entry.critical_count for entry in group),
        high_count=sum(entry.high_count for entry in group),
        unknown_severity_count=sum(entry.unknown_severity_count for entry in group),
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
            f"{merged_count} kernel row(s) were merged across package "
            f"versions. Their CVE counts are lower bounds: the indexer reports a "
            f"cardinality per version, and those sets overlap."
        ),
        detail={"merged_rows": merged_count},
    )


def _merged_condition_warning(merged_count: int) -> ScanWarning:
    return ScanWarning(
        code=WarningCode.GROUPED_CVE_COUNT_IS_LOWER_BOUND,
        message=(
            f"{merged_count} row(s) were merged across scanner conditions, "
            f"because one installed version can have several outstanding fixed "
            f"versions. Their CVE counts are sums of per-condition "
            f"cardinalities, not exact counts."
        ),
        detail={"merged_conditions": merged_count},
    )


def _unrecognized_fixability_warning(buckets: Sequence[PackageBucket]) -> ScanWarning:
    examples = sorted(
        {bucket.scanner_condition for bucket in buckets if bucket.scanner_condition}
    )[:UNKNOWN_FIXABILITY_EXAMPLES]
    findings = sum(bucket.finding_count for bucket in buckets)
    listed = ", ".join(repr(example) for example in examples) or "none, the field was absent"
    return ScanWarning(
        code=WarningCode.UNRECOGNIZED_FIXABILITY,
        message=(
            f"{findings:,} finding(s) in {len(buckets):,} bucket(s) carry a "
            f"scanner condition the mapping does not recognise, so they appear "
            f"neither in the plan nor in the register. This is a gap in the "
            f"mapping's fixability vocabulary, not a class of finding. "
            f"Example condition(s): {listed}."
        ),
        detail={
            "findings": findings,
            "buckets": len(buckets),
            "examples": listed,
        },
    )


def _percentage(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round(100.0 * part / whole, 2)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 2)
