"""The collapse engine: findings in, ranked patch plan out."""

from __future__ import annotations

import pytest
from conftest import (
    DEFECT_PACKAGE,
    DEFECT_VERSION,
    MEASURED_ACTIONS,
    MEASURED_AGENTS,
    MEASURED_COLLAPSE_RATIO,
    MEASURED_CRITICALS,
    MEASURED_DISTINCT_CVES,
    MEASURED_DISTINCT_PACKAGES,
    MEASURED_FINDINGS,
    MEASURED_FIXABLE_CRITICALS,
    MEASURED_FIXABLE_FINDINGS,
    MEASURED_FIXABLE_PACKAGES,
    MEASURED_NO_FIX_CRITICALS,
    MEASURED_NO_FIX_FINDINGS,
    MEASURED_UNFIXABLE_ENTRIES,
    MEASURED_UNKNOWN_FINDINGS,
    NO_FIX_CONDITION,
    make_bucket,
    make_snapshot,
)

from vulnfold.collapse import (
    build_coverage_curve,
    build_patch_plan,
    collapse_findings_to_actions,
    collapse_findings_to_unfixable,
    filter_by_min_severity,
    group_kernel_actions,
    is_kernel_package,
    rank_actions,
)
from vulnfold.config import UNKNOWN_SEVERITY
from vulnfold.errors import ConfigurationError
from vulnfold.models import (
    FieldMapping,
    Fixability,
    IndexerSnapshot,
    RankBy,
    RemediationAction,
    UnfixableEntry,
    WarningCode,
)

# ---------------------------------------------------------------------------
# The recorded fleet (SPEC-01 section 9, criterion 2)
# ---------------------------------------------------------------------------


def test_plan_reports_the_measured_fleet_totals(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert plan.total_findings == MEASURED_FINDINGS
    assert plan.total_agents == MEASURED_AGENTS
    assert plan.total_distinct_cves == MEASURED_DISTINCT_CVES
    assert plan.total_distinct_packages == MEASURED_DISTINCT_PACKAGES


def test_plan_produces_one_action_per_fixable_package_version(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert len(plan.actions) == MEASURED_ACTIONS
    assert len({(action.package_name, action.current_version) for action in plan.actions}) == (
        MEASURED_ACTIONS
    )


def test_collapse_ratio_is_fixable_findings_per_distinct_fixable_package(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert plan.collapse_ratio == MEASURED_COLLAPSE_RATIO
    assert plan.fixable_distinct_packages == MEASURED_FIXABLE_PACKAGES


def test_the_largest_rows_of_the_recorded_fleet_are_all_kernels(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """CONTEXT.md section 2: kernels dominate, whether or not a fix exists."""
    plan = build_patch_plan(real_snapshot, mapping)
    rows: list[RemediationAction | UnfixableEntry] = [*plan.actions, *plan.unfixable]
    rows.sort(key=lambda row: -row.finding_count)

    assert all(row.is_kernel for row in rows[:7])


def test_recorded_fleet_reconciles_with_only_the_expected_warnings(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """Nothing about the fleet is anomalous; both warnings are structural."""
    plan = build_patch_plan(real_snapshot, mapping)

    assert [warning.code for warning in plan.warnings] == [
        WarningCode.UNRECOGNIZED_FIXABILITY,
        WarningCode.MERGED_CVE_COUNT_IS_UPPER_BOUND,
    ]


def test_severity_totals_across_both_lists_match_the_recorded_distribution(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)
    rows: list[RemediationAction | UnfixableEntry] = [*plan.actions, *plan.unfixable]
    # The findings of unrecognised fixability are in neither list, so they are
    # the exact shortfall against the recorded fleet distribution.
    excluded = [
        bucket for bucket in real_snapshot.buckets if bucket.fixability is Fixability.UNKNOWN
    ]
    withheld = {
        severity: sum(bucket.severity_counts.get(severity, 0) for bucket in excluded)
        for severity in mapping.severity_order
    }
    unrated_withheld = sum(bucket.finding_count for bucket in excluded) - sum(withheld.values())

    assert sum(row.critical_count for row in rows) == MEASURED_CRITICALS - withheld["Critical"]
    assert sum(row.high_count for row in rows) == 12_158 - withheld["High"]
    # 7,287 findings carry "-" and 2 carry "None"; neither is a severity.
    assert sum(row.unknown_severity_count for row in rows) == 7_289 - unrated_withheld


# ---------------------------------------------------------------------------
# The fixability partition (SPEC-02 sections 0 and 6)
# ---------------------------------------------------------------------------


def test_plan_reproduces_the_measured_fixability_split(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 10, criterion 2."""
    plan = build_patch_plan(real_snapshot, mapping)

    assert plan.fixable_findings == MEASURED_FIXABLE_FINDINGS
    assert plan.no_fix_findings == MEASURED_NO_FIX_FINDINGS
    assert plan.fixable_criticals == MEASURED_FIXABLE_CRITICALS
    assert plan.no_fix_criticals == MEASURED_NO_FIX_CRITICALS
    assert plan.unknown_fixability_findings == MEASURED_UNKNOWN_FINDINGS


def test_the_three_classes_account_for_every_recorded_finding(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert (
        plan.fixable_findings + plan.no_fix_findings + plan.unknown_fixability_findings
        == MEASURED_FINDINGS
    )
    assert plan.total_criticals == MEASURED_CRITICALS


def test_linux_oracle_is_in_the_register_and_nowhere_in_the_patch_plan(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 10, criterion 3: the defect that motivated the spec.

    Every one of these 4,226 findings is "Package default status": the vendor
    confirms the package affected and has published nothing to upgrade to. The
    plan used to rank it first.
    """
    plan = build_patch_plan(real_snapshot, mapping)

    assert not [action for action in plan.actions if action.package_name == DEFECT_PACKAGE]
    registered = [entry for entry in plan.unfixable if entry.package_name == DEFECT_PACKAGE]
    assert [(entry.current_version, entry.finding_count) for entry in registered] == [
        (DEFECT_VERSION, 4_226)
    ]


def test_every_action_in_the_recorded_plan_names_a_target_version(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 10, criterion 4, asserted over the whole plan."""
    plan = build_patch_plan(real_snapshot, mapping)

    assert plan.actions
    assert all(action.target_version for action in plan.actions)


def test_every_grouped_action_still_names_a_target_version(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping, group_kernels=True)

    assert all(action.target_version for action in plan.actions)


def test_the_register_carries_one_entry_per_no_fix_package_version(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert len(plan.unfixable) == MEASURED_UNFIXABLE_ENTRIES
    assert sum(entry.finding_count for entry in plan.unfixable) == MEASURED_NO_FIX_FINDINGS


def test_coverage_percentages_are_taken_over_the_fixable_findings(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 10, criterion 7, at the model layer."""
    plan = build_patch_plan(real_snapshot, mapping)

    last = plan.coverage_by_findings[-1]

    assert last.cumulative_findings == MEASURED_FIXABLE_FINDINGS
    assert last.findings_percentage == 100.0
    assert plan.coverage_by_criticals[-1].cumulative_criticals == MEASURED_FIXABLE_CRITICALS


def test_a_bucket_belongs_to_exactly_one_of_the_two_lists(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="openssl", version="3.0.2-1", findings=10),
            make_bucket(package="curl", version="8.5.0", findings=4, condition=NO_FIX_CONDITION),
        ]
    )

    plan = build_patch_plan(snapshot, mapping)

    assert [action.package_name for action in plan.actions] == ["openssl"]
    assert [entry.package_name for entry in plan.unfixable] == ["curl"]


def test_one_package_version_can_be_partly_fixable_and_partly_not(
    mapping: FieldMapping,
) -> None:
    """Both rows are real: some of its CVEs have a fix and some have none."""
    snapshot = make_snapshot(
        [
            make_bucket(package="openssl", version="3.0.2-1", findings=10),
            make_bucket(
                package="openssl", version="3.0.2-1", findings=4, condition=NO_FIX_CONDITION
            ),
        ]
    )

    plan = build_patch_plan(snapshot, mapping)

    assert plan.fixable_findings == 10
    assert plan.no_fix_findings == 4
    assert [action.finding_count for action in plan.actions] == [10]
    assert [entry.finding_count for entry in plan.unfixable] == [4]


def test_an_unrecognised_condition_is_excluded_from_both_lists_and_warned_about(
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 10, criterion 5."""
    snapshot = make_snapshot(
        [
            make_bucket(package="openssl", version="3.0.2-1", findings=10),
            make_bucket(package="curl", version="8.5.0", findings=4, condition=None),
        ]
    )

    plan = build_patch_plan(snapshot, mapping)

    assert [action.package_name for action in plan.actions] == ["openssl"]
    assert plan.unfixable == []
    assert plan.unknown_fixability_findings == 4
    assert WarningCode.UNRECOGNIZED_FIXABILITY in {warning.code for warning in plan.warnings}


def test_the_unrecognised_fixability_warning_quotes_the_condition_strings(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package=name, findings=2, condition=f"Package equal to {name}")
            for name in ("a", "b", "c", "d")
        ]
    )

    plan = build_patch_plan(snapshot, mapping)
    warning = next(
        warning
        for warning in plan.warnings
        if warning.code is WarningCode.UNRECOGNIZED_FIXABILITY
    )

    assert warning.detail["findings"] == 8
    assert warning.detail["buckets"] == 4
    # Three examples at most, so the warning stays readable.
    assert str(warning.detail["examples"]).count("Package equal to") == 3


def test_an_unrecognised_condition_is_never_treated_as_no_fix(
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 11: absorbing it would destroy the mapping signal."""
    snapshot = make_snapshot([make_bucket(findings=6, condition="Package equal to 7.2.12")])

    plan = build_patch_plan(snapshot, mapping)

    assert plan.no_fix_findings == 0
    assert plan.unknown_fixability_findings == 6


def test_conditions_naming_several_targets_merge_into_one_action(
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 4: one upgrade clears every outstanding fix."""
    snapshot = make_snapshot(
        [
            make_bucket(version="6.12.74-2", findings=3, condition="Package less than 6.12.100-1"),
            make_bucket(version="6.12.74-2", findings=5, condition="Package less than 6.12.85-1"),
        ]
    )

    plan = build_patch_plan(snapshot, mapping)

    assert len(plan.actions) == 1
    assert plan.actions[0].finding_count == 8
    assert plan.actions[0].target_version == "6.12.100-1"


def test_merging_conditions_warns_that_the_cve_count_is_no_longer_exact(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(findings=3, cves=3, condition="Package less than 1.2"),
            make_bucket(findings=5, cves=5, condition="Package less than 1.3"),
        ]
    )

    plan = build_patch_plan(snapshot, mapping)

    assert plan.actions[0].cve_count == 8
    assert WarningCode.MERGED_CVE_COUNT_IS_UPPER_BOUND in {
        warning.code for warning in plan.warnings
    }


def test_a_kernel_with_a_fix_is_never_merged_with_one_without(
    mapping: FieldMapping,
) -> None:
    """SPEC-02 section 6: kernel grouping applies within each class."""
    snapshot = make_snapshot(
        [
            make_bucket(package="linux-oracle", version="6.17.0-1020.20", findings=7),
            make_bucket(
                package="linux-oracle",
                version="6.17.0-1020.20",
                findings=9,
                condition=NO_FIX_CONDITION,
            ),
        ]
    )

    plan = build_patch_plan(snapshot, mapping, group_kernels=True)

    assert [action.finding_count for action in plan.actions] == [7]
    assert [entry.finding_count for entry in plan.unfixable] == [9]


def test_the_register_is_ranked_by_criticals_whatever_rank_by_says(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(
                package="noisy",
                findings=100,
                severity={"High": 100},
                condition=NO_FIX_CONDITION,
            ),
            make_bucket(
                package="severe",
                findings=10,
                severity={"Critical": 10},
                condition=NO_FIX_CONDITION,
            ),
        ]
    )

    by_findings = build_patch_plan(snapshot, mapping, rank_by=RankBy.FINDINGS)

    assert [entry.package_name for entry in by_findings.unfixable] == ["severe", "noisy"]


def test_collapse_helpers_split_the_snapshot_without_ranking_it(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="openssl", findings=10),
            make_bucket(package="curl", findings=4, condition=NO_FIX_CONDITION),
        ]
    )

    assert [action.package_name for action in collapse_findings_to_actions(snapshot, mapping)] == [
        "openssl"
    ]
    assert [
        entry.package_name for entry in collapse_findings_to_unfixable(snapshot, mapping)
    ] == ["curl"]


# ---------------------------------------------------------------------------
# Severity handling (SPEC-01 section 6.5, criterion 5)
# ---------------------------------------------------------------------------


def test_severity_dash_is_counted_as_unknown_and_nowhere_else(mapping: FieldMapping) -> None:
    snapshot = make_snapshot([make_bucket(findings=10, severity={"-": 10})])

    action = build_patch_plan(snapshot, mapping).actions[0]

    assert action.unknown_severity_count == 10
    assert action.critical_count == 0
    assert action.high_count == 0
    assert action.severity_breakdown == {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        UNKNOWN_SEVERITY: 10,
    }


@pytest.mark.parametrize("placeholder", ["-", "None", ""])
def test_every_declared_placeholder_counts_as_unknown(
    mapping: FieldMapping,
    placeholder: str,
) -> None:
    snapshot = make_snapshot([make_bucket(findings=6, severity={placeholder: 6})])

    action = build_patch_plan(snapshot, mapping).actions[0]

    assert action.unknown_severity_count == 6


def test_findings_with_no_severity_field_are_counted_as_unknown(
    mapping: FieldMapping,
) -> None:
    """A terms aggregation never reports documents that lack the field."""
    snapshot = make_snapshot([make_bucket(findings=10, severity={"High": 4})])

    action = build_patch_plan(snapshot, mapping).actions[0]

    assert action.high_count == 4
    assert action.unknown_severity_count == 6


def test_an_unrecognized_severity_is_unknown_and_is_reported(mapping: FieldMapping) -> None:
    snapshot = make_snapshot([make_bucket(findings=5, severity={"Catastrophic": 5})])

    plan = build_patch_plan(snapshot, mapping)

    assert plan.actions[0].unknown_severity_count == 5
    assert plan.actions[0].severity_breakdown["Low"] == 0
    assert [warning.code for warning in plan.warnings] == [WarningCode.UNRECOGNIZED_SEVERITY]
    assert "Catastrophic" in plan.warnings[0].message


def test_severity_matching_ignores_case(mapping: FieldMapping) -> None:
    snapshot = make_snapshot([make_bucket(findings=3, severity={"critical": 3})])

    action = build_patch_plan(snapshot, mapping).actions[0]

    assert action.critical_count == 3
    assert action.unknown_severity_count == 0


# ---------------------------------------------------------------------------
# Collapsing and ranking
# ---------------------------------------------------------------------------


def test_collapse_groups_same_package_across_agents(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [make_bucket(findings=9, agents={"003": 3, "001": 3, "002": 3})]
    )

    actions = collapse_findings_to_actions(snapshot, mapping)

    assert len(actions) == 1
    assert actions[0].agent_count == 3
    assert actions[0].affected_agents == ["001", "002", "003"]


def test_ranking_puts_criticals_first_then_highs_then_findings(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="many-findings", findings=500, severity={"Medium": 500}),
            make_bucket(package="some-highs", findings=50, severity={"High": 50}),
            make_bucket(package="one-critical", findings=10, severity={"Critical": 1, "High": 9}),
        ]
    )

    ranked = rank_actions(collapse_findings_to_actions(snapshot, mapping))

    assert [action.package_name for action in ranked] == [
        "one-critical",
        "some-highs",
        "many-findings",
    ]


def test_ranking_breaks_ties_alphabetically(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="zlib", findings=5, severity={"High": 5}),
            make_bucket(package="apache2", findings=5, severity={"High": 5}),
            make_bucket(package="nginx", findings=5, severity={"High": 5}),
        ]
    )

    ranked = rank_actions(collapse_findings_to_actions(snapshot, mapping))

    assert [action.package_name for action in ranked] == ["apache2", "nginx", "zlib"]


def test_ranking_breaks_a_full_tie_on_version(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="openssl", version="3.0.9", findings=5),
            make_bucket(package="openssl", version="3.0.2", findings=5),
        ]
    )

    ranked = rank_actions(collapse_findings_to_actions(snapshot, mapping))

    assert [action.current_version for action in ranked] == ["3.0.2", "3.0.9"]


# ---------------------------------------------------------------------------
# Coverage curve (SPEC-01 section 6.3)
# ---------------------------------------------------------------------------


def test_coverage_curve_accumulates_findings_and_criticals(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="a", findings=60, severity={"Critical": 30, "High": 30}),
            make_bucket(package="b", findings=40, severity={"Critical": 10, "High": 30}),
        ]
    )

    curve = build_coverage_curve(
        rank_actions(collapse_findings_to_actions(snapshot, mapping)),
        snapshot.total_findings,
    )

    assert [point.cumulative_findings for point in curve] == [60, 100]
    assert [point.findings_percentage for point in curve] == [60.0, 100.0]
    assert [point.cumulative_criticals for point in curve] == [30, 40]
    assert [point.criticals_percentage for point in curve] == [75.0, 100.0]


def test_coverage_curve_has_one_point_per_action(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert len(plan.coverage_curve) == len(plan.actions)
    assert [point.action_count for point in plan.coverage_curve[:3]] == [1, 2, 3]


def test_coverage_percentages_are_taken_over_the_reported_total(
    mapping: FieldMapping,
) -> None:
    """Percentages use the index's own count, not the sum of the buckets."""
    snapshot = make_snapshot([make_bucket(findings=50)], total_findings=200)

    curve = build_coverage_curve(collapse_findings_to_actions(snapshot, mapping), 200)

    assert curve[0].findings_percentage == 25.0


# ---------------------------------------------------------------------------
# Kernels (SPEC-01 section 6.4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "package",
    [
        "linux-image-6.14.0-37-generic",
        "linux-image-amd64",
        "linux-headers-6.12.0",
        "linux-oracle",
        "linux-aws-generic",
        "kernel-default",
    ],
)
def test_kernel_packages_are_detected(package: str) -> None:
    assert is_kernel_package(package) is True


@pytest.mark.parametrize("package", ["firefox", "openssl", "linux-libc-dev", "Google Chrome"])
def test_other_packages_are_not_kernels(package: str) -> None:
    assert is_kernel_package(package) is False


def test_group_kernels_merges_the_versions_of_one_package(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(
                package="linux-image-amd64",
                version="6.12.90-2",
                findings=2656,
                agents={"001": 2656},
                severity={"Critical": 100, "High": 500},
                cves=2656,
            ),
            make_bucket(
                package="linux-image-amd64",
                version="6.12.100-1",
                findings=1062,
                agents={"002": 1062},
                severity={"Critical": 40, "High": 200},
                cves=1062,
            ),
        ]
    )

    grouped = group_kernel_actions(collapse_findings_to_actions(snapshot, mapping))

    assert len(grouped) == 1
    assert grouped[0].finding_count == 3718
    assert grouped[0].critical_count == 140
    assert grouped[0].affected_agents == ["001", "002"]
    assert grouped[0].current_version == "6.12.100-1, 6.12.90-2"


def test_group_kernels_reports_cve_count_as_a_lower_bound(mapping: FieldMapping) -> None:
    """Versions of one package share CVEs, so their cardinalities cannot be summed."""
    snapshot = make_snapshot(
        [
            make_bucket(package="linux-image-amd64", version="6.12.90-2", findings=200, cves=200),
            make_bucket(package="linux-image-amd64", version="6.12.100-1", findings=80, cves=80),
        ]
    )

    plan = build_patch_plan(snapshot, mapping, group_kernels=True)

    assert plan.actions[0].cve_count == 200
    assert [warning.code for warning in plan.warnings] == [
        WarningCode.GROUPED_CVE_COUNT_IS_LOWER_BOUND
    ]


def test_group_kernels_leaves_other_packages_alone(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="firefox", version="148.0-1", findings=430),
            make_bucket(package="firefox", version="146.0.1-1", findings=205),
        ]
    )

    grouped = group_kernel_actions(collapse_findings_to_actions(snapshot, mapping))

    assert len(grouped) == 2


def test_group_kernels_shrinks_the_recorded_fleet(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping, group_kernels=True)

    assert len(plan.actions) < MEASURED_ACTIONS
    assert plan.total_findings == MEASURED_FINDINGS
    assert plan.coverage_curve[-1].cumulative_findings == MEASURED_FIXABLE_FINDINGS


# ---------------------------------------------------------------------------
# Severity threshold (SPEC-01 section 8)
# ---------------------------------------------------------------------------


def test_min_severity_keeps_actions_at_or_above_the_threshold(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="critical-only", findings=5, severity={"Critical": 5}),
            make_bucket(package="high-only", findings=5, severity={"High": 5}),
            make_bucket(package="medium-only", findings=5, severity={"Medium": 5}),
        ]
    )

    actions = collapse_findings_to_actions(snapshot, mapping)
    kept = filter_by_min_severity(actions, "High", mapping)

    assert {action.package_name for action in kept} == {"critical-only", "high-only"}


def test_min_severity_never_hides_findings_with_unknown_severity(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [make_bucket(package="unrated-only", findings=212, severity={"-": 212})]
    )

    kept = filter_by_min_severity(
        collapse_findings_to_actions(snapshot, mapping), "Critical", mapping
    )

    assert [action.package_name for action in kept] == ["unrated-only"]


def test_min_severity_leaves_the_totals_and_the_curve_untouched(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    full = build_patch_plan(real_snapshot, mapping)
    filtered = build_patch_plan(real_snapshot, mapping, min_severity="Critical")

    assert len(filtered.actions) < len(full.actions)
    assert filtered.total_findings == full.total_findings
    assert filtered.collapse_ratio == full.collapse_ratio
    assert filtered.coverage_curve == full.coverage_curve


def test_min_severity_rejects_a_severity_the_mapping_does_not_declare(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot([make_bucket()])

    with pytest.raises(ConfigurationError, match="Critical, High, Medium, Low"):
        build_patch_plan(snapshot, mapping, min_severity="Catastrophic")


# ---------------------------------------------------------------------------
# Edge cases (SPEC-01 section 6.5)
# ---------------------------------------------------------------------------


def test_an_empty_index_produces_an_empty_plan_rather_than_an_error(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot([], total_findings=0)

    plan = build_patch_plan(snapshot, mapping)

    assert plan.actions == []
    assert plan.coverage_curve == []
    assert plan.collapse_ratio == 0.0
    assert [warning.code for warning in plan.warnings] == [WarningCode.EMPTY_INDEX]


def test_buckets_that_do_not_reconcile_with_the_count_are_reported(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot([make_bucket(findings=32_700)], total_findings=MEASURED_FINDINGS)

    plan = build_patch_plan(snapshot, mapping)

    warning = plan.warnings[0]

    assert warning.code is WarningCode.BUCKET_SUM_MISMATCH
    assert warning.detail["delta"] == 18
    assert "32,718" in warning.message


def test_a_bucket_with_more_agents_than_the_indexer_listed_is_reported(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(
                package="openssl",
                findings=10_000,
                agents={f"{number:05d}": 1 for number in range(10_000)},
                agent_cardinality=12_345,
            )
        ]
    )

    plan = build_patch_plan(snapshot, mapping)

    warning = plan.warnings[0]

    assert warning.code is WarningCode.AGENT_TERMS_TRUNCATED
    assert warning.detail["agents_reported"] == 12_345
    assert warning.detail["agents_listed"] == 10_000


def test_a_package_with_no_version_is_planned_under_unknown(mapping: FieldMapping) -> None:
    snapshot = make_snapshot([make_bucket(package="openssl", version="unknown", findings=4)])

    plan = build_patch_plan(snapshot, mapping)

    assert plan.actions[0].current_version == "unknown"
    assert plan.actions[0].finding_count == 4


# ---------------------------------------------------------------------------
# Ranking mode (--rank-by)
# ---------------------------------------------------------------------------


def test_findings_ranking_orders_by_volume(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="loud", findings=500, severity={"Medium": 500}),
            make_bucket(package="severe", findings=10, severity={"Critical": 10}),
        ]
    )

    ranked = rank_actions(collapse_findings_to_actions(snapshot, mapping), RankBy.FINDINGS)

    assert [action.package_name for action in ranked] == ["loud", "severe"]


def test_criticals_ranking_is_the_default(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="loud", findings=500, severity={"Medium": 500}),
            make_bucket(package="severe", findings=10, severity={"Critical": 10}),
        ]
    )

    ranked = rank_actions(collapse_findings_to_actions(snapshot, mapping))

    assert [action.package_name for action in ranked] == ["severe", "loud"]


def test_both_coverage_curves_are_computed_under_either_ranking(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """Both are product claims, so neither may depend on the active ordering."""
    by_criticals = build_patch_plan(real_snapshot, mapping, rank_by=RankBy.CRITICALS)
    by_findings = build_patch_plan(real_snapshot, mapping, rank_by=RankBy.FINDINGS)

    assert by_criticals.coverage_by_findings == by_findings.coverage_by_findings
    assert by_criticals.coverage_by_criticals == by_findings.coverage_by_criticals


def test_the_active_curve_mirrors_the_active_ranking(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping, rank_by=RankBy.FINDINGS)

    assert plan.rank_by is RankBy.FINDINGS
    assert plan.coverage_curve == plan.coverage_by_findings


def test_the_findings_curve_is_the_best_possible_findings_coverage(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    """No other ordering can clear more findings in the same number of actions."""
    plan = build_patch_plan(real_snapshot, mapping)

    for position in range(0, 20):
        findings_first = plan.coverage_by_findings[position].cumulative_findings
        criticals_first = plan.coverage_by_criticals[position].cumulative_findings

        assert findings_first >= criticals_first


# ---------------------------------------------------------------------------
# Where the collapse comes from
# ---------------------------------------------------------------------------


def test_collapse_sources_factor_findings_into_cve_depth_and_host_spread(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [make_bucket(findings=100, agents={"001": 50, "002": 50}, cves=50)]
    )

    sources = build_patch_plan(snapshot, mapping).collapse_sources

    assert sources.findings_per_action == 100.0
    assert sources.cves_per_action == 50.0
    assert sources.hosts_per_action == 2.0


def test_a_fleet_with_no_shared_packages_reports_no_host_spread(
    mapping: FieldMapping,
) -> None:
    """One kernel per machine collapses through CVE volume, not duplication."""
    snapshot = make_snapshot(
        [
            make_bucket(package="linux-image-a", findings=500, agents={"001": 500}, cves=500),
            make_bucket(package="linux-image-b", findings=300, agents={"002": 300}, cves=300),
        ]
    )

    sources = build_patch_plan(snapshot, mapping).collapse_sources

    assert sources.hosts_per_action == 1.0
    assert sources.cves_per_action == 400.0


def test_a_fleet_running_one_image_everywhere_reports_host_spread(
    mapping: FieldMapping,
) -> None:
    snapshot = make_snapshot(
        [make_bucket(findings=1000, agents={f"{n:03d}": 100 for n in range(10)}, cves=100)]
    )

    sources = build_patch_plan(snapshot, mapping).collapse_sources

    assert sources.hosts_per_action == 10.0
    assert sources.cves_per_action == 100.0


def test_the_recorded_fleet_collapses_through_cve_volume(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    sources = build_patch_plan(real_snapshot, mapping).collapse_sources

    assert sources.cves_per_action > 10.0
    assert sources.hosts_per_action < 1.5


def test_an_empty_plan_reports_no_collapse_sources(mapping: FieldMapping) -> None:
    sources = build_patch_plan(make_snapshot([], total_findings=0), mapping).collapse_sources

    assert (sources.findings_per_action, sources.cves_per_action, sources.hosts_per_action) == (
        0.0,
        0.0,
        0.0,
    )


def test_the_coverage_curve_counts_distinct_hosts(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [
            make_bucket(package="a", findings=10, agents={"001": 5, "002": 5}),
            make_bucket(package="b", findings=8, agents={"002": 4, "003": 4}),
        ]
    )

    curve = build_patch_plan(snapshot, mapping, rank_by=RankBy.FINDINGS).coverage_curve

    assert [point.cumulative_agents for point in curve] == [2, 3]
