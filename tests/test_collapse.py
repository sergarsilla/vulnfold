"""The collapse engine: findings in, ranked patch plan out."""

from __future__ import annotations

import pytest
from conftest import (
    MEASURED_ACTIONS,
    MEASURED_AGENTS,
    MEASURED_COLLAPSE_RATIO,
    MEASURED_DISTINCT_CVES,
    MEASURED_DISTINCT_PACKAGES,
    MEASURED_FINDINGS,
    MEASURED_TOP_SEVEN_FINDINGS,
    MEASURED_TOP_SEVEN_PERCENTAGE,
    make_bucket,
    make_snapshot,
)

from vulnfold.collapse import (
    build_coverage_curve,
    build_patch_plan,
    collapse_findings_to_actions,
    filter_by_min_severity,
    group_kernel_actions,
    is_kernel_package,
    rank_actions,
)
from vulnfold.config import UNKNOWN_SEVERITY
from vulnfold.errors import ConfigurationError
from vulnfold.models import FieldMapping, IndexerSnapshot, WarningCode

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


def test_plan_produces_one_action_per_package_version(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert len(plan.actions) == MEASURED_ACTIONS
    assert len({(action.package_name, action.current_version) for action in plan.actions}) == (
        MEASURED_ACTIONS
    )


def test_collapse_ratio_is_findings_per_distinct_package(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert plan.collapse_ratio == MEASURED_COLLAPSE_RATIO
    assert round(plan.collapse_ratio) == 59


def test_first_seven_actions_eliminate_seventy_one_percent_of_findings(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    seventh = plan.coverage_curve[6]

    assert seventh.cumulative_findings == MEASURED_TOP_SEVEN_FINDINGS
    assert abs(seventh.findings_percentage - MEASURED_TOP_SEVEN_PERCENTAGE) <= 0.1


def test_first_seven_actions_are_all_kernels(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert all(action.is_kernel for action in plan.actions[:7])


def test_recorded_fleet_reconciles_without_warnings(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert plan.warnings == []


def test_severity_totals_across_the_plan_match_the_recorded_distribution(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(real_snapshot, mapping)

    assert sum(action.critical_count for action in plan.actions) == 2_492
    assert sum(action.high_count for action in plan.actions) == 12_158
    # 7,287 findings carry "-" and 2 carry "None"; neither is a severity.
    assert sum(action.unknown_severity_count for action in plan.actions) == 7_289


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
    assert plan.coverage_curve[-1].cumulative_findings == MEASURED_FINDINGS


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
