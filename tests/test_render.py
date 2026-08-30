"""Every format opens with the impact line, because that line is the product."""

from __future__ import annotations

import json
from io import StringIO

import pytest
from conftest import (
    DEFECT_PACKAGE,
    MEASURED_ACTIONS,
    MEASURED_FIXABLE_FINDINGS,
    NO_FIX_CONDITION,
    make_bucket,
    make_snapshot,
)
from rich.console import Console

from vulnfold.collapse import build_patch_plan
from vulnfold.models import (
    FieldMapping,
    IndexerSnapshot,
    PatchPlan,
    RankBy,
    ScanWarning,
    WarningCode,
)
from vulnfold.render import (
    NOTHING_TO_REMEDIATE,
    NOTHING_UNFIXABLE,
    OutputFormat,
    build_table_view,
    impact_lines,
    render_json,
    render_markdown,
)

TABLE_WIDTH = 200


@pytest.fixture
def real_plan(real_snapshot: IndexerSnapshot, mapping: FieldMapping) -> PatchPlan:
    return build_patch_plan(real_snapshot, mapping)


def render_table(plan: PatchPlan, top: int, *, show_unfixable: bool = True) -> str:
    buffer = StringIO()
    console = Console(file=buffer, width=TABLE_WIDTH, no_color=True, legacy_windows=False)
    console.print(build_table_view(plan, top, show_unfixable=show_unfixable))
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# The impact line (SPEC-01 section 7)
# ---------------------------------------------------------------------------


def test_impact_lines_open_with_the_fixability_split(real_plan: PatchPlan) -> None:
    """SPEC-02 section 7.1: the only percentages over the fleet total."""
    lines = impact_lines(real_plan, top=7)

    assert lines[0] == (
        "32,718 findings → 13,664 fixable (41.8%) · 19,039 with no vendor fix (58.2%)"
    )
    assert lines[1] == "Criticals: 2,492 → 1,322 fixable · 1,170 with no vendor fix"


def test_impact_line_states_the_collapse_of_the_fixable_half(real_plan: PatchPlan) -> None:
    assert impact_lines(real_plan, top=7)[3] == (
        "13,664 fixable findings → 560 actions across 453 packages (ratio 30:1)"
    )


def test_impact_lines_state_both_product_claims(real_plan: PatchPlan) -> None:
    """Both claims are shown whichever ranking is active; they need not agree."""
    lines = impact_lines(real_plan, top=7)

    assert lines[5] == (
        "First 7 by findings: 7,727 of the 13,664 fixable findings (56.5%), on 7 hosts."
    )
    assert lines[6] == (
        "First 7 by criticals: 920 of the 1,322 fixable criticals (69.6%), on 7 hosts."
    )


def test_every_headline_percentage_names_the_denominator_it_is_over(
    real_plan: PatchPlan,
) -> None:
    """SPEC-02 section 10, criterion 7, on a plan whose two totals differ."""
    lines = impact_lines(real_plan, top=7)

    assert real_plan.fixable_findings != real_plan.total_findings
    # 41.8% and 58.2% are over the fleet total, and their line says so by
    # opening with it. Every later percentage names the fixable denominator.
    for line in lines[3:]:
        if "%" in line:
            assert "fixable" in line
    assert "32,718" not in "\n".join(lines[3:])


def test_impact_lines_separate_cve_depth_from_host_spread(real_plan: PatchPlan) -> None:
    """SPEC feedback: nothing may imply cross-host collapse where there is none."""
    sources = impact_lines(real_plan, top=7)[4]

    assert sources == (
        "Each action clears 24.4 findings: 19.7 CVEs per package version "
        "× 1.24 hosts carrying it."
    )


def test_both_claims_are_shown_under_either_ranking(
    real_snapshot: IndexerSnapshot,
    mapping: FieldMapping,
) -> None:
    by_criticals = impact_lines(build_patch_plan(real_snapshot, mapping), top=7)
    by_findings = impact_lines(
        build_patch_plan(real_snapshot, mapping, rank_by=RankBy.FINDINGS), top=7
    )

    assert by_criticals[2:] == by_findings[2:]


def test_impact_line_never_promises_more_actions_than_the_plan_has(
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(make_snapshot([make_bucket(findings=10)]), mapping)

    assert impact_lines(plan, top=20)[5].startswith("First 1 by findings:")


def test_a_single_host_is_not_pluralised(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([make_bucket(findings=10)]), mapping)

    assert "on 1 host." in impact_lines(plan, top=1)[5]


def test_impact_line_says_so_when_there_is_nothing_to_do(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([], total_findings=0), mapping)

    assert impact_lines(plan, top=20)[-1] == NOTHING_TO_REMEDIATE


# ---------------------------------------------------------------------------
# JSON (SPEC-01 section 7, criterion 7)
# ---------------------------------------------------------------------------


def test_json_is_the_whole_plan_and_parses(real_plan: PatchPlan) -> None:
    document = json.loads(render_json(real_plan))

    assert document["collapse_ratio"] == 30.16
    assert document["total_findings"] == 32_718
    assert document["fixable_findings"] == MEASURED_FIXABLE_FINDINGS
    assert len(document["actions"]) == MEASURED_ACTIONS
    assert len(document["coverage_curve"]) == MEASURED_ACTIONS
    assert len(document["unfixable"]) == 359


def test_json_round_trips_back_into_a_plan(real_plan: PatchPlan) -> None:
    assert PatchPlan.model_validate_json(render_json(real_plan)) == real_plan


def test_json_is_not_shortened_by_the_top_option(real_plan: PatchPlan) -> None:
    """The machine contract carries the whole plan; --top is a display choice."""
    document = json.loads(render_json(real_plan))

    assert len(document["actions"]) == MEASURED_ACTIONS
    assert len(document["unfixable"]) == 359


def test_json_reports_warnings_as_codes(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([], total_findings=0), mapping)

    document = json.loads(render_json(plan))

    assert document["warnings"][0]["code"] == "empty_index"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def test_markdown_opens_with_the_impact_line(real_plan: PatchPlan) -> None:
    report = render_markdown(real_plan, top=7)

    assert report.startswith("# vulnfold patch plan")
    assert (
        "**32,718 findings → 13,664 fixable (41.8%) · 19,039 with no vendor fix (58.2%)**"
        in report
    )
    assert "**13,664 fixable findings → 560 actions across 453 packages (ratio 30:1)**" in report
    assert (
        "**First 7 by findings: 7,727 of the 13,664 fixable findings (56.5%), on 7 hosts.**"
        in report
    )
    assert "**First 7 by criticals:" in report


def test_markdown_lists_no_more_than_the_requested_actions(real_plan: PatchPlan) -> None:
    report = render_markdown(real_plan, top=5, show_unfixable=False)

    rows = [line for line in report.splitlines() if line.startswith("| ") and " | " in line]

    assert len(rows) == 5 + 1  # the header row is not an action


def test_markdown_names_the_leading_kernels(real_plan: PatchPlan) -> None:
    report = render_markdown(real_plan, top=7)

    assert "linux-image-cloud-amd64" in report
    assert DEFECT_PACKAGE in report


def test_markdown_reports_warnings(mapping: FieldMapping) -> None:
    plan = build_patch_plan(
        make_snapshot([make_bucket(findings=10)], total_findings=99), mapping
    )

    report = render_markdown(plan, top=5)

    assert "## Warnings" in report
    assert "`bucket_sum_mismatch`" in report


def test_markdown_has_no_warnings_section_when_there_are_none(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([make_bucket(findings=10)]), mapping)

    assert "## Warnings" not in render_markdown(plan, top=5)


def test_markdown_renders_an_empty_plan(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([], total_findings=0), mapping)

    report = render_markdown(plan, top=20)

    assert NOTHING_TO_REMEDIATE in report


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------


def test_table_opens_with_the_impact_line(real_plan: PatchPlan) -> None:
    output = render_table(real_plan, top=7)

    assert "32,718 findings → 13,664 fixable (41.8%)" in output
    assert "13,664 fixable findings → 560 actions across 453 packages (ratio 30:1)" in output
    assert "First 7 by findings: 7,727 of the 13,664 fixable findings (56.5%), on 7 hosts." in (
        output
    )
    assert "First 7 by criticals:" in output


def test_table_lists_the_leading_actions(real_plan: PatchPlan) -> None:
    output = render_table(real_plan, top=3)

    assert "linux-image-cloud-amd64" in output
    assert "linux-image-amd64" in output


def test_table_marks_kernel_actions(real_plan: PatchPlan) -> None:
    assert "Kernel" in render_table(real_plan, top=3)


def test_table_shows_unrated_findings_in_their_own_column(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [make_bucket(package="openssl", findings=212, severity={"-": 212})]
    )

    output = render_table(build_patch_plan(snapshot, mapping), top=5)

    assert "Unrated" in output
    assert "212" in output


def test_table_reports_warnings(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([], total_findings=0), mapping)

    output = render_table(plan, top=20)

    assert "empty_index" in output
    assert NOTHING_TO_REMEDIATE in output


def test_output_formats_are_the_three_the_specification_names() -> None:
    assert {member.value for member in OutputFormat} == {"table", "json", "markdown"}


def test_a_warning_carries_a_stable_code() -> None:
    warning = ScanWarning(code=WarningCode.EMPTY_INDEX, message="nothing here")

    assert json.loads(warning.model_dump_json())["code"] == "empty_index"


# ---------------------------------------------------------------------------
# Column widths: Package is the column a reader acts on
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("width", [100, 120, 140, 200])
def test_package_names_survive_at_every_width(real_plan: PatchPlan, width: int) -> None:
    console = Console(file=(buffer := StringIO()), width=width, no_color=True)
    console.print(build_table_view(real_plan, 7))
    output = buffer.getvalue()

    for action in real_plan.actions[:7]:
        assert action.package_name in output


def test_version_gives_up_its_width_before_package_does(real_plan: PatchPlan) -> None:
    console = Console(file=(buffer := StringIO()), width=120, no_color=True)
    console.print(build_table_view(real_plan, 7))
    output = buffer.getvalue()

    assert "linux-image-6.14.0-37-generic" in output
    assert "6.14.0-37.37~24.04.1" not in output
    assert "6.14.0-37.37" in output


def test_markdown_never_truncates_anything(real_plan: PatchPlan) -> None:
    report = render_markdown(real_plan, top=7)

    assert "6.14.0-37.37~24.04.1" in report
    assert "…" not in report


# ---------------------------------------------------------------------------
# The unfixable register (SPEC-02 section 7.3)
# ---------------------------------------------------------------------------


def test_the_defect_row_is_in_the_register_and_not_in_the_plan_table(
    real_plan: PatchPlan,
) -> None:
    """SPEC-02 section 10, criterion 3, at the rendering layer."""
    plan_only = render_markdown(real_plan, top=20, show_unfixable=False)
    with_register = render_markdown(real_plan, top=20)

    assert DEFECT_PACKAGE not in plan_only
    assert DEFECT_PACKAGE in with_register


def test_the_register_heading_says_what_it_is_and_what_to_do_with_it(
    real_plan: PatchPlan,
) -> None:
    report = render_markdown(real_plan, top=3)

    assert "## No vendor fix available — 19,039 findings, 1,170 critical" in report
    assert "require documented risk acceptance" in report


def test_the_register_carries_no_percentage_of_any_total(real_plan: PatchPlan) -> None:
    """SPEC-02 section 10, criterion 7: nothing here is a share of anything."""
    report = render_markdown(real_plan, top=10)
    register = report.split("## No vendor fix available")[1].split("## Warnings")[0]

    assert "%" not in register


def test_the_register_can_be_suppressed(real_plan: PatchPlan) -> None:
    assert "No vendor fix available" not in render_markdown(real_plan, top=3, show_unfixable=False)
    assert "No vendor fix available" not in render_table(real_plan, top=3, show_unfixable=False)


def test_the_table_view_prints_the_register_after_the_plan(real_plan: PatchPlan) -> None:
    output = render_table(real_plan, top=3)

    assert output.index("No vendor fix available") > output.index("linux-image-cloud-amd64")


def test_a_fleet_with_a_fix_for_everything_says_so(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([make_bucket(findings=10)]), mapping)

    assert NOTHING_UNFIXABLE in render_markdown(plan, top=5)
    assert NOTHING_UNFIXABLE in render_table(plan, top=5)


def test_the_plan_table_names_the_version_to_upgrade_to(mapping: FieldMapping) -> None:
    snapshot = make_snapshot(
        [make_bucket(package="openssl", version="3.0.2-1", findings=10)]
    )

    output = render_table(build_patch_plan(snapshot, mapping), top=5)

    assert "Target" in output
    assert "3.0.2-2" in output


def test_the_plan_table_shares_are_over_the_fixable_findings(mapping: FieldMapping) -> None:
    """SPEC-02 section 10, criterion 7, on a plan whose two totals differ."""
    snapshot = make_snapshot(
        [
            make_bucket(package="openssl", findings=25),
            make_bucket(package="curl", findings=75, condition=NO_FIX_CONDITION),
        ]
    )
    plan = build_patch_plan(snapshot, mapping)

    output = render_table(plan, top=5)

    assert plan.total_findings == 100
    assert plan.fixable_findings == 25
    # 25 of 25 fixable findings, not 25 of 100.
    assert "100.0%" in output


def test_the_target_column_survives_at_every_width(real_plan: PatchPlan) -> None:
    """SPEC-02 section 7.2: Target is protected, Version gives way first."""
    for width in (100, 120, 140, 200):
        console = Console(file=(buffer := StringIO()), width=width, no_color=True)
        console.print(build_table_view(real_plan, 7, show_unfixable=False))
        output = buffer.getvalue()

        for action in real_plan.actions[:7]:
            assert action.target_version in output, width
