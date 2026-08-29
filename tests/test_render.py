"""Every format opens with the impact line, because that line is the product."""

from __future__ import annotations

import json
from io import StringIO

import pytest
from conftest import make_bucket, make_snapshot
from rich.console import Console

from vulnfold.collapse import build_patch_plan
from vulnfold.models import FieldMapping, IndexerSnapshot, PatchPlan, ScanWarning, WarningCode
from vulnfold.render import (
    NOTHING_TO_REMEDIATE,
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


def render_table(plan: PatchPlan, top: int) -> str:
    buffer = StringIO()
    console = Console(file=buffer, width=TABLE_WIDTH, no_color=True, legacy_windows=False)
    console.print(build_table_view(plan, top))
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# The impact line (SPEC-01 section 7)
# ---------------------------------------------------------------------------


def test_impact_line_states_the_collapse(real_plan: PatchPlan) -> None:
    headline = impact_lines(real_plan, top=7)[0]

    assert headline == "32,718 findings → 744 actions across 554 packages (ratio 59:1)"


def test_impact_line_states_what_the_leading_actions_remove(real_plan: PatchPlan) -> None:
    detail = impact_lines(real_plan, top=7)[1]

    assert detail.startswith("The first 7 eliminate 23,309 findings (71.2%)")
    assert detail.endswith("criticals.")


def test_impact_line_never_promises_more_actions_than_the_plan_has(
    mapping: FieldMapping,
) -> None:
    plan = build_patch_plan(make_snapshot([make_bucket(findings=10)]), mapping)

    assert impact_lines(plan, top=20)[1].startswith("The first 1 ")


def test_impact_line_says_so_when_there_is_nothing_to_do(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([], total_findings=0), mapping)

    assert impact_lines(plan, top=20)[1] == NOTHING_TO_REMEDIATE


# ---------------------------------------------------------------------------
# JSON (SPEC-01 section 7, criterion 7)
# ---------------------------------------------------------------------------


def test_json_is_the_whole_plan_and_parses(real_plan: PatchPlan) -> None:
    document = json.loads(render_json(real_plan))

    assert document["collapse_ratio"] == 59.06
    assert document["total_findings"] == 32_718
    assert len(document["actions"]) == 744
    assert len(document["coverage_curve"]) == 744


def test_json_round_trips_back_into_a_plan(real_plan: PatchPlan) -> None:
    assert PatchPlan.model_validate_json(render_json(real_plan)) == real_plan


def test_json_is_not_shortened_by_the_top_option(real_plan: PatchPlan) -> None:
    """The machine contract carries the whole plan; --top is a display choice."""
    assert len(json.loads(render_json(real_plan))["actions"]) == 744


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
    assert "**32,718 findings → 744 actions across 554 packages (ratio 59:1)**" in report
    assert "**The first 7 eliminate 23,309 findings (71.2%)" in report


def test_markdown_lists_no_more_than_the_requested_actions(real_plan: PatchPlan) -> None:
    report = render_markdown(real_plan, top=5)

    rows = [line for line in report.splitlines() if line.startswith("| ") and " | " in line]

    assert len(rows) == 5 + 1  # the header row is not an action


def test_markdown_names_the_leading_kernels(real_plan: PatchPlan) -> None:
    report = render_markdown(real_plan, top=7)

    assert "linux-image-6.14.0-37-generic" in report
    assert "linux-oracle" in report


def test_markdown_reports_warnings(mapping: FieldMapping) -> None:
    plan = build_patch_plan(
        make_snapshot([make_bucket(findings=10)], total_findings=99), mapping
    )

    report = render_markdown(plan, top=5)

    assert "## Warnings" in report
    assert "`bucket_sum_mismatch`" in report


def test_markdown_has_no_warnings_section_when_there_are_none(real_plan: PatchPlan) -> None:
    assert "## Warnings" not in render_markdown(real_plan, top=5)


def test_markdown_renders_an_empty_plan(mapping: FieldMapping) -> None:
    plan = build_patch_plan(make_snapshot([], total_findings=0), mapping)

    report = render_markdown(plan, top=20)

    assert NOTHING_TO_REMEDIATE in report


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------


def test_table_opens_with_the_impact_line(real_plan: PatchPlan) -> None:
    output = render_table(real_plan, top=7)

    assert "32,718 findings → 744 actions across 554 packages (ratio 59:1)" in output
    assert "The first 7 eliminate 23,309 findings (71.2%)" in output


def test_table_lists_the_leading_actions(real_plan: PatchPlan) -> None:
    output = render_table(real_plan, top=3)

    assert "linux-image-6.14.0-37-generic" in output
    assert "linux-image-cloud-amd64" in output
    assert "linux-oracle" not in output


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
