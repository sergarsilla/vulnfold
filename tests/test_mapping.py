"""The field mapping is the only thing that knows the target schema."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vulnfold.config import UNKNOWN_VERSION
from vulnfold.errors import AggregationError, MappingError
from vulnfold.mapping import (
    build_composite_query,
    build_count_query,
    load_mapping,
    parse_composite_page,
    parse_count,
    parse_totals,
)
from vulnfold.models import FieldMapping

ALTERNATE_MAPPING = """
version: "5.x"
index_pattern: "wazuh-vulnerabilities-v5-*"
fields:
  package_name: "software.package"
  package_version: "software.release"
  cve_id: "threat.cve"
  severity: "threat.rating"
  agent_id: "endpoint.uid"
  agent_name: "endpoint.label"
severity_order: ["Severe", "Elevated", "Moderate", "Minor"]
severity_unknown: ["n/a", ""]
"""


def _field_references(node: object) -> list[str]:
    """Collect every field name a query body points an aggregation at."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "field" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_field_references(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_field_references(item))
    return found


def _substitute(node: Any, replacements: dict[str, str]) -> Any:
    if isinstance(node, dict):
        return {key: _substitute(value, replacements) for key, value in node.items()}
    if isinstance(node, list):
        return [_substitute(item, replacements) for item in node]
    if isinstance(node, str):
        return replacements.get(node, node)
    return node


@pytest.fixture
def alternate_mapping(tmp_path: Path) -> FieldMapping:
    path = tmp_path / "wazuh-5.x.yaml"
    path.write_text(ALTERNATE_MAPPING, encoding="utf-8")

    return load_mapping(str(path))


def test_shipped_mapping_declares_the_wazuh_4x_fields(mapping: FieldMapping) -> None:
    assert mapping.version == "4.x"
    assert mapping.index_pattern == "wazuh-states-vulnerabilities-*"
    assert mapping.fields.package_name == "package.name"
    assert mapping.fields.cve_id == "vulnerability.id"
    assert mapping.severity_order == ["Critical", "High", "Medium", "Low"]


def test_load_mapping_accepts_a_path_to_a_file(alternate_mapping: FieldMapping) -> None:
    assert alternate_mapping.version == "5.x"
    assert alternate_mapping.fields.package_name == "software.package"


def test_load_mapping_reports_where_it_looked_for_an_unknown_name(tmp_path: Path) -> None:
    with pytest.raises(MappingError) as error:
        load_mapping("wazuh-9.x", search_paths=[tmp_path])

    assert "wazuh-9.x" in str(error.value)
    assert str(tmp_path) in str(error.value)


def test_load_mapping_rejects_a_file_that_is_not_a_mapping(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("- just\n- a list\n", encoding="utf-8")

    with pytest.raises(MappingError, match="YAML mapping at the top level"):
        load_mapping(str(path))


def test_load_mapping_rejects_a_mapping_missing_a_field(tmp_path: Path) -> None:
    path = tmp_path / "partial.yaml"
    path.write_text(
        ALTERNATE_MAPPING.replace('  agent_name: "endpoint.label"\n', ""),
        encoding="utf-8",
    )

    with pytest.raises(MappingError, match="not a complete mapping"):
        load_mapping(str(path))


def test_load_mapping_rejects_an_unknown_key(tmp_path: Path) -> None:
    path = tmp_path / "extra.yaml"
    path.write_text(ALTERNATE_MAPPING + 'unexpected_key: "value"\n', encoding="utf-8")

    with pytest.raises(MappingError, match="not a complete mapping"):
        load_mapping(str(path))


def test_swapping_the_mapping_retargets_every_query_field(
    mapping: FieldMapping,
    alternate_mapping: FieldMapping,
) -> None:
    """SPEC-01 section 9, criterion 6."""
    shipped_body = build_composite_query(mapping, page_size=1000)
    alternate_body = build_composite_query(alternate_mapping, page_size=1000)

    assert set(_field_references(alternate_body)) == {
        "software.package",
        "software.release",
        "threat.cve",
        "threat.rating",
        "endpoint.uid",
    }
    back_translated = _substitute(
        alternate_body,
        {
            "software.package": mapping.fields.package_name,
            "software.release": mapping.fields.package_version,
            "threat.cve": mapping.fields.cve_id,
            "threat.rating": mapping.fields.severity,
            "endpoint.uid": mapping.fields.agent_id,
        },
    )

    assert back_translated == shipped_body


def test_composite_query_never_mentions_a_field_the_mapping_does_not_declare(
    mapping: FieldMapping,
) -> None:
    declared = set(mapping.fields.model_dump().values())

    assert set(_field_references(build_composite_query(mapping, page_size=10))) <= declared


def test_composite_query_groups_documents_that_carry_no_version(
    mapping: FieldMapping,
) -> None:
    body = build_composite_query(mapping, page_size=10)
    sources = body["aggs"]["actions"]["composite"]["sources"]  # type: ignore[index]

    assert sources[1]["ver"]["terms"]["missing_bucket"] is True


def test_composite_query_requests_fleet_totals_only_on_the_first_page(
    mapping: FieldMapping,
) -> None:
    first = build_composite_query(mapping, page_size=10)
    later = build_composite_query(mapping, page_size=10, after_key={"pkg": "a", "ver": "1"})

    assert "total_agents" in first["aggs"]  # type: ignore[operator]
    assert "total_agents" not in later["aggs"]  # type: ignore[operator]


def test_composite_query_carries_the_cursor_of_the_previous_page(
    mapping: FieldMapping,
) -> None:
    cursor = {"pkg": "openssl", "ver": "3.0.2-1"}

    body = build_composite_query(mapping, page_size=10, after_key=cursor)

    assert body["aggs"]["actions"]["composite"]["after"] == cursor  # type: ignore[index]


def test_count_query_matches_every_document() -> None:
    assert build_count_query() == {"query": {"match_all": {}}}


def test_parse_count_reads_the_document_total() -> None:
    assert parse_count({"count": 32718}) == 32718


def test_parse_totals_reads_the_three_fleet_cardinalities(
    composite_pages: list[dict[str, Any]],
) -> None:
    totals = parse_totals(composite_pages[0])

    assert (totals.agents, totals.distinct_cves, totals.distinct_packages) == (15, 5950, 554)


def test_parse_composite_page_reads_buckets_and_the_next_cursor(
    composite_pages: list[dict[str, Any]],
    mapping: FieldMapping,
) -> None:
    page = parse_composite_page(composite_pages[0], mapping)

    assert len(page.buckets) == 248
    assert page.after_key is not None


def test_parse_composite_page_ends_the_walk_on_an_empty_page(
    composite_pages: list[dict[str, Any]],
    mapping: FieldMapping,
) -> None:
    page = parse_composite_page(composite_pages[-1], mapping)

    assert page.buckets == []
    assert page.after_key is None


def test_parse_composite_page_groups_a_missing_version_under_unknown(
    mapping: FieldMapping,
) -> None:
    response = {
        "aggregations": {
            "actions": {
                "buckets": [
                    {
                        "key": {"pkg": "openssl", "ver": None},
                        "doc_count": 4,
                        "agents": {"buckets": [{"key": "001", "doc_count": 4}]},
                        "agent_cardinality": {"value": 1},
                        "severity": {"buckets": [{"key": "High", "doc_count": 4}]},
                        "cves": {"value": 4},
                    }
                ]
            }
        }
    }

    page = parse_composite_page(response, mapping)

    assert page.buckets[0].package_version == UNKNOWN_VERSION


def test_parse_composite_page_reports_a_response_without_aggregations(
    mapping: FieldMapping,
) -> None:
    with pytest.raises(AggregationError, match="aggregations"):
        parse_composite_page({"hits": {"hits": []}}, mapping)


def test_parse_composite_page_reports_a_bucket_missing_a_sub_aggregation(
    mapping: FieldMapping,
) -> None:
    response = {
        "aggregations": {
            "actions": {"buckets": [{"key": {"pkg": "openssl", "ver": "1"}, "doc_count": 1}]}
        }
    }

    with pytest.raises(AggregationError, match="agents"):
        parse_composite_page(response, mapping)


def test_parse_totals_reports_a_malformed_cardinality() -> None:
    with pytest.raises(AggregationError, match="total_agents"):
        parse_totals({"aggregations": {"total_agents": {"value": "many"}}})


def test_canonical_severity_ignores_case(mapping: FieldMapping) -> None:
    assert mapping.canonical_severity("critical") == "Critical"
    assert mapping.canonical_severity("  HIGH  ") == "High"


def test_canonical_severity_returns_nothing_for_a_placeholder(mapping: FieldMapping) -> None:
    assert mapping.canonical_severity("-") is None
    assert mapping.is_explicitly_unknown("-") is True
    assert mapping.is_explicitly_unknown("None") is True


def test_a_value_the_mapping_never_heard_of_is_not_an_explicit_placeholder(
    mapping: FieldMapping,
) -> None:
    assert mapping.canonical_severity("Catastrophic") is None
    assert mapping.is_explicitly_unknown("Catastrophic") is False
