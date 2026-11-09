"""Field mapping: the only place that knows the target schema.

This module owns both halves of the schema adapter — the queries sent to the
indexer and the parsing of what comes back. Both are pure functions over a
:class:`FieldMapping`, so pointing vulnfold at a different Wazuh release is a
YAML file, never a code change.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

import yaml

from vulnfold.config import (
    AGENT_TERMS_SIZE,
    INDEX_TERMS_SIZE,
    MAPPING_FILE_SUFFIX,
    MAPPING_SEARCH_PATHS,
    SEVERITY_TERMS_SIZE,
    UNKNOWN_VERSION,
)
from vulnfold.errors import AggregationError, MappingError
from vulnfold.models import (
    AgentLiveness,
    FieldMapping,
    Fixability,
    IndexInventory,
    LivenessFields,
    LivenessSnapshot,
    PackageBucket,
)

#: Names vulnfold gives its own aggregations. These are query labels, not
#: schema fields, so they are fixed here rather than in ``mappings/``.
ACTIONS_AGG: Final = "actions"
AGENTS_AGG: Final = "agents"
AGENT_CARDINALITY_AGG: Final = "agent_cardinality"
SEVERITY_AGG: Final = "severity"
CVES_AGG: Final = "cves"
TOTAL_AGENTS_AGG: Final = "total_agents"
TOTAL_CVES_AGG: Final = "total_cves"
TOTAL_PACKAGES_AGG: Final = "total_packages"
AGENT_NAMES_AGG: Final = "agent_names"
AGENT_NAME_AGG: Final = "name"
INVENTORY_AGG: Final = "inventory"
INDICES_AGG: Final = "indices"
NEWEST_AGG: Final = "newest"
LATEST_SNAPSHOT_AGG: Final = "latest"
LIVENESS_AGG: Final = "liveness"
LAST_SEEN_AGG: Final = "last_seen"
#: Built-in field naming the index a document lives in; not schema-specific.
INDEX_FIELD: Final = "_index"
PACKAGE_SOURCE: Final = "pkg"
VERSION_SOURCE: Final = "ver"
CONDITION_SOURCE: Final = "cond"

CompositeKey = dict[str, str | None]


@dataclass(frozen=True)
class CompositePage:
    """One page of composite buckets plus the cursor that follows it."""

    buckets: list[PackageBucket]
    after_key: CompositeKey | None


@dataclass(frozen=True)
class SnapshotTotals:
    """Fleet-wide cardinalities, answered once per scan."""

    agents: int
    distinct_cves: int
    distinct_packages: int


def load_mapping(
    name: str,
    search_paths: Sequence[Path] = MAPPING_SEARCH_PATHS,
) -> FieldMapping:
    """Load a field mapping by name or by path.

    Args:
        name: A mapping name such as ``wazuh-4.x``, or a path to a YAML file.
        search_paths: Directories searched, in order, when ``name`` is a name.

    Returns:
        The validated mapping.

    Raises:
        MappingError: The file is missing, is not valid YAML, or does not
            describe a complete mapping.
    """
    path = _resolve_mapping_path(name, search_paths)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MappingError(f"Cannot read mapping file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise MappingError(f"Mapping file {path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise MappingError(
            f"Mapping file {path} must contain a YAML mapping at the top level, "
            f"found {type(raw).__name__}."
        )
    try:
        return FieldMapping.model_validate(raw)
    except ValueError as exc:
        raise MappingError(f"Mapping file {path} is not a complete mapping: {exc}") from exc


def _resolve_mapping_path(name: str, search_paths: Sequence[Path]) -> Path:
    if name.endswith(MAPPING_FILE_SUFFIX) or os.sep in name:
        candidate = Path(name)
        if candidate.is_file():
            return candidate
        raise MappingError(f"Mapping file not found: {candidate}")

    tried = [directory / f"{name}{MAPPING_FILE_SUFFIX}" for directory in search_paths]
    for candidate in tried:
        if candidate.is_file():
            return candidate
    locations = ", ".join(str(candidate) for candidate in tried)
    raise MappingError(f"Mapping {name!r} not found. Looked in: {locations}")


def build_count_query(query: Mapping[str, object] | None = None) -> dict[str, object]:
    """Build the body that totals the findings a scan is about to collapse.

    Args:
        query: Document filter the scan applies, or ``None`` for every document.

    Returns:
        A request body ready to POST to ``_count``.
    """
    return {"query": dict(query) if query is not None else {"match_all": {}}}


def build_document_filter(
    mapping: FieldMapping,
    *,
    superseded: Mapping[str, Sequence[str]],
    agents: Sequence[str] | None,
) -> dict[str, object] | None:
    """Build the query that keeps current documents of the agents in scope.

    Args:
        mapping: Field mapping in force.
        superseded: Index name to the agents whose documents there are
            superseded copies.
        agents: Agents to keep, or ``None`` to keep every agent.

    Returns:
        A ``bool`` query, or ``None`` when nothing needs filtering.
    """
    field = mapping.fields.agent_id
    must_not: list[object] = [
        {"bool": {"filter": [{"term": {INDEX_FIELD: index}}, {"terms": {field: sorted(ids)}}]}}
        for index, ids in sorted(superseded.items())
        if ids
    ]
    clauses: dict[str, object] = {}
    if must_not:
        clauses["must_not"] = must_not
    if agents is not None:
        clauses["filter"] = [{"terms": {field: sorted(agents)}}]
    return {"bool": clauses} if clauses else None


def build_inventory_query(mapping: FieldMapping) -> dict[str, object]:
    """Build the body listing which state indices hold each agent.

    Args:
        mapping: Field mapping in force.

    Returns:
        A request body ready to POST to ``_search``.
    """
    fields = mapping.fields
    per_index: dict[str, object] = {"terms": {"field": INDEX_FIELD, "size": INDEX_TERMS_SIZE}}
    if fields.detected_at is not None:
        per_index["aggs"] = {NEWEST_AGG: {"max": {"field": fields.detected_at}}}
    return {
        "size": 0,
        "track_total_hits": False,
        "aggs": {
            INVENTORY_AGG: {
                "terms": {"field": fields.agent_id, "size": AGENT_TERMS_SIZE},
                "aggs": {INDICES_AGG: per_index},
            }
        },
    }


def parse_inventory(response: Mapping[str, object]) -> IndexInventory:
    """Read which indices hold each agent from an inventory response.

    Args:
        response: Decoded ``_search`` body of :func:`build_inventory_query`.

    Returns:
        Per agent, the findings and newest detection in each index.

    Raises:
        AggregationError: The response does not have the requested shape.
    """
    aggregations = _require_mapping(_get(response, "aggregations"), "aggregations")
    inventory = _require_mapping(_get(aggregations, INVENTORY_AGG), INVENTORY_AGG)
    newest: dict[str, dict[str, str | None]] = {}
    findings: dict[str, dict[str, int]] = {}
    for position, raw in enumerate(_require_list(_get(inventory, "buckets"), INVENTORY_AGG)):
        path = f"{INVENTORY_AGG}.buckets[{position}]"
        bucket = _require_mapping(raw, path)
        agent = _key_string(_get(bucket, "key", path), f"{path}.key")
        indices = _require_mapping(_get(bucket, INDICES_AGG, path), f"{path}.{INDICES_AGG}")
        newest[agent] = {}
        findings[agent] = {}
        for index_position, raw_index in enumerate(
            _require_list(_get(indices, "buckets"), f"{path}.{INDICES_AGG}")
        ):
            index_path = f"{path}.{INDICES_AGG}.buckets[{index_position}]"
            index_bucket = _require_mapping(raw_index, index_path)
            index = _key_string(_get(index_bucket, "key", index_path), f"{index_path}.key")
            findings[agent][index] = _require_int(
                _get(index_bucket, "doc_count", index_path), f"{index_path}.doc_count"
            )
            newest_agg = index_bucket.get(NEWEST_AGG)
            stamp = newest_agg.get("value_as_string") if isinstance(newest_agg, Mapping) else None
            newest[agent][index] = str(stamp) if stamp else None
    return IndexInventory(newest_detection=newest, findings=findings)


def build_latest_snapshot_query(liveness: LivenessFields) -> dict[str, object]:
    """Build the body asking when the newest monitoring snapshot was taken."""
    return {
        "size": 0,
        "track_total_hits": False,
        "aggs": {LATEST_SNAPSHOT_AGG: {"max": {"field": liveness.snapshot_time}}},
    }


def parse_latest_snapshot(response: Mapping[str, object]) -> datetime | None:
    """Read the newest snapshot time, or ``None`` when there is none."""
    aggregations = response.get("aggregations")
    latest = aggregations.get(LATEST_SNAPSHOT_AGG) if isinstance(aggregations, Mapping) else None
    value = latest.get("value") if isinstance(latest, Mapping) else None
    return _epoch_millis(value)


def build_liveness_query(liveness: LivenessFields, *, since: datetime) -> dict[str, object]:
    """Build the body listing every agent in the snapshots taken since ``since``.

    Args:
        liveness: Liveness field mapping in force.
        since: Start of the window that defines who is registered.

    Returns:
        A request body ready to POST to ``_search``.
    """
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"range": {liveness.snapshot_time: {"gte": since.isoformat()}}},
        "aggs": {
            LIVENESS_AGG: {
                "terms": {"field": liveness.agent_id, "size": AGENT_TERMS_SIZE},
                "aggs": {
                    LAST_SEEN_AGG: {"max": {"field": liveness.last_seen}},
                    AGENT_NAME_AGG: {"terms": {"field": liveness.agent_name, "size": 1}},
                },
            }
        },
    }


def parse_liveness(response: Mapping[str, object], *, snapshot_time: datetime) -> LivenessSnapshot:
    """Read every registered agent and when it was last seen.

    Malformed entries are skipped rather than failing the scan: liveness only
    scopes the plan, and a missing agent is reported as unregistered.
    """
    agents: dict[str, AgentLiveness] = {}
    aggregations = response.get("aggregations")
    liveness = aggregations.get(LIVENESS_AGG) if isinstance(aggregations, Mapping) else None
    buckets = liveness.get("buckets") if isinstance(liveness, Mapping) else None
    for raw in buckets if isinstance(buckets, list) else []:
        if not isinstance(raw, Mapping) or raw.get("key") is None:
            continue
        agent = str(raw["key"])
        last_seen_agg = raw.get(LAST_SEEN_AGG)
        last_seen = _epoch_millis(
            last_seen_agg.get("value") if isinstance(last_seen_agg, Mapping) else None
        )
        name_agg = raw.get(AGENT_NAME_AGG)
        name_buckets = name_agg.get("buckets") if isinstance(name_agg, Mapping) else None
        name = None
        if isinstance(name_buckets, list) and name_buckets and isinstance(name_buckets[0], Mapping):
            name = str(name_buckets[0].get("key")) or None
        agents[agent] = AgentLiveness(agent_id=agent, name=name, last_seen=last_seen)
    return LivenessSnapshot(snapshot_time=snapshot_time, agents=agents)


def _epoch_millis(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc)


def build_composite_query(
    mapping: FieldMapping,
    *,
    page_size: int,
    after_key: Mapping[str, str | None] | None = None,
    query: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build one page of the ``(package, version, condition)`` composite aggregation.

    Args:
        mapping: Field mapping that supplies every field name in the body.
        page_size: Buckets requested for this page.
        after_key: Cursor returned by the previous page, or ``None`` to start.
        query: Document filter to apply, or ``None`` for every document.

    Returns:
        A request body ready to POST to ``_search``.
    """
    fields = mapping.fields
    composite: dict[str, object] = {
        "size": page_size,
        "sources": [
            {PACKAGE_SOURCE: {"terms": {"field": fields.package_name}}},
            # Findings whose package version is absent must be grouped, not
            # dropped; without missing_bucket the composite skips them silently.
            {VERSION_SOURCE: {"terms": {"field": fields.package_version, "missing_bucket": True}}},
            # Likewise for the condition: a finding carrying none is reported as
            # unrecognised fixability, which is a mapping defect worth seeing.
            {
                CONDITION_SOURCE: {
                    "terms": {"field": fields.scanner_condition, "missing_bucket": True}
                }
            },
        ],
    }
    if after_key is not None:
        composite["after"] = after_key

    aggregations: dict[str, object] = {
        ACTIONS_AGG: {
            "composite": composite,
            "aggs": {
                AGENTS_AGG: {"terms": {"field": fields.agent_id, "size": AGENT_TERMS_SIZE}},
                AGENT_CARDINALITY_AGG: {"cardinality": {"field": fields.agent_id}},
                SEVERITY_AGG: {"terms": {"field": fields.severity, "size": SEVERITY_TERMS_SIZE}},
                CVES_AGG: {"cardinality": {"field": fields.cve_id}},
            },
        }
    }
    if after_key is None:
        aggregations[TOTAL_AGENTS_AGG] = {"cardinality": {"field": fields.agent_id}}
        aggregations[TOTAL_CVES_AGG] = {"cardinality": {"field": fields.cve_id}}
        aggregations[TOTAL_PACKAGES_AGG] = {"cardinality": {"field": fields.package_name}}
        aggregations[AGENT_NAMES_AGG] = {
            "terms": {"field": fields.agent_id, "size": AGENT_TERMS_SIZE},
            "aggs": {AGENT_NAME_AGG: {"terms": {"field": fields.agent_name, "size": 1}}},
        }

    body: dict[str, object] = {"size": 0, "track_total_hits": False, "aggs": aggregations}
    if query is not None:
        body["query"] = dict(query)
    return body


def parse_totals(response: Mapping[str, object]) -> SnapshotTotals:
    """Read the fleet-wide cardinalities from a first-page response.

    Args:
        response: Decoded ``_search`` body of the first composite page.

    Returns:
        The three fleet-wide cardinalities.

    Raises:
        AggregationError: A cardinality aggregation is missing or malformed.
    """
    aggregations = _require_mapping(_get(response, "aggregations"), "aggregations")
    return SnapshotTotals(
        agents=_cardinality(aggregations, TOTAL_AGENTS_AGG),
        distinct_cves=_cardinality(aggregations, TOTAL_CVES_AGG),
        distinct_packages=_cardinality(aggregations, TOTAL_PACKAGES_AGG),
    )


def parse_agent_names(response: Mapping[str, object]) -> dict[str, str]:
    """Read each agent's name from a first-page response.

    Names only label output, so an index or response without them yields an
    empty or partial mapping rather than failing the scan; output then falls
    back to the agent id.

    Args:
        response: Decoded ``_search`` body of the first composite page.

    Returns:
        Agent id to agent name, for every agent whose name the index carries.
    """
    aggregations = response.get("aggregations")
    if not isinstance(aggregations, Mapping):
        return {}
    agents = aggregations.get(AGENT_NAMES_AGG)
    raw_buckets = agents.get("buckets") if isinstance(agents, Mapping) else None
    if not isinstance(raw_buckets, list):
        return {}
    names: dict[str, str] = {}
    for bucket in raw_buckets:
        if not isinstance(bucket, Mapping):
            continue
        name_agg = bucket.get(AGENT_NAME_AGG)
        name_buckets = name_agg.get("buckets") if isinstance(name_agg, Mapping) else None
        if not isinstance(name_buckets, list) or not name_buckets:
            continue
        first = name_buckets[0]
        if isinstance(first, Mapping) and first.get("key") and bucket.get("key") is not None:
            names[str(bucket["key"])] = str(first["key"])
    return names


def parse_count(response: Mapping[str, object]) -> int:
    """Read the document total from a ``_count`` response.

    Args:
        response: Decoded ``_count`` body.

    Returns:
        Number of documents matching the query.

    Raises:
        AggregationError: The body carries no usable count.
    """
    return _require_int(_get(response, "count"), "count")


def parse_composite_page(
    response: Mapping[str, object],
    mapping: FieldMapping,
) -> CompositePage:
    """Turn one ``_search`` response into buckets and the next cursor.

    Args:
        response: Decoded ``_search`` body for one composite page.
        mapping: Mapping in force, supplying the fixability vocabulary.

    Returns:
        The page's buckets and the ``after_key`` that follows it, if any.

    Raises:
        AggregationError: The response does not carry the expected aggregation.
    """
    aggregations = _require_mapping(_get(response, "aggregations"), "aggregations")
    actions = _require_mapping(_get(aggregations, ACTIONS_AGG), ACTIONS_AGG)
    raw_buckets = _require_list(_get(actions, "buckets"), f"{ACTIONS_AGG}.buckets")

    buckets = [_parse_bucket(raw, index, mapping) for index, raw in enumerate(raw_buckets)]
    after_key = _parse_after_key(actions)
    return CompositePage(buckets=buckets, after_key=after_key)


def _parse_after_key(actions: Mapping[str, object]) -> CompositeKey | None:
    raw = actions.get("after_key")
    if raw is None:
        return None
    key = _require_mapping(raw, f"{ACTIONS_AGG}.after_key")
    return {name: _optional_key_string(value) for name, value in key.items()}


def _parse_bucket(raw: object, index: int, mapping: FieldMapping) -> PackageBucket:
    path = f"{ACTIONS_AGG}.buckets[{index}]"
    bucket = _require_mapping(raw, path)
    key = _require_mapping(_get(bucket, "key", path), f"{path}.key")

    version = _optional_key_string(key.get(VERSION_SOURCE))
    condition = _optional_key_string(key.get(CONDITION_SOURCE))
    agents = _require_mapping(_get(bucket, AGENTS_AGG, path), f"{path}.{AGENTS_AGG}")
    severity = _require_mapping(_get(bucket, SEVERITY_AGG, path), f"{path}.{SEVERITY_AGG}")

    rules = mapping.fixability
    return PackageBucket(
        package_name=_key_string(key.get(PACKAGE_SOURCE), f"{path}.key.{PACKAGE_SOURCE}"),
        package_version=version if version else UNKNOWN_VERSION,
        finding_count=_require_int(_get(bucket, "doc_count", path), f"{path}.doc_count"),
        agent_counts=_terms_counts(agents, f"{path}.{AGENTS_AGG}"),
        agent_cardinality=_cardinality(bucket, AGENT_CARDINALITY_AGG, path),
        severity_counts=_terms_counts(severity, f"{path}.{SEVERITY_AGG}"),
        cve_count=_cardinality(bucket, CVES_AGG, path),
        fixability=rules.classify(condition) if condition else Fixability.UNKNOWN,
        target_version=rules.target_version(condition) if condition else None,
        scanner_condition=condition,
    )


def _terms_counts(agg: Mapping[str, object], path: str) -> dict[str, int]:
    raw_buckets = _require_list(_get(agg, "buckets", path), f"{path}.buckets")
    counts: dict[str, int] = {}
    for index, raw in enumerate(raw_buckets):
        bucket_path = f"{path}.buckets[{index}]"
        bucket = _require_mapping(raw, bucket_path)
        term = _key_string(_get(bucket, "key", bucket_path), f"{bucket_path}.key")
        counts[term] = _require_int(_get(bucket, "doc_count", bucket_path), f"{bucket_path}.doc_count")
    return counts


def _cardinality(container: Mapping[str, object], name: str, path: str = "aggregations") -> int:
    agg = _require_mapping(_get(container, name, path), f"{path}.{name}")
    return _require_int(_get(agg, "value", f"{path}.{name}"), f"{path}.{name}.value")


def _get(container: Mapping[str, object], key: str, path: str = "") -> object:
    if key not in container:
        location = f"{path}.{key}" if path else key
        raise AggregationError(
            f"Indexer response is missing {location!r}. "
            f"The index may not be a Wazuh vulnerability state index, or the "
            f"mapping in use may name the wrong fields."
        )
    return container[key]


def _require_mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AggregationError(f"Expected an object at {path!r}, found {type(value).__name__}.")
    # json.loads only produces str keys, so the value type is the open question.
    return {str(key): item for key, item in value.items()}


def _require_list(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        raise AggregationError(f"Expected a list at {path!r}, found {type(value).__name__}.")
    return value


def _require_int(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AggregationError(f"Expected an integer at {path!r}, found {type(value).__name__}.")
    return value


def _key_string(value: object, path: str) -> str:
    text = _optional_key_string(value)
    if text is None:
        raise AggregationError(f"Expected a value at {path!r}, found null.")
    return text


def _optional_key_string(value: object) -> str | None:
    """Render an aggregation key as text, tolerating non-string keyword types."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    raise AggregationError(f"Aggregation key of type {type(value).__name__} is not usable.")
