"""Data contracts shared by every layer.

These models are the whole vocabulary of the tool. The domain layer consumes
:class:`IndexerSnapshot` and produces :class:`PatchPlan`; neither knows how the
snapshot was fetched, which is what keeps the domain testable without mocks.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class RankBy(str, Enum):
    """What a plan is ordered by.

    Both orderings answer a real question. Criticals-first answers "what do I
    fix to cut severe exposure fastest"; findings-first answers "what do I fix
    to cut the noise fastest". They need not agree, so both coverage curves are
    always reported whichever one is active.
    """

    CRITICALS = "criticals"
    FINDINGS = "findings"


class WarningCode(str, Enum):
    """Stable identifiers for the conditions a scan can report.

    Consumers match on the code, never on the message text.
    """

    EMPTY_INDEX = "empty_index"
    BUCKET_SUM_MISMATCH = "bucket_sum_mismatch"
    AGENT_TERMS_TRUNCATED = "agent_terms_truncated"
    UNRECOGNIZED_SEVERITY = "unrecognized_severity"
    GROUPED_CVE_COUNT_IS_LOWER_BOUND = "grouped_cve_count_is_lower_bound"


class ScanWarning(BaseModel):
    """A condition that degrades a plan without invalidating it."""

    code: WarningCode
    message: str
    detail: dict[str, str | int] = Field(default_factory=dict)


class MappingFields(BaseModel):
    """Document fields a scan reads, named as the target schema names them."""

    model_config = ConfigDict(extra="forbid")

    package_name: str
    package_version: str
    cve_id: str
    severity: str
    agent_id: str
    agent_name: str


class FieldMapping(BaseModel):
    """One schema version's worth of field names and severity vocabulary."""

    model_config = ConfigDict(extra="forbid")

    version: str
    index_pattern: str
    fields: MappingFields
    severity_order: list[str] = Field(min_length=1)
    severity_unknown: list[str]

    def canonical_severity(self, raw: str) -> str | None:
        """Resolve a raw severity string to its canonical spelling.

        Args:
            raw: Severity exactly as the document carried it.

        Returns:
            The matching entry of ``severity_order``, or ``None`` when the value
            conveys no severity. Matching ignores case, because deployments have
            been observed emitting both ``High`` and ``high``.
        """
        folded = raw.strip().casefold()
        for severity in self.severity_order:
            if severity.casefold() == folded:
                return severity
        return None

    def is_explicitly_unknown(self, raw: str) -> bool:
        """Report whether a severity string is a known placeholder for "absent"."""
        folded = raw.strip().casefold()
        return any(unknown.strip().casefold() == folded for unknown in self.severity_unknown)


class PackageBucket(BaseModel):
    """One ``(package, version)`` bucket as the indexer returned it."""

    package_name: str
    package_version: str
    finding_count: int
    agent_counts: dict[str, int]
    agent_cardinality: int
    severity_counts: dict[str, int]
    cve_count: int


class IndexerSnapshot(BaseModel):
    """A read-only view of the fleet's current vulnerability state."""

    total_findings: int
    total_agents: int
    total_distinct_cves: int
    total_distinct_packages: int
    buckets: list[PackageBucket]


class RemediationAction(BaseModel):
    """One upgrade a human can perform, with the noise it removes."""

    package_name: str
    current_version: str
    affected_agents: list[str]
    agent_count: int
    finding_count: int
    cve_count: int
    severity_breakdown: dict[str, int]
    critical_count: int
    high_count: int
    unknown_severity_count: int
    is_kernel: bool


class CoveragePoint(BaseModel):
    """What the first ``action_count`` actions of the plan eliminate.

    ``cumulative_agents`` is the number of distinct hosts those actions touch.
    It is what separates the two ways a fleet's findings compress: many CVEs on
    one package on one host, versus one package repeated across many hosts.
    """

    action_count: int
    cumulative_findings: int
    findings_percentage: float
    cumulative_criticals: int
    criticals_percentage: float
    cumulative_agents: int


class CollapseSources(BaseModel):
    """Where a fleet's compression actually comes from.

    The three numbers satisfy, up to the rounding applied to each:

        findings_per_action = cves_per_action * hosts_per_action

    A fleet whose kernels each sit on their own machine compresses through
    ``cves_per_action`` with ``hosts_per_action`` near 1.0: there is no
    cross-host duplication to collapse. A fleet running one image everywhere
    compresses through ``hosts_per_action`` instead. Reporting only the product
    would let a reader assume the wrong one.
    """

    findings_per_action: float
    cves_per_action: float
    hosts_per_action: float


class PatchPlan(BaseModel):
    """The ranked remediation plan for one fleet.

    Serialized form is a stable contract; fields are added, never repurposed.
    """

    total_findings: int
    total_agents: int
    total_distinct_cves: int
    total_distinct_packages: int
    actions: list[RemediationAction]
    collapse_ratio: float
    collapse_sources: CollapseSources
    rank_by: RankBy
    coverage_curve: list[CoveragePoint]
    coverage_by_findings: list[CoveragePoint]
    coverage_by_criticals: list[CoveragePoint]
    warnings: list[ScanWarning] = Field(default_factory=list)


EVIDENCE_SCHEMA_VERSION = "1"


class EvidenceRecord(BaseModel):
    """A complete, self-describing record of one scan.

    This is the raw material for ISO 27001 control 8.8 evidence, so the schema
    is a stable contract: fields are added, never renamed, retyped or removed,
    and ``schema_version`` rises when that promise cannot be kept. It is
    documented in ``docs/evidence-schema.md``.

    ``actions`` is always the complete ranked plan. ``min_severity`` is a
    display filter and is recorded here for reproducibility, but it never
    shortens the evidence.
    """

    schema_version: str = EVIDENCE_SCHEMA_VERSION
    generated_at: datetime
    tool_version: str
    indexer_url: str
    index_pattern: str
    mapping_version: str
    rank_by: RankBy
    group_kernels: bool
    min_severity: str | None
    total_findings: int
    total_agents: int
    total_distinct_cves: int
    total_distinct_packages: int
    collapse_ratio: float
    collapse_sources: CollapseSources
    actions: list[RemediationAction]
    coverage_by_findings: list[CoveragePoint]
    coverage_by_criticals: list[CoveragePoint]
    warnings: list[ScanWarning] = Field(default_factory=list)
