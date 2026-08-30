# SPEC-02 — Fixability partition

**Precondition:** you have read `CONTEXT.md`, `CLAUDE.md` and
`docs/SPEC-01-collapse-engine.md`. SPEC-01 is implemented and passing; this
extends it.

**Goal:** stop the plan recommending upgrades that do not exist.

---

## 0. Why — read this before touching code

Measured against the live lab on 2026-08-30, over all 32,718 findings:

| Class | `vulnerability.scanner.condition` | Findings | % | Criticals |
|---|---|---|---|---|
| Fixable | `Package less than <version>` | 13,664 | 41.8% | 1,322 |
| No fix available | `Package default status` | 19,039 | 58.2% | 1,170 |
| Other | anything else | 15 | 0.0% | 0 |

`Package default status` means the vendor's own tracker lists the package as
affected and **has published no fixed version**. Verified: the feed sources are
Canonical Security Tracker (15,701) and Debian Security Tracker (3,334), not
NVD; `CVE-2026-74569` on `linux-oracle` is listed "Vulnerable" on Ubuntu's own
CVE page; 74.7% carry `under_evaluation: false`, so they are settled vendor
positions rather than pending triage.

**The current output is wrong in its first row.** A live run ranks
`linux-oracle 6.17.0-1020.20` first — 4,226 findings, 358 criticals — on hosts
whose `apt` candidate version equals the installed version. All 4,226 are
`Package default status`. The plan says "upgrade this" and there is nothing to
upgrade to.

These are not false positives. They are real, vendor-confirmed vulnerabilities
with no available remedy. They must be reported, but as a register requiring
risk acceptance — never as remediation actions.

---

## 1. Scope

**In scope:** reading `vulnerability.scanner.condition`, partitioning the
snapshot on it, parsing the target version out of it, a second output artefact,
new header lines, mapping and evidence-schema changes, tests.

**Out of scope (do not implement):** database, history, acceptance workflow
(who accepted what, when), any second data source, any write, any change to the
read-only posture of `client.py`.

---

## 2. Field mapping — `mappings/wazuh-4.x.yaml`

Add one field and one vocabulary block. Nothing about this may be hardcoded in
Python; a future Wazuh release may rename the field or reword the marker.

```yaml
fields:
  # ... existing six fields unchanged ...
  scanner_condition: "vulnerability.scanner.condition"

# How the condition string classifies a finding.
fixability:
  # Exact value (case-insensitive) meaning "affected, no fixed version exists".
  no_fix_values: ["Package default status"]
  # Prefix (case-insensitive) introducing a target version; the remainder of
  # the string after this prefix is the version to upgrade to.
  fixed_version_prefix: "Package less than "
```

`MappingFields` gains `scanner_condition: str`. A new `FixabilityRules` model
carries `no_fix_values: list[str]` and `fixed_version_prefix: str`, and
`FieldMapping` gains `fixability: FixabilityRules`. Keep
`model_config = ConfigDict(extra="forbid")` on all of them.

`FixabilityRules` gets two methods, mirroring `canonical_severity`:

- `classify(raw: str) -> Fixability` — returns the enum below.
- `target_version(raw: str) -> str | None` — the substring after
  `fixed_version_prefix`, stripped; `None` when the condition is not a
  fixed-version condition or the remainder is empty.

Both fold case and strip whitespace, for the same reason `canonical_severity`
does.

---

## 3. Models — `models.py`

```python
class Fixability(str, Enum):
    FIXABLE = "fixable"        # a target version exists
    NO_FIX = "no_fix"          # vendor confirms affected, no fix published
    UNKNOWN = "unknown"        # condition absent or unrecognised
```

`PackageBucket` gains:

- `fixability: Fixability`
- `target_version: str | None`

`RemediationAction` gains `target_version: str` — **required, never `None`.**
Only fixable buckets become actions, so an action without a target version is a
contract violation.

New model, structurally parallel to `RemediationAction`:

```python
class UnfixableEntry(BaseModel):
    """One (package, version) the vendor confirms affected with no fix."""
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
```

`PatchPlan` gains:

- `unfixable: list[UnfixableEntry]`
- `fixable_findings: int`, `fixable_criticals: int`
- `no_fix_findings: int`, `no_fix_criticals: int`
- `unknown_fixability_findings: int`

**All existing `PatchPlan` fields keep their meaning, and every percentage over
`actions` is now computed against `fixable_findings`, not `total_findings`.**
This is the whole point of the spec: the denominators change.

New warning code: `UNRECOGNIZED_FIXABILITY`, raised once per scan when any
bucket classifies as `UNKNOWN`, with the count and up to three example
condition strings in `detail`.

---

## 4. Query — `mapping.py`

`build_composite_query` adds `scanner_condition` as a **third composite
source**, alongside package and version:

```python
{CONDITION_SOURCE: {"terms": {"field": fields.scanner_condition,
                              "missing_bucket": True}}}
```

`missing_bucket: True` for the same reason as the version source: findings with
no condition must be grouped and reported as `UNKNOWN`, never silently dropped.

Consequences the implementer must handle:

- **Bucket cardinality rises.** One `(package, version)` now fans out into one
  bucket per distinct condition string, and each distinct target version is its
  own string. Measured: 40 distinct conditions cover 89.5% of findings, so the
  tail is long. `COMPOSITE_PAGE_SIZE` is unchanged, but pagination now matters
  in the lab, not just in theory — verify `after_key` paging is exercised.
- **Re-aggregation is required.** Buckets sharing `(package, version)` but
  differing in condition must be merged back together per class before ranking,
  summing findings, unioning agents, and summing severity counts. `cve_count` is
  a cardinality and **is not additive**: sum it and emit a warning. Note that
  summing overstates while kernel grouping's max-of-constituents understates, so
  these need **separate** warning codes — `MERGED_CVE_COUNT_IS_UPPER_BOUND` here,
  `GROUPED_CVE_COUNT_IS_LOWER_BOUND` for kernel grouping. Reusing one code for
  two opposite errors breaks the rule in `models.py` that consumers match on the
  code and never on the message text.
- **One installed version may carry several target versions** (different CVEs
  fixed in different releases). The action's `target_version` is the **maximum**
  by the comparison in §5.

---

## 5. Version comparison

Needed to pick the maximum target version. **Do not add a dependency** and do
not attempt full Debian version-comparison semantics — epochs, tildes and
`~24.04.1` suffixes make that a project of its own, and getting it subtly wrong
is worse than not doing it.

Implement `max_target_version(candidates: list[str]) -> str` in a new pure
module `versions.py`:

- Split each string into runs of digits and runs of non-digits.
- Compare run by run: digit runs numerically, non-digit runs by ASCII.
- A tilde sorts before everything, including end-of-string. This one Debian rule
  is included because `~24.04.1` suffixes are ubiquitous in the measured data
  and ignoring it inverts the order of real versions.
- Ties resolve to the lexicographically greater string, so the result is
  deterministic.

Document in the module docstring that this is a heuristic ordering sufficient
for choosing among a package's own target versions, and explicitly **not** a
general Debian version comparator. Test it against the real suffixes present in
the lab: `6.12.74-2`, `6.12.100-1`, `6.17.0-1020.20`,
`6.14.0-37.37~24.04.1`, `3.5.1+dfsg1-0ubuntu1.2`, `0:2.52.3-0ubuntu0.24.04.1`.

---

## 6. Collapse engine — `collapse.py`

`build_patch_plan` partitions before it ranks:

1. Classify every bucket.
2. `FIXABLE` buckets → merge by `(package, version)` → `RemediationAction` with
   `target_version` = max of the group → rank exactly as SPEC-01 §6.2 specifies.
3. `NO_FIX` buckets → merge by `(package, version)` → `UnfixableEntry`, ranked
   by criticals then findings, independently of `--rank-by`.
4. `UNKNOWN` buckets → counted, warned about, and **excluded from both lists**.
   They are a mapping defect, not a finding class.

`collapse_ratio`, `collapse_sources` and every coverage curve are computed over
the **fixable** set only. Kernel grouping (§6.4) applies within each class
separately; a kernel with a fix and a kernel without one are never merged.

---

## 7. Output — `render.py`

### 7.1 Header

Replaces the current impact block. Four figures, always printed, whatever
`--rank-by` is active:

```
32,718 findings → 13,664 fixable (41.8%) · 19,039 with no vendor fix (58.2%)
Criticals: 2,492 → 1,322 fixable · 1,170 with no vendor fix

13,664 fixable findings → 560 actions across 453 packages (ratio 30:1)
Each action clears 24.4 findings: 19.7 CVEs per package version × 1.24 hosts
First 12 by findings: 8,271 fixable findings (60.5%), on N hosts
First 12 by criticals: 1,015 fixable criticals (76.8%), on N hosts
```

> **Corrected 2026-08-30.** An earlier revision of this block invented "187
> actions" and a "73:1" ratio. Both were wrong. 73:1 was findings ÷ actions,
> which SPEC-01 §6 and the `collapse_ratio` docstring explicitly reject;
> `collapse_ratio` is findings ÷ distinct packages, which over the fixable set
> is 13,664 ÷ 453 = 30:1. The figures above are measured from a live run. Only
> the *shape* of this block is normative — the binding rule is §6, that every
> figure derived from actions is computed over the fixable set.

Every percentage states its denominator in words. No percentage in the output
may be computed over `total_findings` except the fixable/no-fix split itself.

### 7.2 Patch plan table

Unchanged, plus one column: **`Target`**, the version to upgrade to. Column
priority when truncating, most protected first: `Package`, `Target`,
`Critical`, `Findings`, `Hosts`, `Version`, everything else. The current
version is the least useful column and is the first to truncate — SPEC-01's
truncation fix was in the right direction but stopped one column short.

### 7.3 Unfixable register

A second table, printed after the plan in `table` and `markdown`, with a
heading that says what it is and what to do with it:

```
## No vendor fix available — 19,039 findings, 1,170 critical

These packages are confirmed affected by their vendor with no fixed version
published. They cannot be remediated by patching today and require documented
risk acceptance.
```

Columns: `Package`, `Version`, `Hosts`, `Findings`, `CVEs`, `Critical`, `High`,
`Kernel`. Same `--top` limit applies. Add `--no-unfixable` to suppress it for
users who only want the plan.

### 7.4 JSON

`unfixable` and the five new counters are additive fields on the serialized
`PatchPlan`. No existing field is renamed, retyped or removed.

---

## 8. CLI — `cli.py`

- `--no-unfixable` — suppress the register (default: shown).
- `--only` `plan|register|both` — rejected as redundant with the above; do not
  add it.
- `--min-severity` continues to filter display only, in both tables.

---

## 9. Evidence schema — `docs/evidence-schema.md`

`EvidenceRecord` gains the same additive fields as `PatchPlan`, plus
`unfixable: list[UnfixableEntry]`. Bump `EVIDENCE_SCHEMA_VERSION` to `"2"`.

This is an addition, not a break, but the register is the part an auditor reads
and the version must state which shape produced a given file. Document in
`evidence-schema.md` that a version-1 record carries no fixability information
and its percentages are over the undifferentiated total — a reader comparing a
v1 and a v2 record must not treat the coverage numbers as comparable.

---

## 10. Acceptance criteria

1. `mypy --strict` clean; existing 184 tests still pass.
2. Against the recorded fixture, the fixable/no-fix split reproduces 13,664 /
   19,039 findings and 1,322 / 1,170 criticals. **Update the fixture from a live
   run first** — the existing one predates the condition field and cannot carry
   it.
3. `linux-oracle 6.17.0-1020.20` appears in the **unfixable register** and
   **nowhere in the patch plan**. This is the regression test for the defect
   that motivated the spec; name it so.
4. Every `RemediationAction` has a non-empty `target_version`, asserted as a
   property over the whole plan, not on a sample.
5. A bucket whose condition is absent produces `UNRECOGNIZED_FIXABILITY` and is
   excluded from both lists.
6. `max_target_version` is tested against the six real version strings in §5,
   including the tilde case.
7. No percentage in any output is computed over `total_findings` except the
   fixable/no-fix split. Assert this by rendering a plan whose fixable and total
   counts differ and checking the printed figures.
8. Wall-clock for a full scan of the lab stays under 5 s. It is 1.06 s today;
   the third composite source will cost something and this bounds it.

---

## 11. What not to do

- **Do not reconcile against distribution security trackers.** Wazuh already
  sources from Canonical and Debian. A second source adds a dependency, a
  network failure mode and a staleness problem to answer a question the index
  already answers.
- **Do not suppress no-fix findings.** They include 1,170 criticals. Hiding real
  unpatched criticals is a worse defect than the one being fixed.
- **Do not add an acceptance workflow, an owner field, or a due date.** That is
  the paid tier and it needs persistence. This spec stays stateless.
- **Do not treat `UNKNOWN` as `NO_FIX`.** It is a signal that the mapping is
  wrong against this deployment's schema, and silently absorbing it destroys the
  signal.
