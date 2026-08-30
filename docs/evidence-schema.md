# Evidence file schema

`vulnfold scan --evidence PATH` writes one JSON object recording a complete
scan. It is the raw material for ISO 27001 control 8.8 evidence, so it is
treated as a **stable contract**:

- Fields are **added**, never renamed, retyped or removed.
- `schema_version` is a string. It rises only when that promise cannot be kept.
- A consumer that does not recognise a field must ignore it, not fail.

Current version: **`"2"`**.

### Version history

| Version | Change |
|---|---|
| `"1"` | Initial shape (SPEC-01). |
| `"2"` | Added the fixability partition: `unfixable`, the five class counters, `total_criticals` and `fixable_distinct_packages` (SPEC-02). |

**A version-1 record carries no fixability information.** Its `collapse_ratio`,
`collapse_sources` and coverage curves are computed over the undifferentiated
finding total, which includes findings no upgrade can clear. A version-2 record
computes all of them over the fixable findings alone. A reader comparing a v1
and a v2 record **must not treat the coverage numbers as comparable**: the
denominators are different, and the v2 figures will normally look worse for the
same fleet because they no longer count unfixable findings as remediable.

---

## Why it exists

A patch plan printed to a terminal proves nothing after the fact. Control 8.8
(*management of technical vulnerabilities*) asks an organisation to show that it
identified vulnerabilities, evaluated them and acted. The evidence file is the
"identified and evaluated" half, captured at the moment the scan ran and
reproducible from the parameters it records.

The scan is read-only. Nothing in this file is written back to the cluster.

---

## What it is not

It is **not** the display. `--top` and `--format` do not affect it, and neither
`--min-severity` nor `--no-unfixable` shortens it: those flags choose what is
listed on screen, and an audit artefact that silently dropped 22% of a fleet
because those findings carried no severity — or 58% of it because those findings
have no fix — would be worse than no artefact at all. `min_severity` is recorded
so the on-screen output can be reproduced.

---

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Version of this contract. `"2"` today. |
| `generated_at` | string (RFC 3339, UTC) | When the scan ran. |
| `tool_version` | string | vulnfold version that produced the record. |
| `indexer_url` | string | Indexer that was read. **Credentials are stripped**: any `user:password@` in the URL is removed before writing. |
| `index_pattern` | string | Index pattern that was read. |
| `mapping_version` | string | `version` of the field mapping in force, e.g. `"4.x"`. Identifies the schema the field names came from. |
| `rank_by` | `"criticals"` \| `"findings"` | Ordering of `actions`. |
| `group_kernels` | boolean | Whether each kernel package's versions were merged into one action. |
| `min_severity` | string \| null | Display filter in force during the run. Does not affect this file. |
| `total_findings` | integer | Findings the index reported via `_count`. |
| `total_criticals` | integer | Criticals across every bucket, all three fixability classes. Counted from the buckets, not from `_count`. |
| `total_agents` | integer | Distinct agents in the index. |
| `total_distinct_cves` | integer | Distinct CVEs in the index. |
| `total_distinct_packages` | integer | Distinct package names in the index. |
| `fixable_findings` | integer | Findings whose vendor has published a fixed version. |
| `fixable_criticals` | integer | Criticals among them. |
| `fixable_distinct_packages` | integer | Distinct package names carrying at least one fixable finding. Denominator of `collapse_ratio`. |
| `no_fix_findings` | integer | Findings the vendor confirms affected with no fixed version published. |
| `no_fix_criticals` | integer | Criticals among them. **These are real unpatched criticals**, not false positives. |
| `unknown_fixability_findings` | integer | Findings whose scanner condition the mapping does not recognise. In neither `actions` nor `unfixable`; see `unrecognized_fixability`. |
| `collapse_ratio` | number | `fixable_findings / fixable_distinct_packages`. Findings per package, not per action. |
| `collapse_sources` | object | Where the compression comes from, over the fixable set. See below. |
| `actions` | array | The complete ranked plan. Fixable findings only. See below. |
| `unfixable` | array | The complete register of findings with no published fix. See below. |
| `coverage_by_findings` | array | Cumulative curve under findings-first ordering. |
| `coverage_by_criticals` | array | Cumulative curve under criticals-first ordering. |
| `warnings` | array | Conditions that degrade the plan without invalidating it. |

The three class counters partition the fleet:
`fixable_findings + no_fix_findings + unknown_fixability_findings ==
total_findings`.

Both coverage curves are always present, whatever `rank_by` says. They answer
different questions and need not agree on which actions come first. **Every
figure derived from `actions` is taken over the fixable set**, so the only
percentages in this file that are shares of `total_findings` are the ones a
reader computes from the class counters.

---

## `collapse_sources`

Findings compress two different ways, and the remediation effort is nothing
alike. One package version carrying thousands of CVEs on a single host
compresses exactly as hard as one package repeated across a thousand hosts.

| Field | Type | Meaning |
|---|---|---|
| `findings_per_action` | number | Mean findings cleared per action. |
| `cves_per_action` | number | Mean distinct CVEs per package version. **CVE depth.** |
| `hosts_per_action` | number | Mean hosts carrying a package version, weighted by CVE count. **Fleet duplication.** |

Up to the rounding applied to each:

```
findings_per_action = cves_per_action × hosts_per_action
```

`hosts_per_action` near `1.0` means there is no cross-host duplication to
collapse: the compression is entirely CVE volume. Reporting only the product
would let a reader assume the wrong one.

---

## `actions[]`

One remediation a human can perform, ordered by `rank_by`.

| Field | Type | Meaning |
|---|---|---|
| `package_name` | string | Package to upgrade. |
| `current_version` | string | Version currently installed. `"unknown"` when the document carried none. When `group_kernels` merged versions, a comma-separated list in lexicographic order. |
| `target_version` | string | Version to upgrade to. **Never empty**: only findings naming a fixed version become actions. When one installed version has several outstanding fixes, this is the highest of them, since that one upgrade clears them all. |
| `affected_agents` | array of string | Agent ids, sorted. |
| `agent_count` | integer | Length of `affected_agents`. |
| `finding_count` | integer | Findings this action clears. |
| `cve_count` | integer | Distinct CVEs. **Not always an exact cardinality**, and the two inexact cases err in opposite directions, so they carry different warning codes. Merging an installed version across several scanner conditions **sums** the per-condition cardinalities, which can only overstate: `merged_cve_count_is_upper_bound`. A merged kernel action takes the **largest** constituent, because a union cannot be recovered from per-version cardinalities, which can only understate: `grouped_cve_count_is_lower_bound`. |
| `severity_breakdown` | object | Count per severity, plus `unknown`. Every severity the mapping declares is present, including zeros. |
| `critical_count` | integer | Findings at the mapping's most severe level. |
| `high_count` | integer | Findings at the second most severe level. |
| `unknown_severity_count` | integer | Findings carrying no usable severity. Never folded into Low. |
| `is_kernel` | boolean | Whether the package name matches a kernel pattern. |

### Unrated findings

`severity_breakdown.unknown` and `unknown_severity_count` count every finding
whose severity the mapping does not recognise: the placeholders (`-`, `None`,
empty), unrecognised strings, and documents carrying no severity field at all.
In real Wazuh data this is around 22% of findings. It is never reported as Low
and never dropped.

---

---

## `unfixable[]`

One `(package, version)` the vendor confirms affected with no published fix,
ordered by criticals, then highs, then findings — independently of `rank_by`,
because there is no remediation effort here to order.

Same fields as `actions[]`, minus `target_version`: there is nothing to upgrade
to, which is the whole point of the list.

These are **not** false positives. Wazuh sources them from the Canonical and
Debian security trackers, and on the measured fleet 74.7% carry
`under_evaluation: false` — settled vendor positions, not pending triage. They
cannot be remediated by patching today and are the population that requires
documented risk acceptance under control 8.8.

---

## `coverage_by_findings[]` and `coverage_by_criticals[]`

Cumulative effect of applying the first *N* actions of that ordering.

| Field | Type | Meaning |
|---|---|---|
| `action_count` | integer | *N*, starting at 1. |
| `cumulative_findings` | integer | Fixable findings cleared by the first *N*. |
| `findings_percentage` | number | As a percentage of `fixable_findings`, never of `total_findings`. |
| `cumulative_criticals` | integer | Fixable criticals cleared by the first *N*. |
| `criticals_percentage` | number | As a percentage of `fixable_criticals`. |
| `cumulative_agents` | integer | Distinct hosts the first *N* actions touch. |

Each array has exactly one entry per action in the complete plan.

---

## `warnings[]`

| Field | Type | Meaning |
|---|---|---|
| `code` | string | Stable identifier. Match on this, never on `message`. |
| `message` | string | Human-readable text. May change between versions. |
| `detail` | object | Code-specific values. |

| `code` | Raised when |
|---|---|
| `empty_index` | The index matched no findings. |
| `bucket_sum_mismatch` | Aggregated buckets do not sum to the `_count` total. `detail.delta` carries the difference. |
| `agent_terms_truncated` | An action affects more agents than the indexer listed, so its agent list is incomplete. |
| `unrecognized_severity` | A severity value the mapping does not declare was seen. Those findings are counted as unknown. |
| `unrecognized_fixability` | A scanner condition the mapping's `fixability` vocabulary does not cover was seen. Those findings appear in neither `actions` nor `unfixable`. `detail.examples` quotes up to three of the strings, which is what a reader needs to extend the mapping. It is a mapping gap, not a class of finding. |
| `merged_cve_count_is_upper_bound` | A `cve_count` in this record **overstates** the true distinct count. Raised when an installed version was merged across scanner conditions (`detail.merged_conditions`), which sums cardinalities over sets that are usually disjoint but overlap when vendors disagree about one version. |
| `grouped_cve_count_is_lower_bound` | A `cve_count` in this record **understates** the true distinct count. Raised when `--group-kernels` merged versions (`detail.merged_rows`) and the largest constituent cardinality was used in place of a union that cannot be recovered. |

An empty `warnings` array means the scan reconciled cleanly.

---

## Example

Trimmed to one action, one register entry and one point per curve. This is a
real record of the recorded lab fleet, not an invented one:

```json
{
  "schema_version": "2",
  "generated_at": "2026-08-30T09:14:22.481293Z",
  "tool_version": "0.1.0",
  "indexer_url": "https://indexer.example.internal:9200",
  "index_pattern": "wazuh-states-vulnerabilities-*",
  "mapping_version": "4.x",
  "rank_by": "criticals",
  "group_kernels": false,
  "min_severity": null,
  "total_findings": 32718,
  "total_criticals": 2492,
  "total_agents": 15,
  "total_distinct_cves": 5950,
  "total_distinct_packages": 554,
  "fixable_findings": 13664,
  "fixable_criticals": 1322,
  "fixable_distinct_packages": 453,
  "no_fix_findings": 19039,
  "no_fix_criticals": 1170,
  "unknown_fixability_findings": 15,
  "collapse_ratio": 30.16,
  "collapse_sources": {
    "findings_per_action": 24.4,
    "cves_per_action": 19.66,
    "hosts_per_action": 1.24
  },
  "actions": [
    {
      "package_name": "linux-image-cloud-amd64",
      "current_version": "6.12.74-2",
      "target_version": "6.12.105-1",
      "affected_agents": [
        "012"
      ],
      "agent_count": 1,
      "finding_count": 3911,
      "cve_count": 2969,
      "severity_breakdown": {
        "Critical": 290,
        "High": 1633,
        "Medium": 1039,
        "Low": 0,
        "unknown": 949
      },
      "critical_count": 290,
      "high_count": 1633,
      "unknown_severity_count": 949,
      "is_kernel": true
    }
  ],
  "unfixable": [
    {
      "package_name": "linux-oracle",
      "current_version": "6.17.0-1020.20",
      "affected_agents": [
        "017",
        "023"
      ],
      "agent_count": 2,
      "finding_count": 4226,
      "cve_count": 2112,
      "severity_breakdown": {
        "Critical": 358,
        "High": 1788,
        "Medium": 844,
        "Low": 8,
        "unknown": 1228
      },
      "critical_count": 358,
      "high_count": 1788,
      "unknown_severity_count": 1228,
      "is_kernel": true
    }
  ],
  "coverage_by_findings": [
    {
      "action_count": 1,
      "cumulative_findings": 3911,
      "findings_percentage": 28.62,
      "cumulative_criticals": 290,
      "criticals_percentage": 21.94,
      "cumulative_agents": 1
    }
  ],
  "coverage_by_criticals": [
    {
      "action_count": 1,
      "cumulative_findings": 3911,
      "findings_percentage": 28.62,
      "cumulative_criticals": 290,
      "criticals_percentage": 21.94,
      "cumulative_agents": 1
    }
  ],
  "warnings": [
    {
      "code": "unrecognized_fixability",
      "message": "15 finding(s) in 1 bucket(s) carry a scanner condition the mapping does not recognise, so they appear neither in the plan nor in the register. This is a gap in the mapping's fixability vocabulary, not a class of finding. Example condition(s): 'Package equal to 7.2.12'.",
      "detail": {
        "findings": 15,
        "buckets": 1,
        "examples": "'Package equal to 7.2.12'"
      }
    },
    {
      "code": "merged_cve_count_is_upper_bound",
      "message": "506 row(s) were merged across scanner conditions, because one installed version can have several outstanding fixed versions. Their CVE counts are sums of per-condition cardinalities, so they are upper bounds: the sets are usually disjoint, but overlap when vendors disagree about one version.",
      "detail": {
        "merged_conditions": 506
      }
    }
  ]
}
```

---

## Reading it back

```bash
jq '{total_findings, fixable_findings, no_fix_findings}' evidence.json
jq '.collapse_sources' evidence.json
jq '.actions[:7] | map({package_name, current_version, target_version})' evidence.json
jq '.coverage_by_findings[6]' evidence.json      # what the first 7 clear
jq '.unfixable[:7] | map({package_name, finding_count, critical_count})' evidence.json
jq -r '.warnings[] | "\(.code)\t\(.message)"' evidence.json
```
