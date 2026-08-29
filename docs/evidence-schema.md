# Evidence file schema

`vulnfold scan --evidence PATH` writes one JSON object recording a complete
scan. It is the raw material for ISO 27001 control 8.8 evidence, so it is
treated as a **stable contract**:

- Fields are **added**, never renamed, retyped or removed.
- `schema_version` is a string. It rises only when that promise cannot be kept.
- A consumer that does not recognise a field must ignore it, not fail.

Current version: **`"1"`**.

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

It is **not** the display. `--top` and `--format` do not affect it, and
`--min-severity` never shortens it: that flag chooses what is listed on screen,
and an audit artefact that silently dropped 22% of a fleet because those
findings carried no severity would be worse than no artefact at all. The flag is
recorded in `min_severity` so the on-screen output can be reproduced.

---

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Version of this contract. `"1"` today. |
| `generated_at` | string (RFC 3339, UTC) | When the scan ran. |
| `tool_version` | string | vulnfold version that produced the record. |
| `indexer_url` | string | Indexer that was read. **Credentials are stripped**: any `user:password@` in the URL is removed before writing. |
| `index_pattern` | string | Index pattern that was read. |
| `mapping_version` | string | `version` of the field mapping in force, e.g. `"4.x"`. Identifies the schema the field names came from. |
| `rank_by` | `"criticals"` \| `"findings"` | Ordering of `actions`. |
| `group_kernels` | boolean | Whether each kernel package's versions were merged into one action. |
| `min_severity` | string \| null | Display filter in force during the run. Does not affect this file. |
| `total_findings` | integer | Findings the index reported via `_count`. |
| `total_agents` | integer | Distinct agents in the index. |
| `total_distinct_cves` | integer | Distinct CVEs in the index. |
| `total_distinct_packages` | integer | Distinct package names in the index. |
| `collapse_ratio` | number | `total_findings / total_distinct_packages`. Findings per package, not per action. |
| `collapse_sources` | object | Where the compression comes from. See below. |
| `actions` | array | The complete ranked plan. See below. |
| `coverage_by_findings` | array | Cumulative curve under findings-first ordering. |
| `coverage_by_criticals` | array | Cumulative curve under criticals-first ordering. |
| `warnings` | array | Conditions that degrade the plan without invalidating it. |

Both coverage curves are always present, whatever `rank_by` says. They answer
different questions and need not agree on which actions come first.

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
| `affected_agents` | array of string | Agent ids, sorted. |
| `agent_count` | integer | Length of `affected_agents`. |
| `finding_count` | integer | Findings this action clears. |
| `cve_count` | integer | Distinct CVEs. For a merged kernel action this is a **lower bound**: a union cardinality cannot be recovered from per-version cardinalities, so the largest constituent is used and a warning is raised. |
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

## `coverage_by_findings[]` and `coverage_by_criticals[]`

Cumulative effect of applying the first *N* actions of that ordering.

| Field | Type | Meaning |
|---|---|---|
| `action_count` | integer | *N*, starting at 1. |
| `cumulative_findings` | integer | Findings cleared by the first *N*. |
| `findings_percentage` | number | As a percentage of `total_findings`. |
| `cumulative_criticals` | integer | Criticals cleared by the first *N*. |
| `criticals_percentage` | number | As a percentage of all criticals in the plan. |
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
| `grouped_cve_count_is_lower_bound` | `--group-kernels` merged versions, so the merged `cve_count` is a lower bound. |

An empty `warnings` array means the scan reconciled cleanly.

---

## Example

Trimmed to one action and one point per curve:

```json
{
  "schema_version": "1",
  "generated_at": "2026-08-30T09:14:22.481293Z",
  "tool_version": "0.1.0",
  "indexer_url": "https://indexer.example.internal:9200",
  "index_pattern": "wazuh-states-vulnerabilities-*",
  "mapping_version": "4.x",
  "rank_by": "criticals",
  "group_kernels": false,
  "min_severity": null,
  "total_findings": 32718,
  "total_agents": 15,
  "total_distinct_cves": 5950,
  "total_distinct_packages": 554,
  "collapse_ratio": 59.06,
  "collapse_sources": {
    "findings_per_action": 43.98,
    "cves_per_action": 40.12,
    "hosts_per_action": 1.1
  },
  "actions": [
    {
      "package_name": "linux-image-6.14.0-37-generic",
      "current_version": "6.14.0-37.37~24.04.1",
      "affected_agents": ["011"],
      "agent_count": 1,
      "finding_count": 5155,
      "cve_count": 5155,
      "severity_breakdown": {
        "Critical": 393, "High": 1916, "Medium": 1622, "Low": 76, "unknown": 1148
      },
      "critical_count": 393,
      "high_count": 1916,
      "unknown_severity_count": 1148,
      "is_kernel": true
    }
  ],
  "coverage_by_findings": [
    {
      "action_count": 1,
      "cumulative_findings": 5155,
      "findings_percentage": 15.76,
      "cumulative_criticals": 393,
      "criticals_percentage": 15.77,
      "cumulative_agents": 1
    }
  ],
  "coverage_by_criticals": [
    {
      "action_count": 1,
      "cumulative_findings": 5155,
      "findings_percentage": 15.76,
      "cumulative_criticals": 393,
      "criticals_percentage": 15.77,
      "cumulative_agents": 1
    }
  ],
  "warnings": []
}
```

---

## Reading it back

```bash
jq '.collapse_sources' evidence.json
jq '.actions[:7] | map({package_name, finding_count, agent_count})' evidence.json
jq '.coverage_by_findings[6]' evidence.json      # what the first 7 clear
jq -r '.warnings[] | "\(.code)\t\(.message)"' evidence.json
```
