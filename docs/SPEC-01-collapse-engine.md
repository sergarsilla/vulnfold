# SPEC-01 — Collapse engine and CLI

**Precondition:** you have read `CONTEXT.md` (especially decisions D1-D4) and
`CLAUDE.md` (engineering standards).

**Goal:** given a Wazuh indexer, produce a patch plan ranked by impact.
No writes. No heavy dependencies.

---

## 1. Scope

**In scope:** querying the indexer, collapsing findings into actions, ranking,
JSON / table / Markdown output, version-aware field mapping, tests.

**Out of scope (do not implement):** database, web UI, history, user
authentication, multi-tenancy, any write to the cluster, any LLM or ML.

---

## 2. Stack

- Python 3.11+
- `httpx` (HTTP client), `pydantic` v2 (models), `typer` (CLI), `rich` (table),
  `PyYAML` (mappings)
- `pytest` + `respx` for tests
- No ORM. No web framework. No Docker in this phase.

---

## 3. Layout

```
vulnfold/
├── pyproject.toml
├── LICENSE                   # Apache 2.0
├── README.md
├── CONTEXT.md
├── CLAUDE.md
├── mappings/
│   └── wazuh-4.x.yaml
├── src/vulnfold/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── mapping.py
│   ├── client.py
│   ├── collapse.py
│   ├── models.py
│   └── render.py
└── tests/
    ├── fixtures/
    │   └── aggregation_response.json
    ├── test_mapping.py
    ├── test_collapse.py
    ├── test_client.py
    └── test_render.py
```

---

## 4. Field mapping — `mappings/wazuh-4.x.yaml`

Isolates every schema dependency. Porting to 5.0 means adding
`mappings/wazuh-5.x.yaml`. Never hardcode a field name outside this directory.

```yaml
version: "4.x"
index_pattern: "wazuh-states-vulnerabilities-*"
fields:
  package_name: "package.name"
  package_version: "package.version"
  cve_id: "vulnerability.id"
  severity: "vulnerability.severity"
  agent_id: "agent.id"
  agent_name: "agent.name"
severity_order: ["Critical", "High", "Medium", "Low"]
severity_unknown: ["-", "None", ""]
```

---

## 5. Indexer client — `client.py`

### 5.1 Mandatory `composite` pagination

**Do not use `multi_terms` with a fixed `size`.** On a real fleet it truncates
silently and produces a wrong answer with no warning. Use a `composite`
aggregation with `after_key` until buckets are exhausted.

```json
{
  "size": 0,
  "aggs": {
    "actions": {
      "composite": {
        "size": 1000,
        "sources": [
          {"pkg": {"terms": {"field": "package.name"}}},
          {"ver": {"terms": {"field": "package.version"}}}
        ]
      },
      "aggs": {
        "agents":   {"terms": {"field": "agent.id", "size": 10000}},
        "severity": {"terms": {"field": "vulnerability.severity"}},
        "cves":     {"cardinality": {"field": "vulnerability.id"}}
      }
    }
  }
}
```

### 5.2 Client requirements

- Basic auth; configurable TLS verification (Wazuh deployments use self-signed
  certificates by default — support it, but verification must be the default and
  disabling it must be explicit).
- Configurable timeout, default 30s.
- Exponential backoff retry on 429 and 5xx, maximum 3 attempts.
- **Read-only enforcement:** on startup, verify the index exists and is readable.
  Any code path attempting a method other than GET, or a POST to anything other
  than `_search`/`_count`, must raise `ReadOnlyViolationError`.
- Record the `_count` total before aggregating, so the sum of buckets can be
  reconciled against it and a mismatch reported.

---

## 6. Collapse engine — `collapse.py`

### 6.1 Models

```python
class RemediationAction(BaseModel):
    package_name: str
    current_version: str
    affected_agents: list[str]      # ids
    agent_count: int
    finding_count: int              # bucket doc_count
    cve_count: int                  # cardinality
    severity_breakdown: dict[str, int]
    critical_count: int
    high_count: int
    unknown_severity_count: int
    is_kernel: bool

class PatchPlan(BaseModel):
    total_findings: int
    total_agents: int
    total_distinct_cves: int
    total_distinct_packages: int
    actions: list[RemediationAction]     # ranked
    collapse_ratio: float
    coverage_curve: list[CoveragePoint]  # cumulative
```

### 6.2 Ranking

Sort by, in this order:

1. `critical_count` descending
2. `high_count` descending
3. `finding_count` descending

Ties break alphabetically on `package_name`, so output is deterministic and
tests are stable.

### 6.3 Coverage curve — this is the product's headline

Compute the cumulative figure: after applying the first N actions, what
percentage of findings and of criticals disappears. This is the number that
turns the tool into a product:

> "The first 7 actions eliminate 71.2% of findings."

### 6.4 Kernel grouping

Kernel packages are 71% of the noise and are remediated together. Detect by
pattern (`linux-image-*`, `linux-headers-*`, `linux-oracle`, `linux-*-generic`,
`kernel-*`) and set `is_kernel=True`. Offer an optional `--group-kernels` flag
that presents them as a single "upgrade kernel" action per operating system.

### 6.5 Mandatory edge cases

- **Missing severity (`"-"`, `"None"`, empty):** 22% of the real data. Count in
  `unknown_severity_count`. Never treat as Low, never silently drop.
- **Missing or empty `package.version`:** group under `"unknown"`, do not crash.
- **Bucket with more than 10,000 agents:** the sub-`terms` truncates; detect it
  by comparing against a control `cardinality` and surface a warning.
- **Empty index:** return a valid empty `PatchPlan` with a clear message, not an
  exception.
- **Bucket sum does not reconcile with `_count`:** warn, reporting the delta.

---

## 7. Output — `render.py`

Three formats, selected with `--format`:

- `table` (default): `rich` table, top N actions, with the cumulative coverage
  line highlighted at the top.
- `json`: the full serialized `PatchPlan`. This is a stable contract — the paid
  tier will consume it later.
- `markdown`: a report ready to paste into a ticket or meeting minutes.

The header of `table` and `markdown` must always open with the impact line:

```
32,718 findings → 554 actions (ratio 59:1)
The first 7 eliminate 23,309 findings (71.2%) and 1,800 criticals.
```

---

## 8. CLI — `cli.py`

```
vulnfold scan \
  --url https://indexer:9200 \
  --user admin \
  --password-env VULNFOLD_PASSWORD \
  [--index-pattern wazuh-states-vulnerabilities-*] \
  [--mapping wazuh-4.x] \
  [--format table|json|markdown] \
  [--top 20] \
  [--group-kernels] \
  [--min-severity Critical|High|Medium|Low] \
  [--insecure]
```

**The password is read from an environment variable, never from an argument** —
arguments end up in shell history and in `ps`. If someone passes `--password`,
warn and continue.

---

## 9. Acceptance criteria

1. `pytest` green, coverage ≥ 80% on `collapse.py` and `mapping.py`.
2. Test against the real fixture: 32,718 findings, 554 packages, 15 agents →
   ratio 59:1, and the first 7 actions cover 71.2% ± 0.1.
3. No HTTP call other than GET, or POST to `_search`/`_count`. A `respx` test
   proves it.
4. `composite` pagination correctly walks 3 simulated pages.
5. Findings with severity `"-"` appear in `unknown_severity_count` and in no
   other category.
6. Swapping `mappings/wazuh-4.x.yaml` for a file with different field names
   produces the same queries against the new fields, with no code change.
   A test demonstrates it.
7. `vulnfold scan --format json | jq .collapse_ratio` works.
8. No dependency outside those listed in section 2.

---

## 10. What not to do

- Do not add a database, not even "just in case".
- Do not add a web UI.
- Do not call any LLM.
- Do not write to the cluster under any circumstance.
- Do not hardcode field names outside `mappings/`.
- Do not add integrations with other sources (CrowdSec, Trivy, Nessus) yet. The
  design must allow them later; building them now is permanent liability with no
  customer asking for it.