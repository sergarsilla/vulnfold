# SPEC-05 — Prometheus export and Grafana dashboard

**Precondition:** SPEC-04 merged and deployed. The scheduled scan writes one
evidence file a day.

**Goal:** make the plan visible where operators already look, without
vulnfold acquiring a database, a server or a history of its own.

---

## 0. Why Prometheus

vulnfold is a command that exits (SPEC-04 §0). The established way for a batch
job to feed a monitoring stack is the node-exporter *textfile collector*: the
job writes one exposition file atomically, node-exporter serves it, Prometheus
keeps the series. vulnfold persists nothing; the history belongs to the
monitoring stack the operator already runs. This is what D4 allows after its
revision in CONTEXT.md 3.1.

---

## 1. Scope

**In scope:**

- `--metrics PATH`: write the run as Prometheus exposition text, atomically.
- `--metrics-rows N` (default 50): actions and register entries exported as
  rows. Cardinality is bounded by this number, never by the fleet.
- Agent names next to agent ids, read from the mapping's `agent_name` field,
  in the plan, the evidence (`agent_names`, an added field) and the metrics.
- `dashboards/vulnfold.json`: a Grafana dashboard importable into any Grafana
  with a Prometheus datasource.
- Deployment wiring: a `metrics/` volume, the scheduled scan writing to it.

**Out of scope:** pushing anywhere (Pushgateway, remote write), an HTTP
endpoint, alert rules, comparing scans inside vulnfold.

---

## 2. Metrics

All gauges. Totals carry no labels beyond their class.

| Metric | Labels | Value |
|---|---|---|
| `vulnfold_last_scan_timestamp_seconds` | — | Unix time the scan ran |
| `vulnfold_findings` | `class` = fixable, no_fix, unknown | Findings in the class |
| `vulnfold_criticals` | `class` = fixable, no_fix | Criticals in the class |
| `vulnfold_agents` | — | Distinct agents in the index |
| `vulnfold_fixable_packages` | — | Distinct packages with a fix |
| `vulnfold_collapse_ratio` | — | Fixable findings per fixable package |
| `vulnfold_action_findings`, `_criticals`, `_cves`, `_agents` | row labels | Per action |
| `vulnfold_unfixable_findings`, `_criticals` | row labels | Per register entry |
| `vulnfold_coverage_percent` | `measure` = findings, criticals; `actions` | Cumulative share cleared by the first N actions |
| `vulnfold_warnings` | `code` | Warnings of that code |

Row labels: `rank` (zero-padded), `package`, `current_version`,
`target_version` (actions only), `kernel`, `hosts`. `hosts` names at most ten
agents as `name (id)` and states how many more there are, so a label never
grows with the fleet.

Rows are the complete plan in its `rank_by` order, not the display filter:
`--min-severity` shortens the screen, never an export (as for evidence).

---

## 3. Acceptance criteria

1. The file parses as Prometheus exposition text; label values escape `\`,
   `"` and newlines.
2. A failed write leaves the previous file in place (same atomic write as
   evidence).
3. No more than `--metrics-rows` rows per row metric, whatever the fleet size.
4. An index carrying no agent names still scans; names fall back to the id.
5. The evidence record gains `agent_names` without any other field changing.
6. The dashboard imports with only a Prometheus datasource chosen.
