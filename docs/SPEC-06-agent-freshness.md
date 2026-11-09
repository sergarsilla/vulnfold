# SPEC-06 — Plan the fleet that is running, not the one that once reported

**Precondition:** SPEC-05 merged and deployed.

**Goal:** the headline, the plan and the dashboard describe agents that are
reporting now. Findings from machines that stopped reporting, agents that no
longer exist and copies left in superseded indices stay visible, but apart.

---

## 0. Why

The state index keeps the last known state of every agent indefinitely. On the
deployment this was measured against, 86% of the "fixable criticals" came from
agents silent for three to eight months or no longer registered, while every
running machine carried none. A second state index, left behind when the
manager was renamed, still held 11,906 findings frozen at its last write, some
of them duplicating agents that are reporting today.

A plan that ranks a powered-off laptop's kernel first is wrong in the same way
SPEC-02's unfixable rows were: it asks the operator to act on something that
is not there.

---

## 1. Decisions

1. **Active means seen within `--stale-after-days` (default 7).** Not
   "connected now": a laptop switched off last night reports real data.
2. **The plan covers active agents.** Stale and unregistered agents are listed
   apart with their last-seen date and their findings. The evidence record
   keeps the plan of every agent, plus each agent's status, so nothing an
   auditor needs is dropped.
3. **No liveness data is not an error.** When the monitoring index is missing
   or unreadable, every agent counts as active, a warning says so, and the scan
   behaves exactly as before.
4. **One index per agent.** When an agent's findings sit in several state
   indices, only the index holding its most recent detection is read; the
   others are superseded copies. Their findings are excluded everywhere and
   counted in a warning that names the indices. Decided during implementation:
   the duplicates were found while answering decision 2 and distort the
   counts of active agents too.

---

## 2. Data sources

Both are read through the same URL and credentials as the state index, with
`_search` only. Field names live in the mapping (D1):

- **Liveness:** `liveness.index_pattern` (Wazuh 4.x: `wazuh-monitoring-*`),
  written by the Wazuh dashboard every few minutes, one document per agent.
  An agent counts as registered when it appears in the 24 hours before the
  newest snapshot; its last-seen time is its newest `lastKeepAlive`.
- **Freshest index per agent:** a `terms` aggregation on agent id, then on
  `_index`, then `max` of `fields.detected_at`.

---

## 3. Agent status

| Status | Meaning |
|---|---|
| `active` | Seen within the window |
| `stale` | Registered, last seen before the window |
| `unregistered` | Has findings, absent from the newest monitoring snapshots |
| `unknown` | No liveness data was available; treated as active |

---

## 4. Acceptance criteria

1. With liveness data, headline totals, actions and the register cover active
   agents only; a section lists every excluded agent with status, last seen,
   findings and fixable findings.
2. Without it, output equals SPEC-05 output plus one warning.
3. Superseded copies never reach any total; the warning gives their count.
4. The evidence record keeps the plan of all agents and adds `scope`; no
   existing field changes meaning.
5. Metrics add fleet-wide totals, agents by status and excluded agents' rows.
