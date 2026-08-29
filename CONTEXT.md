# CONTEXT.md — vulnfold

> Strategic context. Claude Code must read this before touching anything.
> Version-controlled. When strategy changes, this file is updated — conversations
> are never re-pasted.

**Version:** 1.0
**Last updated:** 2026-08-29

---

## 1. What this is

`vulnfold` collapses Wazuh vulnerability-detection noise into an **actionable
patch plan**.

It is not a finding deduplicator. It is a remediation-action generator, ranked
by impact.

Target output, literally:

> These 7 upgrades across these 12 hosts eliminate 23,309 of your 32,718
> findings and 1,800 of your 2,492 criticals.

---

## 2. The problem, with real data

Measured against a real Wazuh 4.14.7 deployment (15-agent lab, index
`wazuh-states-vulnerabilities-*`):

| Metric | Value |
|---|---|
| Active findings | 32,718 |
| Agents | 15 |
| Distinct CVEs | 5,950 |
| Distinct packages | 554 |
| Findings per agent | 2,181 |
| **Collapse ratio (findings ÷ packages)** | **59:1** |

Severity: 12,158 High · 10,295 Medium · 2,492 Critical · 484 Low ·
**7,287 with no severity assigned (22%)**

**Concentration — the key finding:** the top 7 `(package, version)` buckets are
all Linux kernel packages and account for **23,309 findings, 71.2% of the
total**. A kernel is remediated with one `apt upgrade` and a reboot. Seven
actions remove 71% of the noise.

**Why it gets worse over time:** since the Linux kernel became a CNA in
February 2024 and began assigning CVEs to nearly every fix, each kernel version
carries thousands of CVEs. A single kernel package in the data above accumulates
5,155. This problem grows on its own.

**Upstream confirmation that this is structural, not a misconfiguration:**

- Wazuh issue #26487 — the same CVE is reported for the same agent every
  minute, generating thousands of events. The reporter ended up disabling
  vulnerability scanning entirely.
- Wazuh issue #32869 — the same CVE flips between Active and Solved several
  times a day, for days.
- Wazuh engineering response: the detector emits one alert per CVE-package
  tuple per agent per scan, and alerts with a different agent ID
  **cannot be centralized**.

---

## 3. Why existing tools do not solve this

**DefectDojo** (OWASP, ~4,800 stars, BSD-3): it does have a Wazuh parser, but it
works by importing a manually exported `.json` file. On the simple path it does
not preserve the finding's endpoint. Deduplication in Community Edition is tuned
*per asset*, while the problem here is precisely the same CVE repeated *across*
assets. It also requires deploying Django + Postgres + Celery + Redis. It is
app-centric (Product → Engagement → Test → Finding), not fleet-centric.

**Commercial AI SOC** (Dropzone, Prophet, Exaforce): they solve alert triage,
not vulnerability consolidation, and published pricing starts at $36,000/year.
They structurally ignore the Wazuh user, who chose Wazuh for budget reasons.

**Wazuh 5.0**: its headline changes are clustering, Filebeat removal, a reworked
RBAC and the `engine` module replacing `analysisd`. Vulnerability consolidation
is not part of it.

---

## 4. Architecture decisions (do not revisit without new evidence)

### D1 — Build on Wazuh 4.x, with a field-mapping adapter

100% of the installed base is on 4.x. 5.0 is still in beta and has slipped three
times. Field mappings live in `mappings/*.yaml`; porting to 5.0 means writing a
YAML file, not rewriting code.

### D2 — Read-only against `wazuh-states-vulnerabilities-*`

**Never** `alerts.json`, **never** the agent, **never** `ossec.conf`, **never**
writes to the cluster.

Consequences, which are the competitive advantage:

1. Installation = a URL and read-only credentials. Nobody has to touch their
   SIEM to try it.
2. It sidesteps the Active/Solved flapping bug: we read current state, not the
   event stream.
3. Porting to 5.0 reduces to remapping fields.
4. No contact with Wazuh's GPLv2 code: we query an HTTP API, we do not link
   against it. Our Apache 2.0 stays clean.

### D3 — Remediation first, findings second

The output unit is **the action** (`package + target version + affected hosts`),
not the finding. A clean list of findings is something others already provide.

### D4 — Open-core line

| Free (Apache 2.0) | Paid |
|---|---|
| Collapse engine | Persistence and history |
| CLI, JSON / table / Markdown output | Remediation SLA tracking |
| Field mappings | Multi-tenant (multiple clusters) |
| | Signed evidence for ISO 27001 control 8.8 |

Rationale: the CLI proves the value in 30 seconds and giving it away costs
nothing — it is the distribution channel. What is charged for is what survives
an audit, which requires history, and history requires storing state.

---

## 5. Project constraints

- **5-10 real hours per week.** Code is not the bottleneck (Claude Code);
  non-delegable human attention is.
- **Minimize recurring human surface**, not code surface. Every integration
  shipped is a permanent liability.
- **No personal brand, no public face.** Project brand, not personal brand.
- **No recurring sales work.** Distribution must live inside the product or the
  channel: Wazuh ecosystem, GitHub, SEO. The only non-delegable part is
  answering inbound, roughly 1-2 hours per week.
- **First milestone: a defined revenue target.** Few customers at a high price, not many
  cheap ones.

---

## 6. Ethical and legal boundary (non-negotiable)

- Not one line of code, document or data may derive from employer material or
  from the employer's clients. The domain knowledge belongs to the operator; the company's
  documents and security posture do not.
- The employer is not customer zero without an explicit prior conversation.
- Validation data comes from the personal lab, never from company production.
- No automated posting in the Wazuh community. That community is the
  distribution channel; burning it is unrecoverable.

---

## 7. Current status

- [x] Problem verified against real data (32,718 → 554, 71% kernel)
- [x] Competitive landscape analysed (DefectDojo, commercial AI SOC)
- [x] Platform risk checked (Wazuh 5.0 roadmap)
- [x] Licences confirmed (Apache 2.0 on both existing repos)
- [ ] SPEC-01: collapse engine + CLI
- [ ] Validation against a second Wazuh deployment
- [ ] Repository publication
- [ ] 4.x → 5.0 migration content (SEO window)

## 8. Existing reusable assets

- `sergarsilla/wazuh-llm-triage` (Apache 2.0) — local-LLM triage, abstention
  under low confidence, backpressure, dry-run allowlist. Reusable in phase 2 to
  enrich actions.
- `sergarsilla/wazuh-anomaly-detector` (Apache 2.0) — autoencoder, sanitization
  before analysis, dynamic threshold calibration. Reusable in phase 3.

Both parse `alerts.json`. `vulnfold` does **not** follow that pattern (see D2).