# CONTEXT.md — vulnfold

> Strategic context. Claude Code must read this before touching anything.
> Version-controlled. When strategy changes, this file is updated — conversations
> are never re-pasted.

> **⚠ THIS FILE MUST NOT SHIP IN A PUBLIC REPOSITORY.**
> It names the author and their employer (§6), states the business model and
> price point (§4, §5), and records the competitive analysis. Two of those
> contradict the project's own constraint that there is no public face and no
> personal brand. Before publication this file is either removed from the
> published tree or reduced to the engineering rationale alone — decisions D1,
> D2, D3, D10, D11 and the measured data in §2 — with §3, §5 and §6 moved to the
> private strategy repository. Decide deliberately; do not let publication day
> decide it.

**Version:** 2.0
**Last updated:** 2026-08-31

> **What changed in 2.0.** Version 1.0 was written before the tool had ever run
> against live data. Several of its headline figures turned out to be wrong, and
> the wrongness was not cosmetic: the "seven actions remove 71% of the noise"
> claim counted findings that no upgrade can remove. Every number below is now
> measured, and §2 records what was corrected so nobody re-derives the old
> version from an old conversation.

---

## 1. What this is

`vulnfold` collapses Wazuh vulnerability-detection noise into an **actionable
patch plan**, and separates that plan from the findings nothing can fix.

It is not a finding deduplicator. It is a remediation-action generator, ranked
by impact, plus a register of what cannot be remediated.

Target output, literally:

> 32,718 findings → 13,659 fixable · 19,059 with no vendor fix.
> These 7 upgrades clear 7,727 of the fixable findings and 920 of the 1,322
> fixable criticals. The remaining 19,059 need documented risk acceptance,
> not patching.

---

## 2. The problem, with real data

Measured against a real Wazuh 4.14.7 deployment (15-agent lab, index
`wazuh-states-vulnerabilities-*`), verified 2026-08-30 and again 2026-08-31.

| Metric | Value |
|---|---|
| Active findings | 32,718 |
| Agents | 15 |
| Distinct CVEs | 5,950 |
| Distinct packages | 554 |
| Criticals | 2,492 |
| **Fixable findings** | **13,659 (41.7%)** |
| **Findings with no vendor fix** | **19,059 (58.3%)** |
| Fixable / no-fix criticals | 1,322 / 1,170 |
| Fixable packages | 453 |
| **Collapse ratio (fixable findings ÷ fixable packages)** | **30:1** |
| CVEs per package version | 19.6 |
| **Hosts per action** | **1.24** |

Severity: 12,158 High · 10,295 Medium · 2,492 Critical · 484 Low ·
**7,289 with no severity assigned (22%)**

### 2.1 The finding that reshaped the product

`vulnerability.scanner.condition` says whether a fix exists. **58.3% of findings
have none.** The vendor's own tracker — Canonical for 15,701 of them, Debian for
3,334 — confirms the package affected and has published no fixed version.

These are not false positives. Spot-checked against the primary source:
`CVE-2026-74569` (CVSS 9.8, netfilter use-after-free) on `linux-oracle` is
listed **"Vulnerable"** on Ubuntu's own CVE page. 74.7% of them are not under
evaluation, so they are settled vendor positions.

The largest single row in the fleet — `linux-oracle 6.17.0-1020.20`, 4,226
findings, 358 criticals, on hosts whose `apt` candidate equals the installed
version — has **nothing to upgrade to**. A plan that ranks it first is wrong,
and the first implementation did exactly that.

### 2.2 Corrections to version 1.0 — do not reintroduce these

| v1.0 claim | Status |
|---|---|
| "These 7 upgrades across these 12 hosts eliminate 23,309 findings and 1,800 criticals" | **False.** 19,039 of those 23,309 cannot be eliminated by any upgrade |
| "Collapse ratio 59:1" | **Misleading.** 59:1 counts all findings including the unfixable 58%. Over the fixable set it is 30:1 |
| "Top 7 buckets account for 23,309 findings, 71.2%. Seven actions remove 71% of the noise" | **False.** Most of that concentration is in the register. The true top 7 clear 7,727 fixable findings, 56.6% of what is fixable |
| Issue #26487 as upstream confirmation | **Does not support it.** Wazuh fixed it in 4.10.0 and attributed part of it to an agent with an intermittent manager connection |
| Issue #32869 as upstream confirmation | **Does not support it.** One maintainer comment asking for triage data, never answered, closed unreproduced |
| "Dropzone published pricing starts at $36,000/year" | **Stale.** That was the 2025 published price; public pricing was withdrawn in 2026 |
| D2's consequences are "the competitive advantage" | **Falsified.** See D10 |

**What survives untouched:** the 32,718 measurement itself, the kernel-CNA
mechanism, and the fact that the noise is real and growing.

### 2.3 Why it gets worse over time

Since the Linux kernel became a CNA in February 2024 and began assigning CVEs to
nearly every fix, each kernel version carries thousands of CVEs — one package in
the data above accumulates 5,155. Finding volume rises structurally; the number
of available actions does not.

### 2.4 What is still *not* demonstrated

**Cross-host collapse.** `hosts_per_action` is **1.24**. The pitch has always
implied one upgrade clearing many hosts, and this fleet does not show that: it
compresses through CVE volume per package, not through fleet duplication. The
strongest duplication measured is 2× — and it is in the register, on findings
nothing can fix.

The thesis predicts a homogeneous production fleet behaves very differently.
**That prediction is untested.** Do not print or publish a claim that depends on
it until a second, fleet-shaped dataset exists.

---

## 3. Why existing tools do not solve this

**DefectDojo** (OWASP, ~4,900 stars, BSD-3). Two paths, and version 1.0 only
knew about one:

- *Free:* import a manually exported `.json`. The simple export path does not
  carry the finding's endpoint; the alternative needs a third-party script.
- *Pro:* a **Wazuh Upstream Connector** that reads the same
  `wazuh-states-vulnerabilities-*` index directly from the Indexer, on a
  schedule, configured with a base URL and read-only credentials.

The connector matters: it is D2's architecture, feature for feature. What it
does *not* do is collapse across the fleet. It creates a record per agent and
imports that agent's CVEs as findings — all 32,718 of them, undifferentiated,
including the 19,059 nothing can fix. Its Wazuh parser hardcodes the agent id
into the deduplication key (`dupe_key = f"{cve}-{agent.id}"`), so the same CVE
on sixty servers is sixty findings by design.

**Commercial AI SOC** (Dropzone, Prophet, Exaforce). They solve alert triage,
not vulnerability consolidation. Dropzone published a $36,000/year entry price
for 4,000 investigations as recently as 2025 and withdrew public pricing in
2026, which is movement up-market. All are cloud SaaS: the telemetry leaves your
infrastructure, which structurally excludes the segment that chose Wazuh because
it is self-hosted and free.

**Wazuh 5.0**. Still unreleased as of 2026-08-31; stable is 4.14.7 and 5.0 is at
Beta 4 after four slipped dates. Its vulnerability work is plumbing — a new
synchronisation algorithm, agent-side inventory realignment, CTI expansion.
**Vulnerability consolidation is not in it.** Re-check on the day it ships.

---

## 4. Architecture decisions (do not revisit without new evidence)

The reasoning, the rejected alternatives and the falsification criteria for each
of these live in the strategy repository, one file per decision. This is the
summary, not the record.

### D1 — Build on Wazuh 4.x, with a field-mapping adapter

100% of the installed base is on 4.x. Field mappings live in `mappings/*.yaml`;
porting to 5.0 means writing a YAML file, not rewriting code.

### D2 — Read-only against `wazuh-states-vulnerabilities-*`

**Never** `alerts.json`, **never** the agent, **never** `ossec.conf`, **never**
a write to the cluster. Any code path capable of a non-read request is a defect,
not a feature request.

Four consequences, all still true:

1. Installation is a URL and read-only credentials. Nobody has to touch their
   SIEM to try it.
2. It sidesteps the Active/Solved flapping by construction: current state, not
   the event stream.
3. Porting to 5.0 reduces to remapping fields.
4. No contact with Wazuh's GPLv2 code — querying an HTTP API is not linking, so
   Apache 2.0 stays clean.

### D3 — Remediation first, findings second

The output unit is **the action** (`package + target version + affected hosts`),
never the finding.

### D4 — Open-core line

| Free (Apache 2.0) | Paid |
|---|---|
| Collapse engine | Persistence and history |
| CLI, JSON / table / Markdown output | Remediation SLA tracking |
| Field mappings | Multi-tenant (multiple clusters) |
| | Signed evidence for ISO 27001 control 8.8 |

The free tier is the distribution channel, not a loss leader. The line sits
exactly where statefulness begins: everything charged for requires storing state
over time. Few customers at a high price, because the binding cost is recurring
human surface, which scales with customer count and does not compress.

### D10 — Read-only index access is correct engineering, not a moat

The architecture does not change. The *claim* does. DefectDojo Pro's connector
reads the same index the same way, so D2's consequences are table stakes.
Differentiation now rests on two things and only two: **collapse into
fleet-level remediation actions**, and **correctness of the finding set**.

Do not write "nobody else can do this" about D2 anywhere a reader will see it.

### D11 — Partition by fixability before collapsing

Split on `vulnerability.scanner.condition` before ranking, and emit two
artefacts: the patch plan over fixable findings, and a register of findings with
no available fix. Every percentage is reported against its own denominator; no
coverage figure is ever computed over the undifferentiated total.

The register is probably the more valuable artefact. ISO 27001 control 8.8 fails
in practice because nobody separates *not done* from *cannot be done*, and that
separation needs history and signature — which is precisely what D4 puts behind
the paywall.

**Known risk:** filtering on `scanner.condition` is a dashboard filter, far
cheaper for Wazuh to add than fleet collapse. Do not build the business on the
partition alone.

---

## 5. Project constraints

- **5-10 real hours per week.** Code is not the bottleneck; non-delegable human
  attention is.
- **Minimize recurring human surface**, not code surface. Every integration
  shipped is a permanent liability.
- **No personal brand, no public face.** Project brand, not personal brand.
- **No recurring sales work.** Distribution must live inside the product or the
  channel: Wazuh ecosystem, GitHub, SEO. The only non-delegable part is
  answering inbound, roughly 1-2 hours per week.
- **First milestone: a defined revenue target.** Few customers at a high price. This
  figure is inferred from adjacent anchors and **has never been tested against a
  real buyer**; the first genuine pricing conversation overrides it.

---

## 6. Ethical and legal boundary (non-negotiable)

- Not one line of code, document or data may derive from employer material or
  from the employer's clients. The domain knowledge belongs to the operator; the company's
  documents and security posture do not.
- The employer is not customer zero without an explicit prior conversation.
- Validation data comes from the personal lab, never from company production.
- No automated posting in the Wazuh community. That community is the
  distribution channel; burning it is unrecoverable.
- No bulk cold email.

---

## 7. Current status

- [x] Problem verified against real data, and re-verified after implementation
- [x] Competitive landscape analysed, **including DefectDojo Pro's connector**
- [x] Platform risk checked (Wazuh 5.0 still unreleased, no consolidation)
- [x] Licences confirmed (Apache 2.0 on both existing repos)
- [x] SPEC-01: collapse engine + CLI
- [x] SPEC-02: fixability partition
- [x] SPEC-03: complete condition grammar
- [x] Containerised, deployed via CI, scan runs in ~1 s
- [ ] **Validation against a second Wazuh deployment** — the open item that
      matters most, because it is what would test §2.4
- [ ] Scheduled scanning and evidence retention
- [ ] Repository publication
- [ ] 4.x → 5.0 migration content (SEO window)

## 8. Existing reusable assets

- `sergarsilla/wazuh-llm-triage` (Apache 2.0) — local-LLM triage, abstention
  under low confidence, backpressure, dry-run allowlist. Reusable in phase 2 to
  enrich actions.
- `sergarsilla/wazuh-anomaly-detector` (Apache 2.0) — autoencoder, sanitization
  before analysis, dynamic threshold calibration. Reusable in phase 3.

Both parse `alerts.json`. `vulnfold` does **not** follow that pattern (see D2).
