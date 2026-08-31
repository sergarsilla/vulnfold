# CONTEXT.md — vulnfold

> Why the tool is shaped the way it is. Claude Code must read this before
> touching anything. Version-controlled: when the reasoning changes, this file is
> updated — conversations are never re-pasted.

**Version:** 3.0
**Last updated:** 2026-08-31

> **What changed in 3.0.** Commercial strategy, pricing and the operator's
> circumstances were removed; this file is now safe to publish. Only the
> engineering rationale remains, and the decision identifiers (D1-D4, D10, D11)
> and section numbers are unchanged, because source comments and specifications
> cite them.
>
> **2.0** rewrote the measured data. Version 1.0 was written before the tool had
> ever run, and several of its headline figures were wrong in ways that changed
> the design. §2.2 records them so nobody re-derives them from an old
> conversation.

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
`wazuh-states-vulnerabilities-*`), verified 2026-08-30 and re-verified
2026-08-31.

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
| Wazuh issue #26487 as upstream confirmation | **Does not support it.** Fixed in 4.10.0, and partly attributed to an agent with an intermittent manager connection |
| Wazuh issue #32869 as upstream confirmation | **Does not support it.** One maintainer comment asking for triage data, never answered, closed unreproduced |

**What survives untouched:** the 32,718 measurement itself, the kernel-CNA
mechanism below, and the fact that the noise is real and growing.

### 2.3 Why it gets worse over time

Since the Linux kernel became a CNA in February 2024 and began assigning CVEs to
nearly every fix, each kernel version carries thousands of CVEs — one package in
the data above accumulates 5,155. Finding volume rises structurally; the number
of available actions does not.

### 2.4 What is still *not* demonstrated

**Cross-host collapse.** `hosts_per_action` is **1.24**. The premise has always
implied one upgrade clearing many hosts, and this fleet does not show that: it
compresses through CVE volume per package, not through fleet duplication. The
strongest duplication measured is 2×, and it is in the register, on findings
nothing can fix.

A homogeneous production fleet should behave very differently. **That is
untested.** Do not print, document or publish any claim that depends on it until
a second, fleet-shaped dataset exists. This is the single largest open question
in the project.

---

## 3. Why existing tools do not solve this

**DefectDojo** (OWASP, ~4,900 stars, BSD-3) has two paths:

- *Community:* import a manually exported `.json`. The simple export path does
  not carry the finding's endpoint; the alternative needs a third-party script.
- *Pro:* a **Wazuh Upstream Connector** reading the same
  `wazuh-states-vulnerabilities-*` index directly from the Indexer, on a
  schedule, configured with a base URL and read-only credentials.

The connector matters, because it is D2's architecture feature for feature.
What it does not do is collapse across the fleet: it creates a record per agent
and imports that agent's CVEs as findings — all 32,718, undifferentiated,
including the 19,059 nothing can fix. Its Wazuh parser hardcodes the agent id
into the deduplication key (`dupe_key = f"{cve}-{agent.id}"`), so the same CVE
on sixty servers is sixty findings by design.

**Commercial AI SOC platforms** solve alert triage, not vulnerability
consolidation, and are cloud SaaS: the telemetry leaves the operator's
infrastructure, which excludes anyone running a self-hosted SIEM on purpose.

**Wazuh 5.0** was still unreleased as of 2026-08-31; stable is 4.14.7 and 5.0 is
at Beta 4 after four slipped dates. Its vulnerability work is plumbing — a new
synchronisation algorithm, agent-side inventory realignment, CTI expansion.
**Vulnerability consolidation is not in it.** Re-check on the day it ships.

---

## 4. Architecture decisions (do not revisit without new evidence)

### D1 — Build on Wazuh 4.x, with a field-mapping adapter

100% of the installed base is on 4.x. Every schema dependency lives in
`mappings/*.yaml` — field names *and* the detector's vocabulary — so supporting
another release means writing a YAML file, not changing code.

### D2 — Read-only against `wazuh-states-vulnerabilities-*`

**Never** `alerts.json`, **never** the agent, **never** `ossec.conf`, **never**
a write to the cluster. Any code path capable of a non-read request is a defect,
not a feature request.

Four consequences, all still true:

1. Installation is a URL and read-only credentials. Nobody has to touch their
   SIEM to try it.
2. It sidesteps the Active/Solved flapping by construction: current state, not
   the event stream.
3. Supporting another release reduces to remapping fields.
4. No contact with Wazuh's GPLv2 code — querying an HTTP API is not linking, so
   the Apache 2.0 licence stays clean.

### D3 — Remediation first, findings second

The output unit is **the action** (`package + target version + affected hosts`),
never the finding. A clean list of findings is something others already provide.

### D4 — What is in scope for this repository

In scope: the collapse engine, the CLI, JSON / table / Markdown output, field
mappings, and the evidence record for one run.

**Out of scope, deliberately:** persistence and history, remediation SLA
tracking, multi-tenancy across clusters, and comparing one scan to another. A
specification that asks for any of these is asking for the wrong thing; say so
rather than building it.

### D10 — Read-only index access is correct engineering, not a moat

The architecture does not change. The *claim* does. DefectDojo Pro's connector
reads the same index the same way, so D2's consequences are table stakes.
What differentiates this tool is two things and only two: **collapse into
fleet-level remediation actions**, and **correctness of the finding set**.

Do not write "nobody else can do this" about D2 anywhere a reader will see it.

### D11 — Partition by fixability before collapsing

Split on `vulnerability.scanner.condition` before ranking, and emit two
artefacts: the patch plan over fixable findings, and a register of findings with
no available fix. Every percentage is reported against its own denominator; no
coverage figure is ever computed over the undifferentiated total.

The register is arguably the more valuable artefact. ISO 27001 control 8.8 fails
in practice not because nobody looks, but because nobody separates *not done*
from *cannot be done*.

**Known risk:** filtering on `scanner.condition` is a dashboard filter, far
cheaper for the platform to add than fleet collapse. Do not treat the partition
alone as durable differentiation.

---

## 5. Current status

- [x] Problem verified against real data, and re-verified after implementation
- [x] Competitive landscape analysed, including DefectDojo Pro's connector
- [x] Platform risk checked (Wazuh 5.0 unreleased, no consolidation in it)
- [x] SPEC-01: collapse engine + CLI
- [x] SPEC-02: fixability partition
- [x] SPEC-03: complete condition grammar
- [x] SPEC-04: scheduled scanning and evidence retention
- [x] Containerised, deployed via CI, scan runs in about a second
- [ ] **Validation against a second Wazuh deployment** — the open item that
      matters most, because it is what would test §2.4
- [ ] Repository publication

---

## 6. Where the rest of the reasoning lives

Commercial strategy, the go-to-market constraints, the competitive research with
its sources and verification dates, and one file per decision with its rejected
alternatives and falsification criteria, live in a separate private repository.
They are deliberately not here: this file ships with the code, and a tool's
repository is not the place for a business plan.

If a decision here looks arbitrary, it is because its justification is recorded
there. Ask before overriding it.
