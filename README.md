# vulnfold

Collapse Wazuh vulnerability-detection noise into an actionable patch plan.

vulnfold is not a finding deduplicator. It answers one question:

> These 7 upgrades eliminate 7,727 of the 13,664 findings you can actually fix,
> and 920 of the 1,322 criticals among them.

It answers a second one first, because the first answer is worthless without it:
**how much of this can be fixed at all.** On a real 15-agent deployment, 32,718
active findings split 13,664 fixable (41.8%) against 19,039 the vendor confirms
affected with no published fix (58.2%). The largest single row in that fleet —
4,226 findings, 358 criticals — has no upgrade to recommend. A plan that ranks
it first is wrong.

The fixable half collapses to 453 distinct packages, and the largest rows in
the fleet are all Linux kernels: one `apt upgrade` and a reboot each.

## How it works

vulnfold reads the `wazuh-states-vulnerabilities-*` indices over HTTP and
**never writes to the cluster**. It reads current state rather than the alert
stream, which sidesteps the Active/Solved flapping that makes event-based
tooling unreliable. Installation is a URL and read-only credentials; nothing on
the Wazuh side has to change.

Findings are aggregated with a `composite` aggregation paged to exhaustion. A
fixed-size aggregation truncates silently on a real fleet and produces a
confidently wrong answer.

## Install

```bash
uv venv
uv pip install -e .
```

## Use

```bash
export VULNFOLD_PASSWORD='...'

vulnfold scan \
  --url https://indexer.example.internal:9200 \
  --user vulnfold-readonly
```

The password is read from an environment variable. Passing `--password` works
but warns, because command-line arguments are visible in shell history and in
the process list.

```
Options:
  --url TEXT             Indexer base URL.  [required]
  --user TEXT            Indexer account with read access.  [required]
  --password-env TEXT    Environment variable holding the password.
                         [default: VULNFOLD_PASSWORD]
  --index-pattern TEXT   Override the mapping's index pattern.
  --mapping TEXT         Field mapping name, or path to a mapping file.
                         [default: wazuh-4.x]
  --format [table|json|markdown]
                         Output format.  [default: table]
  --top INTEGER          Rows listed per table in table and markdown.
                         [default: 20]
  --rank-by [criticals|findings]
                         Order actions by criticals or by findings.
                         [default: criticals]
  --group-kernels        Merge each kernel package's versions.
  --evidence PATH        Write the complete run to this JSON file.
  --min-severity TEXT    List only rows relevant at this severity or above.
  --no-unfixable         Suppress the register of findings with no fix.
  --timeout FLOAT        Per-request timeout in seconds.  [default: 30.0]
  --insecure             Disable TLS certificate verification.
```

`--format json` emits the whole plan and is a stable contract:

```bash
vulnfold scan --url ... --user ... --format json | jq .collapse_ratio
```

`collapse_ratio` is fixable findings per distinct fixable package.
`coverage_curve` always describes the complete ranked plan, even when
`--min-severity` shortens the listed actions, so "the first N actions" keeps one
meaning between runs. **Every percentage the tool prints is over the fixable
findings**, except the fixable/no-fix split itself.

## Two claims, two curves

`--rank-by criticals` (the default) answers *what do I fix to cut severe
exposure fastest*. `--rank-by findings` answers *what do I fix to cut the noise
fastest*. They need not agree, so **both** coverage curves are computed and both
headline claims are printed whichever ordering is active.

The header also separates the two ways findings compress:

```
32,718 findings → 13,664 fixable (41.8%) · 19,039 with no vendor fix (58.2%)
Criticals: 2,492 → 1,322 fixable · 1,170 with no vendor fix

13,664 fixable findings → 560 actions across 453 packages (ratio 30:1)
Each action clears 24.4 findings: 19.7 CVEs per package version × 1.24 hosts carrying it.
First 7 by findings: 7,727 of the 13,664 fixable findings (56.5%), on 7 hosts.
First 7 by criticals: 920 of the 1,322 fixable criticals (69.6%), on 7 hosts.
```

A package version carrying thousands of CVEs on one host compresses exactly as
hard as one package repeated across a thousand hosts, and the remediation work
is nothing alike. `1.24 hosts carrying it` says this fleet collapses through CVE
volume, not through fleet duplication. Reading the ratio alone would suggest the
opposite.

## Findings with no vendor fix

`vulnerability.scanner.condition` tells you whether a fix exists. `Package less
than X` names the version to upgrade to; `Package default status` means the
vendor's own tracker lists the package as affected and has published nothing.

On the measured fleet that second class is 58.2% of findings and 1,170
criticals. vulnfold reports it as a **separate register**, printed after the
plan, headed with what it is and what to do about it:

```
No vendor fix available — 19,039 findings, 1,170 critical

These packages are confirmed affected by their vendor with no fixed version
published. They cannot be remediated by patching today and require documented
risk acceptance.
```

These are not false positives — Wazuh sources them from the Canonical and
Debian security trackers — so they are never suppressed. `--no-unfixable` hides
the register on screen; it never shortens the JSON or the evidence file.

A finding whose condition the mapping does not recognise appears in **neither**
list and raises `unrecognized_fixability` naming the strings it saw. That is a
gap in the mapping's vocabulary, not a third class of finding, and folding it
into "no fix" would hide the gap.

## Evidence

```bash
vulnfold scan --url ... --user ... --evidence scan-2026-08-30.json
```

Writes a complete, self-describing record of the run: timestamp, indexer, index
pattern, mapping version, fleet totals, the fixability split, both coverage
curves, the full ranked action list and the full register. Neither
`--min-severity` nor `--no-unfixable` shortens it. The schema is a stable
contract documented in [docs/evidence-schema.md](docs/evidence-schema.md).

Wazuh ships self-signed certificates by default. `--insecure` disables
certificate verification and says so on stderr; verification is on otherwise.

## Field mappings

Every schema dependency lives in `mappings/`. Supporting another Wazuh release
means adding a YAML file, not changing code:

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
  scanner_condition: "vulnerability.scanner.condition"
severity_order: ["Critical", "High", "Medium", "Low"]
severity_unknown: ["-", "None", ""]
fixability:
  no_fix_values: ["Package default status"]
  fixed_version_prefix: "Package less than "
```

The fixability markers are vocabulary, not code: a Wazuh release that rewords
them is a YAML change.

Pass a file directly with `--mapping ./mappings/wazuh-5.x.yaml`.

## Unrated findings

22% of findings in real data carry no severity (`-`, `None`, or no field at
all). They are counted in `unknown_severity_count`, never folded into Low, and
never hidden by `--min-severity`.

## Licence

Apache 2.0. See `LICENSE`.
