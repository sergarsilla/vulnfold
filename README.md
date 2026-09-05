# vulnfold

Collapse Wazuh vulnerability-detection noise into an actionable patch plan.

vulnfold is not a finding deduplicator. It answers one question:

> These 7 upgrades eliminate 7,727 of the 13,659 findings you can actually fix,
> and 920 of the 1,322 criticals among them.

It answers a second one first, because the first answer is worthless without it:
**how much of this can be fixed at all.** On a real 15-agent deployment, 32,718
active findings split 13,659 fixable (41.7%) against 19,059 the vendor confirms
affected with no published fix (58.3%). The largest single row in that fleet —
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
32,718 findings → 13,659 fixable (41.7%) · 19,059 with no vendor fix (58.3%)
Criticals: 2,492 → 1,322 fixable · 1,170 with no vendor fix

13,659 fixable findings → 560 actions across 453 packages (ratio 30:1)
Each action clears 24.4 findings: 19.6 CVEs per package version × 1.24 hosts carrying it.
First 7 by findings: 7,727 of the 13,659 fixable findings (56.6%), on 7 hosts.
First 7 by criticals: 920 of the 1,322 fixable criticals (69.6%), on 7 hosts.
```

A package version carrying thousands of CVEs on one host compresses exactly as
hard as one package repeated across a thousand hosts, and the remediation work
is nothing alike. `1.24 hosts carrying it` says this fleet collapses through CVE
volume, not through fleet duplication. Reading the ratio alone would suggest the
opposite.

## Findings with no vendor fix

`vulnerability.scanner.condition` tells you whether a fix exists. `Package less
than X` names the version to upgrade to. Three forms name none: `Package default
status` means the vendor's own tracker lists the package as affected and has
published nothing, while `Package equal to X` and `Package less than or equal to
X` describe what is affected without naming a release to move to — `X` itself is
vulnerable in both.

On the measured fleet that second class is 58.3% of findings and 1,170
criticals. vulnfold reports it as a **separate register**, printed after the
plan, headed with what it is and what to do about it:

```
No vendor fix available — 19,059 findings, 1,170 critical

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

## Scheduled scanning

A systemd timer runs one scan a day from `/opt/vulnfold` and writes
`evidence/scan-YYYY-MM-DD.json` into the directory the deployment hook creates,
owned by the image's non-root uid. There is no daemon: vulnfold is a command
that exits, so the scheduler is the operating system's, and a failed run
reports itself through `systemctl status` and `journalctl` — deliberately the
only notification channel.

```bash
install -o root -g root -m 755 deploy/vulnfold-scan.sh /usr/local/sbin/vulnfold-scan
install -o root -g root -m 644 deploy/vulnfold-scan.service \
        deploy/vulnfold-scan.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vulnfold-scan.timer
```

The timer is `OnCalendar=daily` with an hour of randomised delay, because the
underlying data moves on the vendor feeds' schedule and not faster, and
`Persistent=true`, so a host that was off still produces the day's evidence
when it comes back. A second run on the same day overwrites: the file is that
day's state, not an append log.

**Evidence is kept for 90 days.** Older files are deleted after a successful
scan and never before one, so a failed scan cannot delete history. Nothing is
compressed or moved into subdirectories — the one moment the file matters is
when someone opens it under audit pressure.

A failed scan leaves no file at all, not even an empty one. The record is built
before anything is written, and the write goes through a temporary file in the
same directory that is then renamed onto the target, so a failure partway
through — a full disk is the realistic one — cannot leave a truncated
`scan-<date>.json` behind. An empty file carrying the day's name would read as
"we scanned and found nothing".

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
  no_fix_prefixes: ["Package equal to ", "Package less than or equal to "]
  fixed_version_prefix: "Package less than "
```

The three vocabularies are matched in that order, and the order matters:
`fixed_version_prefix` is itself a prefix of a `no_fix_prefixes` entry, so
testing it first would read `Package less than or equal to 1.114.4` as fixable
and hand `or equal to 1.114.4` on as a target version.

The fixability markers are vocabulary, not code: a Wazuh release that rewords
them is a YAML change.

Pass a file directly with `--mapping ./mappings/wazuh-5.x.yaml`.

## Unrated findings

22% of findings in real data carry no severity (`-`, `None`, or no field at
all). They are counted in `unknown_severity_count`, never folded into Low, and
never hidden by `--min-severity`.

## What is not proven

One action touches **1.23 hosts** on average in the deployment this was measured
against. That fleet compresses through CVE volume per package, not through
duplication across machines: the rows spanning five hosts carry twenty-two
findings, and the row carrying three thousand nine hundred spans one.

A homogeneous, centrally managed fleet running one kernel version everywhere
should behave differently, and that has not been tested. If you run vulnfold
against such a fleet, the `hosts_per_action` figure in the header is the number
worth reporting back — it is the one measurement this project cannot make for
itself.

## Reporting a security issue

Privately, through the Security tab. See [SECURITY.md](SECURITY.md).

## Changes

See [CHANGELOG.md](CHANGELOG.md).

## Licence

Apache 2.0. See `LICENSE`.
