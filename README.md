# vulnfold

Collapse Wazuh vulnerability-detection noise into an actionable patch plan.

vulnfold is not a finding deduplicator. It answers one question:

> These 7 upgrades across these 12 hosts eliminate 23,309 of your 32,718
> findings and 1,800 of your 2,492 criticals.

On a real 15-agent deployment, 32,718 active findings collapse to 554 distinct
packages — a 59:1 ratio — and the seven largest `(package, version)` buckets,
all Linux kernels, account for 71.2% of everything.

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
  --top INTEGER          Actions listed in table and markdown.  [default: 20]
  --group-kernels        Merge each kernel package's versions.
  --min-severity TEXT    List only actions relevant at this severity or above.
  --timeout FLOAT        Per-request timeout in seconds.  [default: 30.0]
  --insecure             Disable TLS certificate verification.
```

`--format json` emits the whole plan and is a stable contract:

```bash
vulnfold scan --url ... --user ... --format json | jq .collapse_ratio
```

`collapse_ratio` is findings per distinct package. `coverage_curve` always
describes the complete ranked plan, even when `--min-severity` shortens the
listed actions, so "the first N actions" keeps one meaning between runs.

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
severity_order: ["Critical", "High", "Medium", "Low"]
severity_unknown: ["-", "None", ""]
```

Pass a file directly with `--mapping ./mappings/wazuh-5.x.yaml`.

## Unrated findings

22% of findings in real data carry no severity (`-`, `None`, or no field at
all). They are counted in `unknown_severity_count`, never folded into Low, and
never hidden by `--min-severity`.

## Licence

Apache 2.0. See `LICENSE`.
