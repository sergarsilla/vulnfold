# Changelog

Notable changes to vulnfold. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-05

First public release.

### Added

- **Collapse engine and CLI.** Reads a Wazuh 4.x indexer's
  `wazuh-states-vulnerabilities-*` index and collapses findings into ranked
  remediation actions — `package`, `target version`, `affected hosts` — with
  table, JSON and Markdown output.
- **Fixability partition.** Findings are split on
  `vulnerability.scanner.condition` before ranking. Those naming a fixed version
  become the patch plan; those the vendor confirms affected with no published
  fix become a separate register requiring documented risk acceptance. Every
  percentage is reported against its own denominator.
- **Two coverage curves.** `--rank-by criticals` (default) and
  `--rank-by findings` answer different questions and need not agree, so both
  claims are always printed whichever ordering is active.
- **Collapse sources.** The header separates the two ways findings compress —
  CVEs per package version, and hosts carrying it — because reading the ratio
  alone cannot distinguish them and the remediation work is nothing alike.
- **Evidence records.** `--evidence` writes a complete, self-describing JSON
  record of a run for ISO 27001 control 8.8, written atomically so a failed run
  leaves no partial file. Schema documented in `docs/evidence-schema.md`.
- **Field mappings.** Every schema dependency — index pattern, field names, the
  detector's severity and fixability vocabulary — lives in `mappings/*.yaml`.
  Supporting another release is a YAML file, not a code change.
- **Kernel grouping.** `--group-kernels` merges a kernel package's versions,
  reporting the resulting CVE counts as bounded rather than exact.
- **Container image and scheduled scanning.** Multi-stage build running the test
  suite in a stage the runtime depends on, non-root at runtime; systemd service
  and timer for a daily scan with 90-day evidence retention.

### Security

- **Read-only by construction.** The tool issues no request other than a read,
  against one index. Any code path capable of a write is a defect.
- Passwords are read from an environment variable. `--password` works and warns,
  because arguments are visible in the process list.
- TLS verification is on unless `--insecure` is passed, which says so on stderr.
- Credentials are stripped from the indexer URL before it reaches the evidence
  record.

### Known limitations

- Wazuh 4.x only. 5.0 was unreleased when this shipped.
- Cross-host collapse is unproven. On the deployment this was measured against,
  one action touches 1.23 hosts on average: it compresses through CVE volume per
  package, not through fleet duplication. A homogeneous, centrally managed fleet
  should behave differently, and that has not been tested. Treat any claim that
  one upgrade clears many hosts as unverified.
- A condition string the mapping's vocabulary does not cover appears in neither
  list and raises `unrecognized_fixability`. That is a mapping gap to fix, not a
  third class of finding.

[0.1.0]: https://github.com/sergarsilla/vulnfold/releases/tag/v0.1.0
