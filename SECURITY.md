# Security policy

## Reporting a vulnerability

Report privately through GitHub's **[Security tab → Report a
vulnerability](../../security/advisories/new)**. That opens a private advisory
visible only to you and the maintainers.

Please do not open a public issue for a security problem.

Include what you would want to receive yourself: what you did, what happened,
what you expected, and the smallest input that reproduces it.

## What to expect

vulnfold is maintained by a small number of people in their own time. The
honest commitment is an acknowledgement within a week and a fix or a written
decision not to fix. There is no paid support tier and no service level
agreement, and promising one here would be worth nothing.

Fixes land in `main` and are noted in `CHANGELOG.md`. Only the latest release is
supported.

## What counts

vulnfold reads a Wazuh indexer over HTTP and prints a report. Its security
surface is small and specific:

**In scope**

- Any code path that issues a request other than a read. The tool is read-only
  by design; a write of any kind is a defect, not a feature request.
- Credentials appearing anywhere they should not: process arguments, logs, the
  rendered report, or the evidence file.
- TLS verification being skipped when `--insecure` was not passed.
- Indexer responses influencing execution beyond the data they carry — a
  malicious or compromised indexer should be able to produce a wrong report and
  nothing else.
- The evidence file being writable or readable by accounts that should not have
  it, or a failed run leaving a partial file that reads as a successful one.

**Out of scope**

- Vulnerabilities in Wazuh itself. Report those to the Wazuh project.
- A report being wrong because the upstream vendor feed is wrong. vulnfold
  reports what the indexer holds; correctness of the feed is the vendor's.
- Running the tool with `--insecure`, or with an over-privileged indexer
  account, against a host you do not control. Both are documented choices.

## Hardening the deployment

The container runs as a non-root user and needs no capabilities. Run it with
the filesystem read-only so the read-only posture is enforced by the runtime
rather than merely asserted by the code:

```bash
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  -e VULNFOLD_PASSWORD vulnfold:latest scan --url https://indexer:9200 --user readonly
```

Give the indexer account read access to the vulnerability state index and
nothing else. vulnfold never needs more, and an account that can do more is a
liability that this tool cannot protect you from.
