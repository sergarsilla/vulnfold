# SPEC-04 — Scheduled scanning and evidence retention

**Precondition:** SPEC-03 merged and deployed. The container runs from
`/opt/vulnfold` via `docker compose run --rm scan`.

**Goal:** produce a dated evidence file on a schedule, without inventing a
daemon.

---

## 0. Why this is not a service

`vulnfold` is a command that exits. Nothing about it should acquire a
long-running process, a restart policy or a health check. The unit of work is
one scan, and the scheduler is the operating system's.

This matters beyond tidiness: a resident process is recurring human surface, and
the whole strategy exists to minimise that. A timer that fails loudly and does
nothing else has no maintenance tail.

---

## 1. Scope

**In scope:** a systemd service and timer shipped in `deploy/`, evidence written
to a dated file, retention that bounds disk growth, and documentation of the
manual install exactly as `deploy/vulnfold-deploy.sh` documents its own.

**Out of scope:** any change to the scan path, notifications, dashboards,
uploading evidence anywhere, comparing one scan to the previous one. History and
comparison are the paid tier (D4); this spec only produces the raw material.

---

## 2. Files

Two new files in `deploy/`, following the convention already set by
`vulnfold-deploy.sh`: inert in the source tree, installed manually as root, with
the install and grant commands documented in a header comment.

### `deploy/vulnfold-scan.service`

`Type=oneshot`. Runs, in `/opt/vulnfold`:

```
docker compose run --rm --no-deps scan --evidence evidence/scan-%Y-%m-%d.json
```

The date must be expanded at run time by the shell the unit invokes, not by
systemd specifiers, which do not cover date formatting. Prefer
`ExecStart=/usr/local/sbin/vulnfold-scan` — a third small script — over quoting
a shell pipeline inside the unit file, for the same reason
`vulnfold-deploy.sh` exists: a fixed, argument-less command is auditable and
grantable.

Hardening directives that cost nothing here and are worth having on a unit that
runs as root: `NoNewPrivileges=true`, `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp=true`, with `ReadWritePaths=/opt/vulnfold`.
Verify they do not break the Docker socket access the unit needs; if one does,
drop that one and say which in a comment, rather than dropping all of them.

### `deploy/vulnfold-scan.timer`

`OnCalendar=daily` with `RandomizedDelaySec=1h` and `Persistent=true`.

Daily because the underlying data changes on the vendor feed's schedule, not
faster. `Persistent=true` so a host that was off still produces the day's
evidence when it comes back — an audit trail with silent holes is worth less
than one without.

---

## 3. Evidence file naming and retention

- One file per run: `evidence/scan-YYYY-MM-DD.json`. A second run on the same
  day overwrites, which is correct: the file is the day's state, not an append
  log.
- Written by uid 10001 into the bind mount the deployment hook already creates.
- **Retention: keep 90 days, delete older.** ISO 27001 control 8.8 evidence is
  read in an audit window, and a year of daily scans of a 15-agent fleet is
  already tens of megabytes; on a real fleet it is much more.
- Retention runs in the same script, after a successful scan, and never before
  one. A failed scan must not be able to delete history.

Do not compress and do not rotate into subdirectories. Both add a decompression
step to the one moment the file matters — someone reading it under audit
pressure.

---

## 4. Failure behaviour

The scan must fail loudly and leave no partial evidence file. Specifically:

- A failed scan exits non-zero, so `systemctl status` and `journalctl` show it.
  That is the notification channel; do not add another.
- **A failed scan must not leave a truncated or empty `scan-<date>.json`.**
  Already true for the common case, and verified rather than assumed:
  `_write_evidence` in `cli.py` builds the whole record first and only then
  calls `path.write_text(...)`, so an authentication or network failure never
  reaches the write and creates no file.

  The remaining gap is narrow but real for an audit artefact: `write_text` is
  not atomic, so an I/O failure mid-write — a full disk is the realistic one —
  leaves a truncated JSON file carrying that day's name. Write to a temporary
  file in the same directory and `os.replace` onto the target. That is a
  handful of lines in `_write_evidence` and it makes a partial file impossible
  rather than unlikely.
- Retention does not run when the scan failed.

---

## 5. Acceptance criteria

1. `deploy/vulnfold-scan.service`, `deploy/vulnfold-scan.timer` and the
   `vulnfold-scan` script exist, are inert in the tree, and carry install
   instructions in header comments matching the style of
   `vulnfold-deploy.sh`.
2. `systemd-analyze verify` passes on both units.
3. A manual run of the script produces `evidence/scan-<today>.json`, owned by
   uid 10001, containing a complete evidence record that validates against
   `EvidenceRecord`.
4. **A deliberately failed scan** — wrong credentials is the cheapest way —
   exits non-zero and leaves **no** file for that date, not even an empty one.
   Assert this; it is the criterion most likely to be quietly skipped. Add a
   unit test that a write failing partway leaves the previous day's file intact
   and creates no partial one, which is what the atomic rename in section 4
   buys.
5. Retention deletes a file dated 91 days ago and keeps one dated 89 days ago,
   demonstrated with touched fixture files rather than by waiting.
6. Retention does not run when the scan fails.
7. `README.md` gains a short "Scheduled scanning" section: what the timer does,
   where evidence lands, the retention window, and the install commands.

---

## 6. What not to do

- **No daemon, no `Restart=`, no health check.** See section 0.
- **No notification integration.** `journalctl` is the channel. Adding email or
  a webhook adds a credential, a failure mode and a maintenance tail for a
  15-agent lab.
- **No diffing against the previous scan.** That is the paid tier.
- **Do not put the schedule in the container.** A cron inside an image that also
  runs interactively is two behaviours in one artefact, and the published image
  must stay a plain CLI.
