#!/bin/sh
# Scheduled scan hook: takes no arguments and makes no decisions, so the timer
# invokes one fixed, auditable command. It exists for the same reason
# vulnfold-deploy.sh does, plus one of its own: the date in the evidence file
# name has to be expanded at run time, and systemd specifiers cannot format a
# date. Quoting a shell pipeline inside a unit file would hide that expansion
# where nobody reviews it.
#
# vulnfold is a command, not a service: this runs one scan and exits. Failure
# is reported by its exit status, which systemctl status and journalctl show;
# that is deliberately the only notification channel.
#
# Install manually as root; the copy in the source tree is inert until then:
#   install -o root -g root -m 755 deploy/vulnfold-scan.sh \
#           /usr/local/sbin/vulnfold-scan
#   install -o root -g root -m 644 deploy/vulnfold-scan.service \
#           deploy/vulnfold-scan.timer /etc/systemd/system/
#   systemctl daemon-reload
#   systemctl enable --now vulnfold-scan.timer
#
# Check it before trusting the schedule:
#   systemctl start vulnfold-scan.service && systemctl status vulnfold-scan
#   systemctl list-timers vulnfold-scan.timer
set -eu

# Overridable only so the retention rule can be exercised by the test suite.
# The unit passes no environment, so the installed path is always the default.
APP_DIR="${VULNFOLD_APP_DIR:-/opt/vulnfold}"
EVIDENCE_DIR=evidence
RETENTION_DAYS=90

cd "$APP_DIR"

# UTC, because the record's own generated_at is UTC: a scan starting just after
# local midnight must not name a day other than the one it reports on.
EVIDENCE_FILE="$EVIDENCE_DIR/scan-$(date -u +%Y-%m-%d).json"

# Reaches the CLI through the hole compose leaves for it, rather than as
# arguments to `docker compose run`: arguments there *replace* the service
# command, which would drop the indexer URL and user with it. The path is
# relative because the container resolves it inside the bind mount the
# deployment hook creates.
VULNFOLD_EVIDENCE_ARG="--evidence=$EVIDENCE_FILE"
export VULNFOLD_EVIDENCE_ARG

docker compose run --rm --no-deps scan

# Reached only when the scan exited zero, because of set -e above, and that
# ordering is the entire rule: a failed scan must never delete history.
# Age is the file's mtime, so a re-run on the same day renews the day it
# overwrites. -mtime +N is "older than N full days", so 90 keeps 90 days.
find "$EVIDENCE_DIR" -maxdepth 1 -type f -name 'scan-*.json' \
    -mtime "+$RETENTION_DAYS" -delete

echo "vulnfold scan complete: $EVIDENCE_FILE (keeping $RETENTION_DAYS days)"
