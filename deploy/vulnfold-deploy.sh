#!/bin/sh
# Privileged deployment hook: takes no arguments and makes no decisions, so the
# CI account can be granted this one fixed command via sudo.
#
# vulnfold is a command, not a service: there is nothing to restart. The hook
# rebuilds the virtualenv from the tree Jenkins just rsynced and verifies the
# entry point still runs.
#
# Install manually as root; the copy in the source tree is inert until then:
#   install -o root -g root -m 755 deploy/vulnfold-deploy.sh \
#           /usr/local/sbin/deploy-vulnfold
#
# Grant (/etc/sudoers.d/jenkins-deploys, mode 0440):
#   deploys ALL=(root) NOPASSWD: /usr/local/sbin/deploy-vulnfold
set -eu

APP_DIR=/opt/vulnfold
VENV="$APP_DIR/.venv"

cd "$APP_DIR"

[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"

"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet --no-cache-dir .

# The venv stays root-owned: the CI account delivers the source but must not be
# able to alter what actually executes.
"$VENV/bin/vulnfold" --help >/dev/null
echo "vulnfold deployed: $("$VENV/bin/vulnfold" scan --help >/dev/null 2>&1 && echo ok)"
