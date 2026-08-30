#!/bin/sh
# Privileged deployment hook: takes no arguments and makes no decisions, so the
# CI account can be granted this one fixed command via sudo instead of docker
# group membership (root-equivalent on this host).
#
# vulnfold is a command, not a service: there is nothing to start or restart.
# The hook builds the image from the tree Jenkins just rsynced and verifies the
# entry point runs, so a broken build fails here rather than at the next scan.
#
# Install manually as root; the copy in the source tree is inert until then:
#   install -o root -g root -m 755 deploy/vulnfold-deploy.sh \
#           /usr/local/sbin/deploy-vulnfold
#
# Grant (/etc/sudoers.d/jenkins-deploys, mode 0440):
#   deploys ALL=(root) NOPASSWD: /usr/local/sbin/deploy-vulnfold
set -eu

APP_DIR=/opt/vulnfold

cd "$APP_DIR"

# Must match the image's non-root uid, or evidence files are unwritable.
install -d -o 10001 -g 10001 -m 755 "$APP_DIR/evidence"

docker compose build scan

# Proves the wheel installed and the entry point resolves. --help touches no
# network and needs no credentials, so it is safe to run unconditionally.
docker compose run --rm --no-deps scan --help >/dev/null

echo "vulnfold deployed: image built and entry point verified"
