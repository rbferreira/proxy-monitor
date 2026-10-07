#!/bin/sh
# Drops root before the service starts.
#
# The container still *starts* as root, for one reason: a volume created by an
# earlier image holds files owned by root, and a `chown` baked into the image
# only applies to a volume that is empty. Switching user in the Dockerfile alone
# would leave an upgraded installation unable to write its own cache, settings,
# password hash and session key — silently, since every one of those writes is
# already allowed to fail. So ownership is fixed here, on every boot, and only
# then is root given up.
set -e

if [ "$(id -u)" = "0" ]; then
    data_dir=$(dirname "${OUTPUT_FILE:-/data/proxies.txt}")
    mkdir -p "$data_dir" 2>/dev/null || true
    # Not fatal: on a read-only or root-squashed mount the service still runs
    # and reports, write by write, what it could not persist.
    chown -R app:app "$data_dir" 2>/dev/null \
        || echo "WARNING: could not take ownership of $data_dir; state may not persist" >&2
    export HOME=/home/app
    exec setpriv --reuid=app --regid=app --init-groups "$@"
fi

# Already unprivileged (`docker run --user ...`): nothing to fix, nothing to drop.
exec "$@"
