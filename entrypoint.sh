#!/bin/sh
# Ensure log directory exists and is writable by the runtime user
LOG_DIR="${INGEST_LOG_DIR:-/var/log/ingest}"
mkdir -p "$LOG_DIR"
# try to chown/chmod but ignore errors (may run as non-root during build)
chown -R ingest_user:ingest_user "$LOG_DIR" 2>/dev/null || true
chmod 755 "$LOG_DIR" 2>/dev/null || true

# If su-exec is available use it, otherwise try gosu, otherwise fallback to su -c
UID=$(id -u 2>/dev/null || echo 0)
if [ "$UID" -eq 0 ]; then
	# We're root: try to drop privileges to ingest_user
	if command -v su-exec >/dev/null 2>&1; then
		exec su-exec ingest_user "$@"
	elif command -v gosu >/dev/null 2>&1; then
		exec gosu ingest_user "$@"
	else
		# Last resort: use su to run the command as the ingest_user
		exec su -s /bin/sh -c "$*" ingest_user
	fi
else
	# Not root: just exec the command as the current user
	exec "$@"
fi
