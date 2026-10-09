#!/usr/bin/env bash
# Render entry point (Dockerfile.render): run the web server and the audit worker in one container.
#
# A Render persistent disk can be attached to only one service, and the worker must read the ZIP uploads the web
# process stores there, so both share this container and its disk. If either process exits, the other is stopped
# and the container exits non-zero, so Render restarts it.
set -euo pipefail

DATA_DIR="${EVAL_DATA_DIR:-/data}"

if [ "$(id -u)" = "0" ]; then
  # Render mounts the disk owned by root. Take ownership, then re-run this script as `eval`; nothing else runs
  # as root.
  mkdir -p "$DATA_DIR"
  chown eval:eval "$DATA_DIR"
  if [ -n "${EVAL_TRIVY_CACHE_DIR:-}" ]; then
    mkdir -p "$EVAL_TRIVY_CACHE_DIR"
    chown eval:eval "$EVAL_TRIVY_CACHE_DIR"
  fi
  exec env HOME=/home/eval USER=eval LOGNAME=eval \
    setpriv --reuid=eval --regid=eval --init-groups --no-new-privs -- bash "$0" "$@"
fi

mkdir -p "${EVAL_WORK_DIR:-$DATA_DIR/work}"

celery -A eval_app.celery_worker:celery worker -Q audits --loglevel=INFO \
  --concurrency="${EVAL_WORKER_CONCURRENCY:-2}" --max-tasks-per-child=20 &
gunicorn --bind "0.0.0.0:${PORT:-10000}" --workers "${WEB_CONCURRENCY:-2}" --access-logfile - wsgi:app &

stop_all() { kill -TERM $(jobs -p) 2>/dev/null || true; }
shutdown=0
trap 'shutdown=1; stop_all' TERM INT

status=0
wait -n || status=$?
stop_all
wait || true
if [ "$shutdown" = 1 ]; then
  exit 0  # Render asked us to stop (deploy, restart): both processes shut down gracefully
fi
echo "render-start: a process exited unexpectedly (status $status); stopping the container" >&2
exit $(( status == 0 ? 1 : status ))
