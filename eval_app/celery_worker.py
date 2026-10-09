"""Worker entry point: ``celery -A eval_app.celery_worker:celery worker -Q audits``."""

import ctypes
import ctypes.util
import sys

from .dotenv import load_local_env

PR_SET_DUMPABLE = 4


def _make_non_dumpable() -> bool:
    """Analyzer tools run as the worker's own user. Marking the worker non-dumpable makes its /proc/<pid>/environ
    and memory unreadable to them, so a compromised tool cannot lift DATABASE_URL or EVAL_ENCRYPTION_KEYS from the
    parent. The flag is inherited by forked pool processes and reset by execve, so tools are unaffected."""
    if not sys.platform.startswith("linux"):
        return False
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0


_make_non_dumpable()
load_local_env()

from . import create_app  # noqa: E402  (environment must be loaded before the app reads config)

app = create_app()
celery = app.extensions["celery"]
