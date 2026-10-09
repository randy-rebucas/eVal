"""Worker entry point: ``celery -A eval_app.celery_worker:celery worker -Q audits``."""

from .dotenv import load_local_env

load_local_env()

from . import create_app  # noqa: E402  (environment must be loaded before the app reads config)

app = create_app()
celery = app.extensions["celery"]
