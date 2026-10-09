"""Worker entry point: ``celery -A eval_app.celery_worker:celery worker -Q audits``."""

from . import create_app

app = create_app()
celery = app.extensions["celery"]
