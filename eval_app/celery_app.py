"""Celery bound to the Flask app so tasks run inside an application context."""

from __future__ import annotations

from celery import Celery, Task
from flask import Flask


def init_celery(app: Flask) -> Celery:
    class FlaskTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery = Celery(app.import_name, task_cls=FlaskTask)
    celery.conf.update(
        broker_url=app.config["CELERY_BROKER_URL"],
        result_backend=app.config["CELERY_RESULT_BACKEND"],
        task_always_eager=app.config["CELERY_TASK_ALWAYS_EAGER"],
        task_eager_propagates=False,
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_time_limit=app.config["ANALYZER_TIMEOUT_SECONDS"] * 6,
        task_soft_time_limit=app.config["ANALYZER_TIMEOUT_SECONDS"] * 5,
        task_routes={"eval.run_audit": {"queue": "audits"}},
        broker_connection_retry_on_startup=True,
        result_expires=3600,
    )
    celery.set_default()
    app.extensions["celery"] = celery
    from .audits import tasks  # noqa: F401  (register tasks)

    return celery
