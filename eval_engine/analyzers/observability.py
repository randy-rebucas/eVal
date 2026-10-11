"""Observability: can the team see what the application is doing in production?

Checks for structured logging, error tracking, distributed tracing, request/correlation ids, health endpoints,
metrics, audit logs for security-relevant actions, and monitoring of background jobs. Every finding carries a
practical recommendation.

Rule ids keep the ``devops.`` namespace these checks had before they moved out of the DevOps analyzer, so existing
findings keep their fingerprints and triage decisions.
"""

from __future__ import annotations

import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

HEALTH_ROUTE = re.compile(r"""["'`]/(?:health|healthz|livez|readyz|ready|status|ping)["'`/]""", re.I)
WEB_FRAMEWORKS = {"flask", "django", "fastapi", "express", "nestjs", "fastify", "koa", "starlette"}
CODE_SUFFIXES = (".py", ".js", ".ts", ".mjs", ".cjs")
MANIFESTS = ("requirements.txt", "pyproject.toml", "Pipfile", "setup.cfg", "setup.py", "package.json")
MAX_CODE_FILES = 3000
METRICS_HINT = re.compile(r"(?i)prometheus|opentelemetry|statsd|datadog|ddtrace|dd-trace|newrelic|prom-client|"
                          r"micrometer|aws_embedded_metrics|cloudwatch|['\"`]/metrics\b")
ERROR_TRACKING_HINT = re.compile(r"(?i)sentry|rollbar|bugsnag|raygun|airbrake|honeybadger|appsignal|newrelic|ddtrace|"
                                 r"dd-trace|elastic-apm|elasticapm|opentelemetry|errorreporting|"
                                 r"google\.cloud\.error_reporting|applicationinsights|logrocket|highlight\.io")
TRACING_HINT = re.compile(r"(?i)opentelemetry|ddtrace|dd-trace|newrelic|honeycomb|elastic-apm|elasticapm|aws_xray|"
                          r"aws-xray|zipkin|jaeger|traces_sample_rate|tracesSampleRate|applicationinsights|"
                          r"cloud-trace|google\.cloud\.trace")
REQUEST_ID_HINT = re.compile(r"(?i)request[-_]?id|correlation[-_]?id|traceparent|trace_id|x-amzn-trace-id|"
                             r"opentelemetry|asgi[-_]correlation|express-request-id|cls-rtracer")
LOGGER_HINT = re.compile(r"(?i)\b(winston|pino|bunyan|log4js|loglevel|signale|consola|tslog|@nestjs/common)\b")
PY_LOGGING = re.compile(r"^\s*(import logging|from logging|import structlog|from loguru)", re.M)
TEXT_LOGGING = re.compile(r"(?im)^\s*(?:import logging|from logging import|from loguru import)|"
                          r"\b(?:winston|log4js|loglevel|signale|consola|tslog)\b")
STRUCTURED_LOG_HINT = re.compile(
    r"(?i)structlog|python-json-logger|pythonjsonlogger|json_log_formatter|jsonlogger|JsonFormatter|ecs[-_]logging|"
    r"logstash|serialize\s*=\s*True|google\.cloud\.logging|watchtower|\bpino\b|\bbunyan\b|format\.json\(|"
    r"ecs-winston|@elastic/ecs|logfmt|JSONRenderer|json_logs|ExtraAdder|EventRenamer")
AUTH_HINT = re.compile(r"(?i)login_required|flask_login|flask-login|current_user|passport|next-auth|@auth/|"
                       r"django\.contrib\.auth|jsonwebtoken|\bpyjwt\b|\bjwt\.(?:encode|sign)|bcrypt|argon2|"
                       r"LoginManager|OAuth2PasswordBearer|auth0|@clerk/|supabase\.auth|firebase-admin|"
                       r"authenticate\(|check_password|verify_password")
AUDIT_HINT = re.compile(r"(?i)audit|simple_history|django-simple-history|reversion|paper_?trail|activity_?log|"
                        r"security_?log|security_?event|ActivityLog|event_?store")
JOB_FRAMEWORK = re.compile(
    r"(?m)^\s*(?:from|import)\s+(celery|rq|dramatiq|huey|arq|apscheduler|django_q|taskiq)\b|"
    r"""(?:require\(\s*|from\s+)['"](bull|bullmq|bee-queue|agenda|node-cron|node-schedule|kue|graphile-worker|"""
    r"""pg-boss|@nestjs/bull|@nestjs/bullmq|@nestjs/schedule|inngest|@trigger\.dev/sdk)['"]""")
JOB_MONITOR_HINT = re.compile(
    r"(?i)flower|task_failure|task_retry|on_failure|celery[-_]exporter|sentry|rq[-_]dashboard|failure_callback|"
    r"bull-board|@bull-board|bull-arena|\.on\(\s*['\"](?:failed|error)['\"]|OnQueueFailed|OnWorkerEvent|"
    r"dead[-_ ]?letter|cronitor|healthchecks\.io|hc-ping\.com|opentelemetry|prometheus|datadog|ddtrace|newrelic|"
    r"EVENT_JOB_ERROR|add_listener|on_job_failure|failure_ttl")
ROUTE_HINT = re.compile(r"@\w+\.(route|get|post|put|patch|delete)\(|\b(app|router)\.(get|post|put|patch|delete)\(")
PY_PRINT = re.compile(r"^\s*print\(")
JS_CONSOLE = re.compile(r"\bconsole\.(log|error|warn|info)\(")


@register
class ObservabilityAnalyzer(Analyzer):
    name = "observability"
    title = "Observability (logging, errors, tracing, metrics, audit, jobs)"
    categories = (Category.DEVOPS,)

    def run(self, ctx: AnalyzerContext):
        code_files = [f for f in ctx.files if f.endswith(CODE_SUFFIXES) and not is_test_path(f)
                      and "node_modules/" not in f][:MAX_CODE_FILES]
        texts = {f: ctx.read(f) or "" for f in code_files}
        manifests = ctx.files_named(*MANIFESTS)
        corpus = "\n".join([*texts.values(), *(ctx.read(f) or "" for f in manifests)])
        out = []
        source_py = [f for f in code_files if f.endswith(".py")]
        if len(source_py) >= 5 and not any(PY_LOGGING.search(texts[f]) for f in source_py):
            out.append(self._f(ctx, "devops.no-logging", "No logging framework usage detected (Python)",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "None of the Python source files import logging/structlog/loguru. Production "
                               "incidents are hard to diagnose without structured logs.",
                               "Adopt structured logging with levels and request correlation IDs."))
        if set(ctx.languages.frameworks) & WEB_FRAMEWORKS:
            out += self._web_service(ctx, texts, corpus)
        out += self._jobs(ctx, texts, corpus)
        return out

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, file_path="", line=None, evidence=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.DEVOPS, severity=sev, confidence=conf,
                            kind=kind, description=desc, remediation=fix, file_path=file_path, line=line,
                            evidence=evidence)

    def _web_service(self, ctx, texts: dict[str, str], corpus: str):
        out = []
        if not any(HEALTH_ROUTE.search(t) for t in texts.values()):
            out.append(self._f(ctx, "devops.no-health-endpoint", "No health-check endpoint detected",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "A web framework is used but no /health, /healthz, /ready or similar route was found. "
                               "Load balancers and orchestrators need one to route traffic safely.",
                               "Expose a cheap liveness endpoint and a readiness endpoint that checks critical "
                               "dependencies."))
        if not METRICS_HINT.search(corpus):
            out.append(self._f(ctx, "devops.no-metrics", "No application metrics instrumentation detected",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "No metrics library (Prometheus client, OpenTelemetry, StatsD, Datadog, …) or /metrics "
                               "endpoint was found. Without request rate, error rate and latency metrics, "
                               "regressions and capacity problems are noticed by users first.",
                               "Export RED metrics (rate, errors, duration) per endpoint, e.g. with prometheus-client "
                               "/ prom-client or OpenTelemetry, and alert on them."))
        if not ERROR_TRACKING_HINT.search(corpus):
            out.append(self._f(ctx, "devops.no-error-tracking", "No error tracking detected",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "No error tracker (Sentry, Rollbar, Bugsnag, Honeybadger, an APM agent, …) was found. "
                               "Unhandled exceptions are only visible if someone happens to read the logs, and "
                               "there is no grouping, alerting or release tracking of errors.",
                               "Add an error tracker (e.g. sentry-sdk / @sentry/node) with the release and "
                               "environment set, and alert on new error groups."))
        if not TRACING_HINT.search(corpus):
            out.append(self._f(ctx, "devops.no-tracing", "No distributed tracing detected",
                               Severity.INFO, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "No tracer (OpenTelemetry, Datadog APM, New Relic, Honeycomb, X-Ray, …) was found. Slow "
                               "requests cannot be broken down into database, cache and downstream-service time, "
                               "or followed across services.",
                               "Instrument the service with OpenTelemetry (auto-instrumentation covers the web "
                               "framework, HTTP clients and database drivers) and export traces to a backend."))
        if not REQUEST_ID_HINT.search(corpus):
            out.append(self._f(ctx, "devops.no-request-id", "No request/correlation id propagation detected",
                               Severity.INFO, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "No request id, correlation id, or trace context handling was found, so log lines from "
                               "one request cannot be tied together or matched to a user's error report.",
                               "Assign or accept an X-Request-ID per request, add it to every log line, and return "
                               "it in error responses."))
        if TEXT_LOGGING.search(corpus) and not STRUCTURED_LOG_HINT.search(corpus):
            out.append(self._f(ctx, "devops.unstructured-logging", "Logs are plain text, not structured",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "A logger is used, but no JSON/structured formatter was found (structlog, "
                               "python-json-logger, pino, winston format.json, …). Plain-text lines cannot be "
                               "reliably filtered by field (user, request id, status) in a log platform.",
                               "Emit one JSON object per log line with timestamp, level, logger, message, request "
                               "id and relevant context fields."))
        out += self._print_logging(ctx, texts, corpus)
        if AUTH_HINT.search(corpus) and not AUDIT_HINT.search(corpus):
            out.append(self._f(ctx, "devops.no-audit-log", "No audit logging of security-relevant actions detected",
                               Severity.LOW, Confidence.LOW, FindingKind.POTENTIAL,
                               "The application authenticates users, but nothing that records an audit trail was "
                               "found (audit log table/model, audit logger, django-simple-history, …). Logins, "
                               "permission changes, data exports and deletions cannot be reconstructed after an "
                               "incident or for a compliance review.",
                               "Write an append-only audit record (who, what, when, from where, outcome) for "
                               "authentication events, privilege changes and sensitive data access, kept separately "
                               "from debug logs and retained per policy."))
        return out

    def _print_logging(self, ctx, texts: dict[str, str], corpus: str):
        out = []
        logger_lib = LOGGER_HINT.search(corpus)
        for rel, text in texts.items():
            if not ROUTE_HINT.search(text):
                continue
            pattern = PY_PRINT if rel.endswith(".py") else None if logger_lib else JS_CONSOLE
            line = next((i for i, ln in enumerate(text.splitlines(), 1) if pattern and pattern.search(ln)), None)
            if line:
                out.append(self._f(ctx, "devops.print-logging", "Server code logs with print/console instead of a "
                                   "logger", Severity.LOW, Confidence.MEDIUM, FindingKind.CONFIRMED,
                                   "Output from print()/console.log has no level, timestamp, logger name or request "
                                   "context, cannot be filtered or routed, and is easily lost in production.",
                                   "Use a structured logger (logging/structlog, pino/winston) with levels and a "
                                   "request id.", rel, line))
        return out

    def _jobs(self, ctx, texts: dict[str, str], corpus: str):
        """Background jobs fail silently unless someone watches failures, retries and queue depth."""
        found = next(((rel, m) for rel, text in texts.items() if (m := JOB_FRAMEWORK.search(text))), None)
        if not found or JOB_MONITOR_HINT.search(corpus):
            return []
        rel, m = found
        lib = m.group(1) or m.group(2)
        line = texts[rel].count("\n", 0, m.start()) + 1
        return [self._f(ctx, "devops.no-job-monitoring", f"Background jobs ({lib}) without failure monitoring",
                        Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                        f"The project runs background jobs with {lib}, but no failure handler, job dashboard, "
                        "error tracker or metrics exporter was found. Failed, stuck or endlessly retrying jobs go "
                        "unnoticed until a user reports missing emails, payments or reports.",
                        "Report job failures to the error tracker (or a failure signal/event handler), export queue "
                        "depth, failure and latency metrics (e.g. Flower/celery-exporter, bull-board, Prometheus), "
                        "and use a heartbeat check for scheduled jobs.", rel, line)]
