# eVal — electronic validator

**AI generates code. eVal verifies it.**

eVal is a multi-tenant SaaS that audits applications for production readiness. Connect a GitHub repository or
upload a ZIP, run an asynchronous audit, and get evidence-backed findings across security, architecture,
testing, databases, APIs, dependencies, performance, DevOps and maintainability — with transparent scores,
audit history, PR-level gating, GitHub issues and optional AI-assisted explanations.

eVal never executes the code it audits, and it never claims an application is secure: scores are risk
indicators, and categories it could not assess are shown as *not assessed*.

| Doc | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, pipeline, data model |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, controls, known gaps |
| [docs/SCORING.md](docs/SCORING.md) | severity weights, ceilings, risk thresholds, lifecycle |
| [docs/API.md](docs/API.md) | JSON API and web routes |
| [docs/CI.md](docs/CI.md) | GitHub Actions / CI gating, CLI |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what is done, what is not |

## Features

- Users, organizations, roles (viewer/member/admin/owner), projects, tenant isolation on every query
- GitHub repositories (public, or private via encrypted tokens) with branch/commit selection; ZIP uploads
- Asynchronous audits on Celery + Redis with live progress and cancellation
- 17 analyzers: Ruff, Bandit, mypy, ESLint, TypeScript, Semgrep, Trivy, OSV.dev, and built-in checks for
  secrets, API security, database access, DevOps/CI, testing, dependencies, maintainability, architecture
  (import cycles) and performance (static estimates). Missing tools are reported, never silently skipped.
- Findings with evidence, location, severity, confidence, type (confirmed / potential / estimate / AI), and
  remediation; cross-tool deduplication and stable fingerprints
- Deterministic, documented scoring; new / existing / recurring / resolved tracking; commit comparison
- Triage (false positive / accepted risk carry over), GitHub issue creation, HTML/Markdown/JSON/SARIF exports
- Pull-request audits that gate only on findings introduced in changed files; CI script and offline CLI
- Optional AI (Anthropic Claude, OpenAI, OpenAI-compatible local models) for explanations and remediation —
  redacted inputs, validated outputs, never affects scores

## Quick start (Docker)

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"                  # -> EVAL_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # -> EVAL_ENCRYPTION_KEYS
# also set POSTGRES_PASSWORD (and use it in DATABASE_URL only if you run outside compose)
docker compose up -d --build
docker compose exec web flask create-user you@example.com --org "My Company"   # or register in the UI
```

Open http://127.0.0.1:8000. Compose runs `postgres`, `redis`, a one-shot `migrate`, `web` (gunicorn) and a
hardened `worker` (read-only rootfs, dropped capabilities, resource limits). The image includes Ruff, Bandit,
mypy, Semgrep, ESLint, TypeScript and Trivy (toggle with build args `INSTALL_SEMGREP`, `INSTALL_NODE_TOOLS`,
`INSTALL_TRIVY`). Semgrep (`p/default` rules), Trivy (vulnerability DB) and OSV.dev need outbound network
access; see Configuration for offline options.

## Local development

Requires Python 3.12+, Docker (for Postgres/Redis), git.

```bash
python3.12 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,ai]"
cp .env.example .env    # fill in secrets; set EVAL_ENV=development, EVAL_SECURE_COOKIES=false
docker compose up -d postgres redis                      # 127.0.0.1:55450 and :56390
flask --app wsgi db upgrade
flask --app wsgi run --port 5000                         # web
celery -A eval_app.celery_worker:celery worker -Q audits --loglevel=INFO   # add --pool=solo on Windows
```

`.env` is loaded automatically by `flask`, `wsgi.py` and the worker (real environment variables win).
Set `CELERY_TASK_ALWAYS_EAGER=true` to run audits inline without a worker (development only).
Optional JS/TS tools without a global install: `npm install --prefix .tools eslint@9 typescript@5` and set
`EVAL_TOOL_PATH=<repo>/.tools/node_modules/.bin`.

## Testing and linting

```bash
pytest                                  # SQLite in-memory; ~190 tests, ~30 s
TEST_DATABASE_URL=postgresql+psycopg://eval:...@127.0.0.1:55450/eval_test pytest   # against PostgreSQL
ruff check .
bandit -r eval_app eval_engine scripts -c pyproject.toml
flask --app wsgi db check               # models and migrations in sync
```

Tests never call external services: GitHub and AI providers are faked, OSV is disabled (`EVAL_OSV_ENABLED=0`).
Tool-backed analyzer tests are skipped when the tool is not installed. Fixture repositories with deliberate
issues live in `tests/fixtures/` (excluded from linting and test collection).

## Using eVal

1. Create a project, then **Add repository**: connect `owner/repo` (add a GitHub token under *Integrations* for
   private repos and issue creation) or upload a ZIP.
2. Pick a branch or commit and **Run audit**, or **Audit PR** by number.
3. Review the dashboard: overall and category scores, coverage, findings with evidence; filter, triage,
   compare with earlier audits, export, or create GitHub issues.
4. Optional: enable AI under *Integrations → AI-assisted analysis* with an Anthropic/OpenAI key.
5. CI: create an API token and use `scripts/eval_ci.py` (see docs/CI.md).

Offline / without the server:

```bash
eval-audit path/to/repo --format md --output report.md --fail-on high
```

## Configuration

All configuration is via environment variables (`.env.example` documents each). Key ones:

| Variable | Purpose |
|---|---|
| `EVAL_SECRET_KEY` | session signing (≥ 32 chars, required) |
| `EVAL_ENCRYPTION_KEYS` | comma-separated Fernet keys for stored credentials; first encrypts (rotation) |
| `DATABASE_URL`, `REDIS_URL` | PostgreSQL and Redis |
| `EVAL_GIT_ALLOWED_HOSTS` | hosts that may be cloned (default `github.com`) |
| `EVAL_WORKSPACE_MAX_*`, `EVAL_MAX_UPLOAD_MB`, `EVAL_ANALYZER_TIMEOUT_SECONDS` | resource limits |
| `EVAL_OSV_ENABLED` | dependency vulnerability lookup via OSV.dev (sends package names/versions only) |
| `EVAL_SEMGREP_CONFIG` | Semgrep rules (registry pack or local path for air-gapped installs) |
| `EVAL_TRIVY_CACHE_DIR` | persistent Trivy DB cache |
| `EVAL_AI_ALLOWED_BASE_URLS` | allow-list for OpenAI-compatible endpoints (local models) |
| `EVAL_TOOL_PATH` | extra directories searched for analyzer binaries |

## Deployment notes

- Run behind TLS; keep `EVAL_SECURE_COOKIES=true`. Put the worker on a separate host/node pool from the web tier
  where possible, ideally under gVisor/Kata (see docs/SECURITY.md).
- Back up PostgreSQL and the `/data` volume (uploads). Rotate `EVAL_ENCRYPTION_KEYS` by prepending a new key.
- Scale workers horizontally (`docker compose up --scale worker=N`); each handles `--concurrency` audits.
- Migrations: `flask db upgrade` (run by the `migrate` service on deploy).

## Repository layout

```
eval_engine/   analysis engine (no Flask): workspace, sandbox, analyzers, scoring, reports, AI, CLI
eval_app/      Flask SaaS: auth, orgs, projects, audits (Celery), findings, integrations, API, templates
migrations/    Alembic migrations
scripts/       eval_ci.py (CI gate)
tests/         engine + app tests, fixture repositories
docs/          architecture, security, scoring, API, CI, roadmap
```
