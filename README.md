# eVal — electronic validator

**AI generates code. eVal verifies it.**

eVal is a multi-tenant SaaS that audits applications for production readiness. Connect a GitHub repository or
upload a ZIP, run an asynchronous audit, and get evidence-backed findings across security, architecture,
testing, databases, APIs, dependencies, performance, DevOps and maintainability — with transparent scores,
audit history, PR-level gating, GitHub issues and optional AI-assisted explanations.

AI can generate software; eVal verifies that the software is actually engineered correctly. Beyond classic
vulnerabilities, it looks for the engineering gaps generated code tends to leave: authorization flaws, poor error
handling, weak database design, scalability traps, missing observability and undocumented assumptions (see the
concern-to-check map in [PRODUCT.md](PRODUCT.md#vision)).

eVal never executes the code it audits, and it never claims an application is secure: scores are risk
indicators, and categories it could not assess are shown as *not assessed*.

| Doc | Contents |
|---|---|
| [docs/PROJECT.md](docs/PROJECT.md) | project description: eVal Local, the problem, how the AI runs on-device |
| [docs/TECHNOLOGY.md](docs/TECHNOLOGY.md) | AI models, frameworks, libraries, tools, APIs and assets, with licenses |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, pipeline, data model |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, controls, known gaps |
| [docs/SCORING.md](docs/SCORING.md) | severity weights, ceilings, risk thresholds, lifecycle |
| [docs/API.md](docs/API.md) | JSON API and web routes |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | installing the CLI, deploying the server, backups, upgrades, air-gapped |
| [docs/RENDER.md](docs/RENDER.md) | step-by-step: deploy eVal on Render with the Blueprint |
| [docs/CI.md](docs/CI.md) | GitHub Actions / CI gating, CLI |
| [docs/IDE_PUBLISH.md](docs/IDE_PUBLISH.md) | step-by-step: publish the VS Code extension to the Marketplace and Open VSX |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what is done, what is not |
| [docs/LOCAL_AI.md](docs/LOCAL_AI.md) | eVal Local: on-device AI auditing plan |
| [docs/NETWORK.md](docs/NETWORK.md) | what runs locally, what needs the internet, and what is sent |

## Features

- Users, organizations, roles (viewer/member/admin/owner), projects, tenant isolation on every query
- GitHub repositories (public, or private via encrypted tokens) with branch/commit selection; ZIP uploads
- Asynchronous audits on Celery + Redis with live progress and cancellation
- 21 analyzers: Ruff, Bandit, mypy, ESLint, TypeScript, Semgrep, Trivy, OSV.dev, PyPI/npm registry checks, and
  built-in checks for secrets, API security (including object-level authorization/IDOR, error disclosure, cookie
  flags, credentials in logs, upload validation and rate limiting on login routes),
  database access and schema design, DevOps/CI and observability (metrics, tracing, request ids, logging),
  testing, dependencies, maintainability (including swallowed errors), architecture (import cycles), performance
  and scalability (static estimates), **configuration assumptions** (undocumented environment variables,
  hardcoded local endpoints and paths, APIs without an OpenAPI contract), **taint analysis** (request data
  reaching SQL, shell, eval, file paths, upload destinations, pickle/YAML deserialization, outbound URLs,
  templates, redirects) and **AI-generated-code patterns**
  (hallucinated or lookalike packages, undeclared imports, stubs, placeholders, tests that cannot fail). Missing
  tools are reported, never silently skipped.
- Findings with evidence, location, severity, confidence, type (confirmed / potential / estimate / AI), and
  remediation; cross-tool deduplication and stable fingerprints; import **reachability** for vulnerable
  dependencies (imported / declared but unused / transitive)
- Deterministic, documented scoring; new / existing / recurring / resolved tracking; commit comparison
- **Policies as code**: organization default ← repository override ← `.eval.toml`, with excluded paths, disabled
  rules and analyzers, severity overrides, per-path gate thresholds and required analyzers
- Triage with accountability: accepted risks need a reason, an owner (team or vendor, e.g. for third-party
  code) and a review date, carry over to later audits, and reopen when the date passes; an org-wide risk
  register lists them by review date. GitHub issue creation, HTML/Markdown/JSON/SARIF exports
- **Compliance mapping** (CWE, OWASP Top 10, ASVS, SOC 2, ISO 27001) in every report and SARIF tag, and an
  auditor-ready **evidence pack** (reports, CSVs, risk register, decision log, policy, SHA-256 manifest)
- Pull-request audits that gate only on findings introduced in changed files, with a **change-risk score**
  (size, sensitive areas, untested code, introduced findings); CI script and offline CLI
- **GitHub App**: webhook-driven PR audits, check runs with inline annotations, default-branch re-audits on push,
  short-lived installation tokens instead of personal access tokens
- **Scheduled re-audits** (daily/weekly) and **regression alerts** to Slack, Teams or signed webhooks
- Optional AI (Anthropic Claude, OpenAI, OpenAI-compatible local models) for explanations and remediation —
  redacted inputs, validated outputs, never affects scores. **AI fix pull requests** are re-audited before they can
  be opened: the PR states whether every targeted finding is gone and nothing new was introduced
- **In the coding loop**: `eval-audit hook` (Claude Code PostToolUse hook that makes the agent fix what it just
  wrote), `eval-audit mcp` (MCP server for Claude Code, Cursor and other agents), `eval-audit --changed`
- **Enterprise identity**: TOTP two-factor authentication (org-wide requirement), OIDC single sign-on (Okta,
  Entra ID, Google Workspace) with enforcement, SCIM 2.0 provisioning, searchable and exportable audit log

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
pytest                                  # SQLite in-memory; ~430 tests, ~90 s
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
6. Editor: the VS Code extension in `ide/vscode` shows open findings as diagnostics, runs audits of the current
   branch and records triage decisions with the same API token (see [ide/vscode/README.md](ide/vscode/README.md)).

### Dependency findings and suggested fixes

eVal checks dependency manifests and lockfiles without installing packages or executing repository code.
The built-in hygiene checks flag unpinned Python requirements, Python projects without a lockfile, JavaScript
projects without a lockfile, VCS/URL requirements, and wildcard or non-registry JavaScript version specifiers.
For known vulnerabilities, OSV.dev checks exact package versions collected from `requirements*.txt`,
`poetry.lock`, `uv.lock`, and `package-lock.json`. It sends only ecosystem, package name, and version to OSV.dev;
set `EVAL_OSV_ENABLED=0` to disable this lookup. Trivy can provide an additional filesystem scan for
vulnerabilities when installed and enabled on the worker.

Each finding includes its source file, evidence such as the affected package and pinned version, an advisory
reference when available, and a remediation recommendation. When an advisory publishes a fixed version, the
recommendation identifies it; otherwise it advises assessing exposure, applying mitigations, or replacing the
package. The scanner does **not** build a runtime dependency/call graph or determine whether vulnerable code is
reachable, so review the finding and advisory before changing versions. Keep the manifest and lockfile in sync
when upgrading; use a trusted fixed release, then run your tests and audit again.

When the dependency belongs to another team or a vendor and cannot be upgraded right away (for example a
transitive dependency of a third-party SDK), first try pinning the fixed version yourself (npm `overrides`, pip
constraints). If that is not possible, mark the finding **accepted risk** with the reason (and any mitigation), the
owning team or vendor, and a review date. The decision carries over to later audits, appears in the **Risk
register**, and the finding reopens on the review date so it cannot be forgotten.

If AI-assisted analysis is enabled, it can add finding-specific remediation steps and an illustrative patch.
These suggestions are AI-generated and must be reviewed before use. eVal never applies patches or opens a fix
pull request automatically.

Offline / without the server:

```bash
eval-audit path/to/repo --format md --output report.md --fail-on high
```

### Local AI (on-device, no cloud API)

The CLI can explain findings with a model running on your own machine. No API key is needed, and findings
plus redacted evidence never leave the device (`--ai local` accepts loopback endpoints only).

```bash
ollama pull qwen2.5-coder:7b                     # or any OpenAI-compatible local server (LM Studio, llama.cpp)
eval-audit doctor                                # analyzers, model server, offline readiness
eval-audit path/to/repo --ai local --offline --format html -o report.html
eval-audit path/to/repo --ai local --ai-model llama3.1:8b --ai-url http://localhost:1234/v1
```

`--offline` skips checks that need the network (OSV.dev; Semgrep registry rules; Trivy without a pre-seeded
cache), reports them as *not assessed*, and blocks outbound connections from eVal; the report states how many
were blocked. If the model server is not running, the audit still completes and the report says why AI is
missing. AI output never changes scores. See [docs/LOCAL_AI.md](docs/LOCAL_AI.md).

### Auto-fix

With AI enabled, select findings on an audit (or open one finding) and choose **Fix with AI**. eVal asks the model
for exact find/replace edits to the affected files (secrets masked), rejects any edit that does not match the code
exactly once, and shows the result as a diff. From there, **Download .patch** (`git apply`) or, for GitHub
repositories with a credential, **Open pull request**: eVal pushes a new `eval/fix-…` branch from the audited commit
and opens a PR against the audited branch. Nothing is pushed before you click, and eVal never runs the code. Run
your tests before merging.

Before you see the diff, eVal **re-audits the patched code**: it applies the patch to the audited commit, re-runs
the analyzers that worked in the original audit, and compares findings in the changed files. The verdict
(*verified*, *partially verified*, *regressed*, *incomplete*) is shown on the fix page and written into the pull
request. A fix that introduced new findings can only be opened after you confirm you reviewed them.

## Configuration

All configuration is via environment variables (`.env.example` documents each). Key ones:

| Variable | Purpose |
|---|---|
| `EVAL_SECRET_KEY` | session signing (≥ 32 chars, required) |
| `EVAL_ENCRYPTION_KEYS` | comma-separated Fernet keys for stored credentials; first encrypts (rotation) |
| `DATABASE_URL`, `REDIS_URL` | PostgreSQL and Redis |
| `EVAL_GIT_ALLOWED_HOSTS` | hosts that may be cloned (default `github.com`; add your GitHub Enterprise host) |
| `GITHUB_API_URL` | GitHub API; for Enterprise `https://HOST/api/v3` (repositories are then cloned from `HOST`) |
| `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth App behind the "Connect GitHub" button; callback URL `https://YOUR-HOST/integrations/github/callback` |
| `AUTH_GITHUB_*`, `AUTH_GOOGLE_*`, `AUTH_LINKEDIN_*` (`_CLIENT_ID`, `_CLIENT_SECRET`) | social sign-in; callback `https://YOUR-HOST/login/<provider>/callback`. GitHub falls back to the `GITHUB_OAUTH_*` app |
| `EVAL_PROXY_FIX_HOPS` | trusted reverse proxies in front of the app (set behind TLS termination) |
| `EVAL_LOGIN_RATE_LIMIT`, `EVAL_LOGIN_IP_RATE_LIMIT`, `EVAL_MAX_ORGS_PER_USER` | abuse limits |
| `EVAL_ACCEPTED_RISK_MAX_DAYS` | longest an accepted risk lasts before it reopens (default 365) |
| `EVAL_WORKSPACE_MAX_*`, `EVAL_MAX_UPLOAD_MB`, `EVAL_ANALYZER_TIMEOUT_SECONDS` | resource limits |
| `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_PRIVATE_KEY` (or `_FILE`), `GITHUB_APP_WEBHOOK_SECRET`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` | GitHub App for automatic PR audits and check runs (see [docs/CI.md](docs/CI.md#c-github-app-automatic-pull-request-checks)) |
| `EVAL_PUBLIC_URL` | public base URL, for links the worker builds (check runs, notifications) |
| `EVAL_OSV_ENABLED` | dependency vulnerability lookup via OSV.dev (sends package names/versions only) |
| `EVAL_REGISTRY_CHECK_ENABLED` | check that declared dependencies exist on PyPI/npm and are not brand new (sends package names only) |
| `EVAL_SEMGREP_CONFIG` | Semgrep rules (registry pack or local path for air-gapped installs) |
| `EVAL_TRIVY_CACHE_DIR` | persistent Trivy DB cache |
| `EVAL_AI_ALLOWED_BASE_URLS` | allow-list for OpenAI-compatible endpoints (local models) |
| `EVAL_TOOL_PATH` | extra directories searched for analyzer binaries |
| `EVAL_LOCAL_AI_MODEL`, `EVAL_LOCAL_AI_URL` | CLI defaults for `--ai local` (`qwen2.5-coder:7b`, `http://127.0.0.1:11434/v1`) |

## Deployment notes

Full guide: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). In short:

- Run behind TLS; keep `EVAL_SECURE_COOKIES=true` and set `EVAL_PROXY_FIX_HOPS` to the number of proxies. Put the worker on a separate host/node pool from the web tier
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
ide/vscode/    VS Code extension (TypeScript): findings as diagnostics, audits, triage via /api/v1
tests/         engine + app tests, fixture repositories
docs/          architecture, security, scoring, API, CI, roadmap
```
