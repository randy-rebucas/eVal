# eVal Architecture

> **eVal — electronic validator.** AI generates code. eVal verifies it.

eVal is a multi-tenant SaaS that audits source repositories for production readiness.
It ingests code (GitHub or ZIP upload), inspects it **without executing it**, runs
deterministic analyzers first, optionally layers AI-assisted explanation on top, and
produces evidence-backed findings with transparent, reproducible scores.

## 1. High-level components

```
                 ┌──────────────────────────── eval_app (Flask) ────────────────────────────┐
 Browser ──────► │ auth · orgs · projects · audits · findings · reports · integrations · api │
 API client ───► │        (routes → services → models; tenancy enforced in services)        │
                 └───────────────┬──────────────────────────────────────┬───────────────────┘
                                 │ SQLAlchemy                           │ Celery (Redis broker)
                          ┌──────▼──────┐                        ┌──────▼──────────────────┐
                          │ PostgreSQL  │◄───── results ─────────│ worker: run_audit task  │
                          └─────────────┘                        │  uses eval_engine       │
                                                                 └──────┬──────────────────┘
                                                                        │ pure Python, no Flask
                 ┌──────────────────────────── eval_engine ─────────▼────────────────────────┐
                 │ workspace (safe ZIP / git) → languages → analyzers (registry) → normalize   │
                 │ → fingerprint/dedupe → scoring → (optional) AI enrichment → reports         │
                 └─────────────────────────────────────────────────────────────────────────────┘
```

Two top-level Python packages:

| Package | Depends on Flask? | Responsibility |
|---|---|---|
| `eval_engine` | **No** | Analysis engine: workspace handling, language detection, analyzer registry and analyzers, finding model, fingerprinting, deduplication, scoring, AI provider abstraction, report rendering, CLI (`eval-audit`). Can be extracted into a standalone package. |
| `eval_app` | Yes | SaaS layer: users, organizations, RBAC, projects, repositories, audit orchestration, Celery tasks, GitHub integration, credential storage, dashboard, JSON API. |

The engine's public entry point is `eval_engine.pipeline.run_pipeline(path, config) -> AuditResult`.
The web app never imports analyzer internals; it calls the pipeline and persists the result.

## 2. Package layout

```
eval_engine/
  findings.py        Finding / Evidence / Severity / Category / Confidence / FindingKind dataclasses
  workspace.py       Safe ZIP extraction, safe git clone, file walking with limits
  languages.py       Extension/manifest-based language + framework detection
  redaction.py       Secret redaction for logs, evidence, and AI prompts
  sandbox.py         Subprocess runner: argv-only, timeouts, env scrubbing, output caps, rlimits (POSIX)
  fingerprint.py     Stable finding fingerprints (rule + path + normalized snippet)
  dedupe.py          Within-audit dedupe + cross-audit diff (new/existing/resolved/recurring)
  scoring.py         Documented severity weights → category scores → risk level
  pipeline.py        Orchestrates the stages and reports progress via callback
  reports.py         JSON, Markdown, HTML, SARIF 2.1.0 renderers
  cli.py             `eval-audit PATH` — offline audit without the web app
  analyzers/
    base.py          Analyzer interface + AnalyzerContext + AnalyzerOutcome
    registry.py      Registration and selection by language / availability
    ruff.py, bandit.py, mypy_.py, eslint.py, tsc.py, semgrep.py, trivy.py   (external tools)
    secrets.py, devops.py, testing.py, database.py, api_security.py,
    dependencies.py, maintainability.py, architecture.py, performance.py,
    configuration.py, taint.py, ai_code.py                                  (built-in)
  ai/
    base.py          AIProvider protocol, AIRequest/AIResponse
    anthropic_provider.py, openai_provider.py   official SDKs; OpenAI-compatible local endpoints via base_url
    prompts/         Versioned prompt templates (filename carries version)
    enrich.py        Prompt construction, injection hardening, strict JSON validation

eval_app/
  __init__.py        create_app() factory
  config.py          Environment-driven config classes
  extensions.py      db, migrate, login_manager, csrf
  models.py          SQLAlchemy models (see §4)
  security/          crypto (Fernet), tenancy helpers, RBAC decorators, rate limiting, audit events
  auth/              register / login / logout, API tokens
  orgs/              organizations, memberships, invites
  projects/          projects, repositories, uploads
  audits/            audit creation, status, progress, comparison; Celery tasks
  findings/          finding detail, triage + risk register, comparisons, report models, PR summaries, GitHub issues
  integrations/      GitHub client, credential management, AI settings and API token pages
  api/               JSON API (/api/v1) with bearer tokens
  ai_config.py       per-org AI settings -> Enricher for the worker
  templates/, static/
  celery_app.py      Celery app bound to Flask config
```

## 3. Audit pipeline

```
Repository Input → Secure Repository Inspection → Language Detection → Static Analysis
→ AI-Assisted Analysis (optional) → Finding Validation & Deduplication → Deterministic Scoring
→ Report Generation → Remediation (human-approved GitHub Issues; never auto-modify code)
```

| Stage | Module | Notes |
|---|---|---|
| Input | `eval_app.audits.services` | ZIP stored in tenant-scoped upload dir; GitHub repos cloned at a pinned commit. |
| Secure inspection | `workspace.py` | ZIP: rejects absolute paths, `..`, symlinks, device files; enforces file count, total and per-file size, compression ratio (zip bomb). Git: `https://` only, host allow-list, `--depth`, no submodules, hooks disabled, `core.symlinks=false`, credential passed as env-scoped git config (`GIT_CONFIG_*`), never in argv, the URL, or logs. |
| Language detection | `languages.py` | Extension counts + manifests (`package.json`, `pyproject.toml`, `requirements*.txt`, `go.mod`, ...). Frameworks detected from manifest dependencies. |
| Static analysis | `analyzers/*` | External tools are invoked via `sandbox.run()` with argv lists (no shell), timeouts, scrubbed env, and output caps. Missing tools produce an `AnalyzerOutcome(status="skipped", reason=...)` that is surfaced in the report — never a silent pass. Repository code is never imported or executed: built-in analyzers parse with `ast`/regex only. |
| AI analysis | `ai/enrich.py` | Optional per org. Only sends redacted snippets of already-detected findings plus a repository summary. Repository content is wrapped in delimiters and declared untrusted; responses must be strict JSON matching a schema or are discarded. AI output can *explain* and *suggest remediation*; it **cannot** create findings that affect scores — AI-proposed observations are stored with `kind=ai_observation`, `confidence=low`, and excluded from scoring. |
| Validation & dedupe | `dedupe.py`, `fingerprint.py` | Findings must reference a path that exists inside the workspace; line numbers are bounds-checked. Duplicates (same fingerprint, or same rule family+location from different tools) are merged, preserving all sources. |
| Scoring | `scoring.py` | Deterministic, documented in `docs/SCORING.md`. |
| Reports | `reports.py` | JSON, Markdown, HTML, SARIF. |
| Remediation | `eval_app.findings` | User selects findings → GitHub Issues created with the user's stored token. No code is modified. |

Progress is reported through a callback `(stage, percent, message)` that the Celery task
persists to `audits.progress` / `audits.stage` so the UI can poll.

## 4. Data model

All tenant-owned tables carry `organization_id` (FK, indexed, NOT NULL) even where it could be
derived through a join. This makes tenancy checks a single predicate and allows a future
PostgreSQL Row Level Security policy of the form
`USING (organization_id = current_setting('eval.org_id')::uuid)`.

```
users ──< memberships >── organizations ──< projects ──< repositories ──< audits ──< findings
                              │                │                            │
                              │                └──< github_issue_links >────┘ (finding ↔ issue)
                              ├──< integration_credentials (encrypted)
                              ├──< ai_settings (1:1)
                              ├──< api_tokens (hashed, per user per org)
                              └──< audit_events (security audit log)
rules (global catalogue, keyed by rule_id) ──< findings.rule_id
findings are per-audit; `fingerprint` links occurrences of the same problem across audits
```

| Table | Key columns |
|---|---|
| `users` | id (uuid), email (unique, lowercased), password_hash (scrypt), is_active, created_at |
| `organizations` | id, name, slug (unique) |
| `memberships` | user_id, organization_id, role ∈ {owner, admin, member, viewer}; unique(user, org) |
| `projects` | id, organization_id, name, slug; unique(org, slug) |
| `repositories` | id, organization_id, project_id, source ∈ {github, upload}, full_name, default_branch, credential_id (nullable) |
| `uploads` | id, organization_id, repository_id, stored_path, sha256, size_bytes |
| `audits` | id, organization_id, repository_id, upload_id, branch, commit_sha, trigger, pr_number, pr_base_ref, changed_files, status, stage, progress, error, scores (JSON), risk_level, overall_score, tool_status (JSON), ai_summary, engine_version, started/finished_at, previous_audit_id (lifecycle baseline) |
| `findings` | id, organization_id, audit_id, rule_id, fingerprint, category, severity, confidence, kind (confirmed/potential/ai_observation/estimate), title, description, file_path, line_start, line_end, evidence (redacted snippet), remediation, sources (JSON), lifecycle ∈ {new, existing, recurring}, triage_status ∈ {open, accepted_risk, false_positive, fixed}, triage_reason, triage_owner (team or vendor), triage_expires_on, triaged_by_id, triaged_at, ai_explanation (JSON) |
| `resolved_findings` | per-audit record of fingerprints present in the previous audit but absent now |
| `rules` | rule_id (pk), title, category, default_severity, description, references |
| `integration_credentials` | id, organization_id, provider, label, encrypted_secret (Fernet), last4, created_by |
| `github_issue_links` | id, organization_id, finding_fingerprint, repository_id, issue_number, issue_url |
| `ai_settings` | organization_id, provider, model, enabled, credential_id |
| `api_tokens` | id, organization_id, user_id, token_hash (sha256), prefix, last_used_at, revoked_at |
| `audit_events` | organization_id, actor_id, action, target_type, target_id, ip, created_at |

## 5. Security model (summary — see `docs/SECURITY.md`)

* **Untrusted input everywhere**: uploaded archives, cloned repos, analyzer output, AI output.
* **No code execution** of the audited repository. External analyzers are static tools run on a copy.
* **Subprocess hygiene**: argv lists only (`shell=False`), fixed executable allow-list, per-call timeout,
  scrubbed environment (no app secrets), output size caps, POSIX `RLIMIT_AS/CPU/NOFILE/FSIZE`.
  In Docker the worker runs as non-root with a read-only root filesystem and tmpfs work dir.
* **Tenancy**: every protected route resolves the organization from the URL, checks membership and role,
  and every query for tenant data filters by `organization_id`. Cross-tenant IDs return 404, not 403.
* **Credentials**: Fernet (AES-128-CBC + HMAC-SHA256) with `MultiFernet` key rotation; only the last 4
  characters are ever shown; secrets never written to logs, audit events, or templates.
* **AI**: secret redaction before prompts, untrusted-content delimiters, schema-validated JSON output,
  AI cannot alter scores.
* **Web**: CSRF on all forms, secure session cookies, CSP and standard security headers, rate-limited login.

## 6. Extensibility

* **Analyzers** register with `@register` and declare `languages`, `categories`, and `requires_tool`.
* **AI providers** implement `AIProvider.complete_json()`; selected per organization.
* **Report formats** are pure functions over `AuditResult`.
* Future: PR audits (diff-scoped pipeline using the same engine with `changed_files` filter), CI
  integration (`eval-audit --fail-on high` exits non-zero), knowledge graph (import graph already
  computed by `architecture.py`), fix PRs (would require explicit approval flow — not implemented),
  org policies (severity overrides / rule disables — not implemented; see ROADMAP.md).
