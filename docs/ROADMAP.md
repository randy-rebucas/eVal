# Implementation status and roadmap

## Done (verified by tests and a live run)

| Phase | Scope |
|---|---|
| 1 | Flask app factory, env config with fail-fast validation, PostgreSQL models + Alembic migrations, auth (scrypt, rate limiting, fixation protection), organizations, roles, members, projects, Docker/Compose |
| 2 | ZIP uploads (streaming, hashed, hardened extraction), GitHub repositories (API lookup, branches, commits, private repos via encrypted tokens), hardened shallow clone, audit records, Celery + Redis task with progress, cancellation |
| 3 | Language/framework detection, 17 analyzers (Ruff, Bandit, mypy, ESLint, tsc, Semgrep, Trivy, OSV.dev, plus built-in secrets, API security, database, DevOps/CI, testing, dependencies, maintainability, architecture, performance), normalisation, validation, fingerprinting, cross-tool dedupe, deterministic scoring |
| 4 | Audit dashboard, finding detail + triage, audit history, trends, commit comparison, portfolio dashboard, HTML/Markdown/JSON/SARIF reports, `eval-audit` CLI, GitHub issue creation |
| 5 | AI provider abstraction (Anthropic, OpenAI, OpenAI-compatible/local), versioned prompts, injection-hardened enricher, per-org AI settings |
| 6 (partial) | JSON API + tokens, pull-request audits with base-branch baselines, opt-in PR comments, CI gate script and GitHub Actions example |
| 7 (partial) | eVal Local ([LOCAL_AI.md](LOCAL_AI.md)): `eval-audit --ai local` (loopback-only model server, proxies ignored), `--offline` with network guard, small-model batching and output retry, AI-assisted triage ordering in reports, `eval-audit doctor`. Open: real-model benchmarks, `eval-audit serve` |

Test suite: ~190 tests (unit + integration), run on SQLite and PostgreSQL.

## Not built yet (honest list)

**Product**
- **Automated fix pull requests.** Deliberately not implemented. A safe design needs: a human approval step per
  change, a generated branch + PR (never a push to the default branch), re-audit of the patched tree, and clear AI
  provenance. AI "suggested patches" are displayed only.
- **GitHub App + webhooks** (install-based access, automatic PR audits on `pull_request` events, check runs).
  Today: personal access tokens + the CI script.
- **Organization policies** (severity overrides, disabled rules, required analyzers, gate thresholds per repo).
- **Repository knowledge graph.** The import graph is computed (`architecture.build_import_graph`) but not
  persisted or visualised; no call graph or data-flow/taint analysis.
- **PDF export.** HTML report prints well; native PDF needs a renderer.
- Email invitations, email verification, password reset, MFA, SSO/SAML/SCIM.
- Measured performance analysis (load tests, profiling) — performance findings are static estimates only.
- More ecosystems for built-in checks and dependency parsing (Go, Java, Ruby, PHP, .NET); currently covered for
  those only through Semgrep/Trivy when installed.

**Platform / operations**
- PostgreSQL Row Level Security policies (schema is ready; see SECURITY.md §3).
- Kernel-level sandbox for analyzers (gVisor/Kata/Firecracker) and separation of the analysis sandbox from the
  DB-connected worker.
- Upload/archive retention policies and storage on object storage (S3) instead of a local volume.
- Structured logging/metrics/tracing (OpenTelemetry), audit-duration SLOs, Celery monitoring.
- Scheduled audits (Celery beat) and stale-queue detection/alerting.
- Usage metering, billing, quotas beyond the per-org concurrency limit.

**Analysis quality**
- Data-flow analysis for SQL injection / SSRF / path traversal (currently pattern-based; Semgrep rules help).
- Framework-aware route/authorization mapping beyond Flask/FastAPI/Express heuristics.
- Calibrating scoring weights against a labelled corpus of repositories.

## Next steps (suggested order)

1. GitHub App with webhook-triggered PR audits and check runs.
2. Organization policies + per-repository gate thresholds.
3. PostgreSQL RLS + sandbox separation (worker isolation).
4. Approved fix PR workflow (human-in-the-loop) built on AI suggestions.
5. Knowledge graph persistence and visualisation.
