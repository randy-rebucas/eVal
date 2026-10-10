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
| 8 | Verified AI fix pull requests (re-audit of the patched tree), GitHub App (webhook PR/push audits, check runs with annotations, installation tokens), policies as code (org ← repo ← `.eval.toml`, per-path gates, required analyzers), AI-generated-code analyzer (undeclared/lookalike/non-existent packages, stubs, placeholders, hollow tests), PR change-risk score, Claude Code hook + MCP server + `--changed`, compliance mapping (CWE/OWASP/ASVS/SOC 2/ISO 27001) and evidence packs, scheduled re-audits with Slack/Teams/webhook regression alerts, TOTP MFA, OIDC SSO, SCIM, audit log UI, dependency reachability, intra-procedural taint analysis |
| 7 (partial) | eVal Local ([LOCAL_AI.md](LOCAL_AI.md)): `eval-audit --ai local` (loopback-only model server, proxies ignored), `--offline` with network guard, small-model batching and output retry, AI-assisted triage ordering in reports, `eval-audit doctor`. Open: real-model benchmarks, `eval-audit serve` |

Test suite: ~430 tests (unit + integration), run on SQLite and PostgreSQL.

## Not built yet (honest list)

**Product**
- **SAML SSO** (OIDC is supported) and SCIM groups-to-roles mapping.
- **Repository knowledge graph.** The import graph is computed but not persisted or visualised; no call graph.
- **Native PDF export.** The HTML report (also in the evidence pack) prints well; native PDF needs a renderer.
- Email invitations, email verification, password reset.
- Measured performance analysis (load tests, profiling) — performance findings are static estimates only.
- More ecosystems for built-in checks, reachability and taint (Go, Java, Ruby, PHP, .NET); currently covered for
  those only through Semgrep/Trivy when installed.

**Platform / operations**
- PostgreSQL Row Level Security policies (schema is ready; see SECURITY.md §3).
- Kernel-level sandbox for analyzers (gVisor/Kata/Firecracker) and separation of the analysis sandbox from the
  DB-connected worker.
- Upload/archive retention policies and storage on object storage (S3) instead of a local volume.
- Structured logging/metrics/tracing (OpenTelemetry), audit-duration SLOs, Celery monitoring.
- Usage metering, billing, quotas beyond the per-org concurrency limit.

**Analysis quality**
- Inter-procedural and cross-module taint tracking (today: within one function); JavaScript/TypeScript taint.
- Call-graph reachability for dependency vulnerabilities (today: import level).
- Calibrating scoring weights and the change-risk factors against a labelled corpus of repositories.

## Next steps (suggested order)

1. PostgreSQL RLS + sandbox separation (worker isolation).
2. SAML SSO via a vetted library; email invitations and verification.
3. Cross-function taint and JavaScript taint; call-graph reachability.
4. Knowledge graph persistence and visualisation.
