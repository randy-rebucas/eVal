# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Four confirmed audiences. None of them is the default, so each surface decides whose job comes first:

- **Engineering / tech leads** own a team's repositories. They run audits, triage findings, decide what ships, and sign off accepted risks with an owner and a review date.
- **Solo developers and small teams** ship code that is often AI-generated and want an independent check before it goes to production. Their loop is: audit, understand the finding, fix it, re-audit.
- **Security / AppSec reviewers** cover many repositories across an organization. They maintain the risk register, watch coverage, and report upward.
- **Agencies and consultants** audit client or vendor codebases and hand over the report as the deliverable.

Roles inside an organization are viewer, member, admin and owner.

## Product Purpose

eVal ("electronic validator") audits applications for production readiness. Its tagline is "AI generates code. eVal verifies it." A user connects a GitHub repository or uploads a ZIP and runs an asynchronous audit. eVal returns evidence-backed findings across nine categories: security, architecture, testing, database, API, dependencies, performance, DevOps and maintainability. It also produces transparent scores, audit history, PR-level gating, GitHub issues and optional AI explanations.

### Vision

Modern AI coding tools can generate large amounts of application code very quickly. That code can carry security vulnerabilities, architectural problems, poor database design, missing tests, hidden technical debt, poor error handling, performance and scalability problems, dependency risks, authorization flaws, poor observability, DevOps weaknesses and undocumented assumptions.

**AI can generate software. eVal verifies that the software is actually engineered correctly.**

Each of those concerns maps to concrete checks:

| Concern | Where eVal checks it |
|---|---|
| Security vulnerabilities | `secrets`, `taint` (incl. deserialization and upload paths), `api_security` (CORS, JWT, debug mode, CSRF, cookie flags, credentials in logs, upload validation, login rate limiting), Bandit, Semgrep, Trivy. Pattern matches stay *potential* until a traced data flow or the pattern itself proves the weakness |
| Authentication and sessions | `auth_security`, driven by the application profile (framework, auth scheme, datastore, password columns in the ORM/Prisma/SQL schema): CSRF for cookie-authenticated Django/Express/Flask apps only, JWT secrets/expiry/algorithm pinning, unhashed password storage and plaintext comparison, MongoDB operator injection. The report lists which checks applied and why |
| Authorization flaws | `api_security`: unauthenticated state-changing routes, object lookups by URL id without an ownership check (IDOR), mass assignment |
| Architectural problems | `architecture`: module and package cycles, fan-out, dependency direction between layers, cross-service imports and feature-boundary violations, business logic and data access in request handlers, routes mixed with models, no service layer, scattered data access, oversized modules/packages, flat layout, duplicated business logic, config sprawl and settings-module bypass |
| Poor database design | `database`: missing primary keys, money stored as floats, natural keys without unique constraints, unindexed foreign keys, missing migrations |
| Missing tests | `testing`, `ai_code` (tests that cannot fail) |
| Hidden technical debt | `maintainability`, `ai_code` (stubs, placeholders) |
| Poor error handling | swallowed exceptions (Python and JS), exception text or stack traces returned to clients, no global error handler |
| Performance and scalability | `performance` (static risk): network calls repeated in loops, nested-loop lookups, blocking calls, missing timeouts, memory-heavy reads and large body limits, unbounded caches, inefficient serialization, process-local state, in-memory session stores, local-disk uploads. `database`: N+1 queries, unbounded queries, missing pagination |
| Dependency risks | `dependencies` (hygiene, duplicates, conflicts, lockfile drift, unused packages), `osv` (vulnerabilities), `registry` (existence, age, major versions behind), `ai_code` (hallucinated and lookalike packages), reachability |
| Poor observability | `observability`: structured logging, error tracking, tracing, metrics, request ids, health endpoints, audit logs, background-job monitoring; print/console logging in server code |
| DevOps weaknesses | `devops`: Dockerfile, Compose, Kubernetes and CI workflow hardening, missing CI or CI without tests, resource limits, debug settings and dev servers in deployment files, deploys without a test gate, mutable image tags, rollback strategy, environment separation |
| Undocumented assumptions | `configuration`: environment variables missing from .env.example and docs, hardcoded local or private endpoints, machine-specific paths, HTTP APIs without an OpenAPI contract |

All of these are static checks. Scalability and performance findings are static risks, not measurements: reports state separately that measured performance (benchmarks, load tests, profiling) was not assessed.

Success means a team knows what is risky in its code, why it is risky, who owns each accepted risk, and whether a change made things worse. Those answers have to rest on evidence the team can check.

## Positioning

eVal is honest by mechanism, not by tone:

- It never executes the audited code.
- It never claims an application is secure. Scores are risk indicators.
- A category that could not be assessed is shown as **Not assessed**, never as 100.
- Missing analyzer tools are reported, never silently skipped.
- Scoring is deterministic and documented (docs/SCORING.md). Severity ceilings stop an average from hiding a critical issue.
- AI output is labelled, redacted on input, validated on output, and **never affects scores**.
- Triage decisions never change scores, so audits stay comparable and the scores can't be gamed.

## Operating Context

- Self-hosted / internal for now. It runs via Docker Compose (Postgres, Redis, gunicorn web, hardened Celery worker) inside the user's own organization or a client's. The hosted SaaS model has not started.
- Main workflows:
  1. Create a project, then add a repository.
  2. Run an audit on a branch or commit, or audit a PR by number.
  3. Review the dashboard: scores, coverage table and findings.
  4. Filter, triage, compare commits, export, and create GitHub issues.
  5. Gate CI through an API token and `scripts/eval_ci.py`, or use the offline `eval-audit` CLI.
- Artifacts people take away from the product: HTML, Markdown, JSON and SARIF reports. The HTML report is meant to print well. There is no native PDF yet.
- Finding lifecycle vocabulary: new / existing / recurring / resolved. Finding kinds: confirmed / potential / estimate / AI observation. Risk levels: Low / Moderate / High / Critical.

## Capabilities and Constraints

- Stack: Flask + Jinja templates, Bootstrap 5.3 and Bootstrap Icons from the jsDelivr CDN with SRI, one `app.css` and one `app.js`. Server-rendered, with a CSRF-protected form flow.
- 23 analyzers (Ruff, Bandit, mypy, ESLint, tsc, Semgrep, Trivy, OSV.dev, PyPI/npm registry checks, plus built-in checks). Tenant isolation applies to every query.
- Accepted risks need a reason, an owner (a team or vendor) and a review date at most `EVAL_ACCEPTED_RISK_MAX_DAYS` away. They reopen on that date.
- Deliberately not built: automated fix PRs. AI patches are only displayed.
- Not built yet: GitHub App/webhooks, org policies, knowledge-graph visualization, PDF export, email invites/verification, password reset, MFA, SSO. Billing and metering are also not built. See docs/ROADMAP.md.
- The scoring code and docs/SCORING.md must change together.

## Brand Commitments

- Name: **eVal** (lowercase e, capital V), short for "electronic validator".
- Tagline: "AI generates code. eVal verifies it."
- Required disclaimer stance: "scores are risk indicators, not guarantees of production readiness." It appears in the app footer and must survive any redesign.
- No logo exists beyond the Bootstrap `shield-check` icon next to the wordmark.

## Evidence on Hand

- **Real audit outputs** from real repositories. These can be shown as demos once a specific report is chosen.
- Fixture repositories with deliberate issues: `tests/fixtures/` (cleanapp, jsapp).
- **Absent, never fabricate:** customers, testimonials, named users, case studies, logos of adopters, benchmarks or accuracy claims, pricing, and SaaS availability or hosting claims.

## Product Principles

1. **Evidence before verdict.** Every score, finding and gate decision traces to evidence, a location and a documented rule.
2. **Never overclaim.** Show uncertainty plainly: Not assessed, potential, estimate, AI-labelled. The product never implies more safety than it measured.
3. **Accountability over dismissal.** Risks can be accepted, not erased. Each acceptance has an owner and a date, and it comes back.
4. **Severity can't be averaged away.** The worst real problem stays visible at every level of summary.
5. **Serve the reader at hand.** Leads, solo devs, reviewers and consultants are all primary users. Each surface names whose job it serves first.
