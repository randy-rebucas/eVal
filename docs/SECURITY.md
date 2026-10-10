# eVal security model

eVal ingests untrusted source code, runs third-party tools over it, stores third-party credentials, and
(optionally) talks to AI providers. This document lists the threats considered and the controls in place,
with pointers to the code and tests that enforce them. Known gaps are listed at the end — please read them.

## 1. Untrusted repository content

| Threat | Control | Where |
|---|---|---|
| Code execution from the repo | Repository code is never imported, built, installed or run. Built-in analyzers parse with `ast`/regex. | `eval_engine/analyzers/*` |
| Code execution via tool config | Tools that load executable config are run with eVal's own config: mypy `--config-file` (plugins would be imported), ESLint `--config` from a temp dir (`eslint.config.js` is JS), Ruff `--isolated`. Proven by tests that plant a payload and assert it never runs. | `analyzers/mypy_.py`, `eslint.py`, `ruff.py`; `tests/engine/test_analyzers.py::test_mypy_ignores_repo_plugins`, `::test_eslint_never_loads_repo_config` |
| Repository steering the tools | Repository-supplied tool settings and inline suppressions are ignored: Trivy runs with eVal's own empty `--config` and `--ignorefile` (it otherwise reads `./trivy.yaml` and `./.trivyignore`, which could hide results, redirect output, or point the worker at another server); Bandit gets an empty `--ini` (ignores `.bandit`) and `--ignore-nosec`; Semgrep `--disable-nosem`; Ruff `--ignore-noqa`; ESLint `noInlineConfig`. | `analyzers/trivy.py`, `bandit.py`, `semgrep.py`, `ruff.py`; `tests/engine/test_hardening.py` |
| Path traversal / zip slip | Member names normalised; absolute paths, drive letters, `..` and over-deep paths rejected; every write goes through `safe_join`. | `workspace.extract_zip`, `validate_relative_path` |
| Symlink attacks | Symlink members skipped; traversal never follows symlinks; git checkout uses `core.symlinks=false`. | `workspace` |
| Zip bombs / resource exhaustion | Per-file, total and file-count limits enforced while streaming (headers are not trusted); compression-ratio limit; encrypted members rejected. | `workspace.Limits` |
| Malicious git remotes | `https` only; host allow-list (`EVAL_GIT_ALLOWED_HOSTS`); `owner/repo` path validation; ref validation (no `--option` injection); `protocol.allow=never` except https; no submodules, hooks, LFS smudge, fsmonitor; user/system git config ignored; shallow fetch of one ref; `.git` removed before analysis. | `workspace.clone_repo`, `_git_env` |
| Command injection | Subprocesses use argv lists, never a shell, with an allow-listed executable resolved to an absolute path. | `eval_engine/sandbox.py` |
| Runaway tools | Wall-clock timeout kills the process tree; output captured to temp files with a cap; POSIX `RLIMIT_CPU/AS/FSIZE/NOFILE/CORE`; Celery soft/hard task limits. | `sandbox.run`, `celery_app.py` |
| Secret leakage via env | Tools run with a scrubbed environment (no `DATABASE_URL`, `EVAL_*`, keys). | `sandbox._scrubbed_env`; test `test_environment_is_scrubbed` |
| Hostile analyzer output | Findings must reference files inside the workspace (paths are normalised without dropping leading dots, so `.github/` and `.env` findings are kept); line numbers are bounds-checked; everything rendered is HTML-escaped (Jinja autoescape, `html.escape` in reports, Markdown escaping). | `dedupe.validate`, `reports.py`; test `test_untrusted_content_is_escaped_everywhere` |

**Container isolation (production).** The worker container in `docker-compose.yml` runs as an unprivileged user
with a read-only root filesystem, `tmpfs` work dirs, all capabilities dropped, `no-new-privileges`, and memory,
CPU and PID limits. The worker process marks itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`), so analyzer
tools — which run as the same user — cannot read its `/proc/<pid>/environ` (database URL, encryption keys) or
memory. It mounts the data volume read-only, so tools cannot alter stored uploads; the Trivy cache has its own
volume. Audits whose worker died (redelivered task) are marked failed rather than retried, and audits stuck past
Celery's hard time limit are expired so they stop counting against the organization's limit. For stronger isolation run the worker under gVisor/Kata or a dedicated node pool with no
access to the database network other than what it needs (see Known gaps).

## 2. Secrets

* **Redaction** of provider tokens (AWS, GitHub, Anthropic, OpenAI, Slack, Stripe, Google, JWTs, private keys),
  credential assignments, and URL credentials is applied to stored evidence, logs (logging filter), AI prompts,
  AI output, GitHub issue bodies and PR comments. `eval_engine/redaction.py`.
* **Integration credentials** (GitHub tokens, AI keys) are encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
  using `EVAL_ENCRYPTION_KEYS`; multiple keys enable rotation (`crypto.rotate`). Only the last four characters
  are ever displayed. Plaintext is produced only inside the service call that needs it (worker clone, GitHub
  API call). Git tokens go through environment-scoped git config, never argv or URLs.
* **API tokens** are random 256-bit values, shown once (response marked `Cache-Control: no-store`), stored as
  SHA-256 hashes.
* **Passwords** use scrypt (Werkzeug); login takes the same time for unknown users (dummy hash check).

## 3. Multi-tenancy and authorization

* Every tenant-owned table has a NOT NULL `organization_id`. All lookups go through
  `get_scoped_or_404`/`scoped_select`, which filter by the caller's organization. IDs from another tenant return
  **404**, not 403, so existence is not revealed.
* Roles: `viewer < member < admin < owner`. Viewers read; members create audits, triage, create issues; admins
  manage members, credentials (including which repository uses which credential, also at connection time), AI
  settings and delete resources; only owners grant/revoke owner, and the last
  owner cannot be removed or demoted.
* API tokens act with the user's **current** membership role, checked on every request; removing the member
  disables their tokens immediately.
* Tests: `tests/app/test_tenancy.py`, `test_repos_audits.py::test_audits_are_tenant_isolated`,
  `test_api_pr.py::test_api_tenant_isolation`, `test_dashboard_reports_issues.py::test_reports_are_tenant_scoped`.
* **Row Level Security readiness:** because every row carries `organization_id`, enabling PostgreSQL RLS is a
  policy per table, e.g. `CREATE POLICY tenant ON findings USING (organization_id = current_setting('eval.org_id')::uuid)`,
  plus `SET LOCAL eval.org_id` per request/transaction. Not yet enabled (see roadmap).

## 4. Web application

CSRF protection on all forms (Flask-WTF); the bearer-token API is CSRF-exempt and does not accept session
cookies. Session cookies are `HttpOnly`, `SameSite=Lax`, `Secure` outside local development; the session is
cleared on login (fixation). Login is rate limited per IP+email and per IP; registration per IP. If Redis is
unreachable the limiter falls back to in-process counters instead of failing open. Behind a reverse proxy set
`EVAL_PROXY_FIX_HOPS` so limits apply to real client addresses. Each user may own at most `EVAL_MAX_ORGS_PER_USER`
organizations, bounding one account's share of the shared workers. Security headers: strict CSP (no inline
scripts or style attributes; CDN sources pinned to the exact package versions loaded with SRI), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, HSTS when secure cookies
are on. Open redirects are blocked on login. Production refuses to start without strong secrets. A security audit
log (`audit_events`) records logins, membership, credential, AI-settings, export, and issue-creation actions
without secrets.

## 5. AI-specific controls

* Disabled by default, per organization, admin-only to enable.
* During audits, only selected findings with **redacted, length-capped** evidence are sent — never whole files.
  **Auto-fix** (an explicit member action on chosen findings) is the exception: it sends the affected files
  (at most 5; files over 400 lines as ±40-line windows around the findings), with secrets swapped for numbered
  placeholders that are restored only where the model copies them back verbatim. `eval_engine/ai/fix.py`.
* Repository-derived text is wrapped in `<untrusted_repository_content>` delimiters; closing/opening tags inside
  the data are neutralised; the system prompt forbids following embedded instructions.
* Output must be JSON matching a schema; unknown IDs, keys and categories are dropped; strings are capped and
  redacted again; invalid output is discarded entirely.
* AI receives *copies* of findings and can only contribute `ai_explanation` and unscored `ai_observation`
  findings — it cannot change severities, evidence, or scores (test `test_ai_enricher_cannot_change_scores`).
* AI content is labelled as AI-generated and escaped in the UI. Explanation patches are illustrative only.
  Auto-fix edits are exact find/replace pairs: each must match the file exactly once and may only touch files
  that were sent, or the finding's fix is rejected whole. The result is a diff a person reviews; nothing is
  pushed until they open a pull request.
* OpenAI-compatible base URLs must be on the operator allow-list (`EVAL_AI_ALLOWED_BASE_URLS`), preventing
  tenants from using the worker for SSRF.

## 6. Outbound actions

eVal never executes audited code and never writes to a repository on its own. GitHub issues, PR comments and
auto-fix pull requests are created only on an explicit user action (member role). Issues are deduplicated per
fingerprint with redacted bodies. An auto-fix pull request is always a new `eval/fix-…` branch cut from the
audited commit, never a push to an existing branch; each file update carries the blob SHA it replaces, so GitHub
rejects it if the file changed. Opening one needs a repository credential with Contents and Pull requests write
access (the OAuth "repo" scope covers it).

Before an auto-fix can become a pull request, the patched tree is **re-audited** with the analyzers that ran in the
original audit (same policy). If the patch introduced findings, opening the PR requires an explicit
acknowledgement, which is recorded in the security log.

**GitHub App.** Webhooks are rejected unless `X-Hub-Signature-256` matches `GITHUB_APP_WEBHOOK_SECRET` (constant-time
HMAC-SHA256 check). An installation is linked to an organization only through the setup flow: the callback state
is bound to the admin's session and organization, and the GitHub user-authorization code is exchanged to confirm
that this user can access the installation (`GET /user/installations`), so a forged `installation_id` is refused.
An installation can belong to one organization only. Installation tokens are minted per use (one hour), cached in
memory and never stored. Events for unlinked installations are ignored, and webhooks never create repositories.

**Notifications.** Webhook URLs are encrypted at rest; Slack and Teams URLs must be on their documented hosts, and
generic webhooks must resolve to a public address (checked when saved and again when sending; redirects are not
followed). Generic webhooks are signed (`X-Eval-Signature: sha256=…`) with a per-channel secret shown once. Messages
contain finding titles and locations, never evidence.

## 6a. Identity

* **TOTP two-factor authentication** (RFC 6238): secrets are encrypted; a code is accepted once (the last
  accepted time step is stored); ten one-time recovery codes are stored as SHA-256 hashes. Every password and
  social sign-in of an account with TOTP passes the challenge. Organizations can require MFA; an admin cannot turn
  the requirement on without MFA on their own account.
* **OIDC single sign-on** per organization: authorization code flow with PKCE, `state` and `nonce`; ID-token
  signatures are verified against the IdP's JWKS (RS256/ES256), and `iss`, `aud`, `exp`, `iat` are checked; email
  addresses must be in the connection's domains. Because an organization controls its own IdP, **SSO never signs
  into an account it does not own**: only accounts linked to that IdP, accounts the organization provisioned (SCIM
  or SSO), or new accounts. Existing users link SSO from a session in which they already signed in. Enforced SSO
  exempts owners (break-glass), so a broken IdP cannot lock an organization out.
* **SCIM 2.0** provisioning with per-organization bearer tokens (hash stored). SCIM sees only the organization's
  members; it deactivates only accounts the organization created and that belong to no other organization, and it
  never removes owners.
* The **audit log** (Settings → Audit log, CSV export) shows sign-ins, MFA changes, membership, credentials, policies,
  triage, exports, SSO and SCIM events. CSV exports neutralize spreadsheet formulas.

## 7. Known gaps (honest list)

* **Process isolation on Windows** relies on timeouts only (no rlimits); production should use the Linux
  container. Even in the container, analyzers share a kernel with the worker; a kernel-level sandbox
  (gVisor) is recommended for hostile multi-tenant workloads.
* The worker container needs database access to persist results. A stricter design would have the analysis
  sandbox return results to a separate persistence process.
* Semgrep and Trivy run without `RLIMIT_AS` (their runtimes mmap/reserve large address ranges and fail under
  it); their memory is bounded only by the worker container's cgroup limit.
* Semgrep honours a repository's `.semgrepignore`, which a hostile repository could use to hide files.
* `tsc` reads the repository's `tsconfig.json` (that is what it checks). Compiler options such as
  `generateTrace` can make it write files inside the worker's writable scratch space; the CLI never loads
  language-service plugins.
* Analyzer tools run as the worker's user, so a compromised tool can still read other tenants' uploads on the
  (read-only) data volume while it runs. Per-audit sandboxes (gVisor, or a separate uid with only that audit's
  source) would close this.
* Registration reveals whether an email is already registered; hiding it requires email verification.
* Git transfer size cannot be capped before download; limits are enforced after checkout plus the GitHub-reported
  repository size check at connection time.
* The in-memory rate limiter fallback is per-process; configure `REDIS_URL` in production.
* Email verification and password reset are not implemented. SAML SSO is not implemented (OIDC is): SAML needs a
  vetted XML-signature library (e.g. python3-saml/xmlsec) rather than hand-written verification.
* SSO trusts the configured email domains without DNS verification; that only affects accounts the organization
  itself creates, by design (see 6a).
* PostgreSQL RLS policies are designed for but not enabled.
