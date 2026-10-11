# eVal API

Two surfaces:

1. **JSON API** at `/api/v1` — bearer tokens, for CI/CD and scripts (this document, §1–§4).
2. **Web routes** — cookie session + CSRF, for the dashboard (§5).

## 1. Authentication

Create a token under **API tokens** in the web UI. Tokens look like `evl_…`, are shown once, and act as you
within one organization with your *current* role.

```
Authorization: Bearer evl_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

| Status | Meaning |
|---|---|
| 401 | missing, malformed, revoked token, or the owner is no longer a member |
| 403 | the action needs a higher role (`member` to start audits / post comments) |
| 404 | resource does not exist **or belongs to another organization** |
| 409 | audit not finished |
| 422 | request understood but rejected (e.g. invalid ref, closed PR, GitHub error) |
| 429 | rate limited (600 requests/min per token) |

Errors are JSON: `{"error": "message"}`.

Browser clients: `/api/v1` answers CORS requests from the origins in `EVAL_API_CORS_ORIGINS` (by default the
vscode.dev / github.dev extension host), allowing `GET`/`POST` with `Authorization` and `Content-Type`. No
credentials mode: send the token in the header.

## 2. Endpoints

### `GET /api/v1/me`
```json
{"organization": {"id": "…", "slug": "acme", "name": "Acme"}, "user": {"id": "…", "email": "a@x.com"},
 "role": "member", "token": {"name": "ci", "prefix": "evl_AbCdEfGh"}}
```

### `GET /api/v1/projects`
Projects with their repositories: `{"projects": [{"id", "name", "slug", "repositories": [Repository]}]}`.
Repository: `{"id", "project_id", "name", "source": "github"|"upload", "full_name", "default_branch", "has_credential"}`.

### `GET /api/v1/repositories/{repo_id}`
`{"repository": Repository, "audits": [Audit]}` — the 20 most recent audits.

### `GET /api/v1/repositories/{repo_id}/fixes`
The repository's 20 newest AI fix proposals, newest first: `{"fixes": [Fix]}`.
Fix: `{"id", "audit_id", "repository_id", "status": "queued"|"running"|"verifying"|"ready"|"failed"|"pr_opened",
"branch", "commit_sha", "revision", "edited", "verdict": "passed"|"partial"|"regressed"|"incomplete"|"error"|null,
"files": ["path"], "fixed", "not_changed", "ai_model", "pr_url", "fix_branch", "created_at", "url"}`.
`branch` and `commit_sha` are the audited ones, and `fix_branch` is the `eval/fix-…` branch once a pull request is open.

### `GET /api/v1/fixes/{fix_id}`
`{"fix": Fix + {"error", "patches": [{"path", "diff"}], "verification", "findings": [{"id", "changed", "note",
"title", "severity", "location"}], "ide_links": {"codespaces", "github_dev"}}}`. Each `diff` is a unified diff of
one file against the audited commit (as in the `.patch` download), for applying the fix in an editor. `ide_links`
is empty except for github.com repositories.

### `POST /api/v1/repositories/{repo_id}/audits` (member)
* GitHub repository: JSON body `{"ref": "main"}` (branch, tag or commit SHA; default branch if omitted).
* Upload repository: `multipart/form-data` with an `archive` field containing a `.zip`.

Returns **202** `{"audit": Audit}`. Poll `GET /audits/{id}` until `status` is `succeeded`, `failed` or `cancelled`.

### `POST /api/v1/repositories/{repo_id}/pulls/{number}/audits` (member)
Audits the head commit of an **open** GitHub pull request. Findings in the PR's changed files are compared with
the latest successful audit of the PR's base branch. Returns **202** `{"audit": Audit}`.

### `GET /api/v1/audits/{audit_id}`
```json
{"audit": {
  "id": "…", "repository_id": "…", "status": "succeeded", "stage": "complete", "progress": 100, "error": "",
  "trigger": "api", "branch": "main", "commit_sha": "…", "pr_number": null,
  "overall_score": 65.7, "risk_level": "Critical",
  "severity_counts": {"critical": 1, "high": 5, "medium": 9, "low": 6, "info": 1},
  "created_at": "…", "finished_at": "…", "url": "https://eval.example.com/o/acme/audits/…",
  "scores": {"overall": 65.7, "risk": "Critical", "version": "1",
             "categories": {"security": {"assessed": true, "score": 16.1, "risk": "Critical",
                                         "penalty": 83.9, "findings": 6, "ceiling_reason": "…"}, "…": {}}},
  "lifecycle": {"new": 3, "existing": 18, "recurring": 0, "resolved": 2},
  "tools": [{"name": "bandit", "title": "Bandit (Python security)", "status": "ok", "reason": "",
             "findings": 4, "duration": 1.2, "categories": ["security"], "tool": "bandit"}],
  "languages": {"files_by_language": {"python": 12}, "frameworks": ["flask"], "primary": "python"},
  "ai_summary": {"summary": "…", "top_risks": ["…"], "model": "claude-opus-5-5"},
  "gate": {"passed": false, "fail_on": "high", "blocking": 1,
           "reasons": ["1 finding(s) at or above the gate threshold"], "policy": {"gate": {"…": "…"}, "sources": []}},
  "pull_request": {"pr_number": 5, "base_ref": "main", "changed_files": 3, "baseline_audit_id": "…",
                   "introduced_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                   "change_risk": {"score": 40, "level": "medium",
                                   "factors": [{"factor": "tests", "points": 15, "detail": "…"}]}}
}}
```
`scores`, `lifecycle`, `tools`, `languages`, `ai_summary`, `gate` appear once the audit succeeded; `pull_request`
only for PR audits. `gate` is evaluated against the policy stored with the audit and the current triage state (PR
audits: findings introduced in changed files; other audits: open findings), which is what
`scripts/eval_ci.py --fail-on policy` uses. Categories with `"assessed": false` have `"score": null` — they were not analysed.

### `GET /api/v1/audits/{audit_id}/findings`
Query parameters: `severity`, `category`, `kind` (`confirmed|potential|estimate|ai_observation`), `lifecycle`
(`new|existing|recurring`), `triage` (`open` default, `accepted_risk`, `false_positive`, `fixed`, `all`), `q`
(search), `page`. For PR audits, `introduced=1` returns only findings introduced in changed files.

```json
{"findings": [{"id": "…", "rule_id": "bandit:B608", "fingerprint": "…", "title": "…",
  "category": "security", "severity": "high", "confidence": "medium", "kind": "potential",
  "description": "…", "remediation": "…", "file_path": "app.py", "line_start": 16, "line_end": 16,
  "evidence": "15 | …\n16 | …", "sources": ["bandit", "database"], "references": ["https://…"],
  "lifecycle": "new", "triage_status": "open",
  "triage": {"status": "open", "reason": "", "owner": "", "expires_on": null, "triaged_by": null,
             "triaged_at": null, "expired": false},
  "ai_explanation": {}}],
 "page": 1, "pages": 1, "total": 22}
```
`triage.expired` is true when an earlier accepted risk / false positive lapsed on its review date and the finding
reopened; `reason`, `owner` and `expires_on` then describe the lapsed decision.

### `POST /api/v1/findings/{finding_id}/triage` (member)
Body: `{"status": "accepted_risk", "reason": "…", "owner": "Vendor: Acme", "expires_on": "2027-03-31"}`.

| status | reason | owner | expires_on |
|---|---|---|---|
| `accepted_risk` | required (≥ 10 chars) | required — the team or vendor that owns the fix | required, future, ≤ `EVAL_ACCEPTED_RISK_MAX_DAYS` (365) |
| `false_positive` | required | optional | optional (same bounds) |
| `open`, `fixed` | cleared | cleared | cleared |

Returns **200** `{"finding": {…}}`, or **422** `{"error": "…"}` when a rule is not met. Decisions carry over to
later audits of the repository and reopen on `expires_on`.

### `GET /api/v1/risks`
The risk register: accepted risks and false positives in each repository's latest audit, soonest review date
first. Each item is a finding object plus `audit_id` and `repository_id`.

### `GET /api/v1/audits/{audit_id}/report.{fmt}`
`fmt` ∈ `json`, `md`, `html`, `sarif`. Triaged findings are excluded unless `?all=1`; SARIF always includes accepted risks and false positives as `suppressions` (with the reason, owner and review date as justification), so code scanning records them as dismissed rather than fixed. SARIF 2.1.0 is suitable for
GitHub code scanning (`github/codeql-action/upload-sarif`).

### `POST /api/v1/audits/{audit_id}/pr-comment` (member)
Posts the PR summary as a comment on the pull request (requires a repository credential with PR/Issues write).
Explicit opt-in; never automatic. Returns **201** `{"comment_url": "…"}`.

Each finding in `/findings` responses also carries `compliance` (`{"cwe", "owasp", "asvs", "soc2", "iso27001"}`)
and, for dependency vulnerabilities, `reachability` (`imported` | `not-imported` | `transitive`).

### `GET /o/{org}/audits/{audit_id}/evidence.zip` (web session)
Evidence pack: HTML/JSON/SARIF reports, `findings.csv`, `compliance-controls.csv`, `risk-register.csv`,
`decisions.csv`, `policy.json`, `coverage.json` and `manifest.json` with the SHA-256 of every file.

### SCIM 2.0: `/scim/v2/...`
`Authorization: Bearer scim_…` (Settings → Security). `GET/POST /Users`, `GET/PUT/PATCH/DELETE /Users/{id}`,
`GET /ServiceProviderConfig`; `filter=userName eq "…"`; `active: false` or DELETE removes the membership. See
SECURITY.md §6a.

### Webhooks: `POST /webhooks/github`
GitHub App deliveries (`pull_request`, `push`, `check_run`, `installation`), signed with `X-Hub-Signature-256`.

## 3. Example

```bash
curl -s -X POST -H "Authorization: Bearer $EVAL_TOKEN" -H "Content-Type: application/json" \
     -d '{"ref":"main"}' https://eval.example.com/api/v1/repositories/$REPO/audits
curl -s -H "Authorization: Bearer $EVAL_TOKEN" https://eval.example.com/api/v1/audits/$AUDIT
```

For CI, use `scripts/eval_ci.py` (standard library only) — see `docs/CI.md`.

## 4. Stability

`/api/v1` is versioned. Additive fields may appear; removals or semantic changes go to `/api/v2`.

## 5. Web routes (session + CSRF)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET/POST | `/register`, `/login`; POST `/logout` | — | authentication |
| GET/POST | `/orgs` | user | list/create organizations |
| GET | `/o/{org}` | viewer | portfolio dashboard |
| GET/POST | `/o/{org}/members`; POST `…/members/{id}/role`, `…/remove` | viewer / admin | membership |
| GET/POST | `/o/{org}/projects`; GET `…/projects/{id}`; POST `…/delete` | viewer / member / admin | projects |
| GET/POST | `/o/{org}/projects/{id}/repos/new` | member | connect GitHub repo or upload ZIP |
| GET | `/o/{org}/repos/{id}` | viewer | repository, branches/commits, history |
| POST | `/o/{org}/repos/{id}/audits`, `…/pulls`, `…/upload` | member | run audit / PR audit / new upload |
| POST | `/o/{org}/repos/{id}/credential`, `…/delete` | admin | repository credential, delete |
| GET | `/o/{org}/audits/{id}`, `…/status`, `…/compare?base=` | viewer | dashboard, progress JSON, comparison |
| GET | `/o/{org}/audits/{id}/report.{fmt}` | viewer | exports |
| POST | `/o/{org}/audits/{id}/cancel`, `…/issues`, `…/pr-comment` | member | cancel, GitHub issues, PR comment |
| GET | `/o/{org}/findings/{id}`; POST `…/triage` | viewer / member | finding detail, triage (reason, owner, review date) |
| GET | `/o/{org}/risks` | viewer | risk register |
| GET/POST | `/o/{org}/settings/integrations`; POST `…/integrations/{id}/delete`; POST `/o/{org}/settings/ai` | viewer / admin | credentials, AI settings |
| GET/POST | `/o/{org}/settings/tokens`; POST `…/tokens/{id}/revoke` | viewer | personal API tokens |
