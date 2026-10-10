# CI/CD integration

Two ways to gate builds on eVal.

## A. Server mode (recommended): `scripts/eval_ci.py`

Runs the audit on your eVal server (history, PR baselines, dashboards, issues) and fails the build on findings.
Standard library only.

```yaml
# .github/workflows/eval.yml
name: eVal
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write     # only for the SARIF upload step
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - uses: actions/setup-python@<pinned-sha>
        with: { python-version: "3.12" }
      - name: eVal gate
        env:
          EVAL_URL: ${{ vars.EVAL_URL }}
          EVAL_TOKEN: ${{ secrets.EVAL_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          if [ -n "$PR_NUMBER" ]; then
            python scripts/eval_ci.py --repository "${{ vars.EVAL_REPOSITORY_ID }}" --pr "$PR_NUMBER" \
              --fail-on high --sarif eval.sarif
          else
            python scripts/eval_ci.py --repository "${{ vars.EVAL_REPOSITORY_ID }}" --ref "$GITHUB_SHA" \
              --fail-on critical --sarif eval.sarif
          fi
      - uses: github/codeql-action/upload-sarif@<pinned-sha>
        if: always()
        with: { sarif_file: eval.sarif }
```

* Pull requests are gated only on findings **introduced in changed files** relative to the base branch's latest
  audit — pre-existing debt does not block unrelated PRs. Audit the base branch on every push so the baseline
  stays current.
* `--comment` posts a summary on the PR (needs a repository credential with Issues/PR write in eVal).
* Non-GitHub CI (GitLab, Jenkins, Bitbucket): create an *upload* repository in eVal, zip the checkout and use
  `--archive source.zip` (e.g. `git archive --format=zip -o source.zip HEAD`).
* Exit codes: `0` pass, `1` gate failed, `2` usage/API error, `3` audit failed or timed out.

Note that the user-controlled values (PR number) are passed via environment variables, not `${{ }}` inside
`run:` — eVal's own DevOps analyzer flags the latter as script injection.

## B. Offline mode: `eval-audit` CLI

Runs the analysis engine directly in the CI job (no server, no history). Install the package with analyzers:

```bash
pip install "eval-auditor[analyzers]"        # ruff, bandit, mypy; add semgrep/trivy/eslint/tsc as needed
eval-audit . --format sarif --output eval.sarif --fail-on high
```

The CLI audits the working tree statically; it does not execute project code. `--analyzers secrets,devops,…`
selects a subset. Exit codes: `0` below threshold, `1` findings at/above `--fail-on`, `2` usage error.

`--fail-on policy` gates with the `[gate]` section of the repository's `.eval.toml` (see section E), and
`--changed [REF]` reports and gates only on files changed since `REF` (default `HEAD`, untracked files included),
while still analyzing the whole tree for context. `scripts/eval_ci.py --fail-on policy` uses the gate of the policy
configured in eVal (organization ← repository ← `.eval.toml`).

## C. GitHub App (automatic pull-request checks)

With the GitHub App, nobody has to add a workflow: every pull request in an installed repository is audited, and
the result appears as an **eVal audit** check run with inline annotations on the blocking findings. Pushes to the
default branch are re-audited too, so pull-request baselines stay current.

1. GitHub → Settings → Developer settings → GitHub Apps → **New GitHub App**.
   * Webhook URL `https://YOUR-HOST/webhooks/github`, a random webhook secret.
   * Setup URL `https://YOUR-HOST/integrations/github/app/setup`, and tick **Request user authorization (OAuth)
     during installation** (eVal uses it to verify that the person installing can access the installation).
   * Repository permissions: *Contents: read*, *Pull requests: read*, *Checks: read & write*, *Metadata: read*.
     Add *Contents: write*, *Pull requests: write* and *Issues: write* for AI fix pull requests, PR comments and
     issues.
   * Subscribe to events: *Pull request*, *Push*, *Check run*.
2. Generate a private key and a client secret, then set `GITHUB_APP_ID`, `GITHUB_APP_SLUG`,
   `GITHUB_APP_PRIVATE_KEY` (or `GITHUB_APP_PRIVATE_KEY_FILE`), `GITHUB_APP_WEBHOOK_SECRET`, `GITHUB_APP_CLIENT_ID`,
   `GITHUB_APP_CLIENT_SECRET` and `EVAL_PUBLIC_URL`.
3. In eVal: **Settings → Integrations → Install GitHub App** (admins). Repositories of the installed account that
   are already in eVal switch to the App's short-lived tokens; turn automatic audits off per repository under
   **Automation** on the repository page.

The check run passes or fails by the policy gate; a failed audit reports *neutral*. **Re-run** on GitHub starts a
new audit. Webhook deliveries without a valid `X-Hub-Signature-256` are rejected, events for installations not
linked to an organization are ignored, and a webhook never creates repositories.

## D. Inside AI coding agents

eVal can check code while an agent writes it, not only after a pull request is opened.

**Claude Code hook.** `eval-audit hook` reads a `PostToolUse` event on stdin. After each `Write`/`Edit`, it audits
the project with the fast built-in analyzers (offline, typically about a second) and, if the edited file has
findings at or above `high` (`--fail-on` or `EVAL_HOOK_FAIL_ON`), exits with code 2 and prints them. Claude Code
passes that to the agent, which fixes its own output. Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "eval-audit hook --fail-on high" }] }
    ]
  }
}
```

**MCP server.** `eval-audit mcp --root .` serves the Model Context Protocol on stdio with two tools:
`eval_check_files` (fast check of files the agent changed) and `eval_audit` (whole project, optionally
`changed_only`). Paths outside `--root` are refused. Claude Code: `claude mcp add eval -- eval-audit mcp --root .`;
Cursor: add it under *Settings → MCP* with command `eval-audit` and args `["mcp", "--root", "."]`.

## E. Policies (`.eval.toml`)

```toml
[gate]
fail_on = "high"                  # critical | high | medium | low | info | never
max_change_risk = "medium"        # pull requests: fail when the change risk is above this
require_analyzers = ["semgrep"]   # fail if these analyzers did not run

[[gate.paths]]                    # first match wins
pattern = "src/payments/**"
fail_on = "medium"

[rules]
disable = ["eval:maintainability.*"]
[rules.severity]
"bandit:B101" = "low"

[analyzers]
disable = ["mypy"]

[paths]
exclude = ["vendor/**", "migrations/**"]
```

Policies layer: organization default (**Settings → Policy**) ← repository override ← the repository's `.eval.toml`.
On pull-request audits a `.eval.toml` that the pull request changes is ignored, so a PR cannot relax the gate that
judges it; organizations can also ignore repository files entirely. The effective policy is stored with each audit.
