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
