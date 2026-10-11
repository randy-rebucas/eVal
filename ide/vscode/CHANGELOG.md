# Changelog

## Unreleased

- **eVal: Apply Fix Proposal…** applies an eVal AI fix, as generated or edited by hand, to the working tree. Each
  change must still match the local file, it is shown in the refactor preview first, and nothing is saved
  automatically. Also opened by `vscode://randy-rebucas.eval-auditor/applyFix?id=<fix id>` links.

## 0.1.0

- Open findings of the latest eVal audit as diagnostics, with hover details (AI explanation, suggested patch,
  CWE/OWASP mapping, reachability).
- Quick fixes to triage findings: fixed, false positive, accepted risk (reason, owner, review date), with undo.
- Run an audit of the current branch with progress; automatic reload on branch switch, pull or commit.
- Automatic linking from the git remote; status bar score and risk level.
- Runs in VS Code desktop, Remote / Codespaces / Dev Containers, and vscode.dev / github.dev.
