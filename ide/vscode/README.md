# eVal for VS Code

Shows the open findings of your latest eVal audit as editor diagnostics (squiggles and the Problems panel), lets you
run an audit of the checked-out branch, and records triage decisions without leaving the editor. It talks to an
eVal server through the JSON API v1 (`docs/API.md`) with a personal API token.

## Features

- **Diagnostics.** Findings appear on their lines: critical/high as errors, medium as warnings, low as information,
  info as hints. The rule code in the Problems panel links to the finding page in eVal.
- **Hover.** Description, AI explanation and remediation steps, suggested patch, CWE/OWASP mapping, dependency
  reachability and references.
- **Quick fixes** (`Ctrl+.` on a finding): open in eVal, mark fixed, mark false positive, accept risk (reason,
  owner and review date, same rules as the web UI). Each decision can be undone from the notification.
- **Run audit** of the current branch, with progress. Warns when local commits are not pushed, because eVal
  audits what is on GitHub.
- **Status bar**: score and risk level of the loaded audit. A history icon means the audit is of a different
  commit than your checkout, so line numbers may be off.
- Findings reload automatically when you switch branch, pull or commit.
- **Apply Fix Proposal.** Pick one of the repository's AI fixes (as generated, or edited by hand in eVal), or
  paste a fix link. The fix is applied only if every change still matches your files exactly, though changes may
  sit on different lines than in the audited commit. VS Code's refactor preview shows each edit before anything is
  written, and nothing is saved for you. Then run your tests in the terminal and commit. The **Apply in VS Code
  desktop** link on a fix page runs the same command, and so does **Open in Codespaces** followed by this command.

## Which audit is shown

The extension picks, in order: a succeeded audit of the checked-out commit; else the newest succeeded audit of the
current branch; else the newest succeeded audit of any branch. Only open findings are shown. Accepted risks, false
positives and fixed findings are hidden.

## Setup

1. In eVal, create a token under **Settings → API tokens**. Starting audits and triage need the `member` role.
2. Run **eVal: Sign In** and enter the server URL and token. The token is kept in VS Code's secret storage, per
   server URL.
3. The workspace is linked automatically when exactly one eVal GitHub repository matches a git remote
   (`owner/name`). Otherwise run **eVal: Link Workspace to Repository** and pick one. Uploaded (ZIP) repositories can
   be linked and viewed, but new audits for them are started from the web UI or CLI.

Click the status bar item for all commands.

| Setting | Default | |
|---|---|---|
| `eval.serverUrl` | `http://localhost:8000` | eVal base URL |
| `eval.minimumSeverity` | `info` | hide findings below this severity |
| `eval.refreshOnStartup` | `true` | load findings on open and when the checked-out commit changes |

## Cloud IDEs

| Environment | How it runs | Notes |
|---|---|---|
| GitHub Codespaces, Dev Containers, Remote-SSH, Gitpod, code-server | Node build in the remote extension host | Works like desktop. `eval.serverUrl` is resolved **from the remote machine**: use the public eVal URL, or `http://localhost:5000` only when eVal runs in the same container. |
| vscode.dev, github.dev | Browser build in a web worker | Linked from the URL (`vscode-vfs://github/owner/name`); no git extension, so the default branch's audit is shown and audits run on the default branch. The server must allow the origin (`EVAL_API_CORS_ORIGINS`, on by default) and be **HTTPS**; browsers block calls from these https pages to other hosts over http. |

Install by ID, `randy-rebucas.eval-auditor`: from the Extensions view (Marketplace in VS Code and Codespaces, Open
VSX in Gitpod and code-server), or preinstall it for everyone opening the repository in Codespaces / Dev Containers:

```jsonc
// .devcontainer/devcontainer.json
{ "customizations": { "vscode": { "extensions": ["randy-rebucas.eval-auditor"] } } }
```

## Develop

```bash
cd ide/vscode
npm ci
npm test          # compiles and runs unit tests (no VS Code needed)
npm run package   # builds eval-auditor.vsix
code --install-extension eval-auditor.vsix
```

To debug from the repository root, press F5 and pick **eVal extension** (desktop/Node build) or **eVal extension
(web worker)** (the browser build, as on vscode.dev). Both compile first. `npx @vscode/test-web
--extensionDevelopmentPath=ide/vscode --browserType=chromium .` opens the web build in a real browser.

### Release

Published as `randy-rebucas.eval-auditor` to the Visual Studio Marketplace and Open VSX by
`.github/workflows/release-vscode.yml`. Full guide, including account setup:
[docs/IDE_PUBLISH.md](https://github.com/randy-rebucas/eVal/blob/main/docs/IDE_PUBLISH.md). In short: bump
`version` and `CHANGELOG.md`, then push a matching tag:
`git tag vscode-v0.1.1 && git push origin vscode-v0.1.1`. The workflow needs the repository secrets `VSCE_PAT`
and `OVSX_PAT` in the `vscode-marketplace` environment. Manual release: `npm run package`, then
`VSCE_PAT=… npm run publish:marketplace` and `OVSX_PAT=… npm run publish:openvsx`.

`npm run package` bundles both builds with esbuild (`dist/node`, `dist/web`). Layout: `src/api.ts` (API client and audit selection), `src/findings.ts` (mapping to editor concepts, both plain
Node and unit-tested), `src/git.ts` (built-in git extension API), `src/extension.ts` (VS Code wiring).
