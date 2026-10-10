# Network use: what runs locally and what needs the internet

This is eVal's declaration of every network connection it makes. It covers the CLI (`eval-audit`), the web
app and its worker, and installation. The source of truth for analyzers is `Analyzer.network_use` in the code;
[tests/engine/test_network_declaration.py](../tests/engine/test_network_declaration.py) fails if an analyzer
gains network code without declaring it, or if this page stops listing it. Run `eval-audit doctor` to see the
same declaration for your machine.

**Audited code never leaves the machine through any analyzer.** The only components that can send content
derived from source code to a third party are the cloud AI providers, which are opt-in, receive only redacted
snippets of already-detected findings, and are not used in local mode.

## Summary

| Mode | Internet needed? |
|---|---|
| `eval-audit PATH --offline --ai local` | **No.** Everything runs on the machine; outbound connections from eVal are blocked and counted |
| `eval-audit PATH --ai local` | Only for OSV.dev, the PyPI/npm package registries, Semgrep registry rules and the Trivy database (metadata in, package names and versions out) |
| `eval-audit PATH` (defaults) | Same as above |
| Web app | Yes: browser UI assets from a CDN, GitHub for repositories, optional cloud AI |
| Installation | Yes, once: Python packages, optional tools, the Trivy database, the local model |

## Analysis engine (CLI and worker)

### Runs entirely on this machine

| Component | What it does |
|---|---|
| Workspace, ZIP extraction, language detection | Reads files; never executes repository code |
| Built-in analyzers: `secrets`, `api_security`, `database`, `devops`, `testing`, `dependencies` (hygiene), `maintainability`, `architecture`, `performance`, `ai_code` (undeclared imports, lookalike package names from a bundled list, stubs, placeholders, hollow tests) | Pure Python static checks |
| `ruff`, `bandit`, `mypy`, `eslint`, `tsc` | Installed tools run in the sandbox; no network use |
| Deduplication, fingerprints, scoring, lifecycle | Deterministic, local |
| Reports: Markdown, HTML, JSON, SARIF | Self-contained files; the HTML report has inline CSS and loads nothing |
| Local AI (`--ai local`) | Talks only to a model server on a loopback address (`127.0.0.1`, `::1`, `localhost`); `HTTP(S)_PROXY` and `ALL_PROXY` are ignored so traffic cannot be routed off the machine |
| `eval-audit doctor` | Reads the local tool path; queries the local model server's `/v1/models` (loopback only) |

### Needs the internet

| Component | Destination | Sent | Received | Offline (`--offline`) |
|---|---|---|---|---|
| `osv` | `api.osv.dev` | Ecosystem, package name and version of pinned dependencies. No source code | Advisories | Skipped (reported as not assessed). Disable anytime with `EVAL_OSV_ENABLED=0` |
| `registry` | `pypi.org`, `registry.npmjs.org` | Names of declared dependencies (one request per package, at most 300). No source code, no versions | Whether the package exists and when it was first published | Skipped (reported as not assessed). Also skipped when the project configures a private index. Disable anytime with `EVAL_REGISTRY_CHECK_ENABLED=0` |
| `semgrep` | `semgrep.dev` | Rule-pack request only; metrics and version check are off | Rules (`p/default`) | Runs if `EVAL_SEMGREP_CONFIG` is a local rules path, otherwise skipped |
| `trivy` | `mirror.gcr.io`, `ghcr.io` | Database download requests only | Vulnerability, Java and checks databases | Runs on a pre-seeded `EVAL_TRIVY_CACHE_DIR` (with update and online lookups disabled), otherwise skipped |
| Cloud AI (web app only): Anthropic, OpenAI | `api.anthropic.com`, `api.openai.com` | Redacted titles, descriptions and evidence snippets of a capped number of detected findings (default 15), language profile, scores. Never whole files | Explanations, summary | Not available in the CLI; the CLI supports local AI only |

`--offline` also blocks every non-loopback DNS lookup and connection from eVal's own process during the
audit, and the report states how many were blocked (expected: 0). External tools run as separate programs, so
they are kept offline by the flags above or skipped, not by that guard.

## Web app and worker

| Component | Destination | When | Notes |
|---|---|---|---|
| PostgreSQL, Redis | Your own servers (`postgres`, `redis` in Compose) | Always | Not internet; required infrastructure |
| GitHub API | `api.github.com` or `GITHUB_API_URL` (GitHub Enterprise) | Connecting repositories, listing branches and commits, PR audits, creating issues and PR comments | Token sent only to the host it was issued for |
| GitHub App (optional) | Inbound: GitHub → `https://YOUR-HOST/webhooks/github`. Outbound: `api.github.com` | Pull request, push, check-run and installation events | Deliveries are rejected unless signed with `GITHUB_APP_WEBHOOK_SECRET` (HMAC-SHA256). Outbound calls mint one-hour installation tokens and create/update check runs |
| Git fetch | `github.com` or hosts in `EVAL_GIT_ALLOWED_HOSTS` | Auditing a connected repository | HTTPS only, shallow fetch of one ref. ZIP uploads need no network |
| Analyzers | As in the engine table above | Every audit | The worker has no `--offline` switch; use `EVAL_OSV_ENABLED=0`, `EVAL_REGISTRY_CHECK_ENABLED=0`, a local `EVAL_SEMGREP_CONFIG` and a persistent `EVAL_TRIVY_CACHE_DIR` for air-gapped installs |
| AI providers | `api.anthropic.com`, `api.openai.com`, or an OpenAI-compatible URL in `EVAL_AI_ALLOWED_BASE_URLS` | Only when an org enables AI | A local model gateway (e.g. `http://ollama:11434/v1`) keeps AI on your own infrastructure |
| Browser UI assets | `cdn.jsdelivr.net` (Bootstrap 5.3.3, Bootstrap Icons 1.11.3) | Loaded by the user's browser on every page | Pinned versions with Subresource Integrity hashes; the CSP allows only those package paths. Without internet the UI still works but is unstyled; self-host these files for air-gapped use |
| CI script (`scripts/eval_ci.py`) | Your eVal server (`EVAL_URL`) | In CI | HTTPS required except for localhost |

## Installation (one-time, needs the internet)

| Step | Destination |
|---|---|
| `pip install` eVal and its extras | PyPI |
| Docker image build (Python tools, Node tools, Trivy binary) | PyPI, npm registry, GitHub releases |
| Trivy database for offline use: `trivy image --download-db-only --cache-dir DIR` | `mirror.gcr.io` / `ghcr.io` |
| Semgrep rules for offline use (download a rules pack to a directory, set `EVAL_SEMGREP_CONFIG`) | `semgrep.dev` |
| Local model: install Ollama, `ollama pull qwen2.5-coder:7b` | `ollama.com` |

After these steps, `eval-audit PATH --offline --ai local` needs no network connection.
