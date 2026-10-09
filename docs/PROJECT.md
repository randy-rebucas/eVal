# eVal Local: private, on-device code auditing for AI-generated software

**AI generates code. eVal verifies it, without your code leaving your machine.**

## Short descriptions

**One line:** An offline code auditor that checks AI-generated software for production readiness and uses a
local AI model to explain each problem and suggest a fix.

**About 50 words:** eVal audits a codebase for security, dependency, testing, DevOps and maintainability problems
using 17 static analyzers, scores the results deterministically, then uses an AI model running on the user's own
device to explain each finding and suggest a fix. With `--offline --ai local`, nothing leaves the machine. No
API key, no account, no cloud.

## The problem

Developers now ship large amounts of AI-generated code that nobody has fully reviewed. It often contains
hard-coded secrets, injectable SQL, missing timeouts, unpinned dependencies and absent tests. These pass a quick
read but fail in production.

The teams with the most to lose (fintech, healthcare, government, agencies under NDA, any company with
proprietary code) usually **cannot send their source code to a cloud scanner or a cloud LLM**. Policy,
contracts or regulation forbid it. So they either skip automated review or get scanner output with no
explanation of what to do about it.

## The solution

eVal Local runs the entire audit on the developer's computer:

1. **Static analysis:** 17 analyzers (Ruff, Bandit, mypy, ESLint, TypeScript, Semgrep, Trivy, plus built-in
   checks for secrets, API security, database access, DevOps/CI, tests, dependencies, architecture and
   performance) produce findings with file, line, evidence and severity. The code is never executed.
2. **Deterministic scoring:** documented, reproducible scores per category and overall. Categories that
   could not be checked are shown as *not assessed*, never as passing.
3. **Local AI:** a model served on the same machine (Ollama, LM Studio or llama.cpp; default
   `qwen2.5-coder:7b`) explains the most severe findings in plain language. For each one it gives remediation
   steps, a suggested patch, and an estimate of how likely the finding is a false positive. It also writes an
   overall summary.
4. **Report:** HTML, Markdown, JSON or SARIF. Within each severity, findings the AI judges most likely to be
   real come first.

```bash
ollama pull qwen2.5-coder:7b
eval-audit doctor                                              # is this machine ready?
eval-audit ./my-app --ai local --offline --format html -o report.html
```

## How the AI runs locally

| Guarantee | How it is enforced |
|---|---|
| The model is on this machine | `--ai local` accepts only loopback addresses (`127.0.0.1`, `::1`, `localhost`); anything else is refused |
| Traffic cannot be routed elsewhere | Proxy environment variables are ignored for the model connection |
| Nothing else goes online | `--offline` skips checks that need the internet and blocks every outbound connection from eVal; the report states how many were blocked (expected 0) |
| Small models work | Findings are sent in batches of 3, with one retry when the model returns malformed output |
| AI cannot distort results | The model receives copies of already-detected findings with secrets redacted; it can add explanations but cannot change severities or scores. Output that does not match the expected schema is discarded |
| It degrades gracefully | If the model server is down, the audit still completes and the report says why AI is missing |

All network use is declared in [NETWORK.md](NETWORK.md), and a test fails if code gains a network connection
without declaring it.

## Who it is for

- Developers who use AI coding assistants and want a review before merging.
- Teams in regulated or confidential environments that cannot use cloud scanners or cloud LLMs.
- CI pipelines: `--fail-on high` gates a build on deterministic findings, with or without AI.

For teams that want a shared dashboard, the same engine also powers an optional self-hosted web app with
projects, audit history, triage with owners and review dates, GitHub integration and an API.

## Technology

- Python 3.12, with the analysis engine independent of the web framework
- Local AI through the OpenAI-compatible API exposed by Ollama, LM Studio, llama.cpp and vLLM
- Optional server: Flask, Celery, PostgreSQL, Redis, Docker Compose with a hardened, sandboxed worker
- 269 automated tests, including an end-to-end run against a local model server with outbound connections
  blocked

## Status

| Working today | Still open |
|---|---|
| Full static audit and scoring, offline | Measured speed and output quality on real local models on an ordinary laptop |
| `--ai local` explanations, patches and AI-ordered triage | A local web dashboard without Docker (`eval-audit serve`) |
| `--offline` with a count of blocked connections | Offline mode for the server's worker |
| `eval-audit doctor` readiness check | |
| Self-hosted team server with GitHub and API | |

## Documentation

[TECHNOLOGY.md](TECHNOLOGY.md) (models, frameworks, libraries, APIs and assets) ·
[LOCAL_AI.md](LOCAL_AI.md) (design of the on-device AI) · [NETWORK.md](NETWORK.md) (what runs locally and
what needs the internet) · [DEPLOYMENT.md](DEPLOYMENT.md) (installation) · [SECURITY.md](SECURITY.md)
(threat model) · [SCORING.md](SCORING.md) (how scores are computed)
