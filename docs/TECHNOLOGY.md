# Technology, models and third-party assets

Everything eVal is built with, runs, calls or ships, and where each piece runs. Version constraints come from
[pyproject.toml](../pyproject.toml) and the [Dockerfile](../Dockerfile). Licenses are listed for convenience;
confirm them against each project before redistributing eVal or its Docker image.

Legend: **Device** = runs on the user's machine · **Server** = your own infrastructure · **Cloud** = third-party
service · **Bundled** = shipped inside the repository or image.

## AI models

eVal bundles no model. Local models are downloaded by the user through Ollama or a similar runtime.

| Model | Role | Where | License |
|---|---|---|---|
| `qwen2.5-coder:7b` (default) | `--ai local`: finding explanations, remediation steps, suggested patches, false-positive estimates, summary | Device | Apache-2.0 |
| `llama3.1:8b` | Suggested general-purpose alternative | Device | Llama 3.1 Community License |
| `qwen2.5-coder:3b` | Suggested low-memory alternative | Device | Qwen Research License (non-commercial terms) |
| Any model on an OpenAI-compatible server | `--ai local` (CLI); self-hosted AI in the web app | Device / Server | Per model |
| Claude Opus 5.5 (`claude-opus-5-5`) | Default model of the optional Anthropic provider in the web app | Cloud, opt-in | Anthropic commercial terms |
| OpenAI models (operator's choice) | Optional OpenAI provider in the web app | Cloud, opt-in | OpenAI commercial terms |

Recommended local models have not been benchmarked yet; see [LOCAL_AI.md](LOCAL_AI.md).

## AI runtimes and SDKs

| Component | Role | Where | License |
|---|---|---|---|
| Ollama | Default local model server (`http://127.0.0.1:11434/v1`) | Device | MIT |
| LM Studio, llama.cpp, vLLM | Alternative local servers through the same OpenAI-compatible API | Device / Server | Per project |
| `openai` Python SDK (>=1.50) | Client for local servers (JSON mode) and the OpenAI cloud (strict JSON schema) | Device / Server | Apache-2.0 |
| `anthropic` Python SDK (>=0.40) | Claude Messages API with structured JSON output | Server | MIT |
| `httpx2` | HTTP client inside the OpenAI SDK; eVal sets `trust_env=False` so local AI ignores proxy variables | Device / Server | Check upstream |

How eVal uses these safely is described in [SECURITY.md](SECURITY.md) §5 and [LOCAL_AI.md](LOCAL_AI.md).

## AI tools used to build eVal

| Tool | Use |
|---|---|
| Claude Code with Claude Opus 5.5 | Development assistant for code, tests and documentation; commits it contributed to carry a `Co-Authored-By: Claude Opus 5.5` trailer |

All generated code is reviewed, tested (269 tests) and linted (Ruff, Bandit) like any other change.

## Languages and frameworks

| Component | Role | License |
|---|---|---|
| Python 3.12 | Engine, CLI, web app | PSF |
| Flask 3 | Web framework | BSD-3-Clause |
| Jinja2 | HTML templates (autoescaping) | BSD-3-Clause |
| Flask-SQLAlchemy 3, SQLAlchemy 2 | ORM | BSD-3-Clause / MIT |
| Flask-Migrate 4 (Alembic) | Database migrations | MIT |
| Flask-Login | Sessions | MIT |
| Flask-WTF | Forms and CSRF protection | BSD-3-Clause |
| Celery 5 | Background audit queue | BSD-3-Clause |
| JavaScript, CSS | UI behaviour and theme (`app.js`, `theme.js`, `app.css`), no framework | Own code |

## Python libraries

| Library | Role | License |
|---|---|---|
| psycopg 3 (binary) | PostgreSQL driver | LGPL-3.0 |
| redis-py 5 | Celery broker, rate limiting | MIT |
| GitPython 3 | Hardened shallow clones | BSD-3-Clause |
| cryptography | Fernet encryption of stored GitHub tokens and AI keys | Apache-2.0 / BSD |
| requests 2 | GitHub API, OSV.dev | Apache-2.0 |
| email-validator 2 | Email validation | Unlicense |
| python-dotenv | `.env` loading | BSD-3-Clause |
| gunicorn | Production WSGI server (not on Windows) | MIT |
| pytest, pytest-cov | Tests and coverage (development only) | MIT |

Python standard library modules with a notable role: `ast` (parsing code without running it), `socket`
(offline network guard), `urllib` (local model server check), `zipfile` (hardened extraction).

## Static analysis tools

Each tool is optional; a missing tool is reported as *not assessed*. All run as sandboxed subprocesses with
eVal's own configuration, never the repository's.

| Tool | Version | Checks | Network | License |
|---|---|---|---|---|
| Ruff | >=0.6 | Python lint | None | MIT |
| Bandit | >=1.7.9 | Python security | None | Apache-2.0 |
| mypy | >=1.11 | Python types | None | MIT |
| ESLint | 9 | JavaScript/TypeScript lint | None | MIT |
| TypeScript (`tsc`) | 5 | Type checking | None | Apache-2.0 |
| Semgrep CE | >=1.90 | Multi-language security analysis | Downloads registry rules unless configured locally | LGPL-2.1 (engine); rules have their own license, see below |
| Trivy | 0.75.0 (pinned, checksum-verified) | Vulnerable dependencies, IaC misconfigurations, secrets | Downloads its databases | Apache-2.0 |

Built-in analyzers (own code, run on the device): secrets, API security, database access and schema design,
DevOps/CI and observability, testing, dependency hygiene, maintainability, architecture (import cycles),
performance and scalability (static estimates), configuration assumptions, taint analysis, AI-generated-code
patterns, and the OSV.dev lookup.

## External APIs and data sources

| Service | Role | Data sent | Optional | Terms |
|---|---|---|---|---|
| OSV.dev (`api.osv.dev`) | Known vulnerabilities for pinned dependencies | Ecosystem, package name, version | Yes: `EVAL_OSV_ENABLED=0` or `--offline` | Free public API; advisory data mostly CC-BY-4.0 |
| Semgrep Registry (`semgrep.dev`) | Rule pack `p/default` | Rule request only | Yes: local `EVAL_SEMGREP_CONFIG` | Semgrep Rules License (restricts offering the rules as a hosted service; review before running a public SaaS) |
| Trivy databases (`mirror.gcr.io`, `ghcr.io`) | Vulnerability, Java and checks databases | Download request only | Yes: pre-seeded cache | Aqua Security terms; data from upstream advisories |
| GitHub REST API and git over HTTPS | Repositories, branches, commits, PR audits, issues, PR comments | Repository identifiers; issue and comment text (redacted) | Web app only | GitHub terms |
| Anthropic API | Cloud AI | Redacted snippets of detected findings | Web app only, opt-in | Anthropic terms |
| OpenAI API | Cloud AI | Redacted snippets of detected findings | Web app only, opt-in | OpenAI terms |

The complete network declaration is in [NETWORK.md](NETWORK.md).

## Infrastructure

| Component | Version | Role | License |
|---|---|---|---|
| PostgreSQL | 16 (`postgres:16-alpine`) | Database | PostgreSQL License |
| Redis | 7 (`redis:7-alpine`) | Broker, rate limits | BSD-3-Clause up to 7.2; RSALv2/SSPLv1 from 7.4. Pin `redis:7.2-alpine` or use Valkey if this matters |
| Docker, Docker Compose | — | Packaging and deployment | Apache-2.0 |
| `python:3.12-slim-bookworm` | — | Base image | PSF / Debian licenses |
| Node.js, npm (Debian packages) | — | Runtime for ESLint and TypeScript | MIT / Artistic-2.0 |
| GitHub Actions | — | CI: Ruff, Bandit, tests, migration check | GitHub terms |

## UI assets

| Asset | Version | Delivery | License |
|---|---|---|---|
| Bootstrap | 5.3.3 | jsDelivr CDN, with Subresource Integrity hashes | MIT |
| Bootstrap Icons | 1.11.3 | jsDelivr CDN, with Subresource Integrity hashes | MIT |
| IBM Plex Mono (400, 600) | — | Bundled in `eval_app/static/fonts/` with its license file | SIL Open Font License 1.1 |

HTML reports produced by eVal use inline CSS and load no external assets.

## Standards and references

| Standard | Use |
|---|---|
| SARIF 2.1.0 | Report format for GitHub code scanning and other tools |
| CWE (cwe.mitre.org) | Weakness references in findings |
| OpenAI-compatible Chat Completions API | Common interface to local model servers |
| JSON Schema | Validation of AI output |
| Fernet | Symmetric encryption format for stored credentials |
