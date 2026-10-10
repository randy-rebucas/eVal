# eVal Local — on-device AI auditing

Objective: *create a working product that uses AI running locally on a user's device to solve a real problem.*

This document describes how eVal meets that objective: what exists, how it works, and what is still open.

## The problem

Developers increasingly ship AI-generated code they have not fully reviewed. The teams that most need a
production-readiness audit — fintech, healthcare, government, agencies under NDA, anyone with proprietary IP —
are often **not allowed to send source code to a cloud scanner or a cloud LLM**.

**eVal Local** gives them a full audit — deterministic findings, scores, plus AI explanations and suggested
fixes — with no source code leaving the machine: no API key, no account, and it works with the network
switched off.

This extends guarantees eVal already makes (redacted AI inputs, AI never changes scores, audited code is never
executed): with a local model, even the redacted snippets stay on the device.

## Quick start

```bash
pip install -e ".[ai]"
ollama pull qwen2.5-coder:7b                               # or start LM Studio / llama.cpp's server
eval-audit doctor                                          # analyzers, model server, offline readiness
eval-audit ./repo --ai local --offline --format html -o report.html
```

## Current state

| Requirement | Status |
|---|---|
| Working product | 20 analyzers, deterministic scoring, Markdown/HTML/JSON/SARIF reports, CLI and web app |
| AI | `Enricher` explains findings, suggests remediation and patches, rates false-positive likelihood and writes an architectural summary ([enrich.py](../eval_engine/ai/enrich.py)) |
| Runs on the user's device | `eval-audit --ai local` against a model server on the same machine ([local.py](../eval_engine/ai/local.py)); loopback only, proxies ignored, no API key |
| Fully offline | `eval-audit --offline` skips network-dependent checks and blocks outbound connections ([netguard.py](../eval_engine/netguard.py)); every connection eVal can make is declared in [NETWORK.md](NETWORK.md) |
| Verified on a real model | **Open** — see [Open items](#open-items) |

## How it works

### 1. Local AI in the CLI — done

```bash
eval-audit ./repo --ai local                                            # Ollama, qwen2.5-coder:7b
eval-audit ./repo --ai local --ai-model llama3.1:8b --ai-url http://localhost:1234/v1   # LM Studio
```

- `--ai local` accepts **loopback URLs only** (`127.0.0.1`, `::1`, `localhost`) and ignores
  `HTTP(S)_PROXY`/`ALL_PROXY`, so model traffic cannot be routed off the machine. "Local" is enforced, not
  claimed.
- Defaults come from `EVAL_LOCAL_AI_MODEL` and `EVAL_LOCAL_AI_URL`.
- If the model server is unreachable, the audit still completes, a warning points to `eval-audit doctor`, and
  the report says why AI is missing. `--fail-on` gates on deterministic findings only.

### 2. Strict offline mode — done

`--offline`:

- Skips analyzers that need network access in their current configuration, with the reason shown in coverage;
  their categories are reported as *not assessed*:
  - **OSV.dev**: always skipped.
  - **Semgrep**: runs if `EVAL_SEMGREP_CONFIG` points to a local rules path, otherwise skipped (registry rules).
  - **Trivy**: runs with `--skip-db-update --skip-java-db-update --skip-check-update --offline-scan` if
    `EVAL_TRIVY_CACHE_DIR` holds a database (`trivy image --download-db-only --cache-dir DIR`), otherwise skipped.
- Blocks every non-loopback DNS lookup and connection from eVal's own process for the duration of the audit,
  and records each attempt. The report states "outbound connections blocked: N" (expected 0). External tools run
  as subprocesses and are kept offline by the flags above.
- Still allows a local model server, so `--offline --ai local` is the fully private mode.

### 3. Prompts sized for small models — done

- Local runs explain the 6 most severe findings (`--ai-max-findings`) in batches of 3 (`--ai-batch-size`), with
  4,096 output tokens per request, then one summary request.
- A response that is not valid JSON or does not match the schema is retried once (`AIOutputError`); connection
  errors and timeouts are not. Invalid output is still discarded, never partially trusted. Retries are recorded
  in `ai_summary.retries`.
- Prompts stay versioned (`PROMPT_VERSION`); the report names model, provider and prompt version.

### 4. AI as a triage assistant — done

- Within a severity, the report lists findings the AI rated unlikely to be false positives first, unrated ones
  next, likely false positives last. Ordering only — severities and scores stay deterministic.
- Each explained finding shows the AI explanation, false-positive estimate, remediation steps and a suggested
  patch marked "AI-generated, review before use", labelled with the model name.

### 5. One-command setup — done (`doctor`); local UI open

`eval-audit doctor` lists installed and missing analyzers, checks the model server (`GET /v1/models`, loopback
only) and whether the model is present (with the `ollama pull` command if not), and lists which checks
`--offline` would skip. Exit code 0 means `--ai local` is ready. It never installs tools or downloads models.

## Recommended models (to be benchmarked)

| Model | Size | Notes |
|---|---|---|
| `qwen2.5-coder:7b` | ~4.7 GB | Default; strong on code, reliable JSON |
| `llama3.1:8b` | ~4.9 GB | General-purpose fallback |
| `qwen2.5-coder:3b` | ~1.9 GB | Low-memory machines; consider `--ai-batch-size 2` |

## Demo

1. Turn the network off.
2. `eval-audit doctor`
3. `eval-audit ./ai-generated-app --ai local --offline --format html -o report.html`
4. Open the report: scored findings with evidence, AI explanations and patches labelled with the local model,
   likely-real findings first, and "outbound connections blocked: 0".

## Acceptance criteria

- [x] `eval-audit --ai local` produces AI explanations with only a local model server running.
- [x] Non-loopback AI URLs are rejected; proxy variables are ignored for local AI (tested).
- [x] `--offline` completes without network access; unavailable checks are reported as *not assessed*; blocked
      connection attempts are counted in the report (tested end to end with a local model server).
- [x] AI output never changes severities or scores (covered by tests).
- [x] Tests use a fake local model server; no real model is needed in CI.
- [x] README documents setup in under five commands.
- [ ] Verified against a real Ollama model on a typical laptop (latency and output quality recorded).

## Open items

- **Real-model verification and measurements:** run the recommended models on an ordinary laptop (CPU-only and
  with a GPU), record audit time, model latency, JSON validity and retry rate, and fill in the model table.
- **`eval-audit serve`** (optional): a single-user local UI on SQLite with inline tasks, so the dashboard can be
  used without Docker, PostgreSQL or Redis.
- **Web app parity:** the web app supports OpenAI-compatible local endpoints through `EVAL_AI_ALLOWED_BASE_URLS`,
  but has no offline mode; the network guard is CLI-only because it patches sockets process-wide.
