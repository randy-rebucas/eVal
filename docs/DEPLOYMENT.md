# Deploying eVal

eVal ships in two forms. Pick the one that matches how it will be used:

| Form | For | Needs |
|---|---|---|
| [**eVal Local** (CLI)](#1-eval-local-cli-on-a-workstation) | One developer or a CI job auditing code on their own machine; private, on-device AI | Python 3.12, optionally Ollama |
| [**eVal server** (web app + worker)](#2-eval-server-docker-compose) | A team or organization: projects, audit history, triage, GitHub integration, API | Docker, a Linux host, a TLS reverse proxy |
| [**eVal server on Render**](#3-render) | The same server, managed hosting, one-click Blueprint | A Render account (paid plans) and a Git repository |

Related: [SECURITY.md](SECURITY.md) (threat model), [NETWORK.md](NETWORK.md) (what needs the internet),
[LOCAL_AI.md](LOCAL_AI.md) (on-device AI), [CI.md](CI.md) (pipelines).

---

## 1. eVal Local (CLI) on a workstation

### Install

```bash
git clone <your eVal repository> eval && cd eval
python3.12 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install ".[ai,analyzers]"                            # eval-audit, AI clients, Ruff, Bandit, mypy
```

Further analyzers (each one that is missing is reported as *not assessed*, never silently skipped):

| Analyzer | Install |
|---|---|
| Semgrep | `pip install "semgrep>=1.90"` (Linux/macOS) |
| ESLint, TypeScript | `npm install --prefix .tools eslint@9 typescript@5`, then `EVAL_TOOL_PATH=<repo>/.tools/node_modules/.bin` |
| Trivy | Release binary from github.com/aquasecurity/trivy (the server image pins 0.75.0) |

### Local AI (optional)

```bash
# Install Ollama from ollama.com, then:
ollama pull qwen2.5-coder:7b            # ~4.7 GB; qwen2.5-coder:3b (~1.9 GB) for low-memory machines
eval-audit doctor                       # exit 0 = ready
```

Any OpenAI-compatible server on the same machine works (LM Studio, llama.cpp): pass `--ai-url`. Only loopback
addresses are accepted. Defaults can be set with `EVAL_LOCAL_AI_MODEL` and `EVAL_LOCAL_AI_URL`.

### Run

```bash
eval-audit ./repo --format html -o report.html                   # deterministic audit
eval-audit ./repo --ai local --format html -o report.html        # + AI explanations from the local model
eval-audit ./repo --ai local --offline --format html -o report.html   # nothing leaves the machine
eval-audit ./repo --fail-on high                                 # exit 1 on high/critical findings (CI gate)
```

### Fully offline workstation

`--offline` skips OSV.dev and blocks outbound connections. To keep Semgrep and Trivy assessed without the
internet, prepare them once while online:

```bash
# Trivy database
trivy image --download-db-only --cache-dir ~/.cache/eval-trivy
export EVAL_TRIVY_CACHE_DIR=~/.cache/eval-trivy
# Semgrep rules: save a rules pack (YAML) to a directory
export EVAL_SEMGREP_CONFIG=~/eval-rules/
```

`eval-audit doctor` shows what `--offline` will skip on the machine.

---

## 2. eVal server (Docker Compose)

### Architecture

```
            HTTPS                     HTTP 127.0.0.1:8000
 users ───► reverse proxy (TLS) ───► web (gunicorn, 3 workers)
                                       │            │
                                       ▼            ▼
                                   PostgreSQL ◄── worker (Celery, queue "audits")  ──► analyzers (sandboxed)
                                       ▲            │
                                       └── Redis ◄──┘  (broker, rate limits)
```

| Service | Image | Role | Persistent volume |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | Data | `pg-data` |
| `redis` | `redis:7-alpine` (AOF on) | Task broker, rate limiting | `redis-data` |
| `migrate` | eVal image | Runs `flask db upgrade`, then exits | — |
| `web` | eVal image | UI and JSON API on port 8000 | `eval-data` (uploads) |
| `worker` | eVal image | Clones/extracts sources and runs analyzers | `eval-data` (read-only), `trivy-cache` |

The same image serves `web`, `worker` and `migrate`. It contains Ruff, Bandit, mypy, Semgrep, ESLint,
TypeScript and Trivy; each is optional (build args below).

### Host requirements

- Linux x86-64 with Docker Engine and the Compose plugin. Windows hosts are for development only: analyzer
  resource limits (rlimits) are POSIX-only.
- Per worker container: 2 CPUs and 4 GB RAM (Compose limits), plus a 4 GB tmpfs for checkouts. Size the host
  for `N × worker` plus PostgreSQL and the web tier.
- Disk for uploads (`EVAL_MAX_UPLOAD_MB`, default 50 MB each), PostgreSQL, and the Trivy database (~1 GB).
- Outbound HTTPS as listed in [NETWORK.md](NETWORK.md), unless you deploy air-gapped (see below).

### Step 1: configure

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"                               # EVAL_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # EVAL_ENCRYPTION_KEYS
python -c "import secrets; print(secrets.token_urlsafe(24))"                               # POSTGRES_PASSWORD
```

Required in `.env`:

| Variable | Value |
|---|---|
| `EVAL_SECRET_KEY` | At least 32 random characters. The app refuses to start without it |
| `EVAL_ENCRYPTION_KEYS` | Fernet key(s) encrypting stored GitHub tokens and AI keys. **Back it up**: without it, stored credentials cannot be decrypted |
| `POSTGRES_PASSWORD` | Database password used by Compose |

Compose sets `DATABASE_URL`, `REDIS_URL`, `EVAL_ENV=production`, the data/work directories and the Trivy cache
itself; values in its `environment` block take precedence over `.env`.

Production settings to review:

| Variable | Recommendation |
|---|---|
| `EVAL_SECURE_COOKIES` | `true` (default). Set `false` only for plain-HTTP evaluation on a non-localhost name |
| `EVAL_PROXY_FIX_HOPS` | Number of reverse proxies in front of `web` (usually `1`). Without it, all users share the proxy's IP for rate limiting |
| `EVAL_ALLOW_REGISTRATION` | `false` for private instances; create users with the CLI (step 3) |
| `EVAL_MAX_ORGS_PER_USER` | Organizations one user may create (default 5) |
| `EVAL_GIT_ALLOWED_HOSTS`, `GITHUB_API_URL` | Add your GitHub Enterprise host and `https://HOST/api/v3` |
| `EVAL_WORKSPACE_MAX_*`, `EVAL_MAX_UPLOAD_MB`, `EVAL_ANALYZER_TIMEOUT_SECONDS` | Repository size and time limits. Celery's hard limit per audit is 6 × the analyzer timeout (30 min by default) |
| `EVAL_AI_ALLOWED_BASE_URLS` | OpenAI-compatible endpoints organizations may use (e.g. a self-hosted Ollama) |

The full list, with defaults, is in [.env.example](../.env.example).

### Step 2: build and start

```bash
docker compose up -d --build
docker compose ps          # migrate: exited (0); web, worker, postgres, redis: running/healthy
```

Build arguments, if you need a smaller image:

```bash
docker compose build --build-arg INSTALL_SEMGREP=false --build-arg INSTALL_NODE_TOOLS=false \
                     --build-arg INSTALL_TRIVY=false --build-arg TRIVY_VERSION=0.75.0
```

### Step 3: first user

```bash
docker compose exec web flask create-user admin@example.com --org "My Company"   # prompts for the password
```

The user owns the new organization. Add members under the organization's **Members** page.

### Step 4: TLS reverse proxy

`web` listens on `127.0.0.1:8000` only. Put a TLS-terminating proxy in front and set
`EVAL_PROXY_FIX_HOPS=1`. Example (nginx):

```nginx
server {
    listen 443 ssl http2;
    server_name eval.example.com;
    ssl_certificate     /etc/ssl/eval.crt;
    ssl_certificate_key /etc/ssl/eval.key;
    client_max_body_size 60m;                       # >= EVAL_MAX_UPLOAD_MB

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

eVal sets its own security headers (CSP, HSTS when secure cookies are on, `X-Frame-Options`); the proxy does
not need to add them.

### Step 5: verify

1. Open `https://eval.example.com/login` and sign in.
2. Create a project and upload a small ZIP. The audit should go *queued → running → completed*.
3. On the audit page, check **Analyzer coverage**: tools that are missing or could not reach the network show
   as skipped or failed with a reason.
4. `docker compose logs worker --tail 50` shows the task completing.

There is no dedicated health endpoint yet; `GET /login` returning 200 is a usable liveness check for the web
tier.

### Optional: GitHub and AI

- **GitHub:** per organization under *Settings → Integrations* (token stored encrypted). For GitHub
  Enterprise, set `GITHUB_API_URL` and `EVAL_GIT_ALLOWED_HOSTS` first.
- **Cloud AI (Anthropic, OpenAI):** per organization under *Integrations → AI-assisted analysis*; keys are
  stored encrypted, never in `.env`.
- **Self-hosted AI:** run a model server on your infrastructure and allow it. Example
  `docker-compose.override.yml`:

  ```yaml
  services:
    ollama:
      image: ollama/ollama
      volumes: [ollama:/root/.ollama]
      restart: unless-stopped
  volumes:
    ollama:
  ```

  Then `docker compose exec ollama ollama pull qwen2.5-coder:7b`, set
  `EVAL_AI_ALLOWED_BASE_URLS=http://ollama:11434/v1` in `.env`, restart, and select the OpenAI-compatible
  provider with that URL in the organization's AI settings. No code then leaves your network for AI.

### Scaling

- Workers: `docker compose up -d --scale worker=N`. Each worker runs 2 audits at a time (`--concurrency=2`)
  and is recycled after 20 tasks.
- Web: increase gunicorn `--workers` in the image `CMD` or run more `web` replicas behind the proxy.
- Put workers on separate hosts or a separate node pool from the web tier where possible, ideally under
  gVisor or Kata ([SECURITY.md](SECURITY.md) §1, §7).
- Use a managed PostgreSQL and Redis by overriding `DATABASE_URL` and `REDIS_URL`; Redis is also required
  for shared rate limits across web processes.

### Backups and restore

Back up **three** things: the database, the uploads volume, and `.env` (above all `EVAL_ENCRYPTION_KEYS`).

```bash
docker compose exec -T postgres pg_dump -U eval -Fc eval > eval-$(date +%F).dump
docker run --rm -v eval_eval-data:/data -v "$PWD":/backup alpine tar czf /backup/eval-data-$(date +%F).tgz -C /data .
```

Restore into a fresh deployment (same `.env`):

```bash
docker compose up -d postgres redis
docker compose exec -T postgres pg_restore -U eval -d eval --clean --if-exists < eval-YYYY-MM-DD.dump
docker run --rm -v eval_eval-data:/data -v "$PWD":/backup alpine tar xzf /backup/eval-data-YYYY-MM-DD.tgz -C /data
docker compose up -d
```

Redis holds only queued tasks and rate-limit counters; it does not need backing up. The `trivy-cache`
volume can be rebuilt.

### Upgrades

```bash
git pull
docker compose build
docker compose up -d        # migrate runs first; web and worker start after it succeeds
```

Take a database backup before upgrading, and upgrade when no audits are running: recreating the worker
interrupts audits in progress, which are then marked failed (not retried) and can be run again.

### Key rotation

- **`EVAL_ENCRYPTION_KEYS`:** prepend a new key (`NEW,OLD`) and restart. New credentials are encrypted with the
  new key; existing ones still decrypt with the old key. There is no bulk re-encryption command yet, so keep
  the old key until every stored credential has been re-entered, then remove it.
- **`EVAL_SECRET_KEY`:** changing it signs everyone out.
- **`POSTGRES_PASSWORD`:** change it in PostgreSQL (`ALTER USER eval PASSWORD ...`) and in `.env`, then
  restart `web` and `worker`.

### Air-gapped deployment

See [NETWORK.md](NETWORK.md) for every connection. For a server without internet access:

1. Build the image where the internet is available and load it on the target (`docker save` / `docker load`).
2. Set `EVAL_OSV_ENABLED=0` and point `EVAL_SEMGREP_CONFIG` at a rules directory mounted into the worker.
3. Seed the Trivy database into the `trivy-cache` volume while online:
   `docker compose run --rm worker trivy image --download-db-only --cache-dir /trivy-cache`.
4. Use ZIP uploads or an internal GitHub Enterprise host; use a self-hosted model for AI.
5. Self-host Bootstrap 5.3.3 and Bootstrap Icons 1.11.3, or the UI renders unstyled.

**Limitation:** the CLI's `--offline` mode does not exist for the worker yet. Trivy on the worker still tries
to refresh a stale database and then fails, which shows as *failed* in coverage. Refresh the cache regularly,
or disable Trivy with `INSTALL_TRIVY=false`.

### Operations checklist

- [ ] TLS in front of `web`; `EVAL_SECURE_COOKIES=true`; `EVAL_PROXY_FIX_HOPS` set
- [ ] `EVAL_ALLOW_REGISTRATION=false` unless the instance is meant to be open
- [ ] `.env` stored in a secret manager; `EVAL_ENCRYPTION_KEYS` backed up separately from database backups
- [ ] Daily `pg_dump` and `eval-data` backups, with a tested restore
- [ ] Worker isolated from the web tier (separate host/node pool, ideally gVisor/Kata)
- [ ] Log collection for `web` and `worker` (both log to stdout)
- [ ] Trivy cache refreshed, or Trivy disabled, on hosts without internet access

---

## 3. Render

eVal includes a Render Blueprint ([render.yaml](../render.yaml)) that creates everything in one step.
**For a click-by-click walkthrough, follow [RENDER.md](RENDER.md).** This section is the reference.

### What gets created

| Resource | Render type | Default plan | Purpose |
|---|---|---|---|
| `eval` | Web service, Docker ([Dockerfile.render](../Dockerfile.render)) | `2c-4g` | Web UI and API **and** the audit worker, with a 10 GB disk at `/data` |
| `eval-db` | Render Postgres 16 | `0.5c-1g` | Database |
| `eval-redis` | Render Key Value | `256mb`, `noeviction`, private network only | Celery broker, rate limits |

**Why web and worker share one service.** The worker reads the ZIP uploads that the web process stores on
disk, and a Render disk can be attached to only one service. [scripts/render-start.sh](../scripts/render-start.sh)
therefore runs gunicorn and the Celery worker side by side. It starts as root only to take ownership of the
mounted disk, then drops to the unprivileged `eval` user (`setpriv`, no-new-privs). If either process dies,
the container exits so Render restarts it.

Trade-offs compared with Docker Compose:

- A service with a disk cannot be scaled to several instances, and deploys have a short downtime. Scale
  vertically (plan, `WEB_CONCURRENCY`, `EVAL_WORKER_CONCURRENCY`). Running workers as a separate, scalable
  service needs uploads in object storage, which is on the [roadmap](ROADMAP.md).
- The Compose worker hardening (read-only root filesystem, dropped capabilities, separate container from the
  web tier) is not available. Analyzers still run in eVal's process sandbox with resource limits. For hostile
  multi-tenant workloads, prefer the Compose deployment with gVisor ([SECURITY.md](SECURITY.md)).
- The free plan is not supported: free web services cannot have a disk, and analyzers need memory.

### Deploy

1. Push the repository to GitHub or GitLab (Render deploys from a Git repository).
2. Generate an encryption key and keep a copy somewhere safe, outside Render:

   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. In the Render Dashboard: **New → Blueprint**, select the repository, and review the resources.
4. When prompted, paste the key into `EVAL_ENCRYPTION_KEYS`. `EVAL_SECRET_KEY` is generated by Render;
   `DATABASE_URL` and `REDIS_URL` are wired to the new database and Key Value automatically.
5. **Apply.** Render builds the image, runs `flask db upgrade` as the pre-deploy step, then starts the service.
   The first build takes several minutes (Semgrep, Node tools and Trivy are installed).
6. Create the first user from the service's **Shell** tab:

   ```bash
   flask create-user admin@example.com --org "My Company"
   ```

7. Open `https://eval-XXXX.onrender.com/login` (or add a custom domain under **Settings → Custom Domains**).
8. Verify as in [step 5 of the Compose guide](#step-5-verify): upload a small ZIP and check that the audit
   completes and that **Analyzer coverage** lists the tools.

### Configuration notes

| Setting | Value in the Blueprint | Note |
|---|---|---|
| `DATABASE_URL` | Render's `postgresql://…` | eVal selects the psycopg 3 driver automatically |
| `EVAL_PROXY_FIX_HOPS` | `1` | Render's proxy terminates TLS. If the security audit log shows the same client IP for everyone, review this value |
| `EVAL_ALLOW_REGISTRATION` | `false` | Change in **Environment** if the instance should be open to sign-ups |
| `EVAL_WORK_DIR` | `/tmp/eval-work` | Checkouts are temporary and stay off the disk |
| `EVAL_TRIVY_CACHE_DIR` | `/data/trivy-cache` | The Trivy database persists across deploys |
| `WEB_CONCURRENCY`, `EVAL_WORKER_CONCURRENCY` | `2`, `2` | Gunicorn workers and simultaneous audits; raise with the plan |
| `maxShutdownDelaySeconds` | `300` | On deploy, running audits get up to 5 minutes to finish; longer ones are marked failed and can be re-run |
| Region | Oregon (default) | Set `region` in `render.yaml` **before** the first deploy; it cannot be changed later |

Other variables from [.env.example](../.env.example) (GitHub Enterprise, limits, `EVAL_AI_ALLOWED_BASE_URLS`) can
be added under the service's **Environment** tab.

### AI on Render

- **Cloud AI:** enable per organization in the eVal UI (*Integrations → AI-assisted analysis*); keys are
  stored encrypted in the database.
- **Self-hosted model:** run an OpenAI-compatible server (for example Ollama) as a Render private service, then
  set `EVAL_AI_ALLOWED_BASE_URLS` to its private-network URL (`http://<service-host>:11434/v1`). Render
  instances have no GPU, so expect slow responses from CPU inference; a smaller model and fewer findings per
  audit help.

### Operations

- **Deploys:** every push to the tracked branch deploys automatically. Migrations run in the pre-deploy step;
  if they fail, the old version keeps running.
- **Backups:** use Render Postgres backups for the database (retention depends on the plan) and keep your own
  `pg_dump` for long-term copies. Render snapshots persistent disks; check the retention for your plan.
  **Back up `EVAL_ENCRYPTION_KEYS` separately:** without it, stored GitHub tokens and AI keys cannot be
  decrypted.
- **Logs:** web and worker log to the same service log; filter for `celery` or `gunicorn`.
- **Key rotation:** as in [Key rotation](#key-rotation); edit the variables under **Environment**, which
  triggers a redeploy.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Deploy fails with `Invalid configuration: EVAL_ENCRYPTION_KEYS must be set` | The key was not entered when the Blueprint was created; add it under **Environment** |
| Health check fails, logs show `render-start: a process exited unexpectedly` | The named process (gunicorn or celery) crashed; the lines above it show why, often a missing variable or an unreachable database |
| Audits stay *queued* | The worker is not connected to Key Value: check `REDIS_URL` and the `celery` lines in the log |
| Trivy shows *failed* in coverage | The Trivy database download failed; it is retried on the next audit |
| An audit fails right after a deploy | It was still running when the shutdown grace period ended; run it again |

The Render setup was tested locally with Docker: a root-owned volume at `/data`, a `postgresql://` URL and
`PORT=10000`. In that test the migrations ran, a ZIP uploaded through the web process was audited by the
worker in the same container, a stop request shut both processes down gracefully, and killing the worker
stopped the container. It has not yet been deployed on Render itself.

---

Not built yet (see [ROADMAP.md](ROADMAP.md)): health/readiness endpoints, metrics and tracing, scheduled
audits, object storage for uploads, PostgreSQL row-level security.
