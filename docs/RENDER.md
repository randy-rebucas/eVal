# Deploy eVal on Render: step-by-step

This guide takes you from the repository to a running eVal at `https://<your-service>.onrender.com`, in about
30 minutes (most of it is the first build). Reference material (why it is set up this way, every setting,
troubleshooting) is in [DEPLOYMENT.md § 3](DEPLOYMENT.md#3-render).

## What you will end up with

| Resource | Name | What it does |
|---|---|---|
| Web service (Docker) | `eval` | The eVal website and API, plus the audit worker; 10 GB disk for uploads |
| Postgres | `eval-db` | Projects, audits, findings, users |
| Key Value | `eval-redis` | Audit queue |

All three are on paid Render plans (`2c-4g`, `0.5c-1g`, `256mb`). A disk is required for uploads, and Render
does not offer disks on free web services. Check current prices on Render's pricing page before you start.

## Before you start

- [ ] A Render account with a payment method
- [ ] Access to the GitHub repository `randy-rebucas/eVal`
- [ ] Python 3 on your computer (only to generate one key in step 2)
- [ ] 30 minutes

---

## Step 1: Push the Render files to GitHub

Render builds from GitHub, so these files must be on the branch Render will deploy (`main`):

| File | Purpose |
|---|---|
| `render.yaml` | The Blueprint: describes the three resources |
| `Dockerfile.render` | The image Render builds |
| `scripts/render-start.sh` | Starts the website and the worker |
| `eval_app/config.py` | Accepts Render's database URL |

From the repository folder:

```bash
git status                        # the files above should be listed
pytest -q                         # optional: all tests should pass
git add render.yaml Dockerfile.render scripts/render-start.sh eval_app/config.py \
        tests/app/test_config.py tests/app/test_render_deploy.py docs/
git commit -m "Add Render deployment"
git push origin main
```

If you prefer to review first, push a branch, open a pull request, merge it into `main`, then continue.

## Step 2: Create the encryption key

eVal encrypts stored GitHub tokens and AI keys with this key. Generate it on your computer:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

If `cryptography` is not installed, run the command inside the project's virtual environment, or
`pip install cryptography` first.

Copy the output (44 characters ending in `=`) and **save it in your password manager now**. If it is lost,
stored credentials cannot be recovered.

## Step 3 (optional): Choose region and sizes

Open `render.yaml` if you want to change anything. The region **cannot be changed after the first deploy**.

```yaml
services:
  - type: web
    name: eval
    region: frankfurt        # add this line: oregon (default), ohio, virginia, frankfurt or singapore
    plan: 2c-4g              # instance size for website + worker
```

Use the same `region` for `eval-redis` and `eval-db` so they can talk over Render's private network. Commit and
push if you changed anything.

## Step 4: Create the Blueprint on Render

1. Sign in at dashboard.render.com.
2. Click **New** → **Blueprint**.
3. Connect GitHub if asked, then select the repository **randy-rebucas/eVal**.
4. Give the Blueprint a name (for example `eval`) and select the branch **main**.
5. Render reads `render.yaml` and lists the three resources: `eval`, `eval-db`, `eval-redis`.
6. Render asks for the one value it cannot generate: paste the key from step 2 into
   **`EVAL_ENCRYPTION_KEYS`**.
7. Click **Apply** (or **Deploy Blueprint**).

Render now creates the database and Key Value, then builds and deploys the web service.

## Step 5: Watch the first deploy

Open the **eval** service and its **Logs**. The first deploy takes several minutes:

| Phase | What you see | Typical time |
|---|---|---|
| Build | Docker steps installing Python packages, Semgrep, ESLint/TypeScript, Trivy | 5–10 min |
| Pre-deploy | `Running upgrade ... -> ...` (database migrations) | Under 1 min |
| Start | `Listening at: http://0.0.0.0:10000` (website) and `celery@... ready.` (worker) | Under 1 min |

The deploy is finished when the service shows **Live**. The service URL is shown at the top of the service page,
for example `https://eval-xxxx.onrender.com`.

If it fails, see [Troubleshooting](#troubleshooting).

## Step 6: Create your admin account

Registration is turned off by default, so create the first user from the server:

1. In the **eval** service, open the **Shell** tab.
2. Run (use your own email and organization name):

   ```bash
   flask create-user you@example.com --org "My Company"
   ```

3. Enter a password twice when prompted. You should see `created user you@example.com with org my-company`.

## Step 7: Sign in and run a test audit

1. Open `https://<your-service>.onrender.com/login` and sign in.
2. Create a project.
3. Make a test ZIP from the sample app in this repository:

   ```powershell
   # Windows PowerShell
   Compress-Archive -Path tests\fixtures\vulnapp\* -DestinationPath vulnapp.zip
   ```

   ```bash
   # macOS / Linux
   (cd tests/fixtures/vulnapp && zip -r ../../../vulnapp.zip .)
   ```

4. In the project, click **Add repository**, choose **Upload**, and upload `vulnapp.zip`.
5. The audit runs: *queued → running → completed* in about a minute. The sample app is deliberately insecure,
   so expect a **Critical** risk score with findings such as a hard-coded AWS key and SQL string formatting.
6. Scroll to **Analyzer coverage**: Ruff, Bandit, mypy, Semgrep, ESLint, TypeScript and Trivy should be
   listed as run (Trivy downloads its database on the first audit).

eVal is now deployed.

## Step 8 (optional): Finish the setup

| Task | Where |
|---|---|
| Custom domain (e.g. `eval.yourcompany.com`) | Render: **eval → Settings → Custom Domains**; Render issues the TLS certificate |
| Invite your team | eVal: your organization → **Members** |
| Let people sign up themselves | Render: **eval → Environment** → set `EVAL_ALLOW_REGISTRATION` to `true` (redeploys) |
| Connect GitHub repositories | eVal: **Settings → Integrations** → add a GitHub token |
| AI explanations | eVal: **Integrations → AI-assisted analysis** (Anthropic or OpenAI key, stored encrypted) |
| CI gate for pull requests | eVal: create an API token, then follow [CI.md](CI.md) with `EVAL_URL` set to your Render URL |

## Day-to-day

- **Updates:** every push to `main` deploys automatically. Migrations run before the new version starts; if
  they fail, the old version keeps running. Expect a short downtime per deploy (the service has a disk).
- **Running audits during a deploy** get up to 30 seconds to finish (Render's fixed limit for a service with a disk). Anything longer is marked failed and can
  be re-run.
- **Settings:** change environment variables under **eval → Environment**; saving redeploys the service.
- **Logs:** **eval → Logs**. Website lines come from `gunicorn`, audit lines from `celery`.
- **Backups:** Render backs up Postgres according to your plan. Also keep the encryption key from step 2 in
  your password manager. Without it a database backup cannot decrypt stored credentials.
- **More capacity:** choose a larger plan for `eval`, then raise `EVAL_WORKER_CONCURRENCY` (simultaneous
  audits) and `WEB_CONCURRENCY` (website workers) under **Environment**.

## Troubleshooting

| Problem | What to do |
|---|---|
| Blueprint creation fails on a plan or field | Render may have renamed a plan; pick the nearest one in the dashboard or edit `render.yaml` and push |
| Deploy fails: `Invalid configuration: EVAL_ENCRYPTION_KEYS must be set` | Add the key from step 2 under **eval → Environment** and redeploy |
| Deploy fails during **Pre-deploy** | The database is not ready or the URL is wrong: check that `eval-db` is **Available** and `DATABASE_URL` is set under **Environment**, then **Manual Deploy** |
| Logs show `render-start: a process exited unexpectedly` | Read the lines above it: the website or the worker crashed, usually because of a missing variable or an unreachable database |
| Sign-in page loads but login does nothing | Open the site over `https://` (cookies are secure-only) |
| Audits stay **queued** | The worker cannot reach Key Value: check `REDIS_URL` under **Environment** and look for `celery` errors in the logs |
| Trivy shows **failed** in coverage | Its database download failed; it retries on the next audit |
| `flask create-user` says the email exists | The user is already there; sign in, or use another email |

More detail: [DEPLOYMENT.md § 3](DEPLOYMENT.md#3-render).

## Removing the deployment

Delete the Blueprint's resources in the Render Dashboard (**eval**, **eval-db**, **eval-redis**). Deleting
**eval-db** permanently deletes all audits and users; take a backup first if you need the data.
