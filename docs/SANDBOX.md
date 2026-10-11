# Sandbox terminals

eVal's audits never run your code. Testing a fix does, so eVal can optionally open a **terminal** on a fix: a
shell in an isolated container, holding the audited commit with the fix's current revision applied. A member can
run the tests there, adjust the fix's files, and save them back as a new fix revision. That revision is re-audited
like any other edit.

The feature is **off by default**. The operator enables it by running the sandbox service and setting three
variables. Each organization's admin then opts in under **Settings → Security → Sandbox terminals**.

If you can't run gVisor, don't enable this. Use **Open in Codespaces** on the fix page instead. It gives the same
terminal on GitHub's machines (see [README § Auto-fix](../README.md#auto-fix)).

## How it works

```
browser ──https──▶ eVal web ──Celery──▶ worker ──signed POST (tar)──▶ sandbox service ──Docker API──▶ container
   │                   │                  (fetches the audited commit,                    (runsc, no network,
   │                   └─ issues a 2-minute terminal token                                  no capabilities)
   └──────────────wss (token as the first message)──────────────────▶ sandbox service ◀──attach──┘
```

1. A member clicks **Open a terminal on this fix**. eVal records a `SandboxSession` and a `sandbox.opened`
   audit-log event.
2. The worker fetches the audited commit the same way an audit does, **without `.git`**. It adds the fix's files
   and sends one tar to the sandbox service, signed with `EVAL_SANDBOX_SECRET`.
3. The sandbox service creates the container, copies the tar in and starts a shell. Inside, the audited tree is
   committed to a fresh local git repository and the fix is applied on top, so `git diff` shows exactly the fix.
4. The terminal page asks eVal for a token (valid for 2 minutes, for this session and user only) and opens a
   websocket straight to the sandbox service. The token travels as the first message, never in a URL.
5. **Save files to the fix** reads the fix's files back out of the container and saves them as a new fix
   revision, through the same path as an edit in the browser. It is checked for staleness, re-audited and logged.
6. The session ends when the member clicks **End**, when the time limit passes (`EVAL_SANDBOX_MAX_MINUTES`,
   default 30), or after `EVAL_SANDBOX_IDLE_MINUTES` (default 10) with no terminal attached. The container
   and its files are then deleted.

## What isolates the code

| Layer | Setting |
|---|---|
| Kernel | gVisor (`runsc`), a user-space kernel between the code and the host. The service refuses to start without it, unless `EVAL_SANDBOX_ALLOW_RUNC=true` (development only; the terminal page then shows a red warning) |
| Network | `none` by default: no DNS, no internet, no route to eVal, Postgres or Redis. `EVAL_SANDBOX_NETWORK` may name a dedicated network whose egress you control. `host` and `bridge` are refused |
| Privileges | Runs as uid 1000, with every capability dropped, `no-new-privileges`, not privileged, and no devices |
| Filesystem | No bind mounts or volumes. The workspace exists only inside the container, which is deleted when it stops |
| Secrets | None. The tar has no `.git` (so no remote URL or token), the environment has only `TERM`, `HOME` and `LANG`, and the service itself holds only `EVAL_SANDBOX_SECRET` |
| Resources | Memory (`EVAL_SANDBOX_MEMORY_MB`, 2048, no swap), CPU (`EVAL_SANDBOX_CPUS`, 1), processes (`EVAL_SANDBOX_PIDS`, 256), file size (`EVAL_SANDBOX_MAX_FILE_MB`, 512), `/tmp` 256 MB |
| Capacity | `EVAL_SANDBOX_MAX_SESSIONS` (8) on the server, `EVAL_SANDBOX_MAX_PER_ORG` (2), 20 sessions opened per organization per hour |
| Access | Members only, and only the member who opened a terminal can see, use, save from or end it. Each terminal connection needs a fresh token, and the websocket checks `Origin` against `EVAL_SANDBOX_ALLOWED_ORIGINS` |

**The sandbox service holds the Docker socket, which is root-equivalent on that host.** That is why it is a
separate service with no database, credentials or app secrets. Run it on a **dedicated host or VM**, not next
to Postgres or the eVal workers, and don't publish port 8100 except through the TLS proxy for `wss://`.

## Setup

1. Install gVisor on the sandbox host and register the runtime with Docker
   ([gvisor.dev/docs/user_guide/install](https://gvisor.dev/docs/user_guide/install/)). Check it with
   `docker info --format '{{json .Runtimes}}'`, which must list `runsc`.
2. Build the workspace image, adding any toolchains your repositories need:
   `docker build -f sandbox/workspace.Dockerfile -t eval-sandbox-workspace:latest sandbox`. With the default
   `none` network, nothing can be installed in a session, so the image must contain what your tests need.
3. Generate a secret (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) and start the service with
   `docker compose --profile sandbox up -d sandbox`, or use `Dockerfile.sandbox` on its own host. It reads:

   | Variable | Value |
   |---|---|
   | `EVAL_SANDBOX_SECRET` | the shared secret (at least 32 characters) |
   | `EVAL_SANDBOX_ALLOWED_ORIGINS` | eVal's public origin, e.g. `https://eval.example.com` |
   | `EVAL_SANDBOX_RUNTIME` | `runsc` (default) |
   | `EVAL_SANDBOX_NETWORK`, `_MEMORY_MB`, `_CPUS`, `_PIDS`, `_MAX_FILE_MB`, `_MAX_SESSIONS`, `_MAX_PER_ORG`, `_MAX_MINUTES`, `_IDLE_MINUTES`, `EVAL_SANDBOX_IMAGE` | optional limits, see the table above |

4. Put TLS in front of port 8100, so browsers connect with `wss://` (eVal refuses other schemes outside development).
5. Set these on the eVal web app and worker. eVal won't start with only some of them set:

   | Variable | Value |
   |---|---|
   | `EVAL_SANDBOX_URL` | how the worker and web reach the service, e.g. `http://sandbox:8100` |
   | `EVAL_SANDBOX_PUBLIC_URL` | how browsers reach it, e.g. `wss://sandbox.eval.example.com` |
   | `EVAL_SANDBOX_SECRET` | the same secret |
   | `EVAL_SANDBOX_MAX_MINUTES` | session length shown to users (the service enforces its own maximum too) |

6. An organization admin enables **Settings → Security → Sandbox terminals**.

## Limits and known gaps

- Only the files already in the fix can be saved back. Other files you change in the terminal are discarded when
  it ends.
- A dropped connection reconnects automatically. One browser tab at a time: opening the terminal elsewhere takes
  it over.
- Output produced while no tab is attached is not replayed.
- Not supported on Render, where services can't run containers. Use Codespaces there.
