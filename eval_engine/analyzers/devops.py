"""DevOps, CI/CD and deployment configuration: Dockerfiles, Compose, Kubernetes manifests, CI pipelines (GitHub
Actions in depth) and platform/environment files.

Looks for secrets baked into images, containers running as root, missing health checks and resource limits, CI
without tests, unsafe deployment patterns (dev servers and debug settings in production, deploys without a test gate,
mutable image tags), and missing rollback strategy and environment separation.

Logging, metrics, tracing, request ids and health endpoints are covered by the observability analyzer."""

from __future__ import annotations

import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext
from .registry import register

CI_MARKERS = (".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml",
              "bitbucket-pipelines.yml", ".travis.yml", ".buildkite/", ".drone.yml")
DB_PORTS = {"5432", "3306", "6379", "27017", "9200", "11211", "5672", "1433"}
SECRET_ENV = re.compile(r"(?i)^\s*(?:ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*[ =]\s*\S+")
ACTION_USES = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
SCRIPT_KEY = re.compile(r"^\s*(?:-\s+)?(run|script)\s*:(.*)$")  # shell steps, actions/github-script
UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|"
    r"review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.message|head_commit\.message|"
    r"head_commit\.author\.(?:email|name)|pull_request\.head\.ref|pull_request\.head\.label|workflow_run\.head_branch)"
)
TEST_COMMAND = re.compile(
    r"(?i)\bpytest\b|\bunittest\b|\btox\b|\bnox\b|manage\.py\s+test|\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?"
    r"(?:test|ci|check|verify)\b|\bnpx\s+(?:jest|vitest|mocha|playwright|cypress)|\bjest\b|\bvitest\b|\bmocha\b|"
    r"\bgo\s+test\b|\bcargo\s+test\b|\bmvnw?\s+(?:-\S+\s+)*(?:test|verify|install)\b|\bgradlew?\s+(?:\S+\s+)*"
    r"(?:test|check|build)\b|\bmake\s+(?:test|check|ci)\b|\bphpunit\b|\brspec\b|\bdotnet\s+test\b|"
    r"\bplaywright\s+test\b|\bcypress\s+run\b|\bctest\b|\bbazel\s+test\b")
DEPLOY_COMMAND = re.compile(
    r"(?i)\bkubectl\s+(?:apply|set\s+image|rollout\s+restart|replace)|\bhelm\s+(?:upgrade|install)\b|"
    r"\bterraform\s+apply\b|\bfly(?:ctl)?\s+deploy\b|\bvercel\b[^\n]*--prod|\bnetlify\s+deploy\b|"
    r"\baws\s+ecs\s+update-service\b|\baws\s+deploy\b|\bgcloud\s+(?:run|app|functions)\s+deploy\b|"
    r"\b(?:serverless|sls)\s+deploy\b|\bheroku\s+container:release\b|git\s+push\s+heroku|\beb\s+deploy\b|"
    r"\baz\s+webapp\b|\brailway\s+up\b|api\.render\.com/deploy|appleboy/ssh-action|\bssh\s+[^\n]*@|\brsync\s|"
    r"\bscp\s|azure/webapps-deploy|aws-actions/amazon-ecs-deploy|google-github-actions/deploy|"
    r"superfly/flyctl-actions|cloudflare/wrangler-action|\bwrangler\s+(?:deploy|publish)\b|\bfirebase\s+deploy\b|"
    r"\bdocker[- ]compose\b[^\n]*\bup\b")
ROLLBACK_HINT = re.compile(r"(?i)roll[- ]?back|rollout\s+undo|helm\s+rollback|--atomic|blue[- ]?green|canary|"
                           r"previous\s+(?:release|version|image|deployment)|revert\s+(?:the\s+)?deploy|"
                           r"deployment_circuit_breaker|deploymentCircuitBreaker")
ENV_NAME_HINT = re.compile(r"(?i)\b(?:staging|stage|preview|pre-?prod|qa|uat|sandbox)\b")
MUTABLE_IMAGE = re.compile(r"(?i)(?:docker\s+push\s+|--image[= ]|set\s+image\s+\S+=|image:\s*)[\"']?"
                           r"[\w./${}:-]+:latest\b")
DEBUG_SETTING = re.compile(
    r"""(?i)\b(?:DEBUG|FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG)\s*[=:]\s*["']?(?:1|true|yes|on)\b["']?|"""
    r"""\b(?:FLASK_ENV|NODE_ENV|APP_ENV|RAILS_ENV|ENVIRONMENT)\s*[=:]\s*["']?(?:development|dev)\b""")
K8S_DEBUG_ENV = re.compile(  # Kubernetes `- name: X / value: Y` and render.yaml `- key: X / value: Y` pairs
    r"""(?i)(?:name|key):\s*["']?(?:DEBUG|FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG)["']?\s*\n\s*value:\s*["']?"""
    r"""(?:1|true|yes|on)\b|(?:name|key):\s*["']?(?:FLASK_ENV|NODE_ENV|APP_ENV|RAILS_ENV)["']?\s*\n\s*value:\s*"""
    r"""["']?(?:development|dev)\b""")
DEV_SERVER = re.compile(
    r"(?i)\bflask[\"',\s]+run\b|manage\.py\b[\"',\s]+runserver\b|\b(?:npm|pnpm|yarn|bun)[\"',\s]+(?:run[\"',\s]+)?dev\b|"
    r"\bnodemon\b|\bng[\"',\s]+serve\b|\bnext[\"',\s]+dev\b|\bvite[\"',\s]*(?:$|[\"\]]|--)|\b(?:uvicorn|gunicorn)\b"
    r"[^\n]*--reload\b|http\.server\b|webpack-dev-server|react-scripts[\"',\s]+start\b|--debug\b")
PROD_ENV_FILE = re.compile(r"(?i)(^|/)\.env\.(prod|production)(\.[\w-]+)?$")
PROD_COMPOSE = re.compile(r"(?i)(^|/)(docker-)?compose[.-](prod|production)[\w.-]*\.ya?ml$")
DEV_DOCKERFILE = re.compile(r"(?i)(^|/)(Dockerfile[.-](dev|development|local|test)|(dev|development|local|test)"
                            r"\.dockerfile)$")
PLATFORM_FILES = ("render.yaml", "fly.toml", "app.yaml", "Procfile", "railway.json", "railway.toml")
K8S_WORKLOAD = re.compile(r"(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|ReplicaSet)\s*$")
K8S_IMAGE = re.compile(r"""(?m)^\s*-?\s*image:\s*["']?([^\s"'#]+)""")


@register
class DevOpsAnalyzer(Analyzer):
    name = "devops"
    title = "DevOps & deployment configuration"
    categories = (Category.DEVOPS,)

    def run(self, ctx: AnalyzerContext):
        findings = []
        dockerfiles = [f for f in ctx.files if f.rsplit("/", 1)[-1].startswith("Dockerfile")
                       or f.endswith(".dockerfile")]
        for df in dockerfiles:
            findings.extend(self._dockerfile(ctx, df))
        if dockerfiles and not ctx.files_named(".dockerignore"):
            findings.append(self._repo(ctx, "devops.missing-dockerignore", "Dockerfile without .dockerignore",
                                       Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "Without .dockerignore the whole build context (including .git, .env files "
                                       "and local artifacts) is sent to the builder and may end up in images.",
                                       "Add a .dockerignore excluding .git, .env*, dependencies, and build output."))
        for compose in ctx.files_named("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            findings.extend(self._compose(ctx, compose))
        ci_files = [f for f in ctx.files if any(f.startswith(m) or f == m for m in CI_MARKERS)]
        if not ci_files:
            findings.append(self._repo(ctx, "devops.no-ci", "No CI/CD pipeline configuration found",
                                       Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "No CI configuration was detected (GitHub Actions, GitLab CI, Jenkins, "
                                       "CircleCI, Azure Pipelines, …). Changes can ship without automated tests, "
                                       "linting, or security checks.",
                                       "Add a CI pipeline that runs tests, linters, and dependency/security scans "
                                       "on every pull request."))
        else:
            ci_text = "\n".join(ctx.read(f) or "" for f in ci_files if not f.endswith("/"))
            if not TEST_COMMAND.search(ci_text):
                findings.append(self._repo(ctx, "devops.ci-no-tests", "CI pipeline does not run tests",
                                           Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                           "CI configuration exists, but no test command (pytest, npm test, jest, "
                                           "go test, mvn verify, …) was found in it. Changes are built and possibly "
                                           "deployed without automated verification.",
                                           "Run the test suite on every pull request and make it a required check "
                                           "before merge and before deploy.", ci_files[0]))
        workflows = [f for f in ci_files if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))]
        for wf in workflows:
            findings.extend(self._github_workflow(ctx, wf))
        findings.extend(self._deployment_pipeline(ctx, workflows))
        for rel in [f for f in ctx.files if f.endswith((".yml", ".yaml")) and not f.startswith(".github/")
                    and "node_modules/" not in f]:
            findings.extend(self._kubernetes(ctx, rel))
        findings.extend(self._debug_config(ctx, dockerfiles))
        return findings

    # ------------------------------------------------------------------------------------------------
    def _repo(self, ctx, rule, title, sev, conf, kind, desc, fix, file_path="", line=None, evidence=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.DEVOPS, severity=sev, confidence=conf,
                            kind=kind, description=desc, remediation=fix, file_path=file_path, line=line,
                            evidence=evidence)

    def _dockerfile(self, ctx: AnalyzerContext, path: str):
        out = []
        lines = ctx.lines(path)
        user_set = False
        stage_starts = [i for i, ln in enumerate(lines) if ln.strip().upper().startswith("FROM ")]
        last_stage = stage_starts[-1] if stage_starts else 0
        has_healthcheck = False
        stages: set[str] = set()  # `FROM image AS name`: later `FROM name` builds on that stage, not a registry image
        for i, raw in enumerate(lines, start=1):
            line = raw.strip()
            upper = line.upper()
            if upper.startswith("USER ") and i - 1 >= last_stage:
                user_set = line.split(None, 1)[1].strip() not in ("root", "0", "0:0")
            if upper.startswith("HEALTHCHECK"):
                has_healthcheck = True
            if upper.startswith("FROM "):
                words = [w for w in line.split()[1:] if not w.startswith("--")]  # --platform=…
                image = words[0] if words else ""
                registry_image = image.lower() not in stages
                if len(words) >= 3 and words[1].upper() == "AS":
                    stages.add(words[2].lower())
                if registry_image and image.lower() != "scratch" and "$" not in image and "@sha256:" not in image:
                    tag = image.rsplit("/", 1)[-1]
                    if ":" not in tag or tag.endswith(":latest"):
                        out.append(self._repo(ctx, "devops.dockerfile-unpinned-base", "Base image is not pinned",
                                              Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                              f"`{image}` resolves to whatever 'latest' is at build time, making "
                                              "builds non-reproducible and silently pulling breaking changes.",
                                              "Pin a specific version tag (ideally also the digest).", path, i))
            # `ENV DB_PASSWORD_FILE=/run/secrets/db` points at a mounted secret instead of holding one.
            if SECRET_ENV.match(raw) and not re.search(r"(?i)^\s*(?:ENV|ARG)\s+\w*_(?:FILE|PATH|DIR)\b", raw):
                out.append(self._repo(ctx, "devops.dockerfile-secret-in-env", "Secret baked into image via ENV/ARG",
                                      Severity.HIGH, Confidence.MEDIUM, FindingKind.CONFIRMED,
                                      "Values set with ENV/ARG are stored in image layers and visible to anyone "
                                      "who can pull the image (`docker history`).",
                                      "Pass secrets at runtime (environment, secret mounts, or BuildKit "
                                      "`--mount=type=secret`).", path, i))
            if re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh\b", line):
                out.append(self._repo(ctx, "devops.dockerfile-curl-pipe-shell", "Remote script piped to a shell",
                                      Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "Piping a downloaded script into a shell executes unverified remote code "
                                      "during the build.",
                                      "Download, verify a checksum or signature, then execute.", path, i))
            if upper.startswith("ADD ") and re.search(r"\bhttps?://", line):
                out.append(self._repo(ctx, "devops.dockerfile-add-url", "ADD with a remote URL",
                                      Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "ADD fetches remote content without integrity verification.",
                                      "Use curl/wget with checksum verification, or COPY local files.", path, i))
        if stage_starts and not user_set:
            out.append(self._repo(ctx, "devops.dockerfile-runs-as-root", "Container runs as root",
                                  Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                  "The final stage never switches to a non-root USER, so a compromise of the "
                                  "process gives root inside the container.",
                                  "Create an unprivileged user and add `USER <name>` to the final stage.",
                                  path, stage_starts[-1] + 1))
        if stage_starts and not has_healthcheck:
            out.append(self._repo(ctx, "devops.dockerfile-no-healthcheck", "Dockerfile has no HEALTHCHECK",
                                  Severity.INFO, Confidence.HIGH, FindingKind.CONFIRMED,
                                  "Without a health check, orchestrators cannot detect a hung process (not "
                                  "needed if Kubernetes probes are configured instead).",
                                  "Add a HEALTHCHECK or configure liveness/readiness probes.", path))
        return out

    def _compose(self, ctx: AnalyzerContext, path: str):
        out = []
        for i, raw in enumerate(ctx.lines(path), start=1):
            line = raw.strip()
            if re.match(r"^privileged:\s*true", line):
                out.append(self._repo(ctx, "devops.compose-privileged", "Privileged container",
                                      Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "privileged: true disables container isolation and grants host-level access.",
                                      "Remove privileged mode; grant only the specific capabilities needed.", path, i))
            m = re.match(r"""^-\s*["']?(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d+):(\d+)["']?""", line)
            # Comparison against a parsed compose value, not a socket bind.
            if m and m.group(3) in DB_PORTS and m.group(1) in (None, "0.0.0.0"):  # noqa: S104  # nosec B104
                out.append(self._repo(ctx, "devops.compose-db-port-exposed", "Data store port published on all "
                                      "interfaces", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.CONFIRMED,
                                      f"Port {m.group(3)} (a database/cache port) is published without binding to "
                                      "127.0.0.1, exposing it to the network if this file is used beyond local dev.",
                                      "Do not publish data store ports, or bind them to 127.0.0.1.", path, i))
            if "/var/run/docker.sock" in line:
                out.append(self._repo(ctx, "devops.compose-docker-socket", "Docker socket mounted into container",
                                      Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "Access to the Docker socket is equivalent to root on the host.",
                                      "Avoid mounting the socket; use a constrained API proxy if required.", path, i))
        services = _yaml_section(ctx.lines(path), "services")
        unlimited = [(name, line) for name, (line, block) in services.items() if not re.search(
            r"(?m)^\s*(?:mem_limit|memswap_limit|cpus|mem_reservation|limits)\s*:", block)]
        if unlimited:
            out.append(self._repo(ctx, "devops.compose-no-resource-limits", f"{len(unlimited)} Compose service(s) "
                                  "without memory/CPU limits", Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                  "Services without mem_limit/cpus (or deploy.resources.limits) can consume all of "
                                  "the host's memory and CPU; one leaking or overloaded container starves the others "
                                  "and can trigger the kernel OOM killer on unrelated processes. (Matters when this "
                                  "file runs anything beyond local development.)",
                                  "Set deploy.resources.limits (memory, cpus) or mem_limit/cpus for every service, "
                                  "sized from observed usage.", path, unlimited[0][1],
                                  evidence="no limits: " + ", ".join(n for n, _ in unlimited[:15])))
        return out

    def _github_workflow(self, ctx: AnalyzerContext, path: str):
        out = []
        text = ctx.read(path) or ""
        lines = text.splitlines()
        if "pull_request_target" in text and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
            line = next((i for i, ln in enumerate(lines, 1) if "pull_request.head" in ln), None)
            out.append(self._repo(ctx, "devops.gha-pull-request-target-checkout",
                                  "pull_request_target workflow checks out untrusted PR code",
                                  Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                  "pull_request_target runs with repository secrets and a write token; checking "
                                  "out and building the PR head lets external contributors run code with them.",
                                  "Use the pull_request trigger for untrusted code, or never execute the checked-out "
                                  "PR code in a pull_request_target job.", path, line))
        if not re.search(r"^\s*permissions\s*:", text, re.M):
            out.append(self._repo(ctx, "devops.gha-default-permissions", "Workflow does not restrict GITHUB_TOKEN "
                                  "permissions", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                  "Without a permissions block, the token may get the repository's default (often "
                                  "read/write) scope.",
                                  "Add `permissions: contents: read` at the top and widen per job only as needed.",
                                  path))
        unpinned = 0
        first = None
        script_indent = None  # indent of a `run:`/`script:` key whose block scalar (| or >) is open
        for i, ln in enumerate(lines, start=1):
            indent = len(ln) - len(ln.lstrip())
            if script_indent is not None and ln.strip() and indent <= script_indent:
                script_indent = None
            executes = script_indent is not None
            if key := SCRIPT_KEY.match(ln):
                if re.fullmatch(r"[|>][-+]?\s*(?:#.*)?", key.group(2).strip()):
                    script_indent = key.start(1)
                else:
                    executes = True
            # Only where the value is executed: `env:` / `with:` inputs are the safe way to pass event data.
            if executes and UNTRUSTED_CONTEXT.search(ln):
                out.append(self._repo(ctx, "devops.gha-script-injection", "Untrusted event data interpolated into "
                                      "a workflow", Severity.HIGH, Confidence.MEDIUM, FindingKind.CONFIRMED,
                                      "Attacker-controlled fields (titles, bodies, branch names) expanded with "
                                      "${{ }} inside run steps allow shell injection in CI.",
                                      "Pass the value through an environment variable and reference it as \"$VAR\".",
                                      path, i))
            m = ACTION_USES.match(ln)
            if m and not m.group(1).startswith("./") and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                unpinned += 1
                first = first or i
        if unpinned:
            out.append(self._repo(ctx, "devops.gha-unpinned-actions", f"{unpinned} third-party action reference(s) "
                                  "not pinned to a commit SHA", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                  "Tags like @v4 are mutable; a compromised action repository can change the code "
                                  "your pipeline runs.",
                                  "Pin actions to full commit SHAs (tools like Dependabot can keep them updated).",
                                  path, first))
        return out

    # ------------------------------------------------------------------------------------------------ deployment
    def _deployment_pipeline(self, ctx: AnalyzerContext, workflows: list[str]):
        """GitHub Actions deploy jobs: test gate, environment protection/separation, immutable artifacts, and
        whether any rollback strategy exists."""
        out = []
        deploys = []  # (workflow, job, line, block)
        for wf in workflows:
            text = ctx.read(wf) or ""
            jobs = _yaml_section(text.splitlines(), "jobs")
            chained = bool(re.search(r"(?m)^\s*workflow_run\s*:", text))
            for job, (line, block) in jobs.items():
                if not (DEPLOY_COMMAND.search(block) or re.search(r"(?i)deploy", job)):
                    continue
                deploys.append((wf, job, line, block))
                if not chained and not TEST_COMMAND.search(block) and not any(
                        TEST_COMMAND.search(jobs[n][1]) for n in _needs_closure(job, jobs) if n in jobs):
                    out.append(self._repo(ctx, "devops.deploy-without-test-gate", f"Deploy job `{job}` does not "
                                          "depend on a test job", Severity.LOW, Confidence.MEDIUM,
                                          FindingKind.POTENTIAL,
                                          "The job deploys, but neither it nor any job it `needs:` runs tests, and "
                                          "the workflow is not chained after a CI workflow. A red build can reach "
                                          "users unless branch protection enforces CI before every merge.",
                                          "Add `needs: [test]` (a job that runs the test suite) to the deploy job, "
                                          "or trigger deployment with workflow_run after CI succeeds.", wf, line))
                if (m := MUTABLE_IMAGE.search(block)):
                    out.append(self._repo(ctx, "devops.deploy-mutable-tag", "Deployment uses the mutable `:latest` "
                                          "image tag", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                          "Deploying `:latest` means the running version is whatever the tag "
                                          "pointed to at pull time: you cannot tell what is deployed, nodes can run "
                                          "different builds, and rolling back to a known version is not possible.",
                                          "Tag images with the commit SHA or release version and deploy that tag "
                                          "(optionally by digest).", wf, line + block[:m.start()].count("\n") + 1))
        if not deploys:
            return out
        names = " ".join(ctx.files)
        workflow_text = "\n".join(ctx.read(wf) or "" for wf in workflows)
        unprotected = [(wf, job, line) for wf, job, line, block in deploys
                       if not re.search(r"(?m)^\s+environment\s*:", block)]
        if unprotected and not ENV_NAME_HINT.search(workflow_text) and not ENV_NAME_HINT.search(names):
            wf, job, line = unprotected[0]
            out.append(self._repo(ctx, "devops.no-environment-separation", "Deployments go straight to a single "
                                  "environment", Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                  f"Deploy job `{job}` uses no GitHub `environment:` and nothing in the pipeline or "
                                  "repository refers to a staging, preview or QA environment. Every change is first "
                                  "exercised in production, and production secrets are available to any job of the "
                                  "workflow.",
                                  "Deploy to a staging environment first, and use GitHub environments (with required "
                                  "reviewers and environment-scoped secrets) for production.", wf, line))
        docs = [f for f in ctx.files if f.lower().endswith((".md", ".rst", ".txt", ".sh", ".yml", ".yaml"))
                or f.rsplit("/", 1)[-1] in ("Makefile", "justfile", "Procfile")]
        if not any(ROLLBACK_HINT.search(ctx.read(f) or "") for f in docs[:3000]):
            wf, job, line, _ = deploys[0]
            out.append(self._repo(ctx, "devops.no-rollback-strategy", "No rollback strategy found",
                                  Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                  f"The pipeline deploys (`{job}`), but neither the workflows, deploy scripts nor the "
                                  "documentation describe how to roll back (no rollback step, `helm rollback`, "
                                  "`kubectl rollout undo`, blue/green or canary, or runbook). A bad release has to be "
                                  "fixed forward under pressure.",
                                  "Deploy immutable, versioned artifacts, keep the previous release available, and "
                                  "document (and rehearse) the rollback command, including how database migrations "
                                  "are reverted or kept backward compatible.", wf, line))
        return out

    def _kubernetes(self, ctx: AnalyzerContext, path: str):
        text = ctx.read(path) or ""
        if not K8S_WORKLOAD.search(text) or "containers:" not in text:
            return []
        out = []
        docs, pos = [], 0
        for sep in re.finditer(r"(?m)^---\s*$", text):
            docs.append((pos, text[pos:sep.start()]))
            pos = sep.end()
        docs.append((pos, text[pos:]))
        for offset, doc in docs:
            m = K8S_WORKLOAD.search(doc)
            if not m or "containers:" not in doc or "{{" in doc:
                continue  # not a workload, or a Helm template whose values are set elsewhere
            kind = m.group(1)
            line = text.count("\n", 0, offset + m.start()) + 1
            name_m = re.search(r"(?m)^metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+name:\s*[\"']?([\w.-]+)", doc)
            label = f"{kind} `{name_m.group(1) if name_m else '?'}`"
            if not re.search(r"(?m)^\s+limits\s*:", doc):
                out.append(self._repo(ctx, "devops.k8s-no-resource-limits", f"{label} has no resource limits",
                                      Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "Containers without resources.limits can use all memory/CPU of the node, "
                                      "starving neighbours; without requests the scheduler cannot place pods "
                                      "sensibly.",
                                      "Set resources.requests and resources.limits (at least memory) for every "
                                      "container, or enforce defaults with a LimitRange.", path, line))
            if kind in ("Deployment", "StatefulSet", "DaemonSet") and not re.search(
                    r"livenessProbe|readinessProbe|startupProbe", doc):
                out.append(self._repo(ctx, "devops.k8s-no-probes", f"{label} has no liveness/readiness probes",
                                      Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "Without probes Kubernetes sends traffic to pods that are still starting or "
                                      "hung, and never restarts a deadlocked process.",
                                      "Add a readinessProbe (dependencies ready) and a livenessProbe (process "
                                      "responsive) pointing at cheap health endpoints.", path, line))
            explicit_root = re.search(r"(?m)^\s*runAsUser:\s*0\s*$", doc)
            if explicit_root or not re.search(r"runAsNonRoot:\s*true|runAsUser:\s*[1-9]", doc):
                out.append(self._repo(ctx, "devops.k8s-runs-as-root", f"{label} may run containers as root",
                                      Severity.MEDIUM, Confidence.HIGH if explicit_root else Confidence.MEDIUM,
                                      FindingKind.CONFIRMED if explicit_root else FindingKind.POTENTIAL,
                                      "runAsUser: 0 is set." if explicit_root else
                                      "No securityContext sets runAsNonRoot: true or a non-zero runAsUser, so the "
                                      "container runs as whatever user the image defaults to, usually root.",
                                      "Set securityContext.runAsNonRoot: true, a non-zero runAsUser, "
                                      "allowPrivilegeEscalation: false and readOnlyRootFilesystem: true.",
                                      path, line))
            if re.search(r"(?m)^\s*privileged:\s*true", doc):
                out.append(self._repo(ctx, "devops.k8s-privileged", f"{label} runs a privileged container",
                                      Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                      "privileged: true gives the container full access to the node's devices and "
                                      "kernel; a compromise of the app is a compromise of the node.",
                                      "Remove privileged mode and grant only the specific capabilities needed.",
                                      path, line))
            for im in K8S_IMAGE.finditer(doc):
                image = im.group(1)
                tag = image.rsplit("/", 1)[-1]
                if "@sha256:" not in image and "$" not in image and (":" not in tag or tag.endswith(":latest")):
                    out.append(self._repo(ctx, "devops.k8s-unpinned-image", f"{label} uses an unpinned image",
                                          Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                          f"`{image}` resolves to 'latest' at pull time: pods of one deployment can "
                                          "run different builds and rollbacks cannot return to a known version.",
                                          "Reference an explicit version tag or digest.", path,
                                          text.count("\n", 0, offset + im.start()) + 1))
                    break
            if (d := K8S_DEBUG_ENV.search(doc)):
                out.append(self._debug_finding(ctx, path, text.count("\n", 0, offset + d.start()) + 1))
        return out

    def _debug_finding(self, ctx, path, line):
        return self._repo(ctx, "devops.debug-in-deployment-config", "Debug/development mode set in deployment "
                          "configuration", Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                          "A deployment file enables debug mode or a development environment. Debug modes expose "
                          "stack traces, configuration and sometimes interactive consoles, and development settings "
                          "disable caching and security hardening.",
                          "Set debug off and the environment to production in deployment files; keep debug settings "
                          "in local-only configuration.", path, line)

    def _dev_server_finding(self, ctx, path, line):
        return self._repo(ctx, "devops.dev-server-in-production", "Container/platform starts a development server",
                          Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                          "The start command runs a development server (flask run, runserver, npm run dev, "
                          "nodemon, --reload, …). These are single-process, unoptimized, may enable debuggers, and "
                          "are documented as unsuitable for production.",
                          "Start a production server (gunicorn/uvicorn workers without --reload, `node server.js` "
                          "on a production build, `next start`) and keep dev commands for local use.", path, line)

    def _debug_config(self, ctx: AnalyzerContext, dockerfiles: list[str]):
        """Debug settings and development servers in files that describe how the app runs in production."""
        out = []
        for path in dockerfiles:
            if DEV_DOCKERFILE.search(path):
                continue
            lines = ctx.lines(path)
            stages = [i for i, ln in enumerate(lines) if ln.strip().upper().startswith("FROM ")]
            first = stages[-1] if stages else 0
            debug_line = server_line = None
            for i, raw in enumerate(lines[first:], start=first + 1):
                line = raw.strip()
                upper = line.upper()
                if upper.startswith("ENV ") and not debug_line:
                    pairs = re.sub(r"^ENV\s+(\w+)\s+(?!.*=)", r"\1=", line, flags=re.I)
                    if DEBUG_SETTING.search(pairs):
                        debug_line = i
                if upper.startswith(("CMD", "ENTRYPOINT")) and DEV_SERVER.search(line):
                    server_line = i
            if debug_line:
                out.append(self._debug_finding(ctx, path, debug_line))
            if server_line:
                out.append(self._dev_server_finding(ctx, path, server_line))
        for path in ctx.files_named(*PLATFORM_FILES):
            text = ctx.read(path) or ""
            if path.endswith("Procfile"):
                for i, ln in enumerate(text.splitlines(), start=1):
                    if re.match(r"^\s*(web|worker)\s*:", ln) and DEV_SERVER.search(ln):
                        out.append(self._dev_server_finding(ctx, path, i))
                        break
            if (m := DEBUG_SETTING.search(text) or K8S_DEBUG_ENV.search(text)):
                out.append(self._debug_finding(ctx, path, text.count("\n", 0, m.start()) + 1))
        for path in [f for f in ctx.files if PROD_ENV_FILE.search(f) or PROD_COMPOSE.search(f)]:
            text = ctx.read(path) or ""
            if (m := DEBUG_SETTING.search(text) or K8S_DEBUG_ENV.search(text)):
                out.append(self._debug_finding(ctx, path, text.count("\n", 0, m.start()) + 1))
        return out


def _yaml_section(lines: list[str], key: str) -> dict[str, tuple[int, str]]:
    """Children of a top-level mapping key (Compose `services:`, workflow `jobs:`): name -> (line, block text)."""
    children: dict[str, tuple[int, str]] = {}
    inside, child_indent, current = False, None, None
    for i, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent == 0:
            inside, current = bool(re.match(rf"^{re.escape(key)}\s*:\s*$", raw)), None
            continue
        if not inside:
            continue
        child_indent = indent if child_indent is None else child_indent
        if indent == child_indent and (m := re.match(r"""^\s*["']?([\w.-]+)["']?\s*:\s*$""", raw)):
            current = m.group(1)
            children[current] = (i, "")
        elif current and indent > child_indent:
            line, block = children[current]
            children[current] = (line, block + raw + "\n")
    return children


def _needs_closure(job: str, jobs: dict[str, tuple[int, str]]) -> set[str]:
    """Jobs that ``job`` transitively `needs:`."""
    seen: set[str] = set()
    todo = [job]
    while todo:
        block = jobs.get(todo.pop(), (0, ""))[1]
        m = re.search(r"(?m)^\s+needs\s*:[ \t]*(.*)$", block)
        if not m:
            continue
        inline = m.group(1).strip()
        if inline:
            names = re.findall(r"[\w.-]+", inline)
        else:
            names = []
            for ln in block[m.end():].splitlines()[1:]:
                item = re.match(r"""^\s+-\s*["']?([\w.-]+)""", ln)
                if not item:
                    break
                names.append(item.group(1))
        for name in names:
            if name in jobs and name not in seen:
                seen.add(name)
                todo.append(name)
    return seen
