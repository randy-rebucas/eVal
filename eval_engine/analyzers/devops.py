"""DevOps, CI/CD, deployment configuration, logging and operability checks."""

from __future__ import annotations

import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

CI_MARKERS = (".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml",
              "bitbucket-pipelines.yml", ".travis.yml", ".buildkite/", ".drone.yml")
DB_PORTS = {"5432", "3306", "6379", "27017", "9200", "11211", "5672", "1433"}
SECRET_ENV = re.compile(r"(?i)^\s*(?:ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*[ =]\s*\S+")
ACTION_USES = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)")
UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|"
    r"review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.message|head_commit\.message|"
    r"head_commit\.author\.(?:email|name)|pull_request\.head\.ref|pull_request\.head\.label|workflow_run\.head_branch)"
)
HEALTH_ROUTE = re.compile(r"""["'`]/(?:health|healthz|livez|readyz|ready|status|ping)["'`/]""", re.I)
WEB_FRAMEWORKS = {"flask", "django", "fastapi", "express", "nestjs", "fastify", "koa", "starlette"}


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
        for wf in [f for f in ci_files if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))]:
            findings.extend(self._github_workflow(ctx, wf))
        findings.extend(self._operability(ctx))
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
        for i, raw in enumerate(lines, start=1):
            line = raw.strip()
            upper = line.upper()
            if upper.startswith("USER ") and i - 1 >= last_stage:
                user_set = line.split(None, 1)[1].strip() not in ("root", "0", "0:0")
            if upper.startswith("HEALTHCHECK"):
                has_healthcheck = True
            if upper.startswith("FROM "):
                image = line.split()[1] if len(line.split()) > 1 else ""
                if image.lower() != "scratch" and "$" not in image and "@sha256:" not in image:
                    tag = image.rsplit("/", 1)[-1]
                    if ":" not in tag or tag.endswith(":latest"):
                        out.append(self._repo(ctx, "devops.dockerfile-unpinned-base", "Base image is not pinned",
                                              Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                              f"`{image}` resolves to whatever 'latest' is at build time, making "
                                              "builds non-reproducible and silently pulling breaking changes.",
                                              "Pin a specific version tag (ideally also the digest).", path, i))
            if SECRET_ENV.match(raw):
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
        for i, ln in enumerate(lines, start=1):
            if UNTRUSTED_CONTEXT.search(ln):
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

    def _operability(self, ctx: AnalyzerContext):
        out = []
        frameworks = set(ctx.languages.frameworks)
        source_py = [f for f in ctx.python_files() if not is_test_path(f)]
        if len(source_py) >= 5:
            uses_logging = any(re.search(r"^\s*(import logging|from logging|import structlog|from loguru)",
                                         ctx.read(f) or "", re.M) for f in source_py)
            if not uses_logging:
                out.append(self._repo(ctx, "devops.no-logging", "No logging framework usage detected (Python)",
                                      Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                      "None of the Python source files import logging/structlog/loguru. Production "
                                      "incidents are hard to diagnose without structured logs.",
                                      "Adopt structured logging with levels and request correlation IDs."))
        if frameworks & WEB_FRAMEWORKS:
            code_files = [f for f in ctx.files if f.endswith((".py", ".js", ".ts", ".mjs")) and not is_test_path(f)]
            has_health = any(HEALTH_ROUTE.search(ctx.read(f) or "") for f in code_files[:3000])
            if not has_health:
                out.append(self._repo(ctx, "devops.no-health-endpoint", "No health-check endpoint detected",
                                      Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                      "A web framework is used but no /health, /healthz, /ready or similar route "
                                      "was found. Load balancers and orchestrators need one to route traffic "
                                      "safely.",
                                      "Expose a cheap liveness endpoint and a readiness endpoint that checks "
                                      "critical dependencies."))
        return out
