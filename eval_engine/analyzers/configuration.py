"""Configuration and undocumented assumptions: environment variables the code needs but nobody documented,
endpoints and paths that only exist on the author's machine, and HTTP APIs without a contract.

AI-generated code tends to invent configuration on the fly (``os.environ["STRIPE_KEY"]``) and to hardcode the
values that happened to work locally. These checks surface those assumptions so they are written down or removed.
"""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
ENV_EXAMPLES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults", "example.env",
                "env.example", "sample.env", ".env.local.example", ".env.development.example"}
DOC_SUFFIXES = (".md", ".rst", ".txt", ".adoc", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".json", ".tf", ".env")
DOC_NAMES = {"Dockerfile", "Procfile", "Makefile", "Jenkinsfile"}
NOT_DOCS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock",
            "requirements.txt", "tsconfig.json", ".env"}
# Provided by the OS, the runtime, or the CI/hosting platform; not application configuration.
PLATFORM_VARS = {"PATH", "HOME", "USER", "USERNAME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "PWD", "SHELL", "LANG",
                 "LC_ALL", "TERM", "HOSTNAME", "CI", "NODE_ENV", "PYTHONPATH", "PYTHONUNBUFFERED", "VIRTUAL_ENV",
                 "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "SYSTEMROOT", "COMSPEC", "EDITOR", "DEBUG", "TZ",
                 "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "KUBERNETES_SERVICE_HOST", "DYNO"}
PLATFORM_PREFIXES = ("GITHUB_", "RUNNER_", "npm_", "VERCEL_", "RENDER_", "HEROKU_", "AWS_LAMBDA_", "NETLIFY_",
                     "PYTEST_", "COVERAGE_", "VSCODE_", "JEST_")
PY_ENV_CALLS = {"os.getenv", "getenv", "os.environ.get", "environ.get", "env", "env.str", "env.int", "env.bool",
                "env.list", "env.url", "env.db", "config", "decouple.config"}
JS_ENV = re.compile(r"\b(?:process\.env|import\.meta\.env)(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*[\"'`]"
                    r"([A-Za-z_][A-Za-z0-9_]*)[\"'`]\s*\])")
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{1,}")
LOCAL_ENDPOINT = re.compile(
    r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/\s]+@)?(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|host\.docker\.internal)(?::\d+)?(?:/|$)",
    re.I)
JS_LOCAL_ENDPOINT = re.compile(
    r"""["'`](?:[a-z][a-z0-9+.-]*://)(?:[^@/\s"'`]+@)?(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"""
    r"""192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?""", re.I)
# A UI default or placeholder the user can change, not a hardcoded dependency.
JS_DEFAULT_HINT = re.compile(r"(?i)\b(placeholder|default\w*|example)\b|\bvalue\s*:")
MACHINE_PATH = re.compile(r"^(?:/home/[^/\s]+/|/Users/[^/\s]+/|[A-Za-z]:\\+(?:Users|Documents and Settings)\\+[^\\]+)")
JS_MACHINE_PATH = re.compile(r"""["'`](?:/home/[^/\s"'`]+/|/Users/[^/\s"'`]+/|[A-Za-z]:\\\\(?:Users|Documents """
                             r"""and Settings)\\\\)""")
API_DOC_HINT = re.compile(r"(?i)openapi|swagger|flasgger|apispec|flask_smorest|flask-smorest|drf_spectacular|drf_yasg|"
                          r"spectree|@nestjs/swagger|fastify-swagger|@fastify/swagger|tsoa|redoc")
API_DOC_FILE = re.compile(r"(?i)(^|/)(openapi|swagger)[^/]*\.(ya?ml|json)$|(^|/)docs?/api(\.md|/)|(^|/)API\.md$")
PY_ROUTE = re.compile(r"^\s*@\w+\.(route|get|post|put|patch|delete|api_route)\(", re.M)
JS_ROUTE = re.compile(r"\b(?:app|router|server)\.(get|post|put|patch|delete)\(\s*[\"'`]/", re.M)
MAX_VAR_FINDINGS = 40


def _call_name(node: ast.Call) -> str:
    parts = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def _is_platform(name: str) -> bool:
    return name in PLATFORM_VARS or name.startswith(PLATFORM_PREFIXES)


@register
class ConfigurationAnalyzer(Analyzer):
    name = "configuration"
    title = "Configuration & documented assumptions"
    categories = (Category.MAINTAINABILITY, Category.DEVOPS)
    languages = ("python", "javascript", "typescript")

    def run(self, ctx: AnalyzerContext):
        reads: dict[str, tuple[str, int, bool]] = {}  # var -> (file, line, required)
        findings = []
        py_files = [f for f in ctx.python_files() if not is_test_path(f)]
        js_files = [f for f in ctx.files_with_suffix(*JS_SUFFIXES) if not is_test_path(f)
                    and not f.rsplit("/", 1)[-1].startswith(("vite.config", "webpack.config", "jest.config",
                                                             "vitest.config", "playwright.config"))]
        for rel in py_files:
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            defaults = self._python_env(tree, rel, reads)
            findings.extend(self._python_literals(ctx, rel, tree, defaults))
        for rel in js_files:
            findings.extend(self._js(ctx, rel, reads))
        findings.extend(self._env_documentation(ctx, reads))
        findings.extend(self._api_contract(ctx, py_files, js_files))
        return findings

    # --------------------------------------------------------------------------------- environment variables
    @staticmethod
    def _python_env(tree, rel, reads) -> set[int]:
        """Record env vars read by the module; return ids of constants used as env fallbacks (not hardcoding)."""
        fallbacks: set[int] = set()
        for node in ast.walk(tree):
            name, required = None, False
            if isinstance(node, ast.Subscript) and ast.unparse(node.value) in ("os.environ", "environ") and \
                    isinstance(node.slice, ast.Constant) and isinstance(node.ctx, ast.Load):
                name, required = node.slice.value, True
            elif isinstance(node, ast.Call) and _call_name(node) in PY_ENV_CALLS and node.args and \
                    isinstance(node.args[0], ast.Constant):
                name = node.args[0].value
                default = node.args[1] if len(node.args) > 1 else next(
                    (k.value for k in node.keywords if k.arg == "default"), None)
                required = default is None and _call_name(node) not in ("os.getenv", "getenv", "os.environ.get",
                                                                         "environ.get")
                for extra in [*node.args[1:], *(k.value for k in node.keywords)]:
                    fallbacks.update(id(n) for n in ast.walk(extra))
            if isinstance(name, str) and ENV_NAME.fullmatch(name) and not _is_platform(name):
                prev = reads.get(name)
                if prev is None or (required and not prev[2]):
                    reads[name] = (rel, node.lineno, required)
        return fallbacks

    def _env_documentation(self, ctx, reads):
        if not reads:
            return []
        examples = [f for f in ctx.files if f.rsplit("/", 1)[-1] in ENV_EXAMPLES]
        docs = [f for f in ctx.files if f.rsplit("/", 1)[-1] not in NOT_DOCS and (
            f.endswith(DOC_SUFFIXES) or f.rsplit("/", 1)[-1] in DOC_NAMES or f.rsplit("/", 1)[-1] in ENV_EXAMPLES)
            and not is_test_path(f)]
        corpus = "\n".join(ctx.read(f) or "" for f in docs[:2000])
        documented = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", corpus))
        missing = sorted(v for v in reads if v not in documented)
        if not missing:
            return []
        if not examples:
            required = [v for v in missing if reads[v][2]]
            if not required and len(missing) < 3:
                return []  # one or two optional settings with in-code defaults are self-describing enough
            rel, line, _ = reads[missing[0]]
            return [self._f(ctx, "config.no-env-example", f"{len(missing)} environment variable(s) used but no "
                            ".env.example and no documentation", Severity.MEDIUM if len(missing) >= 5 or required
                            else Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                            "The code reads configuration from the environment, but the repository has no "
                            ".env.example (or similar) and the variables are not mentioned in any documentation. "
                            "Nobody can deploy or run it without reading the source. Variables: "
                            + ", ".join(missing[:30]) + ("…" if len(missing) > 30 else "")
                            + (f". Required (no default): {', '.join(required[:15])}." if required else "."),
                            "Add a .env.example listing every variable with a safe placeholder and a one-line "
                            "comment; document required variables in the README.", rel, line,
                            Category.MAINTAINABILITY)]
        out = []
        for var in missing[:MAX_VAR_FINDINGS]:
            rel, line, required = reads[var]
            out.append(self._f(ctx, "config.undocumented-env-var", f"Environment variable {var} is not documented",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.CONFIRMED,
                               f"`{var}` is read here" + (" with no default, so startup or the request fails when it "
                                                         "is missing" if required else "")
                               + f", but it does not appear in {', '.join(examples[:2])} or any documentation.",
                               f"Add `{var}=` with a placeholder and a comment to {examples[0]}.", rel, line,
                               Category.MAINTAINABILITY))
        return out

    # ------------------------------------------------------------------------------ hardcoded assumptions
    def _python_literals(self, ctx, rel, tree, fallbacks):
        endpoint = path = None
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or id(node) in fallbacks:
                continue
            value = node.value.strip()
            if endpoint is None and len(value) < 300 and LOCAL_ENDPOINT.match(value) and ("://" in value or
                                                                                         ":" in value):
                endpoint = (node.lineno, value)
            if path is None and MACHINE_PATH.match(value):
                path = node.lineno
        return self._literal_findings(ctx, rel, endpoint[0] if endpoint else None, path)

    def _js(self, ctx, rel, reads):
        endpoint = path = None
        for i, line in enumerate(ctx.lines(rel), start=1):
            for m in JS_ENV.finditer(line):
                name = m.group(1) or m.group(2)
                if ENV_NAME.fullmatch(name) and not _is_platform(name) and name not in reads:
                    reads[name] = (rel, i, False)
            if endpoint is None and JS_LOCAL_ENDPOINT.search(line) and not JS_ENV.search(line) \
                    and not JS_DEFAULT_HINT.search(line):
                endpoint = i
            if path is None and JS_MACHINE_PATH.search(line):
                path = i
        return self._literal_findings(ctx, rel, endpoint, path)

    def _literal_findings(self, ctx, rel, endpoint_line, path_line):
        out = []
        if endpoint_line:
            out.append(self._f(ctx, "config.hardcoded-endpoint", "Local or private network address hardcoded",
                               Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                               "A localhost or private-network address is written into the code. It works on the "
                               "author's machine and silently points somewhere wrong (or nowhere) in every other "
                               "environment.",
                               "Read the address from configuration (environment variable or settings) and document "
                               "it; keep local defaults only in .env.example or dev settings.", rel, endpoint_line,
                               Category.DEVOPS))
        if path_line:
            out.append(self._f(ctx, "config.machine-specific-path", "Absolute path to a user's home directory",
                               Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                               "The code depends on a path that only exists on one developer's machine.",
                               "Use paths relative to the project, a configured data directory, or tempfile.",
                               rel, path_line, Category.DEVOPS))
        return out

    # ------------------------------------------------------------------------------------- API contract
    def _api_contract(self, ctx, py_files, js_files):
        frameworks = set(ctx.languages.frameworks)
        if "fastapi" in frameworks:
            return []  # FastAPI publishes an OpenAPI document automatically
        routes = sum(len(PY_ROUTE.findall(ctx.read(f) or "")) for f in py_files) + sum(
            len(JS_ROUTE.findall(ctx.read(f) or "")) for f in js_files)
        if routes < 5 or any(API_DOC_FILE.search(f) for f in ctx.files):
            return []
        manifests = ctx.files_named("requirements.txt", "pyproject.toml", "package.json", "Pipfile")
        if any(API_DOC_HINT.search(ctx.read(f) or "") for f in [*manifests, *py_files, *js_files][:3000]):
            return []
        return [self._f(ctx, "config.undocumented-api", f"{routes} HTTP routes without an API contract",
                        Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                        "No OpenAPI/Swagger specification, generator, or API reference document was found. Request "
                        "and response shapes, status codes and auth requirements exist only in the code, so clients "
                        "rely on undocumented assumptions and breaking changes go unnoticed.",
                        "Publish an OpenAPI document (generated, e.g. flask-smorest / drf-spectacular / "
                        "swagger-jsdoc, or hand-written) and review changes to it in pull requests.", "", None,
                        Category.MAINTAINABILITY)]

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line, category):
        return self.finding(ctx, rule=rule, title=title, category=category, severity=sev, confidence=conf, kind=kind,
                            description=desc, remediation=fix, file_path=rel, line=line)
