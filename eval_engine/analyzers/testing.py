"""Testing practices. All checks are static: test files are read, never run.

* no tests at all, a language with substantial code and no tests, and a low test-to-code ratio;
* an ``npm test`` placeholder script, and CI that never runs the test suite;
* missing integration tests: the application has a datastore but no test touches a database or lives in an
  integration / e2e suite;
* missing API tests: the application defines HTTP route handlers but no test uses an HTTP test client;
* critical paths without tests: authentication, password, token, payment, billing, webhook… modules and endpoints
  that no test file references. Endpoints come from Flask/FastAPI decorators, Express-style routers, Django
  ``urls.py``, NestJS controllers and Next.js file routes; a test reaches one by route name (``reverse``,
  ``url_for``, ``url_path_for``) or by a URL whose trailing segments match, so f-strings, template literals,
  concatenation and mount prefixes count;
* untested error paths: a suite that never checks a failure although the code raises and returns errors, and
  modules with their own test file whose errors that file never exercises;
* tests without assertions (Python) and tests whose only assertions are weak (truthiness, not-None, type checks);
* duplicated test setup: the same opening statements copied into several tests instead of a fixture or
  ``beforeEach``.

Assertions that can never fail and JavaScript test files without any assertion are reported by ``ai_code``.
"""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict

from ..findings import Category, Confidence, FindingKind, Severity
from ..languages import CODE_LANGUAGES, EXTENSIONS
from .architecture import JS_EXTS, ArchitectureAnalyzer, _body, _is_exempt, _js_block, _stem, _tokens
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

CI_TEST_COMMANDS = re.compile(
    r"\b(pytest|tox|nox|python -m unittest|npm (run )?test|npm t\b|yarn test|pnpm test|jest|vitest|mocha|"
    r"go test|cargo test|mvn (-\S+ )*test|gradle(w)? test|\./gradlew test|bundle exec rspec|rspec|phpunit|"
    r"dotnet test|make test|playwright test|cypress run)\b"
)
DEFAULT_NPM_TEST = "no test specified"

RATIO_MIN_LOC = 200
LANGUAGE_WITHOUT_TESTS_LOC = 500
LANGUAGE_GROUPS = {"typescript": "javascript", "vue": "javascript", "svelte": "javascript"}
SUITE_ERROR_SITES = 5             # raise/throw/error responses in source before a happy-path-only suite is flagged
MODULE_ERROR_SITES = 2
DUPLICATE_SETUP_STATEMENTS = 3    # identical opening statements…
DUPLICATE_SETUP_TESTS = 3         # …in at least this many tests
MAX_LISTED = 12
MAX_PER_RULE = 30

# --------------------------------------------------------------------------------------------- what tests do
API_TEST_CLIENT = re.compile(
    r"\btest_client\(|\bTestClient\(|\bAsyncClient\(|\bAPIClient\(|\bAPIRequestFactory\(|\bRequestFactory\(|"
    r"\bclient\.(?:get|post|put|patch|delete|options|head)\(|\bLiveServerTestCase\b|"
    r"from\s+django\.test\s+import[^\n]*\bClient\b|\bsupertest\b|\brequest\(\s*(?:app|server)\b|"
    r"\.inject\(\s*\{|\bapp\.request\(|\bnew\s+(?:Next)?Request\(|\bpactum\b|"
    r"\b(?:fetch|axios\.\w+|requests\.\w+|httpx\.\w+)\(\s*[\"'`]https?://(?:localhost|127\.0\.0\.1)"
)
INTEGRATION_PATH = re.compile(r"(?:^|[/_.-])(?:integration|e2e|functional|acceptance|end[-_]?to[-_]?end)(?:[/_.-]|s/)",
                              re.I)
DB_IN_TESTS = re.compile(
    r"\bcreate_all\(|\bdrop_all\(|\bdb\.session\b|\bsessionmaker\(|\bcreate_engine\(|testcontainers|"
    r"pytest\.mark\.django_db|from\s+django\.test\s+import[^\n]*\b(?:TestCase|TransactionTestCase)\b|"
    r"\bsqlite:|:memory:|DATABASE_UR[LI]|\bmongomock\b|mongodb-memory-server|MongoMemoryServer|fakeredis|"
    r"\bmongoose\.connect\(|\bsequelize\.sync\(|\bknex\.migrate|\bprisma\.\w+\.(?:create|deleteMany|findMany)\(|"
    r"\bTest\.createTestingModule\(|\bnew\s+Pool\(|\bdef\s+(?:db|database|db_session|session)\s*\("
)
ERROR_CHECK = re.compile(
    r"pytest\.raises|assertRaises|\braises\(|status(?:_code)?\s*(?:==|!=|>=?|<=?|,)\s*[45]\d\d\b|"
    r"\b[45]\d\d\s*==\s*\w+\.status|\bHTTP_[45]\d\d(?:_|\b)|"
    r"HTTPStatus\.(?:BAD_REQUEST|UNAUTHORIZED|FORBIDDEN|NOT_FOUND|CONFLICT|UNPROCESSABLE_ENTITY|"
    r"INTERNAL_SERVER_ERROR)|\.expect\(\s*[45]\d\d\b|\btoThrow|\brejects\b|toBeRejected|assert\.(?:throws|rejects)|"
    r"\.(?:toBe|toEqual|toStrictEqual|equal|equals|is)\(\s*[45]\d\d\b"
)
JS_ERROR_SITE = re.compile(r"\bthrow\b|\.status\(\s*[45]\d\d\b|\bsendStatus\(\s*[45]\d\d\b|\bstatus:\s*[45]\d\d\b")
JS_MATCHER = re.compile(r"\.\s*(not\s*\.\s*)?(to[A-Z]\w*)\s*\(")
JS_WEAK_MATCHERS = {"toBeTruthy", "toBeDefined", "toBeInstanceOf"}
JS_WEAK_NEGATED = {"toBeNull", "toBeUndefined", "toBeFalsy"}
JS_TEST_BLOCK = re.compile(r"^\s*(?:it|test)(?:\.only)?\s*\(\s*[\"'`][^\n]*?(?:=>|function\s*\w*\s*\([^)]*\))\s*\{",
                           re.M)

# --------------------------------------------------------------------------------------------- critical paths
CRITICAL_NAMES = {
    "auth", "authentication", "authenticate", "login", "logout", "signin", "signout", "signup", "register",
    "registration", "password", "passwords", "oauth", "token", "tokens", "jwt", "permission", "permissions",
    "rbac", "acl", "payment", "payments", "pay", "billing", "checkout", "charge", "charges", "refund", "refunds",
    "invoice", "invoices", "subscription", "subscriptions", "webhook", "webhooks", "stripe", "paypal", "transfer",
    "transfers", "wallet", "withdraw", "withdrawal", "deposit",
}
PY_ROUTE_PATH = re.compile(
    r"""^\s*@\w+(?:\.\w+)*\.(route|get|post|put|patch|delete|api_route)\(\s*[rf]?["']([^"']*)["']([^\n]*)""", re.M)
JS_ROUTE_PATH = re.compile(
    r"""\b(?:app|router|server|api|\w+Router)\.(get|post|put|patch|delete|all)\(\s*["'`](/[^"'`\n]*)["'`]""")
DJANGO_PATH = re.compile(r"""\b(?:re_)?path\(\s*r?["']([^"']*)["']([^\n]*)""")
NEST_PREFIX = re.compile(r"""@Controller\(\s*["'`]([^"'`]*)["'`]""")
NEST_ROUTE = re.compile(r"""@(Get|Post|Put|Patch|Delete|All)\(\s*(?:["'`]([^"'`]*)["'`])?\s*\)""")
NEXT_METHOD = re.compile(r"^export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", re.M)
PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)", re.M)
ROUTE_NAME_KW = re.compile(r"""\b(?:endpoint|name)\s*=\s*["']([\w.:-]+)["']""")
# How tests reach an endpoint: by route name, or by a URL literal (plain, f-string, template literal, concatenation).
URL_NAME_REF = re.compile(
    r"""\b(?:reverse|reverse_lazy|url_for|url_path_for|resolve_url|redirect)\(\s*["']([\w.:-]+)["']""")
# Interpolations ({...} / ${...}) are taken whole: f"/o/{org['id']}/x" holds quotes that are not the closing one.
TEST_URL = re.compile(r"""(["'`])(?:https?://[^/"'`\s]*)?(/(?:\$?\{[^{}\n]*\}|(?!\1)[^\s\\{])*)""")
URL_PARAM = re.compile(r"[<{(:*$\[]")
WEAK_UNITTEST = {"assertIsNotNone", "assertIsInstance"}


def _code_lines(ctx: AnalyzerContext, files: list[str]) -> int:
    return sum(sum(1 for ln in ctx.lines(f) if ln.strip()) for f in files)


def _language(rel: str) -> str | None:
    lang = EXTENSIONS.get("." + rel.rsplit(".", 1)[-1].lower())
    return LANGUAGE_GROUPS.get(lang, lang) if lang in CODE_LANGUAGES else None


GENERIC_MODULE_NAMES = {"__init__", "__main__", "index", "main", "app", "conftest"}  # say nothing about the subject


def _module_name(rel: str) -> str:
    """``app/auth.service.ts`` → ``auth``; the name a test file for it would carry."""
    return rel.rsplit("/", 1)[-1].split(".", 1)[0].lower()


def _subject(test_rel: str) -> str:
    """The module a test file is named after: ``test_orders.py``, ``orders_test.go``, ``orders.spec.ts`` → orders."""
    name = _module_name(test_rel)
    if name.startswith("test_"):
        return name[5:]
    if name.endswith("_test"):
        return name[:-5]
    return name


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _is_error_status(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, int) and 400 <= node.value < 600


def _is_error_site(n: ast.AST) -> bool:
    """``raise``, ``abort(...)``, ``Response(..., status=4xx)`` or ``return body, 4xx``."""
    if isinstance(n, ast.Raise):
        return True
    if isinstance(n, ast.Call):
        return _call_name(n) == "abort" or any(
            k.arg in ("status", "status_code") and _is_error_status(k.value) for k in n.keywords)
    return (isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
            and any(_is_error_status(e) for e in n.value.elts[1:]))


def _segments(path: str) -> list[str]:
    """``/users/<int:id>/password?x=1`` → ``['users', '*', 'password']``; parameters become wildcards."""
    path = re.split(r"[?#]", path, maxsplit=1)[0]
    return ["*" if URL_PARAM.search(s) else s.lower() for s in path.split("/") if s]


def _url_matches(route: list[str], url: list[str]) -> bool:
    """The URL ends with the route (a mount prefix may come before it); wildcards on either side match a segment."""
    n = len(route)
    return 0 < n <= len(url) and all(a == b or "*" in (a, b) for a, b in zip(route, url[-n:], strict=True))


def _next_route_path(rel: str) -> str | None:
    """Next.js file routes: ``app/api/auth/[id]/route.ts`` → ``/api/auth/[id]``, ``pages/api/x.ts`` → ``/api/x``."""
    parts = rel.split("/")
    if parts[-1].startswith("route.") and "app" in parts[:-1]:
        start = len(parts) - 1 - parts[-2::-1].index("app")
        segs = [p for p in parts[start:-1] if not (p.startswith("(") and p.endswith(")"))]  # drop route groups
    elif "pages" in parts[:-1] and "api" in parts[parts.index("pages"):-1]:
        name = parts[-1].split(".", 1)[0]
        segs = parts[parts.index("pages") + 1:-1] + ([] if name == "index" else [name])
    else:
        return None
    return "/" + "/".join(segs)


def extract_routes(ctx, controllers: list[str]) -> list[tuple[str, int, str, str, set[str]]]:
    """HTTP routes as ``(file, line, verb, path, names)``; ``names`` are what tests can pass to reverse()/url_for()."""
    routes = []
    for rel in controllers:
        text = ctx.read(rel) or ""
        if rel.endswith(".py"):
            for m in PY_ROUTE_PATH.finditer(text):
                func = PY_DEF.search(text, m.end())
                names = set(ROUTE_NAME_KW.findall(m.group(3))) | ({func.group(1)} if func else set())
                verb = "" if m.group(1) in ("route", "api_route") else m.group(1).upper()
                routes.append((rel, _line(text, m.start()), verb, m.group(2), names))
            continue
        for m in JS_ROUTE_PATH.finditer(text):
            routes.append((rel, _line(text, m.start()), m.group(1).upper(), m.group(2), set()))
        prefix = NEST_PREFIX.search(text)
        if prefix or "@Controller(" in text:
            base = prefix.group(1).strip("/") if prefix else ""
            for m in NEST_ROUTE.finditer(text):
                path = "/" + "/".join(p for p in (base, (m.group(2) or "").strip("/")) if p)
                routes.append((rel, _line(text, m.start()), m.group(1).upper(), path, set()))
        path = _next_route_path(rel)
        if path:
            verbs = NEXT_METHOD.findall(text) or [""]
            routes.append((rel, 1, "/".join(verbs), path, set()))
    for rel in ctx.files_named("urls.py"):
        text = ctx.read(rel) or ""
        for m in DJANGO_PATH.finditer(text):
            path = "/" + m.group(1).lstrip("^").rstrip("$")
            routes.append((rel, _line(text, m.start()), "", path, set(ROUTE_NAME_KW.findall(m.group(2)))))
    return routes


def _test_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Functions pytest/unittest would collect: named test*, and not fixtures (``@pytest.fixture def test_user``)."""
    return [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
            and n.name.startswith("test")
            and not any("fixture" in ast.unparse(d.func if isinstance(d, ast.Call) else d) for d in n.decorator_list)]


@register
class TestingAnalyzer(Analyzer):
    name = "testing"
    title = "Testing practices"
    categories = (Category.TESTING,)

    def applicable(self, ctx: AnalyzerContext):
        if not any(ctx.languages.has(lang) for lang in CODE_LANGUAGES):
            return "no application source code detected"
        return None

    def run(self, ctx: AnalyzerContext):
        findings = []
        code_files = [f for f in ctx.files if _language(f)]
        tests = [f for f in code_files if is_test_path(f)]
        source = [f for f in code_files if not is_test_path(f)]
        src_loc, test_loc = _code_lines(ctx, source), _code_lines(ctx, tests)

        if not tests:
            findings.append(self._f(
                ctx, "testing.no-tests", "No automated tests found", Severity.HIGH, Confidence.HIGH,
                FindingKind.CONFIRMED,
                f"No test files were found for {src_loc} lines of source code. Regressions, including security "
                "regressions, will reach production undetected.",
                "Add unit tests for business logic and integration tests for API endpoints and data access; run "
                "them in CI.", evidence=f"0 test files; {len(source)} source files ({src_loc} non-blank lines)"))
        else:
            findings.extend(self._languages_without_tests(ctx, source, tests))
            if src_loc >= RATIO_MIN_LOC:
                findings.extend(self._ratio(ctx, src_loc, test_loc))

        findings.extend(self._npm_placeholder(ctx))
        findings.extend(self._assertionless_python_tests(ctx, [t for t in tests if t.endswith(".py")]))
        findings.extend(self._ci(ctx, tests))
        if not tests:
            return findings

        texts = {t: ctx.read(t) or "" for t in tests}
        api_tests = [t for t, text in texts.items() if API_TEST_CLIENT.search(text)]
        sources = [f for f in source if f.endswith((".py", *JS_EXTS))]
        controllers = sorted(f for f in sources if ArchitectureAnalyzer._is_controller(ctx, f))
        findings.extend(self._api_tests(ctx, controllers, api_tests))
        if src_loc >= RATIO_MIN_LOC:
            findings.extend(self._integration_tests(ctx, texts))
        findings.extend(self._critical_paths(ctx, sources, controllers, texts, bool(api_tests)))
        findings.extend(self._error_paths(ctx, sources, texts))
        findings.extend(self._weak_assertions(ctx, tests))
        findings.extend(self._duplicated_setup(ctx, tests))
        return findings

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel="", line=None, evidence=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.TESTING, severity=sev, confidence=conf,
                            kind=kind, description=desc, remediation=fix, file_path=rel, line=line,
                            evidence=evidence)

    # ------------------------------------------------------------------ presence and size
    def _languages_without_tests(self, ctx, source, tests):
        tested = {_language(t) for t in tests}
        by_lang: dict[str, list[str]] = defaultdict(list)
        for f in source:
            by_lang[_language(f)].append(f)
        out = []
        for lang, files in sorted(by_lang.items()):
            loc = _code_lines(ctx, files)
            if lang in tested or loc < LANGUAGE_WITHOUT_TESTS_LOC:
                continue
            out.append(self._f(
                ctx, "testing.language-without-tests", f"No tests for the {lang} code", Severity.LOW,
                Confidence.HIGH, FindingKind.CONFIRMED,
                f"The project has tests, but none of them are written in {lang}, which holds {loc} lines of source "
                f"in {len(files)} files. That part of the application is untested unless something outside the "
                "repository exercises it.",
                f"Add a {lang} test runner and tests for that code, starting with its entry points.",
                sorted(files)[0], evidence=f"{lang}: {len(files)} source files, {loc} lines, 0 test files"))
        return out

    def _ratio(self, ctx, src_loc, test_loc):
        ratio = test_loc / max(src_loc, 1)
        evidence = f"{test_loc} test lines / {src_loc} source lines = {ratio:.2f}"
        if ratio < 0.1:
            return [self._f(
                ctx, "testing.low-test-ratio", "Very low test-to-code ratio", Severity.MEDIUM, Confidence.MEDIUM,
                FindingKind.POTENTIAL, "Test code is under 10% of source code size. This is a coarse proxy, not "
                "coverage — measure line/branch coverage in CI for a real figure.",
                "Prioritize tests for authentication, authorization, data writes, and payment flows.",
                evidence=evidence)]
        if ratio < 0.3:
            return [self._f(
                ctx, "testing.modest-test-ratio", "Modest test-to-code ratio", Severity.LOW, Confidence.MEDIUM,
                FindingKind.POTENTIAL, "Test code is under 30% of source code size (a coarse proxy, not coverage).",
                "Measure coverage in CI and grow tests around critical paths.", evidence=evidence)]
        return []

    def _npm_placeholder(self, ctx):
        out = []
        for pkg in ctx.files_named("package.json"):
            try:
                data = json.loads(ctx.read(pkg) or "{}")
            except json.JSONDecodeError:
                continue
            script = (data.get("scripts") or {}).get("test", "") if isinstance(data, dict) else ""
            if isinstance(script, str) and DEFAULT_NPM_TEST in script:
                out.append(self._f(
                    ctx, "testing.npm-default-test-script", "npm test script is the default placeholder",
                    Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                    "`npm test` exits with an error stub, so no JavaScript tests run.",
                    "Configure a real test runner (Vitest, Jest, node:test) in the test script.", pkg,
                    evidence=f'"test": "{script[:120]}"'))
        return out

    def _ci(self, ctx, tests):
        ci_files = [f for f in ctx.files if f.startswith(".github/workflows/") or f in (
            ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml")]
        if tests and ci_files and not any(CI_TEST_COMMANDS.search(ctx.read(f) or "") for f in ci_files):
            return [self._f(
                ctx, "testing.ci-does-not-run-tests", "CI does not appear to run the test suite", Severity.MEDIUM,
                Confidence.MEDIUM, FindingKind.POTENTIAL,
                "CI configuration exists but no recognizable test command (pytest, npm test, go test, …) was found.",
                "Run the test suite on every pull request and block merges on failure.", ci_files[0])]
        return []

    # ------------------------------------------------------------------ kinds of tests
    def _api_tests(self, ctx, controllers, api_tests):
        if not controllers or api_tests:
            return []
        return [self._f(
            ctx, "testing.missing-api-tests", f"No API tests for {len(controllers)} route handler module(s)",
            Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
            "The application defines HTTP routes, but no test sends a request through an HTTP test client (Flask "
            "test_client, FastAPI/Starlette TestClient, Django Client, supertest, fastify inject…). Routing, request "
            "parsing, authentication, status codes and response shapes are therefore never tested.",
            "Add API tests that call each endpoint through the framework's test client and assert on the status "
            "code and response body, including unauthenticated and invalid-input requests.", controllers[0],
            evidence="route handler modules: " + ", ".join(controllers[:MAX_LISTED]))]

    def _integration_tests(self, ctx, texts):
        datastores = ctx.profile.datastores
        if not datastores:
            return []
        if any(INTEGRATION_PATH.search(t) or DB_IN_TESTS.search(text) for t, text in texts.items()):
            return []
        stores = ", ".join(sorted(datastores))
        return [self._f(
            ctx, "testing.missing-integration-tests", "No integration tests against the datastore", Severity.MEDIUM,
            Confidence.MEDIUM, FindingKind.POTENTIAL,
            f"The application uses {stores}, but no test sets up a database (test database, in-memory engine, "
            "testcontainers, mongodb-memory-server…) and there is no integration or e2e test suite. Queries, "
            "migrations, constraints and transactions are only exercised in production.",
            "Add integration tests that run the data-access code against a real (or in-memory) instance of the "
            "datastore, created and torn down by a fixture, and run them in CI.",
            evidence="datastores: " + "; ".join(f"{k}: {v}" for k, v in sorted(datastores.items()))[:400])]

    # ------------------------------------------------------------------ critical paths
    def _critical_paths(self, ctx, sources, controllers, texts, has_api_tests):
        corpus = "\n".join(texts.values())
        subjects = {_subject(t) for t in texts}
        untested = []
        for rel in sorted(sources):
            if _is_exempt(rel) or _module_name(rel) in GENERIC_MODULE_NAMES:
                continue
            if not set(_tokens(_stem(rel))) & CRITICAL_NAMES:
                continue
            name = _module_name(rel)
            if name in subjects or re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", corpus, re.I):
                continue
            untested.append((rel, None, f"module {rel}"))
        # Endpoints are only checked when API tests exist; otherwise missing-api-tests already covers them.
        if has_api_tests:
            untested += self._untested_critical_endpoints(ctx, controllers, corpus)
        if not untested:
            return []
        rel, line, _ = untested[0]
        return [self._f(
            ctx, "testing.untested-critical-paths", f"{len(untested)} critical path(s) without tests",
            Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
            "Authentication, credential, token, permission, payment, billing or webhook code is never referenced "
            "by any test: no test file is named after these modules, imports them, or calls these endpoints. "
            "Failures here lock users out, leak access or lose money, so they need tests first.",
            "Add tests for each listed module and endpoint, covering the success path and the refusal paths "
            "(wrong password, expired token, missing permission, declined payment, invalid webhook signature).",
            rel, line, evidence="; ".join(desc for *_, desc in untested[:MAX_LISTED]))]

    @staticmethod
    def _untested_critical_endpoints(ctx, controllers, corpus):
        referenced = {re.split(r"[.:]", n)[-1] for n in URL_NAME_REF.findall(corpus)}
        urls = []
        for m in TEST_URL.finditer(corpus):
            segs = _segments(m.group(2))
            urls.append(segs)
            if m.group(2).endswith("/"):
                urls.append([*segs, "*"])  # "/users/" + id
        out = []
        for rel, line, verb, path, names in extract_routes(ctx, controllers):
            route = _segments(path)
            words = set(re.split(r"[^a-z]+", path.lower())) | {w for n in names for w in _tokens(n)}
            if not route or all(s == "*" for s in route) or not words & CRITICAL_NAMES:
                continue
            if names & referenced or any(_url_matches(route, url) for url in urls):
                continue
            out.append((rel, line, f"endpoint {verb + ' ' if verb else ''}{path} ({rel}:{line})"))
        return out

    # ------------------------------------------------------------------ error paths
    @staticmethod
    def _error_sites(ctx, rel) -> list[int]:
        if not rel.endswith(".py"):
            text = ctx.read(rel) or ""
            return [_line(text, m.start()) for m in JS_ERROR_SITE.finditer(text)]
        tree = ctx.python_ast(rel)
        if tree is None:
            return []
        return sorted(n.lineno for n in ast.walk(tree) if _is_error_site(n))

    def _error_paths(self, ctx, sources, texts):
        sites = {rel: self._error_sites(ctx, rel) for rel in sources if not _is_exempt(rel)}
        total = sum(len(v) for v in sites.values())
        checked = {t for t, text in texts.items() if ERROR_CHECK.search(text)}
        if not checked:
            if total < SUITE_ERROR_SITES:
                return []
            top = sorted((rel for rel in sites if sites[rel]), key=lambda r: -len(sites[r]))
            return [self._f(
                ctx, "testing.no-error-path-tests", "Tests only cover the happy path", Severity.MEDIUM,
                Confidence.MEDIUM, FindingKind.POTENTIAL,
                f"The source raises, throws or returns an error response in {total} places, but no test expects an "
                "exception (pytest.raises, assertRaises, toThrow, rejects) or asserts on a 4xx/5xx status. "
                "Validation, authorization failures and error handling are untested.",
                "For each function and endpoint, add tests for invalid input, missing or wrong credentials, missing "
                "records and failing dependencies, asserting on the exception or status code.", top[0],
                sites[top[0]][0], evidence=", ".join(f"{r}: {len(sites[r])}" for r in top[:MAX_LISTED]))]
        by_subject: dict[str, list[str]] = defaultdict(list)
        for t in texts:
            if _subject(t) not in GENERIC_MODULE_NAMES:
                by_subject[_subject(t)].append(t)
        out = []
        for rel, lines in sorted(sites.items()):
            own_tests = by_subject.get(_module_name(rel), [])
            if len(lines) < MODULE_ERROR_SITES or not own_tests or any(t in checked for t in own_tests):
                continue
            out.append(self._f(
                ctx, "testing.untested-error-paths", f"Error paths in {rel} are not tested", Severity.LOW,
                Confidence.MEDIUM, FindingKind.POTENTIAL,
                f"{rel} raises or returns an error in {len(lines)} places, but its tests ({', '.join(own_tests[:3])}) "
                "never expect an exception or an error status, so only the success path is checked.",
                "Add a test per failure branch that triggers it and asserts on the exception type or status code.",
                rel, lines[0], evidence=f"error sites at lines {', '.join(map(str, lines[:10]))}"))
            if len(out) >= MAX_PER_RULE:
                break
        return out

    # ------------------------------------------------------------------ assertions
    def _assertionless_python_tests(self, ctx: AnalyzerContext, test_files: list[str]):
        out = []
        for rel in test_files:
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            empty = [node for node in _test_functions(tree) if not _has_assertion(node)]
            if empty:
                out.append(self.finding(
                    ctx, rule="testing.tests-without-assertions",
                    title=f"{len(empty)} test function(s) without assertions",
                    category=Category.TESTING, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description="These tests contain no assert statement, pytest.raises, or assert* call, so they "
                    "only check that code does not crash: " + ", ".join(n.name for n in empty[:10]),
                    remediation="Assert on return values, side effects, and error cases.",
                    file_path=rel, line=empty[0].lineno))
        return out

    def _weak_assertions(self, ctx, tests):
        out = []
        for rel in tests:
            if rel.endswith(".py"):
                tree = ctx.python_ast(rel)
                if tree is None:
                    continue
                weak = [n for n in _test_functions(tree) if _only_weak(n)]
                if not weak:
                    continue
                line, names = weak[0].lineno, ", ".join(n.name for n in weak[:10])
                count = len(weak)
                what = f"{count} test(s) whose only assertions are weak"
            elif rel.endswith(JS_EXTS):
                text = ctx.read(rel) or ""
                matchers = list(JS_MATCHER.finditer(text))
                if not matchers or not all(_js_weak(m) for m in matchers):
                    continue
                line, names, count = _line(text, matchers[0].start()), "", len(matchers)
                what = f"{count} assertion(s), all weak"
            else:
                continue
            out.append(self._f(
                ctx, "testing.weak-assertions", what, Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                "These tests only check that a value exists, is truthy, is not None, has some type or is non-empty "
                "(`assert result`, `is not None`, `isinstance`, `len(x) > 0`, `toBeTruthy`, `toBeDefined`). They "
                "pass for almost any wrong answer" + (f": {names}" if names else "."),
                "Assert on the exact expected value, shape or side effect (`assert total == 30`, "
                "`toEqual({...})`).", rel, line))
            if len(out) >= MAX_PER_RULE:
                break
        return out

    # ------------------------------------------------------------------ duplicated setup
    def _duplicated_setup(self, ctx, tests):
        groups: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
        shown: dict[str, str] = {}
        for rel in tests:
            if rel.endswith(".py"):
                tree = ctx.python_ast(rel)
                for func in _test_functions(tree) if tree is not None else ():
                    head = []
                    for stmt in _body(func):
                        if isinstance(stmt, ast.Assert | ast.With | ast.AsyncWith):
                            break
                        head.append(stmt)
                    if len(head) >= DUPLICATE_SETUP_STATEMENTS:
                        key = "py:" + "\n".join(ast.dump(s) for s in head[:DUPLICATE_SETUP_STATEMENTS])
                        groups[key].append((rel, func.lineno, func.name))
                        shown.setdefault(key, "\n".join(ast.unparse(s) for s in head[:DUPLICATE_SETUP_STATEMENTS]))
            elif rel.endswith(JS_EXTS):
                text = ctx.read(rel) or ""
                for m in JS_TEST_BLOCK.finditer(text):
                    block = _js_block(text, m.end() - 1)
                    if not block:
                        continue
                    head = []
                    for ln in block[1:-1].splitlines():
                        ln = " ".join(ln.split())
                        if not ln:
                            continue
                        if "expect(" in ln or "assert" in ln:
                            break
                        head.append(ln)
                    if len(head) >= DUPLICATE_SETUP_STATEMENTS:
                        key = "js:" + "\n".join(head[:DUPLICATE_SETUP_STATEMENTS])
                        groups[key].append((rel, _line(text, m.start()), m.group(0).strip()[:60]))
                        shown.setdefault(key, "\n".join(head[:DUPLICATE_SETUP_STATEMENTS]))
        out = []
        for key, locs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            if len(locs) < DUPLICATE_SETUP_TESTS:
                continue
            rel, line, _ = locs[0]
            files = sorted({r for r, *_ in locs})
            fix = ("Move the shared setup into a pytest fixture (in conftest.py if several files need it) or a "
                   "setUp method." if key.startswith("py:") else
                   "Move the shared setup into beforeEach (or a helper/factory) in the enclosing describe block.")
            out.append(self._f(
                ctx, "testing.duplicated-test-setup",
                f"Same setup repeated in {len(locs)} tests", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                f"{len(locs)} tests in {len(files)} file(s) start with the same {DUPLICATE_SETUP_STATEMENTS}+ setup "
                "statements. Copied setup drifts: when the setup has to change, some copies are missed and tests "
                "silently test a stale scenario.", fix, rel, line,
                evidence=shown[key][:400] + "\n— in " + ", ".join(f"{r}:{ln}" for r, ln, _ in locs[:8])))
            if len(out) >= MAX_PER_RULE:
                break
        return out


def _has_assertion(func: ast.AST) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name.startswith(("assert", "expect")) or name in ("raises", "fail", "approx", "verify", "check"):
                return True
        if isinstance(node, ast.With):
            for item in node.items:
                c = item.context_expr
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in (
                        "raises", "warns", "assertRaises", "assertLogs"):
                    return True
    return False


def _weak_expr(e: ast.AST) -> bool:
    """`x`, `x is not None`, `x != None`, `isinstance(...)`, `hasattr(...)`, `len(x) > 0`."""
    if isinstance(e, ast.Name):
        return True
    if isinstance(e, ast.Call):
        return _call_name(e) in ("isinstance", "hasattr", "callable")
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, right = e.ops[0], e.comparators[0]
        if isinstance(op, ast.IsNot | ast.NotEq) and isinstance(right, ast.Constant) and right.value is None:
            return True
        if isinstance(e.left, ast.Call) and _call_name(e.left) == "len" and isinstance(right, ast.Constant):
            return ((isinstance(op, ast.Gt | ast.NotEq) and right.value == 0)
                    or (isinstance(op, ast.GtE) and right.value == 1))
    return False


def _assertion_counts(func: ast.AST) -> tuple[int, int]:
    """(weak, strong) assertions in a test function; exception checks and assertion helpers count as strong."""
    weak = strong = 0
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            if _weak_expr(node.test):
                weak += 1
            else:
                strong += 1
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name in WEAK_UNITTEST or (name == "assertTrue" and node.args and _weak_expr(node.args[0])):
                weak += 1
            elif name.startswith(("assert", "expect")) or name in ("raises", "warns", "fail", "verify", "check"):
                strong += 1
    return weak, strong


def _only_weak(func: ast.AST) -> bool:
    weak, strong = _assertion_counts(func)
    return weak > 0 and strong == 0


def _js_weak(m: re.Match) -> bool:
    return m.group(2) in (JS_WEAK_NEGATED if m.group(1) else JS_WEAK_MATCHERS)
