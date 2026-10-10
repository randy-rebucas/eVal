"""API and web-application security: authentication coverage, object-level authorization (IDOR), error
disclosure and error handling, debug mode, CORS, JWT and TLS verification, mass assignment, CSRF, cookie flags,
credentials written to logs, file-upload validation, rate limiting, and hardening middleware."""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete", "api_route"}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_DECORATOR = re.compile(r"(?i)(login|auth|jwt|token|permission|role|admin|scope|org_required|require|protect"
                            r"|current_user|verify|guard|access)")
PUBLIC_NAMES = re.compile(r"(?i)(login|logout|register|signup|sign_up|health|ready|live|webhook|callback|reset|"
                          r"forgot|verify_email|static|index|home|public|oauth|ping|metrics|csp_report)")
JS_ROUTE = re.compile(r"""\b(?:app|router|server)\.(post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]\s*,\s*(.*)$""")
REQUEST_BODY = re.compile(r"request\.(json|form|args|values|get_json\(\))|await request\.json")
JS_AUTH_HINT = re.compile(r"(?i)(auth|jwt|passport|session|requireUser|isAuthenticated|protect|guard|verify)")
JS_ANY_ROUTE = re.compile(r"""\b(?:app|router|server)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]"""
                          r"""\s*,(.*)$""")
JS_GLOBAL_AUTH = re.compile(r"(?i)\.use\([^)]*(auth|jwt|passport|requireUser|isAuthenticated|protect|guard)")
JS_ERROR_MIDDLEWARE = re.compile(r"\(\s*(?:err|error|e)\s*(?::\s*\w+)?\s*,\s*req\w*\s*(?::\s*\w+)?\s*,\s*res\w*\s*"
                                 r"(?::\s*\w+)?\s*,\s*next\w*|setErrorHandler\(")
JS_ERROR_LEAK = re.compile(r"\bres\.(?:status\(\s*\d+\s*\)\.)?(?:send|json|end|write)\([^;]*"
                           r"\b(?:err|error|e|ex)\.stack\b")
# Object lookups by a value taken from the URL: the classic insecure direct object reference (IDOR) shape.
OBJECT_LOOKUPS = {"get", "get_or_404", "first_or_404", "filter_by", "filter", "get_object_or_404", "find_one",
                  "find_by_id", "one_or_none", "scalar_one_or_none", "scalar_one", "where", "delete", "update"}
JS_LOOKUP_BY_PARAM = re.compile(r"\.(?:findById|findByPk|findOne|findUnique|findFirst|findOneBy|getById|"
                                r"findByIdAndUpdate|findByIdAndDelete|deleteOne|updateOne|update|delete|destroy)"
                                r"\([^;]*req\.params")
# Evidence that a handler scopes the object to the caller (ownership, tenant, or an explicit permission check).
OWNERSHIP = re.compile(r"(?i)(current_user|g\.user|request\.user|request\.state\.user|owner|org_id|organization|"
                       r"tenant|account_id|created_by|author_id|abort\(\s*40[34]|forbidden|permissiondenied|has_perm|"
                       r"permission|can_\w+\(|authoriz|check_access|policy|membership|scope)")
JS_OWNERSHIP = re.compile(r"(?i)(req\.user|req\.auth|res\.locals\.(user|session)|owner|tenant|orgId|organizationId|"
                          r"\b403\b|forbidden|authoriz|permission|can\(|ability|policy)")
OBJECT_AUTHZ_DECORATOR = re.compile(r"(?i)(permission|owner|role|admin|policy|authoriz|access|scope|org_required|"
                                    r"tenant|member)")
PATH_PARAM = re.compile(r"<(?:[^:<>]+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}|:(\w+)")
RESPONSE_CALLS = {"jsonify", "JSONResponse", "make_response", "Response", "HTTPException", "abort", "HttpResponse",
                  "JsonResponse", "PlainTextResponse", "HTMLResponse"}
BROAD_CATCH = {"", "Exception", "BaseException"}

# Cookies: settings that turn a security flag off, and cookie names that carry a session or credential.
COOKIE_FLAG_KEYS = {"SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY", "CSRF_COOKIE_SECURE", "REMEMBER_COOKIE_SECURE",
                    "REMEMBER_COOKIE_HTTPONLY", "LANGUAGE_COOKIE_SECURE"}
SENSITIVE_COOKIE = re.compile(r"(?i)(sess|token|auth|jwt|sid|remember|login|refresh|access|identity)")
DEV_SETTINGS = re.compile(r"(?i)(^|/)[^/]*(dev|local|develop|debug|test)[^/]*\.py$")
DEV_CONFIG_CLASS = re.compile(r"(?i)(dev|local|test|debug)")  # class DevelopmentConfig / TestingConfig
JS_COOKIE_FLAG_OFF = re.compile(r"\b(httpOnly|secure)\s*:\s*false\b")
JS_COOKIE_CONTEXT = re.compile(r"(?i)cookie|session")
JS_BARE_COOKIE = re.compile(r"""\bres\.cookie\(\s*["'`]([\w.-]+)["'`]\s*,\s*[^,()]+(?:\([^()]*\))?\s*\)""")

# Logging: logger receivers, identifiers that hold credentials, and calls that mask a value before it is logged.
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
LOGGER_RECEIVER = re.compile(r"(?i)(^|[._])(log|logger|logging)$")
SENSITIVE_WORD = re.compile(r"(^|_)(password|passwd|passphrase|secret|secret_key|api_key|apikey|token|bearer|"
                            r"authorization|credential|credentials|private_key|card_number|cvv|cvc|ssn)(_|$)")
NOT_SENSITIVE_PREFIX = {"is", "has", "num", "n", "len", "count", "max", "min", "should", "use", "needs", "show"}
NOT_SENSITIVE_SUFFIX = {"id", "ids", "count", "len", "length", "type", "url", "uri", "expires", "expiry", "exp", "at",
                        "hash", "hashed", "name", "field", "fields", "policy", "min", "max", "valid", "ok", "required",
                        "set", "changed", "reset", "strength", "prefix", "hint", "label", "endpoint", "path", "file",
                        "ttl", "age", "lifetime", "version", "status", "error", "errors", "scope", "scopes", "kind",
                        "format", "size", "index", "idx", "usage", "limit", "mask", "masked", "redacted"}
MASKING_CALL = re.compile(r"(?i)(mask|redact|hash|digest|^len$|^bool$|^type$|truncat|obfuscat|fingerprint|censor|"
                          r"scrub|sanitiz|anonymi)")
REQUEST_SECRET_DUMPS = {"request.headers", "request.cookies", "request.COOKIES", "request.META", "req.headers",
                        "req.cookies", "request.authorization"}
JS_LOG_CALL = re.compile(r"\b(?:console|logger|log|winston|pino|this\.logger)\.(?:log|info|warn|error|debug|trace)"
                         r"\s*\((.*)$")
JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*")

# Uploads: where an uploaded file is read, and evidence that its type or size is checked before it is stored.
UPLOAD_TYPES = ("UploadFile", "FileStorage", "UploadedFile")
UPLOAD_CHECK = re.compile(r"(?i)(allowed_file|allowed_ext|ALLOWED_|splitext|rsplit\(\s*['\"]\.|\.suffix\b|content_type|"
                          r"mimetype|mime|imghdr|filetype|magic\.|endswith\(|validat|is_valid\(|max_content_length|"
                          r"content_length|\.size\b|FileExtensionValidator)")
JS_CLIENT_FILENAME = re.compile(r"(?:\b(?:cb|callback|done)\s*\(\s*null\s*,[^)]*|path\.(?:join|resolve)\([^)]*|"
                                r"(?:writeFile|createWriteStream|rename|\.mv)\w*\([^)]*)\boriginalname\b")

# Rate limiting: authentication endpoints that attackers brute-force, and libraries/settings that throttle them.
AUTH_ENDPOINT = re.compile(r"(?i)(login|log_in|signin|sign_in|token|password|passwd|reset|otp|mfa|2fa|"
                           r"two_factor|verify|register|signup|sign_up)")
PY_RATE_LIMIT = re.compile(r"(?i)(flask[_-]limiter|\bLimiter\b|slowapi|ratelimit|rate_limit|throttl|django[_-]axes|"
                           r"\baxes\b|fastapi[_-]limiter|brute_?force|login_attempts|failed_attempts|lockout)")


def _is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _config_key(target) -> str:
    """``SESSION_COOKIE_SECURE`` from ``X = ...``, ``app.config["X"] = ...`` or ``settings.X = ...``."""
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
        return str(target.slice.value)
    if isinstance(target, ast.Attribute):
        return target.attr
    return target.id if isinstance(target, ast.Name) else ""


def _sensitive_name(name: str) -> bool:
    """Whether an identifier or key names a credential (``password``, ``apiKey``, ``access_token``), and not
    something about one (``token_count``, ``password_reset_url``, ``is_secret``)."""
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower().strip("_")
    parts = snake.split("_")
    if parts[0] in NOT_SENSITIVE_PREFIX or parts[-1] in NOT_SENSITIVE_SUFFIX:
        return False
    return bool(SENSITIVE_WORD.search(snake))


def _logged_secret(args) -> str | None:
    """Source text of the first argument expression that puts a credential into a log record, if any."""
    stack = list(args)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Constant):
            continue
        label = None
        if isinstance(node, ast.Call):
            callee = _decorator_name(node)
            if MASKING_CALL.search(callee.split(".")[-1]):
                continue  # mask(token), len(password), hash(...)
            if callee.endswith(".get") and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) and _sensitive_name(node.args[0].value):
                return ast.unparse(node)  # request.headers.get("Authorization"), data.get("password")
        elif isinstance(node, ast.Name):
            label = node.id
        elif isinstance(node, ast.Attribute):
            if ast.unparse(node) in REQUEST_SECRET_DUMPS:
                return ast.unparse(node)
            label = node.attr
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                and isinstance(node.slice.value, str):
            label = node.slice.value
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values, strict=False):
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and _sensitive_name(k.value) \
                        and not isinstance(v, ast.Constant):
                    return ast.unparse(v)
        if label and _sensitive_name(label):
            return ast.unparse(node)
        stack.extend(ast.iter_child_nodes(node))
    return None


def _js_logged_secret(args: str) -> str | None:
    """Like ``_logged_secret`` for the argument text of a JavaScript logging call (string literals ignored)."""
    text = re.sub(r"`([^`]*)`", lambda m: " ".join(re.findall(r"\$\{([^}]*)\}", m.group(1))), args)
    text = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", "''", text)
    for m in JS_IDENT.finditer(text):
        ident = m.group(0).replace("?.", ".")
        if ident in REQUEST_SECRET_DUMPS:
            return ident
        before = text[:m.start()].rstrip()
        if before.endswith(("(",)) and MASKING_CALL.search(re.split(r"[^\w$]", before[:-1])[-1] or "_"):
            continue
        if _sensitive_name(ident.rsplit(".", 1)[-1]):
            return ident
    return None


def _decorator_name(dec: ast.AST) -> str:
    target = dec.func if isinstance(dec, ast.Call) else dec
    parts = []
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    return ".".join(reversed(parts))


def _route_info(dec: ast.AST) -> tuple[str, set[str]] | None:
    if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in ROUTE_METHODS):
        return None
    path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else "?"
    if not isinstance(path, str) or not path.startswith("/") and path != "?":
        return None
    if dec.func.attr in ("route", "api_route"):
        methods = {"GET"}
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, ast.List | ast.Tuple | ast.Set):
                methods = {e.value.upper() for e in kw.value.elts if isinstance(e, ast.Constant)
                           and isinstance(e.value, str)}
    else:
        methods = {dec.func.attr.upper()}
    return path, methods


def _fastapi_protected(func: ast.FunctionDef | ast.AsyncFunctionDef, dec: ast.Call) -> bool:
    for kw in dec.keywords:
        if kw.arg == "dependencies":
            return True
    defaults = list(func.args.defaults) + [d for d in func.args.kw_defaults if d is not None]
    for d in defaults:
        if isinstance(d, ast.Call) and _decorator_name(d).endswith(("Depends", "Security")):
            inner = d.args[0] if d.args else None
            if inner is not None and AUTH_DECORATOR.search(ast.unparse(inner)):
                return True
    return False


@register
class APISecurityAnalyzer(Analyzer):
    name = "api_security"
    title = "API & web security"
    categories = (Category.API, Category.SECURITY)

    def applicable(self, ctx: AnalyzerContext):
        if not (ctx.languages.has("python") or ctx.languages.has("javascript") or ctx.languages.has("typescript")):
            return "no Python or JavaScript/TypeScript files detected"
        return None

    def run(self, ctx: AnalyzerContext):
        findings: list = []
        unprotected: list[tuple[str, int, str, str]] = []
        auth_routes: list[tuple[str, int, str]] = []
        auth_seen = error_handler_seen = rate_limit_seen = False
        route_count = 0
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            text = ctx.read(rel) or ""
            rate_limit_seen = rate_limit_seen or bool(PY_RATE_LIMIT.search(text))
            if re.search(r"(?i)(login_required|jwt_required|LoginManager|HTTPBearer|OAuth2PasswordBearer|"
                         r"permission_required|auth_required|@\w*auth)", text):
                auth_seen = True
            file_guard = bool(re.search(r"\.before_request\b", text)) and bool(
                re.search(r"(?i)(current_user|abort\(\s*40[13]|login|auth|token)", text))
            findings.extend(self._python_file(ctx, rel, tree, text))
            if re.search(r"\.(errorhandler|register_error_handler|exception_handler|add_exception_handler)\b", text):
                error_handler_seen = True
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if any("errorhandler" in _decorator_name(d) or "exception_handler" in _decorator_name(d)
                       for d in node.decorator_list):
                    findings.extend(self._error_details(ctx, rel, node))
                routes = [(d, _route_info(d)) for d in node.decorator_list]
                routes = [(d, r) for d, r in routes if r]
                if not routes:
                    continue
                route_count += 1
                findings.extend(self._error_details(ctx, rel, node))
                path, methods = routes[0][1]
                if "POST" in methods and AUTH_ENDPOINT.search(f"{node.name} {path}"):
                    auth_routes.append((rel, node.lineno, f"POST {path}"))
                others = [_decorator_name(d) for d in node.decorator_list if d is not routes[0][0]]
                protected = file_guard or any(AUTH_DECORATOR.search(n) for n in others) or _fastapi_protected(
                    node, routes[0][0])
                if protected:
                    findings.extend(self._python_idor(ctx, rel, node, path, others))
                elif methods & MUTATING and not PUBLIC_NAMES.search(node.name + path):
                    unprotected.append((rel, node.lineno, f"{'/'.join(sorted(methods & MUTATING))} {path}",
                                        node.name))

        for rel in ctx.files_with_suffix(".js", ".mjs", ".cjs", ".ts"):
            if is_test_path(rel):
                continue
            text = ctx.read(rel) or ""
            if JS_AUTH_HINT.search(text) and re.search(r"(?i)(passport|jsonwebtoken|express-session|jwt)", text):
                auth_seen = True
            findings.extend(self._js_file(ctx, rel, text))
            findings.extend(self._js_idor(ctx, rel))
            if JS_ERROR_MIDDLEWARE.search(text):
                error_handler_seen = True
            for i, line in enumerate(ctx.lines(rel), start=1):
                if JS_ANY_ROUTE.search(line):
                    route_count += 1
                m = JS_ROUTE.search(line)
                if m and not JS_AUTH_HINT.search(m.group(3)) and not PUBLIC_NAMES.search(m.group(2)):
                    unprotected.append((rel, i, f"{m.group(1).upper()} {m.group(2)}", m.group(2)))

        findings.extend(self._unprotected(ctx, unprotected, auth_seen))
        findings.extend(self._project_level(ctx))
        findings.extend(self._no_error_handler(ctx, route_count, error_handler_seen))
        findings.extend(self._python_rate_limit(ctx, auth_routes, rate_limit_seen))
        return findings

    def _python_rate_limit(self, ctx, auth_routes, rate_limit_seen):
        if not auth_routes or rate_limit_seen:
            return []
        manifests = ctx.files_named("requirements.txt", "pyproject.toml", "Pipfile", "setup.cfg", "setup.py")
        if any(PY_RATE_LIMIT.search(ctx.read(f) or "") for f in manifests):
            return []
        rel, line, desc = auth_routes[0]
        return [self._f(ctx, "api.no-rate-limiting", f"Authentication endpoint without rate limiting: {desc}",
                        Severity.LOW, Confidence.LOW, FindingKind.POTENTIAL,
                        f"{len(auth_routes)} login/token/password route(s) were found (first: {desc}) but no rate "
                        "limiting library, decorator or lockout logic (Flask-Limiter, slowapi, django-ratelimit, "
                        "django-axes, …) appears in the code or dependencies. Without it, passwords and one-time "
                        "codes can be brute-forced and credential lists replayed. A gateway, WAF or reverse proxy may "
                        "already limit these routes — verify.",
                        "Rate-limit authentication endpoints per IP and per account (e.g. Flask-Limiter "
                        "`@limiter.limit('5/minute')`, slowapi, django-ratelimit) and add progressive lockout.",
                        rel, line)]

    # ------------------------------------------------------------------------------------------- python
    def _python_file(self, ctx, rel, tree, text):
        out = []
        settings_like = rel.endswith(("settings.py", "config.py", "settings/production.py", "settings/base.py"))
        # Cookie flags turned off in a dev/test settings file or config class are expected, not a finding.
        dev_only = {id(n) for c in ast.walk(tree) if isinstance(c, ast.ClassDef) and DEV_CONFIG_CLASS.search(c.name)
                    for n in ast.walk(c)} if not DEV_SETTINGS.search(rel) else None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _decorator_name(node)
                kws = {k.arg: k.value for k in node.keywords if k.arg}
                if name.endswith(".run") and isinstance(kws.get("debug"), ast.Constant) and kws["debug"].value is True:
                    out.append(self._f(ctx, "api.flask-debug-enabled", "Application started with debug=True",
                                       Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "Debug mode exposes an interactive debugger (remote code execution in Flask/"
                                       "Werkzeug) and detailed tracebacks.",
                                       "Read debug from configuration and keep it off outside local development.",
                                       rel, node.lineno, Category.SECURITY))
                if name.split(".")[-1] == "decode" and "jwt" in name.lower():
                    opts = kws.get("options")
                    verify_off = (isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False) or (
                        isinstance(opts, ast.Dict) and any(
                            isinstance(k, ast.Constant) and k.value == "verify_signature"
                            and isinstance(v, ast.Constant) and v.value is False
                            for k, v in zip(opts.keys, opts.values, strict=False)))
                    algs = kws.get("algorithms")
                    none_alg = isinstance(algs, ast.List | ast.Tuple) and any(
                        isinstance(e, ast.Constant) and str(e.value).lower() == "none" for e in algs.elts)
                    if verify_off or none_alg:
                        out.append(self._f(ctx, "api.jwt-verification-disabled", "JWT signature verification "
                                           "disabled", Severity.CRITICAL if none_alg else Severity.HIGH,
                                           Confidence.HIGH, FindingKind.CONFIRMED,
                                           "Tokens are decoded without verifying their signature, so anyone can forge "
                                           "identity claims.",
                                           "Always verify signatures with an explicit allow-list of algorithms "
                                           "(e.g. algorithms=['RS256']).", rel, node.lineno, Category.SECURITY))
                if name in ("CORS", "flask_cors.CORS") or name.endswith(".CORS"):
                    origins = kws.get("origins") or kws.get("resources")
                    creds = isinstance(kws.get("supports_credentials"), ast.Constant) and \
                        kws["supports_credentials"].value is True
                    wildcard = origins is None or "'*'" in ast.unparse(origins) or '"*"' in ast.unparse(origins)
                    if wildcard:
                        out.append(self._cors(ctx, rel, node.lineno, creds))
                if name.endswith("set_cookie"):
                    out.extend(self._py_set_cookie(ctx, rel, node, kws))
                for kw in node.keywords:  # app.config.update(SESSION_COOKIE_SECURE=False)
                    if kw.arg in COOKIE_FLAG_KEYS and _is_false(kw.value) and dev_only is not None \
                            and id(node) not in dev_only:
                        out.append(self._cookie_setting(ctx, rel, node.lineno, kw.arg))
                if isinstance(node.func, ast.Attribute) and node.func.attr in LOG_METHODS and \
                        LOGGER_RECEIVER.search(ast.unparse(node.func.value)):
                    leaked = _logged_secret(node.args[1:] if node.args and isinstance(node.args[0], ast.Constant)
                                            else node.args) or _logged_secret(k.value for k in node.keywords)
                    if leaked and len([f for f in out if f.rule_id.endswith("sensitive-data-logged")]) < 20:
                        out.append(self._sensitive_log(ctx, rel, node.lineno, leaked))
                if name.endswith(("requests.get", "requests.post", "requests.put", "requests.patch",
                                  "requests.delete", "requests.request", "httpx.get", "httpx.post")) and isinstance(
                        kws.get("verify"), ast.Constant) and kws["verify"].value is False:
                    out.append(self._f(ctx, "api.tls-verify-disabled", "TLS certificate verification disabled",
                                       Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "verify=False accepts any certificate, enabling man-in-the-middle attacks.",
                                       "Keep verification on; pass a CA bundle path for private CAs.", rel,
                                       node.lineno, Category.SECURITY))
                for kw in node.keywords:
                    if kw.arg is None and REQUEST_BODY.search(ast.unparse(kw.value)):
                        out.append(self._f(ctx, "api.mass-assignment", "Request body unpacked directly into an "
                                           "object", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                           "Passing **request data into a model/constructor lets clients set any "
                                           "field, including ones like is_admin, role, or organization_id.",
                                           "Validate input with an explicit schema and copy only allowed fields.",
                                           rel, node.lineno))
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = ast.unparse(node.targets[0])
                value = node.value
                if target in ("app.secret_key", "SECRET_KEY", "app.config['SECRET_KEY']",
                              'app.config["SECRET_KEY"]') and isinstance(value, ast.Constant) and isinstance(
                        value.value, str) and value.value:
                    out.append(self._f(ctx, "api.hardcoded-session-secret", "Session/signing secret hardcoded",
                                       Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "The key that signs session cookies/tokens is in source code; anyone with "
                                       "the code can forge sessions.",
                                       "Load it from the environment and fail startup if it is missing.",
                                       rel, node.lineno, Category.SECURITY))
                if settings_like and target == "DEBUG" and isinstance(value, ast.Constant) and value.value is True:
                    out.append(self._f(ctx, "api.debug-setting-true", "DEBUG = True in settings", Severity.MEDIUM,
                                       Confidence.MEDIUM, FindingKind.POTENTIAL,
                                       "Debug mode in a settings/config module risks shipping it to production.",
                                       "Derive DEBUG from an environment variable defaulting to False.",
                                       rel, node.lineno, Category.SECURITY))
                cookie_key = _config_key(node.targets[0])
                if cookie_key in COOKIE_FLAG_KEYS and _is_false(value) and dev_only is not None \
                        and id(node) not in dev_only:
                    out.append(self._cookie_setting(ctx, rel, node.lineno, cookie_key))
                if target == "ALLOWED_HOSTS" and "'*'" in ast.unparse(value):
                    out.append(self._f(ctx, "api.django-allowed-hosts-wildcard", "ALLOWED_HOSTS allows any host",
                                       Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "A wildcard host enables Host-header attacks (password reset poisoning, cache "
                                       "poisoning).", "List the exact hostnames served.", rel, node.lineno))
        if ctx.profile.cookie_auth and "flask_login" in text and "request.form" in text and not re.search(
                r"(CSRFProtect|flask_wtf|FlaskForm|csrf)", text):
            out.append(self._f(ctx, "api.flask-no-csrf", "Cookie-authenticated form handling without CSRF "
                               "protection", Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                               "This module uses session-cookie auth and reads form posts, but no CSRF protection "
                               "was found in it (it may be configured elsewhere).",
                               "Enable Flask-WTF CSRFProtect app-wide (or SameSite=Strict cookies plus origin "
                               "checks).", rel, None))
        out.extend(self._python_uploads(ctx, rel, tree))
        return out

    def _py_set_cookie(self, ctx, rel, node, kws):
        """``response.set_cookie("session", ...)`` without Secure/HttpOnly (Flask, Django and Starlette all default
        both to off)."""
        name_node = node.args[0] if node.args else kws.get("key")
        cookie = name_node.value if isinstance(name_node, ast.Constant) and isinstance(name_node.value, str) else ""
        if not SENSITIVE_COOKIE.search(cookie) or re.search(r"(?i)csrf|xsrf", cookie):
            return []
        off = [flag for flag in ("secure", "httponly") if _is_false(kws.get(flag))]
        missing = [flag for flag in ("secure", "httponly") if flag not in kws]
        if not off and not missing:
            return []
        flags = ", ".join(f"{f}=False" for f in off) + (", " if off and missing else "") + ", ".join(
            f"no {f}" for f in missing)
        return [self._f(ctx, "api.insecure-cookie", f"Cookie `{cookie}` set without Secure/HttpOnly ({flags})",
                        Severity.MEDIUM, Confidence.HIGH if off else Confidence.MEDIUM, FindingKind.POTENTIAL,
                        f"`{cookie}` looks like a session or credential cookie. Without HttpOnly any XSS can read it; "
                        "without Secure the browser also sends it over plain HTTP, where it can be intercepted. "
                        "Flask, Django and Starlette leave both flags off unless they are passed. (A proxy that "
                        "rewrites Set-Cookie headers would mitigate this — verify.)",
                        "Pass secure=True, httponly=True and samesite='Lax' (or 'Strict') when setting session or "
                        "token cookies.", rel, node.lineno, Category.SECURITY)]

    def _cookie_setting(self, ctx, rel, line, key):
        return self._f(ctx, "api.insecure-cookie", f"{key} disabled", Severity.MEDIUM, Confidence.MEDIUM,
                       FindingKind.CONFIRMED,
                       f"`{key} = False` turns off a protection on the framework's session/auth cookie: "
                       + ("the cookie is also sent over plain HTTP, where it can be intercepted."
                          if key.endswith("SECURE") else "JavaScript (and therefore any XSS) can read the cookie.")
                       + " This module is not a development-only settings file; if it is overridden in production, "
                       "move the override here.",
                       f"Set {key} = True in production settings (keep False only in local development settings).",
                       rel, line, Category.SECURITY)

    def _sensitive_log(self, ctx, rel, line, expr):
        return self._f(ctx, "api.sensitive-data-logged", f"Credential written to a log: `{expr[:60]}`",
                       Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                       f"`{expr[:120]}` is passed to a logging call. Logs are copied to aggregators, backups and "
                       "support tools and are read by far more people than the data store, so passwords, tokens or "
                       "keys in them are effectively disclosed. (The value may already be masked by the caller or a "
                       "log filter — verify.)",
                       "Do not log credentials. Log an identifier (user id, key id, last 4 characters) instead, and "
                       "add a redacting log filter as a safety net.", rel, line, Category.SECURITY)

    def _python_uploads(self, ctx, rel, tree):
        """Handlers that store an uploaded file without any visible check of its type or size."""
        out = []
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            src = ast.unparse(func)
            annotated = any(a.annotation is not None and any(t in ast.unparse(a.annotation) for t in UPLOAD_TYPES)
                            for a in [*func.args.args, *func.args.kwonlyargs])
            if not (annotated or re.search(r"\brequest\.(files|FILES)\b", src)):
                continue
            store = next((n for n in ast.walk(func) if isinstance(n, ast.Call) and (
                _decorator_name(n).split(".")[-1] in ("save", "copyfileobj", "upload_fileobj", "put_object")
                or (_decorator_name(n) == "open" and any(isinstance(m, ast.Constant) and isinstance(m.value, str)
                                                         and "w" in m.value
                                                         for m in [*n.args[1:2], *(k.value for k in n.keywords
                                                                                   if k.arg == "mode")])))), None)
            if store is None or UPLOAD_CHECK.search(src):
                continue
            out.append(self._f(ctx, "api.upload-unvalidated", f"File upload stored without a type or size check in "
                               f"`{func.name}()`", Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                               "The handler saves an uploaded file but checks neither its extension/content type nor "
                               "its size. Attackers can upload HTML/SVG (stored XSS when served back), server-side "
                               "scripts (code execution if the directory is executable or served), or huge files "
                               "(disk exhaustion). The check may live in a helper or the web server — verify.",
                               "Allow-list extensions and verify the content type/magic bytes, cap the size "
                               "(MAX_CONTENT_LENGTH / DATA_UPLOAD_MAX_MEMORY_SIZE / a proxy limit), store under a "
                               "generated name outside the web root, and serve with Content-Disposition: attachment.",
                               rel, store.lineno, Category.SECURITY))
        return out

    def _python_idor(self, ctx, rel, func, path, decorators):
        """An authenticated handler that loads a record by a URL parameter without any visible ownership check."""
        params = {g for m in PATH_PARAM.finditer(path) for g in m.groups() if g}
        if not params or any(OBJECT_AUTHZ_DECORATOR.search(d) for d in decorators):
            return []
        # Names bound to the authenticated principal by dependency injection, e.g. ``user = Depends(current_user)``.
        principals = set()
        positional = func.args.args[len(func.args.args) - len(func.args.defaults):]
        for arg, default in [*zip(positional, func.args.defaults, strict=False),
                             *zip(func.args.kwonlyargs, func.args.kw_defaults, strict=False)]:
            if isinstance(default, ast.Call) and _decorator_name(default).endswith(("Depends", "Security")):
                principals.add(arg.arg)
        body = "\n".join(ast.unparse(s) for s in func.body)
        for name in params:
            body = re.sub(rf"\b{re.escape(name)}\b", "_", body)
        if OWNERSHIP.search(body) or any(re.search(rf"\b{re.escape(p)}\b", body) for p in principals):
            return []
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            name = _decorator_name(node)
            if name.split(".")[-1] not in OBJECT_LOOKUPS or name.startswith(("request.", "os.", "self.request")):
                continue
            used = {n.id for a in [*node.args, *(k.value for k in node.keywords)] for n in ast.walk(a)
                    if isinstance(n, ast.Name)}
            hit = sorted(used & params)
            if hit:
                return [self._f(ctx, "api.idor-unscoped-lookup", f"Object loaded by URL parameter `{hit[0]}` "
                                "without an ownership check", Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                                f"`{func.name}()` is authenticated, but it fetches a record using `{hit[0]}` from "
                                "the URL and never compares it with the current user, organization, or a "
                                "permission. Any signed-in user may read or change other users' records by "
                                "changing the id (insecure direct object reference). The check may live in a "
                                "helper eVal cannot see — verify.",
                                "Scope the query to the caller (e.g. `filter_by(id=..., owner_id=current_user.id)`) "
                                "or check ownership/permission after loading and return 404/403.",
                                rel, node.lineno, Category.SECURITY)]
        return []

    def _error_details(self, ctx, rel, func):
        """Exception text or tracebacks returned to the client from a handler."""
        handlers: list[tuple[str | None, list[ast.stmt]]] = []
        for dec in func.decorator_list:
            dname = _decorator_name(dec)
            if ("errorhandler" in dname or "exception_handler" in dname) and isinstance(dec, ast.Call) and dec.args \
                    and ast.unparse(dec.args[0]) in ("Exception", "BaseException", "500") and func.args.args:
                handlers.append((func.args.args[-1].arg, func.body))
        for node in ast.walk(func):
            if isinstance(node, ast.ExceptHandler) and (
                    "" if node.type is None else ast.unparse(node.type)) in BROAD_CATCH:
                handlers.append((node.name, node.body))
        for exc_name, body in handlers:
            for stmt in body:
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Return) and node.value is not None:
                        src = ast.unparse(node.value)
                    elif isinstance(node, ast.Call) and _decorator_name(node).split(".")[-1] in RESPONSE_CALLS:
                        src = ast.unparse(node)
                    else:
                        continue
                    traceback_leak = "traceback.format_exc" in src or "format_exception" in src
                    text_leak = bool(exc_name) and bool(re.search(
                        rf"\b(str|repr)\(\s*{exc_name}\s*\)|\{{{exc_name}(!r|!s)?\}}|\b{exc_name}\.args\b", src))
                    if traceback_leak or text_leak:
                        return [self._f(ctx, "api.error-details-exposed",
                                        "Stack trace returned to the client" if traceback_leak else
                                        "Unexpected exception text returned to the client",
                                        Severity.MEDIUM, Confidence.HIGH if traceback_leak else Confidence.MEDIUM,
                                        FindingKind.CONFIRMED if traceback_leak else FindingKind.POTENTIAL,
                                        "A handler for unexpected errors sends the exception message"
                                        + (" and traceback" if traceback_leak else "") + " in the response. "
                                        "Internal errors can reveal SQL, file paths, hostnames, library versions, "
                                        "or secrets, and they help attackers probe the system.",
                                        "Log the exception server-side with a correlation id and return a generic "
                                        "message (and that id) to the client.", rel, node.lineno, Category.SECURITY)]
        return []

    def _js_idor(self, ctx, rel):
        lines = ctx.lines(rel)
        text = "\n".join(lines)
        global_auth = bool(JS_GLOBAL_AUTH.search(text))
        starts = [(i, m) for i, ln in enumerate(lines) if (m := JS_ANY_ROUTE.search(ln))]
        out = []
        for k, (start, m) in enumerate(starts):
            if not (global_auth or JS_AUTH_HINT.search(m.group(3))):
                continue  # unauthenticated routes are reported (when mutating) as route-without-auth instead
            end = min(starts[k + 1][0] if k + 1 < len(starts) else len(lines), start + 60)
            window = lines[start:end]
            if JS_OWNERSHIP.search("\n".join(window)):
                continue
            hit = next((start + j for j, ln in enumerate(window) if JS_LOOKUP_BY_PARAM.search(ln)), None)
            if hit is not None:
                out.append(self._f(ctx, "api.idor-unscoped-lookup", f"Object loaded by URL parameter without an "
                                   f"ownership check: {m.group(1).upper()} {m.group(2)}", Severity.MEDIUM,
                                   Confidence.LOW, FindingKind.POTENTIAL,
                                   "This authenticated route fetches or changes a record by `req.params` and never "
                                   "compares it with `req.user`, a tenant, or a permission. Any signed-in user may "
                                   "access other users' records by changing the id (IDOR). Verify whether a "
                                   "middleware enforces ownership.",
                                   "Include the owner in the query (`where: { id, ownerId: req.user.id }`) or check "
                                   "ownership after loading and return 404/403.", rel, hit + 1, Category.SECURITY))
        return out

    def _no_error_handler(self, ctx, route_count, error_handler_seen):
        frameworks = set(ctx.languages.frameworks)
        if error_handler_seen or route_count < 3:
            return []
        if "express" in frameworks:
            return [self._f(ctx, "api.no-error-handler", "Express app without an error-handling middleware",
                            Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                            "No `(err, req, res, next)` middleware was found. Express's default handler returns the "
                            "stack trace unless NODE_ENV=production, and errors are not logged or shaped consistently.",
                            "Register a final error-handling middleware that logs the error with a request id and "
                            "returns a generic JSON error.", "", None)]
        if "flask" in frameworks:
            return [self._f(ctx, "api.no-error-handler", "Flask app without an application-wide error handler",
                            Severity.INFO, Confidence.MEDIUM, FindingKind.POTENTIAL,
                            "No `errorhandler`/`register_error_handler` was found, so API clients get Flask's HTML "
                            "error pages and error responses are not shaped or correlated consistently.",
                            "Register handlers for HTTPException and Exception that log with a request id and return "
                            "a consistent JSON error body.", "", None)]
        return []

    # ------------------------------------------------------------------------------------------------ js
    def _js_file(self, ctx, rel, text):
        out = []
        lines = ctx.lines(rel)
        logged = 0
        for i, line in enumerate(lines, start=1):
            off = sorted(set(JS_COOKIE_FLAG_OFF.findall(line)))
            if off and JS_COOKIE_CONTEXT.search("\n".join(lines[max(0, i - 4):i])):  # this line and 3 above
                out.append(self._f(ctx, "api.insecure-cookie", "Cookie option " + ", ".join(f"{o}: false" for o in off),
                                   Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                   "A cookie or session configuration turns off "
                                   + " and ".join("HttpOnly (any XSS can read the cookie)" if o == "httpOnly" else
                                                  "Secure (the browser also sends the cookie over plain HTTP)"
                                                  for o in off)
                                   + ". If this is a session or token cookie it can be stolen. (Development-only "
                                   "configuration is fine — verify which environment uses it.)",
                                   "Use httpOnly: true, secure: true (behind TLS; set app.set('trust proxy', 1) "
                                   "behind a proxy) and sameSite: 'lax' for session and token cookies.", rel, i,
                                   Category.SECURITY))
            m = JS_BARE_COOKIE.search(line)
            if m and SENSITIVE_COOKIE.search(m.group(1)) and not re.search(r"(?i)csrf|xsrf", m.group(1)):
                out.append(self._f(ctx, "api.insecure-cookie", f"Cookie `{m.group(1)}` set without options",
                                   Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                   "Express's res.cookie() sets neither HttpOnly nor Secure by default, so this "
                                   "session/token cookie is readable by scripts and sent over plain HTTP.",
                                   "Pass { httpOnly: true, secure: true, sameSite: 'lax' }.", rel, i,
                                   Category.SECURITY))
            m = JS_LOG_CALL.search(line)
            leaked = _js_logged_secret(m.group(1)) if m else None
            if leaked and logged < 20:
                logged += 1
                out.append(self._sensitive_log(ctx, rel, i, leaked))
            if JS_CLIENT_FILENAME.search(line):
                out.append(self._f(ctx, "api.upload-client-filename", "Uploaded file stored under the client's file "
                                   "name", Severity.HIGH, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                   "`originalname` comes from the multipart request and is chosen by the client. Used "
                                   "as the destination name it allows path traversal (`../../`) and overwriting "
                                   "other uploads or application files.",
                                   "Generate the stored name server-side (crypto.randomUUID() plus an allow-listed "
                                   "extension) and keep originalname only as metadata.", rel, i, Category.SECURITY))
        multer = re.search(r"\bmulter\s*\(", text)
        if multer and "fileFilter" not in text:
            line = text.count("\n", 0, multer.start()) + 1
            out.append(self._f(ctx, "api.upload-unvalidated", "multer upload without a fileFilter"
                               + ("" if "limits" in text else " or size limits"), Severity.MEDIUM, Confidence.MEDIUM,
                               FindingKind.POTENTIAL,
                               "multer accepts every file type" + ("" if "limits" in text else " of unlimited size")
                               + " unless configured. Attackers can upload HTML/SVG (stored XSS when served back), "
                               "executable scripts, or huge files. Validation may happen later in the handler — "
                               "verify.",
                               "Add a fileFilter that allow-lists MIME types/extensions, set limits.fileSize, and "
                               "store uploads outside the web root.", rel, line, Category.SECURITY))
        for i, line in enumerate(lines, start=1):
            if JS_ERROR_LEAK.search(line):
                out.append(self._f(ctx, "api.error-details-exposed", "Stack trace returned to the client",
                                   Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                   "The error's stack trace is sent in the response, revealing file paths, library "
                                   "versions and internal structure.",
                                   "Log the error server-side with a correlation id and return a generic message.",
                                   rel, i, Category.SECURITY))
            if re.search(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", line):
                out.append(self._f(ctx, "api.tls-verify-disabled", "TLS certificate verification disabled",
                                   Severity.HIGH, Confidence.HIGH, FindingKind.CONFIRMED,
                                   "Disabling certificate validation enables man-in-the-middle attacks.",
                                   "Keep verification on; supply a CA bundle for private CAs.", rel, i,
                                   Category.SECURITY))
            if re.search(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]", line, re.I):
                out.append(self._f(ctx, "api.jwt-verification-disabled", "JWT 'none' algorithm accepted",
                                   Severity.CRITICAL, Confidence.HIGH, FindingKind.CONFIRMED,
                                   "Accepting alg=none lets anyone forge tokens.", "Allow-list signing algorithms.",
                                   rel, i, Category.SECURITY))
            if re.search(r"\bcors\(\s*\)", line) or re.search(r"origin\s*:\s*(['\"]\*['\"]|true)\b", line):
                creds = "credentials: true" in text or "credentials:true" in text
                out.append(self._cors(ctx, rel, i, creds))
            if re.search(r"\b(?:create|update|insert|new\s+\w+|findOneAndUpdate|updateOne)\(\s*req\.body\s*[,)]", line):
                out.append(self._f(ctx, "api.mass-assignment", "Request body passed directly to the data layer",
                                   Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                   "Clients can set any field (role, isAdmin, ownerId) when req.body is persisted "
                                   "without an allow-list.", "Validate with a schema (zod, joi) and pick allowed "
                                   "fields explicitly.", rel, i))
        return out

    # --------------------------------------------------------------------------------------------- shared
    def _cors(self, ctx, rel, line, creds):
        return self._f(ctx, "api.cors-wildcard", "CORS allows any origin" + (" with credentials" if creds else ""),
                       Severity.HIGH if creds else Severity.MEDIUM, Confidence.MEDIUM, FindingKind.CONFIRMED,
                       "Any website can call this API from a browser" + (
                           " with the user's cookies, enabling cross-site data theft." if creds else
                           ". Acceptable only for genuinely public, unauthenticated APIs."),
                       "Restrict origins to an explicit allow-list of trusted front-end URLs.", rel, line)

    def _unprotected(self, ctx, unprotected, auth_seen):
        if not unprotected:
            return []
        if not auth_seen:
            rel, line, desc, _ = unprotected[0]
            return [self._f(ctx, "api.no-authentication", "State-changing endpoints with no authentication mechanism "
                            "detected", Severity.HIGH, Confidence.MEDIUM, FindingKind.POTENTIAL,
                            f"{len(unprotected)} POST/PUT/PATCH/DELETE route(s) were found (first: {desc}) and no "
                            "authentication library or decorator was detected anywhere in the codebase.",
                            "Add authentication and enforce authorization on every state-changing endpoint.",
                            rel, line)]
        return [self._f(ctx, "api.route-without-auth", f"State-changing route without visible auth: {desc}",
                        Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                        "The project uses authentication elsewhere, but this route has no auth decorator/middleware "
                        "on it. It may be protected globally (middleware, before_request, gateway) — verify.",
                        "Protect the route explicitly and check object-level authorization (the caller may only "
                        "modify resources they own).", rel, line)
                for rel, line, desc, _name in unprotected[:50]]

    def _project_level(self, ctx):
        out = []
        frameworks = set(ctx.languages.frameworks)
        if "express" in frameworks:
            all_js = "".join(ctx.read(f) or "" for f in ctx.files_with_suffix(".js", ".ts", ".mjs")
                             if not is_test_path(f))
            if "helmet" not in all_js:
                out.append(self._f(ctx, "api.express-no-helmet", "Express app without security headers middleware",
                                   Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                   "helmet (or equivalent) was not found; responses likely lack CSP, HSTS, "
                                   "X-Content-Type-Options and framing protection.",
                                   "Add helmet() or set the headers at the reverse proxy.", "", None))
            if "rate-limit" not in all_js and "rateLimit" not in all_js and "login" in all_js.lower():
                out.append(self._f(ctx, "api.no-rate-limiting", "No rate limiting detected", Severity.LOW,
                                   Confidence.LOW, FindingKind.POTENTIAL,
                                   "Login routes exist but no rate limiting middleware was found, enabling "
                                   "credential stuffing and brute force.",
                                   "Rate-limit authentication endpoints (express-rate-limit, gateway policies).",
                                   "", None))
        return out

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line, category=Category.API):
        return self.finding(ctx, rule=rule, title=title, category=category, severity=sev, confidence=conf, kind=kind,
                            description=desc, remediation=fix, file_path=rel, line=line)
