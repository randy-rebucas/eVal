"""API and web-application security: authentication coverage, object-level authorization (IDOR), error
disclosure and error handling, debug mode, CORS, JWT and TLS verification, mass assignment, CSRF, and hardening
middleware."""

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
        auth_seen = error_handler_seen = False
        route_count = 0
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            text = ctx.read(rel) or ""
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
        return findings

    # ------------------------------------------------------------------------------------------- python
    def _python_file(self, ctx, rel, tree, text):
        out = []
        settings_like = rel.endswith(("settings.py", "config.py", "settings/production.py", "settings/base.py"))
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
                if target == "ALLOWED_HOSTS" and "'*'" in ast.unparse(value):
                    out.append(self._f(ctx, "api.django-allowed-hosts-wildcard", "ALLOWED_HOSTS allows any host",
                                       Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "A wildcard host enables Host-header attacks (password reset poisoning, cache "
                                       "poisoning).", "List the exact hostnames served.", rel, node.lineno))
        if "flask_login" in text and "request.form" in text and not re.search(
                r"(CSRFProtect|flask_wtf|FlaskForm|csrf)", text):
            out.append(self._f(ctx, "api.flask-no-csrf", "Cookie-authenticated form handling without CSRF "
                               "protection", Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                               "This module uses session-cookie auth and reads form posts, but no CSRF protection "
                               "was found in it (it may be configured elsewhere).",
                               "Enable Flask-WTF CSRFProtect app-wide (or SameSite=Strict cookies plus origin "
                               "checks).", rel, None))
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
        for i, line in enumerate(ctx.lines(rel), start=1):
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
