"""API and web-application security: authorization coverage, debug mode, CORS, JWT and TLS verification,
mass assignment, CSRF, and hardening middleware."""

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
        auth_seen = False
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
            if file_guard:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                routes = [(d, _route_info(d)) for d in node.decorator_list]
                routes = [(d, r) for d, r in routes if r]
                if not routes:
                    continue
                path, methods = routes[0][1]
                others = [_decorator_name(d) for d in node.decorator_list if d is not routes[0][0]]
                protected = any(AUTH_DECORATOR.search(n) for n in others) or _fastapi_protected(node, routes[0][0])
                if not protected and methods & MUTATING and not PUBLIC_NAMES.search(node.name + path):
                    unprotected.append((rel, node.lineno, f"{'/'.join(sorted(methods & MUTATING))} {path}",
                                        node.name))

        for rel in ctx.files_with_suffix(".js", ".mjs", ".cjs", ".ts"):
            if is_test_path(rel):
                continue
            text = ctx.read(rel) or ""
            if JS_AUTH_HINT.search(text) and re.search(r"(?i)(passport|jsonwebtoken|express-session|jwt)", text):
                auth_seen = True
            findings.extend(self._js_file(ctx, rel, text))
            for i, line in enumerate(ctx.lines(rel), start=1):
                m = JS_ROUTE.search(line)
                if m and not JS_AUTH_HINT.search(m.group(3)) and not PUBLIC_NAMES.search(m.group(2)):
                    unprotected.append((rel, i, f"{m.group(1).upper()} {m.group(2)}", m.group(2)))

        findings.extend(self._unprotected(ctx, unprotected, auth_seen))
        findings.extend(self._project_level(ctx))
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

    # ------------------------------------------------------------------------------------------------ js
    def _js_file(self, ctx, rel, text):
        out = []
        for i, line in enumerate(ctx.lines(rel), start=1):
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
