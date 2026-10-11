"""Authentication, session and data-layer checks that depend on the application's profile (``ctx.profile``).

Each check runs only where the app's own design makes it relevant: CSRF where browsers send credentials
automatically (cookie auth), JWT checks where the app issues or verifies JWTs, password-storage checks where it keeps
passwords (a ``password`` field in its ORM models, Prisma schema or SQL DDL, or its own password check), and NoSQL
operator injection where MongoDB is the data store. The audit report lists which of these applied and why.
"""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .api_security import JS_ROUTE, PUBLIC_NAMES, _decorator_name, _is_false
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")
JWT_SECRET_SETTING = re.compile(r"(?i)^(?:jwt_?secret(?:_?key)?|jwt_?signing_?key|secret_?key_?jwt)$")
PW_NAME = re.compile(r"(?i)^(?:user_|current_|given_|input_|submitted_|plain_|raw_|stored_|db_)?"
                     r"(?:password|passwd|pwd)$")
NOT_A_STORED_PW = re.compile(r"(?i)confirm|repeat|again|retype|new|old|verify|[12]$")
JS_PW_COMPARE = re.compile(r"(?i)\b((?:[\w$]+(?:\?\.|\.))+(?:password|passwd))\s*(?:===?|!==?)\s*"
                           r"((?:[\w$]+(?:\?\.|\.))*[\w$]*(?:password|passwd))\b")
JS_JWT_LITERAL_KEY = re.compile(r"""\bjwt\.(sign|verify)\(\s*[^,]+,\s*(["'`])([^"'`]+)\2""")
JS_JWT_SIGN_2ARGS = re.compile(r"\bjwt\.sign\(\s*(\{[^{}]*\}|[^,(){}]+)\s*,\s*[^,(){}]+\)")
JS_JWT_VERIFY_NO_OPTS = re.compile(r"\bjwt\.verify\(\s*[^,()]+,\s*[^,(){}]+\s*(?:\)|,\s*(?:\(|function\b|async\b))")
JS_CSRF_LIBS = re.compile(r"\b(?:csurf|csrf-csrf|lusca|tiny-csrf|csrf-sync|doubleCsrf|csrfSync|csrfProtection)\b")
JS_SAMESITE = re.compile(r"""sameSite\s*:\s*["'`]?(?:strict|lax)""", re.I)
JS_NOSQL = re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|"
                      r"countDocuments|exists|replaceOne)\(\s*(?:req\.(?:body|query)\b(?!\.)|"
                      r"\{[^}]*:\s*req\.(?:body|query)\.[\w$]+\s*[,}])")
JS_NOSQL_SANITIZED = re.compile(r"mongo-sanitize|mongoSanitize|sanitizeFilter|express-mongo-sanitize")


def _literal_str(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(node.value.strip())


def _dict_keys(node: ast.Dict) -> set[str]:
    return {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def _pw_side(node) -> str | None:
    """``user.password`` / ``row["password"]`` / ``password`` → the password-like name, else None."""
    if isinstance(node, ast.Attribute):
        name = node.attr
    elif isinstance(node, ast.Name):
        name = node.id
    elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value,
                                                                                                  str):
        name = node.slice.value
    elif isinstance(node, ast.Call) and _decorator_name(node).endswith(".get") and node.args \
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        name = node.args[0].value
    else:
        return None
    return name if PW_NAME.match(name) else None


def _plaintext_pair(a, b) -> bool:
    """Two password-like expressions, at least one read from a stored record, that are not a confirmation field."""
    if not (_pw_side(a) and _pw_side(b)) or ast.unparse(a) == ast.unparse(b):
        return False
    if NOT_A_STORED_PW.search(ast.unparse(a)) or NOT_A_STORED_PW.search(ast.unparse(b)):
        return False
    return any(isinstance(n, ast.Attribute | ast.Subscript) for n in (a, b))


@register
class AuthSecurityAnalyzer(Analyzer):
    name = "auth_security"
    title = "Authentication, sessions & data layer"
    categories = (Category.SECURITY,)

    def applicable(self, ctx: AnalyzerContext):
        if not (ctx.languages.has("python") or ctx.languages.has("javascript") or ctx.languages.has("typescript")):
            return "no Python or JavaScript/TypeScript files detected"
        return None

    def run(self, ctx: AnalyzerContext):
        profile = ctx.profile
        findings: list = []
        middleware_lists: list[tuple[str, int]] = []
        trees: list[ast.Module] = []
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            trees.append(tree)
            findings.extend(self._python(ctx, rel, tree, profile, middleware_lists))
        js_files = [f for f in ctx.files_with_suffix(*JS_SUFFIXES) if not is_test_path(f)]
        for rel in js_files:
            findings.extend(self._js(ctx, rel, profile))
        findings.extend(self._django_csrf_middleware(ctx, profile, middleware_lists, trees))
        findings.extend(self._express_csrf(ctx, profile, js_files))
        findings.extend(self._password_storage(ctx, profile))
        return findings

    # ------------------------------------------------------------------------------------------- python
    def _python(self, ctx, rel, tree, profile, middleware_lists):
        out = []
        jwt_on, django_csrf = "jwt" in profile.auth, profile.cookie_auth and "django" in profile.web_frameworks
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _decorator_name(node)
                last = name.split(".")[-1]
                kws = {k.arg: k.value for k in node.keywords if k.arg}
                if jwt_on and "jwt" in name.lower() and last in ("encode", "decode"):
                    key = node.args[1] if len(node.args) > 1 else kws.get("key")
                    if _literal_str(key):
                        out.append(self._jwt_secret(ctx, rel, node.lineno))
                    if last == "encode" and node.args and isinstance(node.args[0], ast.Dict) \
                            and "exp" not in _dict_keys(node.args[0]):
                        out.append(self._jwt_no_expiry(ctx, rel, node.lineno, FindingKind.POTENTIAL))
                    if last == "decode" and "algorithms" not in kws and not self._verify_off(kws):
                        out.append(self._jwt_unpinned(ctx, rel, node.lineno))
                if jwt_on and last in ("create_access_token", "create_refresh_token") \
                        and _is_false(kws.get("expires_delta")):
                    out.append(self._jwt_no_expiry(ctx, rel, node.lineno, FindingKind.CONFIRMED))
                if profile.keeps_passwords and last == "compare_digest" and len(node.args) == 2 \
                        and _plaintext_pair(*node.args):
                    out.append(self._plaintext_compare(ctx, rel, node.lineno, ast.unparse(node)))
            elif isinstance(node, ast.Compare) and profile.keeps_passwords and len(node.ops) == 1 \
                    and isinstance(node.ops[0], ast.Eq | ast.NotEq) and _plaintext_pair(node.left,
                                                                                       node.comparators[0]):
                out.append(self._plaintext_compare(ctx, rel, node.lineno, ast.unparse(node)))
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                key = node.targets[0].slice.value if isinstance(node.targets[0], ast.Subscript) and isinstance(
                    node.targets[0].slice, ast.Constant) else ast.unparse(node.targets[0]).rsplit(".", 1)[-1]
                if jwt_on and JWT_SECRET_SETTING.match(str(key)) and _literal_str(node.value):
                    out.append(self._jwt_secret(ctx, rel, node.lineno))
                if key == "MIDDLEWARE" and isinstance(node.value, ast.List | ast.Tuple) and any(
                        isinstance(e, ast.Constant) and "django.middleware" in str(e.value) for e in node.value.elts):
                    middleware_lists.append((rel, node.lineno))
            elif django_csrf and isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                if any("csrf_exempt" in ast.unparse(d) for d in node.decorator_list) and not PUBLIC_NAMES.search(
                        node.name):
                    out.append(self._f(ctx, "auth.csrf-exempt", f"CSRF protection disabled on `{node.name}`",
                                       Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                       "This Django app authenticates browsers with session cookies, and this view "
                                       "opts out of CSRF checks. A page on any other site can submit requests to it "
                                       "with the victim's session. It is safe only if the view is not authenticated "
                                       "by the session cookie (e.g. token-only API or signed webhook) — verify.",
                                       "Remove @csrf_exempt, or authenticate this view with a header token / "
                                       "signature instead of the session.", rel, node.lineno))
        return out

    @staticmethod
    def _verify_off(kws) -> bool:
        opts = kws.get("options")
        return _is_false(kws.get("verify")) or (isinstance(opts, ast.Dict) and any(
            isinstance(k, ast.Constant) and k.value == "verify_signature" and _is_false(v)
            for k, v in zip(opts.keys, opts.values, strict=False)))

    # ----------------------------------------------------------------------------------------------- js
    def _js(self, ctx, rel, profile):
        out = []
        lines = ctx.lines(rel)
        text = "\n".join(lines)
        jwt_on, mongo = "jwt" in profile.auth, "mongodb" in profile.datastores
        sanitized = bool(JS_NOSQL_SANITIZED.search(text)) or any(
            JS_NOSQL_SANITIZED.search(ctx.read(m) or "") for m in ctx.files_named("package.json"))
        for i, line in enumerate(lines, start=1):
            if jwt_on:
                if JS_JWT_LITERAL_KEY.search(line):
                    out.append(self._jwt_secret(ctx, rel, i))
                m = JS_JWT_SIGN_2ARGS.search(line)
                if m and not re.search(r"\bexp\s*:", m.group(1)):
                    out.append(self._jwt_no_expiry(ctx, rel, i, FindingKind.POTENTIAL))
                if JS_JWT_VERIFY_NO_OPTS.search(line):  # the call closes (or takes a callback) with no options
                    out.append(self._jwt_unpinned(ctx, rel, i))
            if profile.keeps_passwords:
                m = JS_PW_COMPARE.search(line)
                if m and m.group(1) != m.group(2) and not NOT_A_STORED_PW.search(m.group(0)):
                    out.append(self._plaintext_compare(ctx, rel, i, m.group(0)))
            if mongo and not sanitized and JS_NOSQL.search(line):
                out.append(self._f(ctx, "auth.nosql-injection", "MongoDB query built from request body/query values",
                                   Severity.HIGH, Confidence.MEDIUM, FindingKind.POTENTIAL,
                                   "Request bodies and query strings can carry objects, not just strings (JSON, or "
                                   "`?user[$ne]=x` with Express's query parser). Passed into a MongoDB filter, "
                                   "`{\"$ne\": null}` or `{\"$gt\": \"\"}` matches any document — the classic login "
                                   "bypass — and `$where` runs JavaScript. No mongo-sanitize / sanitizeFilter was "
                                   "found; validation may happen in middleware — verify.",
                                   "Validate input with a schema (zod/joi) and cast values to String/Number before "
                                   "querying; enable mongoose `sanitizeFilter` or express-mongo-sanitize.", rel, i))
        return out

    # ------------------------------------------------------------------------------------- project level
    def _django_csrf_middleware(self, ctx, profile, middleware_lists, trees):
        if not (profile.cookie_auth and "django" in profile.web_frameworks) or not middleware_lists:
            return []
        # Code only (string literals and names, no comments): a commented-out entry is the usual way this goes wrong.
        if any("CsrfViewMiddleware" in str(n.value if isinstance(n, ast.Constant) else
                                           n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute)
                                           else " ".join(a.name for a in n.names))
               for tree in trees for n in ast.walk(tree)
               if isinstance(n, ast.Constant | ast.Name | ast.Attribute | ast.ImportFrom | ast.Import)):
            return []
        rel, line = middleware_lists[0]
        return [self._f(ctx, "auth.django-csrf-middleware-missing", "Django CsrfViewMiddleware is not enabled",
                        Severity.MEDIUM, Confidence.MEDIUM, FindingKind.CONFIRMED,
                        "MIDDLEWARE is defined without django.middleware.csrf.CsrfViewMiddleware and the middleware is "
                        "not referenced anywhere else in the code, while the app uses session-cookie authentication. "
                        "Every state-changing view can be triggered from another site with the victim's session.",
                        "Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE (after SessionMiddleware).",
                        rel, line)]

    def _express_csrf(self, ctx, profile, js_files):
        if not (profile.cookie_auth and "express" in profile.web_frameworks):
            return []
        routes = [(rel, i) for rel in js_files for i, ln in enumerate(ctx.lines(rel), start=1) if JS_ROUTE.search(ln)]
        if not routes:
            return []
        corpus = "\n".join(ctx.read(f) or "" for f in [*js_files, *ctx.files_named("package.json")])
        if JS_CSRF_LIBS.search(corpus) or JS_SAMESITE.search(corpus):
            return []
        rel, line = routes[0]
        return [self._f(ctx, "auth.express-no-csrf", "Cookie-authenticated Express app without CSRF protection",
                        Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                        f"The app authenticates with cookies ({profile.auth['cookie']}) and has {len(routes)} "
                        "state-changing route(s), but no CSRF middleware (csrf-csrf, csrf-sync, lusca, …) and no "
                        "SameSite=Lax/Strict cookie setting were found. Browsers default to SameSite=Lax in most but "
                        "not all cases — verify.",
                        "Set the session cookie to sameSite: 'lax' (or 'strict') and add a CSRF token middleware such "
                        "as csrf-csrf for form posts.", rel, line)]

    def _password_storage(self, ctx, profile):
        if not profile.password_columns or profile.password_hashing:
            return []
        rel, line = profile.password_columns[0]
        return [self._f(ctx, "auth.password-stored-unhashed", "Password field with no password hashing in the app",
                        Severity.HIGH, Confidence.MEDIUM, FindingKind.POTENTIAL,
                        f"The schema stores a `password` field ({len(profile.password_columns)} found, first here) "
                        "but no password hashing function or library (bcrypt, argon2, scrypt, PBKDF2, passlib, "
                        "werkzeug/django hashers) appears anywhere in the code or dependencies. Passwords are probably "
                        "stored in plain text, so a database leak exposes every user's password. A hasher eVal does "
                        "not recognize may be in use — verify.",
                        "Hash with argon2id, scrypt or bcrypt (e.g. argon2-cffi, passlib, bcryptjs) before storing, "
                        "and verify with the library's constant-time check. Rename the column password_hash.",
                        rel, line)]

    # ----------------------------------------------------------------------------------------- findings
    def _jwt_secret(self, ctx, rel, line):
        return self._f(ctx, "auth.jwt-hardcoded-secret", "JWT signing key hardcoded", Severity.HIGH, Confidence.HIGH,
                       FindingKind.CONFIRMED,
                       "The key that signs or verifies JWTs is a string literal in the source. Anyone with the code "
                       "(or a leaked copy of it) can mint valid tokens for any user.",
                       "Load the key from the environment or a secrets manager, use at least 256 random bits (or an "
                       "asymmetric key pair), and rotate the exposed key.", rel, line)

    def _jwt_no_expiry(self, ctx, rel, line, kind):
        confirmed = kind == FindingKind.CONFIRMED
        return self._f(ctx, "auth.jwt-no-expiry", "JWT issued without an expiry", Severity.MEDIUM,
                       Confidence.HIGH if confirmed else Confidence.MEDIUM, kind,
                       ("Tokens are created with expiry explicitly disabled" if confirmed else
                        "The token payload has no `exp` claim and no expiry option is passed")
                       + ", so a stolen token works forever and cannot be revoked by waiting it out."
                       + ("" if confirmed else " The library or a wrapper may add a default expiry — verify."),
                       "Issue short-lived access tokens (e.g. 15 minutes: `exp` / expiresIn) and use refresh tokens "
                       "with server-side revocation.", rel, line)

    def _jwt_unpinned(self, ctx, rel, line):
        return self._f(ctx, "auth.jwt-algorithm-not-pinned", "JWT verified without an algorithm allow-list",
                       Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
                       "The token is verified without specifying which algorithms are accepted, so the token header "
                       "chooses. Depending on the library and version this enables algorithm confusion (an RS256 "
                       "public key used as an HS256 secret) or rejects nothing at all.",
                       "Pass an explicit allow-list: `algorithms=['RS256']` (PyJWT/python-jose) or "
                       "`{ algorithms: ['RS256'] }` (jsonwebtoken).", rel, line)

    def _plaintext_compare(self, ctx, rel, line, expr):
        return self._f(ctx, "auth.plaintext-password-compare", "Password compared directly with a stored value",
                       Severity.HIGH, Confidence.MEDIUM, FindingKind.POTENTIAL,
                       f"`{expr[:120]}` compares a submitted password with one read from a record. That only works "
                       "if passwords are stored in plain text (or with a reversible encoding), and `==` also leaks "
                       "timing. The stored field may already hold a hash computed from the input — verify.",
                       "Store a salted password hash (argon2id/scrypt/bcrypt) and check it with the library's "
                       "verify function (check_password_hash, bcrypt.compare, argon2 verify).", rel, line)

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line):
        return self.finding(ctx, rule=rule, title=title, category=Category.SECURITY, severity=sev, confidence=conf,
                            kind=kind, description=desc, remediation=fix, file_path=rel, line=line)
