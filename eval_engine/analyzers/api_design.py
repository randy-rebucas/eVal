"""API design and contract checks: request-body validation, status codes, idempotency of operations that move money
or create orders, versioning, and the consistency of error responses.

Routes come from Flask/FastAPI decorators (with the Blueprint/APIRouter prefix declared in the same file), Django
``path("api/...")`` entries, Express-style ``app.post('/x', ...)`` calls and Next.js route handlers. Each check looks
for the evidence a careful implementation leaves behind (a schema, an explicit status, an idempotency key, a version
segment) and reports only when none is visible.

Pagination is checked by the database analyzer (``database.missing-pagination``) and the API contract (OpenAPI) by the
configuration analyzer (``config.undocumented-api``).
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..findings import Confidence, FindingKind, Severity
from .architecture import _js_block
from .base import AnalyzerContext, is_test_path
from .db_migrations import _paren_body
from .db_model import top_level_entries
from .db_queries import MAX_PER_RULE, Issue

ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete", "api_route"}
BODY_METHODS = {"POST", "PUT", "PATCH"}
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts")

# Validation: where a handler reads a JSON body, and evidence that it is checked (a schema, a validator, a type check,
# or an explicit 400/422 response).
PY_BODY_READ = re.compile(r"\brequest\.(?:json\b|get_json\(|data\b)|json\.loads\(\s*request\.body|"
                          r"await\s+request\.json\(\)")
PY_VALIDATION = re.compile(r"(?i)validat|schema|serializer|is_valid\(|\.load\(|model_validate|parse_obj|parse_raw|"
                           r"TypeAdapter|validate_on_submit|BadRequest|UnprocessableEntity|abort\(\s*4(?:00|22)|"
                           r"\b4(?:00|22)\b|HTTP_4(?:00|22)|isinstance\(")
PY_VALIDATION_DECORATOR = re.compile(r"(?i)validat|schema|use_args|use_kwargs|arguments|expects_json|input|body")
JS_BODY_READ = re.compile(r"\breq\.body\b|\bawait\s+(?:req|request)\.json\(\)|\bctx\.request\.body\b")
JS_VALIDATION = re.compile(r"(?i)validat|schema|(?<!JSON)\.parse(?:Async)?\(|safeParse|celebrate|checkSchema|"
                           r"\bbody\(\s*['\"`]|\bcheck\(\s*['\"`]|\bjoi\b|\bzod\b|\byup\b|\bajv\b|superstruct|typebox|"
                           r"\.status\(\s*4(?:00|22)\s*\)|sendStatus\(\s*4(?:00|22)|status\s*:\s*4(?:00|22)\b|"
                           r"\.code\(\s*4(?:00|22)\s*\)|typeof\s+\w")
SPEC_VALIDATOR = re.compile(r"OpenApiValidator|express-openapi-validator|openapi-backend|connexion|ValidationPipe")

# Status codes and error shapes. A body is an error when it carries an error field, success/ok false, or status
# "error"; its "shape" is the set of fields that carry the human-readable message.
ERROR_FLAG_KEYS = {"error", "errors", "err", "error_message", "errorMessage"}
MESSAGE_KEYS = ERROR_FLAG_KEYS | {"detail", "message", "msg", "reason"}
EMPTY_VALUES = {"None", "False", "''", '""', "[]", "{}", "null", "undefined", "false"}
PY_JSON_CALLS = {"jsonify", "JSONResponse", "JsonResponse", "ORJSONResponse", "UJSONResponse"}
PY_WRAPPER_CALLS = {"make_response", "Response"}
PY_STATUS_SET = re.compile(r"\.status_code\s*=|\bresponse\.status\s*=")
JS_SEND = re.compile(r"\b(res|reply)((?:\.(?:status|code)\([^()]*\))*)\.(?:json|send)\(\s*(?=\{)")
JS_NEXT_JSON = re.compile(r"\b(?:NextResponse|Response)\.json\(")
JS_STATUS_SET = re.compile(r"\bres\.status\(|\bres\.statusCode\s*=|\breply\.code\(|\breply\.status\(")
HTTP_EXCEPTION_RESHAPED = re.compile(r"exception_handler\(\s*(?:Starlette)?HTTPException|"
                                     r"add_exception_handler\(\s*(?:Starlette)?HTTPException")

# Idempotency: retried POSTs that move money or create orders, and payment-provider calls that create them.
MONEY_TOKENS = {"pay", "payment", "payments", "charge", "charges", "checkout", "order", "orders", "purchase",
                "purchases", "transfer", "transfers", "payout", "payouts", "refund", "refunds", "withdraw",
                "withdrawal", "withdrawals", "deposit", "deposits", "invoice", "invoices", "subscribe", "subscription",
                "subscriptions", "billing", "transaction", "transactions", "booking", "bookings", "reservation",
                "reservations", "donate", "donation", "donations", "remit", "topup"}
NOT_A_CREATE = {"webhook", "webhooks", "callback", "hook", "hooks", "notify", "ipn", "search", "query", "preview",
                "quote", "estimate", "calculate", "validate", "verify", "status", "filter", "lookup", "export",
                "report", "reports", "cancel", "list"}
IDEMPOTENCY = re.compile(r"(?i)idempoten")
PY_STRIPE_CREATE = re.compile(r"^stripe\.(?:PaymentIntent|Charge|Refund|Transfer|Payout|Subscription|Invoice|"
                              r"checkout\.Session)\.create$")
JS_STRIPE_CREATE = re.compile(r"\bstripe\.(?:paymentIntents|charges|refunds|transfers|payouts|subscriptions|invoices|"
                              r"checkout\.sessions)\.create\(")

# Versioning: a version segment in a path or mount prefix, or a header/media-type/framework versioning scheme.
VERSION_SEGMENT = re.compile(r"(?i)(?:^|/)v\d+(?:\.\d+)?(?:/|$)|\{version\}|<(?:\w+:)?version>|:version\b")
VERSION_CODE = re.compile(r"(?i)api[_-]?version|accept-version|versioning|enableVersioning|@Version\(|"
                          r"application/vnd\.")
GRAPHQL = re.compile(r"(?i)graphql")
MIN_API_ROUTES = 5

JS_ROUTE = re.compile(r"\b(?:app|router|server|routes|\w+Router)\.(get|post|put|patch|delete|all)\(\s*(['\"`])"
                      r"(/[^'\"`]*)\2")
JS_SERVER_FILE = re.compile(r"\bexpress\b|\bRouter\(|\bfastify\b|\bkoa\b|\bres\.(?:json|send|status)\(")
JS_MOUNT = re.compile(r"\b(?:app|router|server|\w+Router)\.use\(\s*['\"`](/[^'\"`]*)['\"`]|"
                      r"setGlobalPrefix\(\s*['\"`]([^'\"`]*)['\"`]|\bprefix\s*:\s*['\"`](/[^'\"`]*)['\"`]")
NEXT_HANDLER = re.compile(r"^export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(", re.M)
NEXT_ROUTE_FILE = re.compile(r"(?:^|/)app/(.*?)/?route\.[jt]sx?$")
DJANGO_PATH = re.compile(r"""\b(?:re_)?path\(\s*r?['"]\^?(api/[^'"]*)['"]""")


@dataclass
class Route:
    file: str
    line: int
    methods: frozenset[str]
    path: str  # including the prefix of a Blueprint/APIRouter declared in the same file
    name: str
    func: ast.FunctionDef | ast.AsyncFunctionDef | None = None  # Python handler
    decorators: list[str] = field(default_factory=list)
    args: str = ""  # JavaScript: the route call's arguments (middleware and inline handler)


@dataclass
class _ErrorBody:
    shape: tuple[str, ...]  # message-carrying fields, e.g. ("error",) or ("detail",)
    status: int | str | None  # None = framework default (200), "?" = not a literal
    file: str
    line: int


def _dotted(node: ast.AST) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    parts = []
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    return ".".join(reversed(parts))


def _str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _status(node: ast.AST) -> int | str:
    """A literal status (``400``, ``status.HTTP_400_BAD_REQUEST``, ``HTTPStatus.BAD_REQUEST``) or "?"."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    m = re.search(r"HTTP_(\d{3})", ast.unparse(node))
    if m:
        return int(m.group(1))
    try:
        from http import HTTPStatus

        name = ast.unparse(node)
        if name.startswith("HTTPStatus."):
            return int(HTTPStatus[name.split(".", 1)[1]])
    except (KeyError, ValueError):
        pass
    return "?"


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", text)}


def _is_error(entries: dict[str, str]) -> bool:
    """Whether a response body (field -> value source) reports a failure."""
    for key, value in entries.items():
        value = value.strip()
        if key in ERROR_FLAG_KEYS and value not in EMPTY_VALUES:
            return True
        if key in ("success", "ok") and value in ("False", "false"):
            return True
        if key == "status" and value.strip("'\"`").lower() in ("error", "fail", "failed", "failure"):
            return True
    return False


def _shape(entries: dict[str, str]) -> tuple[str, ...]:
    return tuple(sorted(k for k in entries if k in MESSAGE_KEYS))


def _py_entries(node: ast.AST | None) -> dict[str, str] | None:
    if not isinstance(node, ast.Dict):
        return None
    return {key: ast.unparse(v) for k, v in zip(node.keys, node.values, strict=False) if (key := _str(k)) is not None}


def _py_response(expr: ast.AST | None, bare_dict: bool) -> tuple[dict[str, str] | None, int | str | None]:
    """(body fields, status) of a returned or constructed response. Bare dicts count only in route handlers."""
    status: int | str | None = None
    if isinstance(expr, ast.Tuple) and expr.elts:
        if len(expr.elts) > 1:
            status = _status(expr.elts[1])
        expr = expr.elts[0]
    if isinstance(expr, ast.Dict):
        return (_py_entries(expr) if bare_dict else None), status
    if not isinstance(expr, ast.Call):
        return None, status
    name = _dotted(expr).split(".")[-1]
    kws = {k.arg: k.value for k in expr.keywords if k.arg}
    if name in PY_WRAPPER_CALLS:
        if len(expr.args) > 1:
            status = _status(expr.args[1])
        elif "status" in kws:
            status = _status(kws["status"])
        inner, inner_status = _py_response(expr.args[0], False) if expr.args else (None, None)
        return inner, status if status is not None else inner_status
    if name not in PY_JSON_CALLS:
        return None, status
    for key in ("status_code", "status"):
        if key in kws:
            status = _status(kws[key])
    if name == "jsonify" and not expr.args:
        return {k: ast.unparse(v) for k, v in kws.items()}, status
    body = expr.args[0] if expr.args else kws.get("content") or kws.get("data")
    return _py_entries(body), status


def _line_of(lines: list[str], start: int, end: int, pattern: re.Pattern) -> int:
    for n in range(start, min(end, len(lines)) + 1):
        if pattern.search(lines[n - 1]):
            return n
    return start


def _pos_line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


class _Collector:
    def __init__(self, ctx: AnalyzerContext):
        self.ctx = ctx
        self.routes: list[Route] = []
        self.mounts: list[tuple[str, str, int]] = []  # (prefix, file, line)
        self.django_api: list[tuple[str, str, int]] = []
        self.errors: list[_ErrorBody] = []
        self.status_200: list[Issue] = []
        self.provider_calls: list[tuple[str, int, str]] = []  # payment-provider creates without an idempotency key
        self.sources: dict[str, str] = {}
        self.fastapi_http_exceptions: list[tuple[str, int]] = []

    # ---------------------------------------------------------------------------------------------- python
    def python(self, rel: str) -> None:
        tree = self.ctx.python_ast(rel)
        if tree is None:
            return
        text = self.sources[rel] = self.ctx.read(rel) or ""
        lines = self.ctx.lines(rel)
        prefix = ""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node)
            short = name.split(".")[-1]
            kws = {k.arg: k.value for k in node.keywords if k.arg}
            if short in ("Blueprint", "APIRouter") and not prefix:
                prefix = (_str(kws.get("url_prefix")) or _str(kws.get("prefix")) or "").rstrip("/")
            if short in ("register_blueprint", "include_router", "mount"):
                p = _str(kws.get("url_prefix")) or _str(kws.get("prefix")) or (
                    _str(node.args[0]) if short == "mount" and node.args else None)
                if p:
                    self.mounts.append((p, rel, node.lineno))
            if PY_STRIPE_CREATE.match(name) and "idempotency_key" not in kws and not any(
                    k.arg is None for k in node.keywords):
                self.provider_calls.append((rel, node.lineno, name))
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and \
                    _dotted(node.exc).split(".")[-1] == "HTTPException":
                self.fastapi_http_exceptions.append((rel, node.lineno))
        for m in DJANGO_PATH.finditer(text):
            self.django_api.append((m.group(1), rel, _pos_line(text, m.start())))

        handlers: set[int] = set()
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for dec in func.decorator_list:
                info = self._py_route(dec)
                if info is None:
                    continue
                path, methods = info
                others = [_dotted(d) for d in func.decorator_list if d is not dec]
                self.routes.append(Route(rel, func.lineno, methods, prefix + path, func.name, func, others))
                handlers.add(id(func))
                break
        self._py_responses(rel, tree, lines, handlers)

    @staticmethod
    def _py_route(dec: ast.AST) -> tuple[str, frozenset[str]] | None:
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in ROUTE_METHODS):
            return None
        path = _str(dec.args[0]) if dec.args else _str(next((k.value for k in dec.keywords
                                                             if k.arg in ("path", "rule")), None))
        if path is None or (path and not path.startswith("/")):
            return None
        if dec.func.attr in ("route", "api_route"):
            methods = {"GET"}
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, ast.List | ast.Tuple | ast.Set):
                    methods = {e.value.upper() for e in kw.value.elts if _str(e)}
        else:
            methods = {dec.func.attr.upper()}
        return path, frozenset(methods)

    def _py_responses(self, rel, tree, lines, handlers) -> None:
        """Error bodies (for format consistency) and error bodies sent with a success status."""
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            is_handler = id(func) in handlers
            status_set = bool(PY_STATUS_SET.search(ast.unparse(func)))
            # `resp = jsonify(...)` … `return resp, 400`: the status travels with the variable, not the call.
            bound = {id(n.value): n.targets[0].id for n in ast.walk(func) if isinstance(n, ast.Assign)
                     and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
            returned_status = {n.value.elts[0].id: _status(n.value.elts[1]) for n in ast.walk(func)
                               if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
                               and len(n.value.elts) > 1 and isinstance(n.value.elts[0], ast.Name)}
            seen: set[int] = set()
            for node in ast.walk(func):
                if isinstance(node, ast.Return) and node.value is not None:
                    expr = node.value
                elif isinstance(node, ast.Call) and _dotted(node).split(".")[-1] in PY_JSON_CALLS | PY_WRAPPER_CALLS:
                    expr = node
                else:
                    continue
                if id(expr) in seen:
                    continue
                for sub in ast.walk(expr):
                    seen.add(id(sub))
                entries, status = _py_response(expr, is_handler and isinstance(node, ast.Return))
                if entries is None:
                    continue
                if status is None and bound.get(id(expr)) in returned_status:
                    status = returned_status[bound[id(expr)]]
                failed = _is_error(entries)
                if failed or (isinstance(status, int) and status >= 400):
                    shape = _shape(entries)
                    if shape:
                        self.errors.append(_ErrorBody(shape, status, rel, node.lineno))
                if failed and not status_set and (status is None or (isinstance(status, int) and status < 300)):
                    self.status_200.append(_status_issue(rel, node.lineno, status))

    # ---------------------------------------------------------------------------------------------- javascript
    def js(self, rel: str) -> None:
        text = self.sources[rel] = self.ctx.read(rel) or ""
        if not text:
            return
        for m in JS_STRIPE_CREATE.finditer(text):
            args = _paren_body(text, m.end() - 1) or ""
            if "idempotencyKey" not in args and "idempotency_key" not in args:
                self.provider_calls.append((rel, _pos_line(text, m.start()), m.group(0).rstrip("(")))
        for m in JS_MOUNT.finditer(text):
            p = next(g for g in m.groups() if g is not None)
            self.mounts.append(("/" + p.lstrip("/"), rel, _pos_line(text, m.start())))
        server = bool(JS_SERVER_FILE.search(text))
        if server:
            for m in JS_ROUTE.finditer(text):
                open_pos = text.index("(", m.start())
                args = _paren_body(text, open_pos) or ""
                self.routes.append(Route(rel, _pos_line(text, m.start()), frozenset({m.group(1).upper()}),
                                         m.group(3), m.group(3), args=args))
        route_file = NEXT_ROUTE_FILE.search(rel)
        if route_file:
            path = "/" + "/".join(p for p in route_file.group(1).split("/") if not p.startswith("("))
            for m in NEXT_HANDLER.finditer(text):
                params = _paren_body(text, m.end() - 1) or ""
                brace = text.find("{", m.end() + len(params))
                body = _js_block(text, brace) if brace >= 0 else None
                self.routes.append(Route(rel, _pos_line(text, m.start()), frozenset({m.group(1)}), path, m.group(1),
                                         args=body or ""))
        if server or route_file:
            self._js_responses(rel, text)

    def _js_responses(self, rel, text) -> None:
        for m in JS_SEND.finditer(text):
            body = _js_block(text, m.end())
            if body is None:
                continue
            entries = {k: v for k, v, _ in top_level_entries(body)}
            chain = m.group(2)
            literal = re.search(r"\.(?:status|code)\(\s*(\d{3})\s*\)", chain)
            if literal:
                status: int | str | None = int(literal.group(1))
            elif chain:
                status = "?"
            else:
                # `res.status(400); return res.json({...})` sets the status on this or one of the 3 lines above.
                line_start = text.rfind("\n", 0, m.start()) + 1
                before = text[max(0, line_start - 600):line_start].splitlines()[-3:] + [text[line_start:m.start()]]
                status = "?" if JS_STATUS_SET.search("\n".join(before)) else None
            self._js_error(rel, _pos_line(text, m.start()), entries, status)
        for m in JS_NEXT_JSON.finditer(text):
            args = _paren_body(text, m.end() - 1)
            if not args or not args.lstrip().startswith("{"):
                continue
            first = _js_block(args, len(args) - len(args.lstrip()))
            if first is None:
                continue
            rest = args[args.index(first) + len(first):]
            literal = re.search(r"\bstatus\s*:\s*(\d{3})", rest)
            status = int(literal.group(1)) if literal else ("?" if re.search(r"\bstatus\b", rest) else None)
            self._js_error(rel, _pos_line(text, m.start()), {k: v for k, v, _ in top_level_entries(first)}, status)

    def _js_error(self, rel, line, entries, status) -> None:
        failed = _is_error(entries)
        if failed or (isinstance(status, int) and status >= 400):
            shape = _shape(entries)
            if shape:
                self.errors.append(_ErrorBody(shape, status, rel, line))
        if failed and (status is None or (isinstance(status, int) and status < 300)):
            self.status_200.append(_status_issue(rel, line, status))


def _status_issue(rel: str, line: int, status) -> Issue:
    explicit = isinstance(status, int)
    return Issue(
        "api.error-status-200", f"Error response sent with HTTP {status if explicit else 200}", Severity.LOW,
        Confidence.HIGH if explicit else Confidence.MEDIUM, FindingKind.CONFIRMED,
        "The response body reports a failure (an error field, success/ok false, or status \"error\") but the HTTP "
        f"status is {status if explicit else '200, the framework default'}. Clients, retries, caches, monitoring and "
        "API gateways read the status code, not the body, so the failure is counted as a success: errors go "
        "unnoticed, failed writes are not retried, and error rates in dashboards stay at zero.",
        "Return the status that matches the outcome: 400/422 for invalid input, 401/403 for auth, 404 for missing "
        "resources, 409 for conflicts, 5xx for server faults (e.g. `return jsonify(error=...), 400`, "
        "`res.status(400).json(...)`, `NextResponse.json(body, { status: 400 })`).", rel, line)


# ================================================================================================== checks
def design_issues(ctx: AnalyzerContext) -> list[Issue]:
    col = _Collector(ctx)
    for rel in ctx.python_files():
        if not is_test_path(rel):
            col.python(rel)
    for rel in ctx.files_with_suffix(*JS_SUFFIXES):
        if not is_test_path(rel):
            col.js(rel)
    out: list[Issue] = []
    out += _validation(ctx, col)
    out += col.status_200[:MAX_PER_RULE]
    out += _idempotency(col)
    out += _versioning(col)
    out += _error_format(ctx, col)
    return out


def _validation(ctx, col: _Collector) -> list[Issue]:
    """Handlers that read a JSON request body and use it without any visible schema, validator or 400/422 check."""
    if any(SPEC_VALIDATOR.search(t) for t in col.sources.values()):
        return []  # requests are validated against an OpenAPI spec or a global pipe before reaching handlers
    out = []
    for r in col.routes:
        if not r.methods & BODY_METHODS:
            continue
        if r.func is not None:
            src = ast.unparse(r.func)
            if not PY_BODY_READ.search(src) or PY_VALIDATION.search(src) or any(
                    PY_VALIDATION_DECORATOR.search(d) for d in r.decorators):
                continue
            line = _line_of(ctx.lines(r.file), r.func.lineno, r.func.end_lineno or r.func.lineno, PY_BODY_READ)
            how = "request.json / get_json()"
        else:
            if not JS_BODY_READ.search(r.args) or JS_VALIDATION.search(r.args):
                continue
            line = r.line + r.args[:JS_BODY_READ.search(r.args).start()].count("\n")
            how = "req.body"
        method = "/".join(sorted(r.methods & BODY_METHODS))
        out.append(Issue(
            "api.missing-input-validation", f"Request body used without validation: {method} {r.path}",
            Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
            f"The handler reads the JSON body ({how}) but no schema, validator, type check or 400/422 response is "
            "visible in it. Missing fields raise 500s, wrong types reach the database and business logic, unexpected "
            "fields pass through, and oversized or nested values are accepted. Validation may happen in a helper or "
            "middleware eVal cannot see — verify.",
            "Validate every request body against an explicit schema before using it (pydantic / marshmallow / "
            "DRF serializers / flask-smorest in Python; zod, joi, express-validator or a Fastify schema in "
            "JavaScript) and return 400 or 422 with the validation errors.", r.file, line))
    return out[:MAX_PER_RULE]


def _idempotency(col: _Collector) -> list[Issue]:
    out = []
    for rel, line, call in col.provider_calls:
        out.append(Issue(
            "api.missing-idempotency", f"Payment provider call without an idempotency key: {call}",
            Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
            f"`{call}` creates a charge, payment, refund or transfer without an idempotency key. Network timeouts and "
            "client or job retries repeat the call, and each repeat creates another charge.",
            "Pass an idempotency key derived from the order or request (Stripe: `idempotency_key=` in Python, "
            "`{ idempotencyKey }` request option in Node) so retries return the original result.", rel, line))
    if any(IDEMPOTENCY.search(t) for t in col.sources.values()):
        return out[:MAX_PER_RULE]  # the API handles idempotency keys somewhere (often in middleware)
    for r in col.routes:
        tokens = _tokens(f"{r.name} {r.path}")
        if "POST" not in r.methods or not tokens & MONEY_TOKENS or tokens & NOT_A_CREATE:
            continue
        out.append(Issue(
            "api.missing-idempotency", f"Payment or order endpoint without idempotency: POST {r.path}",
            Severity.MEDIUM, Confidence.LOW, FindingKind.POTENTIAL,
            "This POST endpoint appears to create a payment, order or similar record, and the codebase never reads an "
            "Idempotency-Key header or stores request keys. POST is not idempotent: a client that retries after a "
            "timeout, a double-clicked button or a replaying proxy creates a duplicate order or charge.",
            "Accept an `Idempotency-Key` header on endpoints that create orders or move money, store the key with "
            "the result (unique constraint, expiry), and return the stored response when the same key is reused.",
            r.file, r.line))
    return out[:MAX_PER_RULE]


def _versioning(col: _Collector) -> list[Issue]:
    """An /api surface with no version in any path or mount prefix and no header/media-type versioning scheme."""
    mounted_api = [m for m in col.mounts if m[0].startswith("/api") and not GRAPHQL.search(m[0])]
    paths = [(r.path, r.file, r.line) for r in col.routes if not GRAPHQL.search(r.path)]
    api = [p for p in paths if p[0].startswith("/api")] + [("/" + p, f, ln) for p, f, ln in col.django_api]
    if mounted_api:
        api = [p for p in paths if not p[0].startswith("/api")] + api
    if len(api) < MIN_API_ROUTES:
        return []
    every = [p for p, _, _ in paths] + [m[0] for m in col.mounts] + [p for p, _, _ in col.django_api]
    if any(VERSION_SEGMENT.search(p) for p in every) or any(VERSION_CODE.search(t) for t in col.sources.values()):
        return []
    path, rel, line = (mounted_api[0] if mounted_api else api[0])
    return [Issue(
        "api.unversioned", f"{len(api)} API routes without versioning", Severity.LOW, Confidence.LOW,
        FindingKind.POTENTIAL,
        f"The API (first: {path}) has no version in its paths or mount prefixes and no header or media-type "
        "versioning. Every change to a request or response shape then reaches all clients at once, including mobile "
        "apps and integrations that cannot update in step, so breaking changes cannot be shipped safely.",
        "Version the public API before clients depend on it: a path prefix (`/api/v1`, via the Blueprint/APIRouter "
        "prefix or `app.use('/api/v1', router)`) or a header/media-type scheme, and keep the old version running "
        "until clients migrate.", rel, line)]


def _error_format(ctx, col: _Collector) -> list[Issue]:
    """Error responses that carry their message in different fields across the API."""
    errors = list(col.errors)
    reshaped = any(HTTP_EXCEPTION_RESHAPED.search(t) for t in col.sources.values())
    if {"fastapi", "starlette"} & set(ctx.languages.frameworks) and not reshaped:
        errors += [_ErrorBody(("detail",), "?", rel, line) for rel, line in col.fastapi_http_exceptions]
    shapes: dict[tuple[str, ...], list[_ErrorBody]] = defaultdict(list)
    for e in errors:
        shapes[e.shape].append(e)
    if len(shapes) < 2 or len(errors) < 4:
        return []
    ranked = sorted(shapes.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    listing = "; ".join(f"{{{', '.join(s)}}} ×{len(es)} (first {es[0].file}:{es[0].line})" for s, es in ranked[:5])
    outlier = ranked[1][1][0]
    return [Issue(
        "api.inconsistent-error-format", f"Error responses use {len(shapes)} different formats", Severity.LOW,
        Confidence.MEDIUM, FindingKind.POTENTIAL,
        f"Across {len(errors)} error responses the message is carried in different fields: {listing}. Clients must "
        "special-case each endpoint to show or log an error, and errors in the less common format are easily "
        "dropped.",
        "Define one error envelope (for example `{\"error\": {\"code\", \"message\", \"details\"}}` or RFC 9457 "
        "problem+json), build it in a single helper or exception handler, and use it from every endpoint.",
        outlier.file, outlier.line, evidence=listing)]
