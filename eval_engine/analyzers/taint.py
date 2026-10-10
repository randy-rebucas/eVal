"""Lightweight taint analysis for Python web code: request data reaching a dangerous sink in the same function.

Sources: ``request.args/form/values/json/data/cookies/headers/files`` (Flask, also via ``.get()`` and
``get_json()``), ``request.GET/POST/COOKIES/META/body`` (Django), ``request.query_params/path_params`` and the
parameters of FastAPI/Flask route handlers (``@app.get(...)``, ``@router.post(...)``, ``@app.route(...)``).

Propagation (intra-procedural, flow-insensitive within a function): assignments, augmented assignments, f-strings,
``+`` / ``%`` / ``.format()``, ``str()``, ``"".join()``, subscripts and string methods of tainted values. Results
of other function calls are *not* tainted, and ``int()``, ``float()``, ``uuid.UUID()``, ``secure_filename()``,
``shlex.quote()``, ``html.escape()`` / ``escape()``, ``os.path.basename()`` and ``urllib.parse.quote()`` sanitize.
Decoders (``base64.b64decode()``, ``unquote()``, ``zlib.decompress()``) and ``.read()`` keep the taint.
The analysis favours precision: it reports a flow only when it can name the source line, the variables it passed
through, and the sink. Flows across functions or modules are not followed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

REQUEST_ATTRS = {"args", "form", "values", "json", "data", "cookies", "headers", "files", "GET", "POST", "COOKIES",
                 "META", "body", "query_params", "path_params", "query_string", "view_args"}
REQUEST_CALLS = {"get_json", "get_data"}
SANITIZERS = {"int", "float", "bool", "UUID", "secure_filename", "quote", "escape", "basename", "abs", "len",
              "quote_plus", "urlencode"}
PROPAGATING_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "replace", "format", "encode", "decode",
                       "split", "get", "getlist", "title", "casefold", "removeprefix", "removesuffix", "read"}
# Decoders whose output is still the attacker's bytes (``pickle.loads(base64.b64decode(cookie))``).
PROPAGATING_FUNCS = {"b64decode", "urlsafe_b64decode", "b32decode", "a2b_base64", "unhexlify", "decompress",
                     "unquote", "unquote_plus"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}
SAFE_PARAM_TYPES = {"int", "float", "bool", "UUID", "date", "datetime", "Decimal"}


@dataclass(frozen=True)
class Sink:
    rule: str
    title: str
    severity: Severity
    cwe: str
    remediation: str


SQL = Sink("taint.sql-injection", "SQL injection: request data reaches a SQL statement", Severity.CRITICAL, "CWE-89",
           "Pass request values as bound parameters (execute(sql, params)) instead of building the SQL string.")
CMD = Sink("taint.command-injection", "Command injection: request data reaches a shell command", Severity.CRITICAL,
           "CWE-78", "Do not use a shell: pass an argument list to subprocess without shell=True, and validate input "
           "against an allow-list.")
CODE = Sink("taint.code-injection", "Code injection: request data reaches eval/exec", Severity.CRITICAL, "CWE-95",
            "Never evaluate request data. Parse it explicitly (json.loads, ast.literal_eval for literals).")
PATH = Sink("taint.path-traversal", "Path traversal: request data selects a file path", Severity.HIGH, "CWE-22",
            "Resolve the path under a fixed base directory and reject anything outside it (werkzeug.utils.safe_join, "
            "or Path.resolve() plus an is_relative_to() check), or map identifiers to files server-side.")
SSRF = Sink("taint.ssrf", "Server-side request forgery: request data chooses an outbound URL", Severity.HIGH,
            "CWE-918", "Allow-list destination hosts and schemes, and block private and link-local addresses.")
SSTI = Sink("taint.template-injection", "Template injection: request data is rendered as a template", Severity.HIGH,
            "CWE-1336", "Render fixed templates and pass request values as context variables.")
REDIRECT = Sink("taint.open-redirect", "Open redirect: request data chooses the redirect target", Severity.MEDIUM,
                "CWE-601", "Redirect only to relative paths on this site, or to an allow-list of URLs.")
DESERIALIZE = Sink("taint.insecure-deserialization", "Insecure deserialization: request data is unpickled",
                   Severity.CRITICAL, "CWE-502", "Never unpickle/unmarshal client data: it executes arbitrary code. "
                   "Accept JSON (or another data-only format) and validate it with a schema; sign server-issued blobs "
                   "with an HMAC and verify before decoding.")
YAML_LOAD = Sink("taint.insecure-yaml-load", "Insecure deserialization: request data is loaded with an unsafe YAML "
                 "loader", Severity.CRITICAL, "CWE-502", "Use yaml.safe_load() (or Loader=yaml.SafeLoader).")
NOSQL = Sink("taint.nosql-injection", "NoSQL injection: request JSON is used in a MongoDB query", Severity.HIGH,
             "CWE-943", "JSON values can be objects such as {\"$ne\": null}: cast each value to str/int (or validate "
             "with a schema such as pydantic) before it goes into a filter, and never pass request data to $where.")
UPLOAD = Sink("taint.upload-path-traversal", "Uploaded file saved under a client-supplied file name", Severity.HIGH,
              "CWE-22", "Never build the destination from the client's file name: generate a server-side name "
              "(uuid4 plus an allow-listed extension) or pass it through werkzeug.utils.secure_filename(), and save "
              "under a fixed upload directory.")

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra", "text", "from_statement"}
SHELL_FUNCS = {"system", "popen"}
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
HTTP_FUNCS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen", "stream"}
HTTP_MODULES = {"requests", "httpx", "urllib", "request", "session", "client", "http", "aiohttp"}
PICKLE_MODULES = {"pickle", "cPickle", "_pickle", "marshal", "dill", "jsonpickle", "shelve", "cloudpickle"}
PICKLE_FUNCS = {"loads", "load", "decode", "Unpickler", "open"}
MONGO_METHODS = {"find", "find_one", "find_one_and_update", "find_one_and_delete", "find_one_and_replace", "update_one",
                 "update_many", "delete_one", "delete_many", "replace_one", "count_documents", "distinct", "aggregate"}
# Only JSON bodies carry objects; query-string and form values reach the handler as strings.
JSON_ORIGINS = ("request.json", "request.get_json", "request.data", "request.body")
NOSQL_CASTS = {"str", "int", "float", "bool", "ObjectId", "escape"}
SAFE_YAML_LOADERS ={"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader", "FullLoader", "CFullLoader"}


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _root(node) -> str:
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


class _Function:
    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef):
        self.func = func
        self.tainted: dict[str, tuple[str, int]] = {}  # var -> (origin description, line)
        self.paths: dict[str, list[str]] = {}  # var -> chain of variable names from the source

    # ---------------------------------------------------------------- taint of an expression
    def source(self, node) -> tuple[str, int] | None:
        """The origin if ``node`` is tainted, else None."""
        if isinstance(node, ast.Attribute):
            if _root(node) == "request" and (node.attr in REQUEST_ATTRS or _has_request_attr(node)):
                return (f"request.{_first_request_attr(node)}", node.lineno)
            return self.source(node.value) if _root(node) in self.tainted else None
        if isinstance(node, ast.Subscript):
            return self.source(node.value)
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        if isinstance(node, ast.JoinedStr):
            return next((s for v in node.values if (s := self.source(v))), None)
        if isinstance(node, ast.FormattedValue):
            return self.source(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return self.source(node.left) or self.source(node.right)
        if isinstance(node, ast.Call):
            fname = _name(node.func)
            if fname in SANITIZERS:
                return None
            if isinstance(node.func, ast.Attribute):
                if _root(node.func) == "request" and (fname in REQUEST_CALLS or _has_request_attr(node.func)):
                    return (f"request.{_first_request_attr(node.func) or fname}()", node.lineno)
                if fname in PROPAGATING_METHODS and self.source(node.func.value):
                    return self.source(node.func.value)
                if fname in ("format", "join"):  # "...".format(x), "".join(xs), os.path.join(base, x)
                    return next((s for a in [*node.args, *(k.value for k in node.keywords)]
                                 if (s := self.source(a))), None)
            if fname in ("str", *PROPAGATING_FUNCS) and node.args:
                return self.source(node.args[0])
            return None
        if isinstance(node, ast.Await):  # body = await request.json() (Starlette/FastAPI)
            return self.source(node.value)
        if isinstance(node, ast.IfExp):
            if _is_validation(node.test):  # `x if is_safe(x) else default` / `x if x.startswith("/") else ...`
                return self.source(node.orelse)
            return self.source(node.body) or self.source(node.orelse)
        if isinstance(node, ast.List | ast.Tuple):
            return next((s for e in node.elts if (s := self.source(e))), None)
        return None

    def chain(self, node) -> list[str]:
        names = [n.id for n in ast.walk(node) if isinstance(n, ast.Name) and n.id in self.tainted]
        if not names:
            return []
        return self.paths.get(names[0], []) + [names[0]]

    # ---------------------------------------------------------------- propagation
    def propagate(self, params: dict[str, int]) -> None:
        for p, line in params.items():
            self.tainted[p] = (f"route parameter '{p}'", line)
            self.paths[p] = []
        assigns = [n for n in ast.walk(self.func) if isinstance(n, ast.Assign | ast.AugAssign | ast.AnnAssign)]
        for _ in range(4):  # fixpoint over a few rounds (loops, out-of-order assignments)
            changed = False
            for node in assigns:
                value = node.value
                if value is None:
                    continue
                origin = self.source(value)
                if isinstance(node, ast.AugAssign) and not origin:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    for name in [n.id for n in ast.walk(t) if isinstance(n, ast.Name)]:
                        if origin and name not in self.tainted:
                            self.tainted[name] = origin
                            self.paths[name] = self.chain(value)
                            changed = True
            if not changed:
                break

    # ---------------------------------------------------------------- sinks
    def _mongo_filter(self, node):
        """The part of a MongoDB filter that carries request JSON (or any request data under ``$where``)."""
        def json_tainted(value) -> bool:
            if isinstance(value, ast.Call) and _name(value.func) in NOSQL_CASTS:
                return False
            origin = self.source(value)
            return bool(origin) and origin[0].startswith(JSON_ORIGINS)

        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values, strict=False):
                if isinstance(k, ast.Constant) and k.value == "$where" and self.source(v):
                    return v
                if json_tainted(v):
                    return v
            return None
        return node if json_tainted(node) else None

    def sinks(self, mongo: bool = False):
        for node in ast.walk(self.func):
            if not isinstance(node, ast.Call):
                continue
            fname, root = _name(node.func), _root(node.func)
            first = node.args[0] if node.args else None
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            hit = None
            sql_call = (fname in SQL_METHODS and isinstance(node.func, ast.Attribute)) \
                or (fname == "text" and root in ("sqlalchemy", "sa", "text"))
            file_call = (fname in ("open", "send_file") and isinstance(node.func, ast.Name)) \
                or (fname in ("remove", "unlink", "rmtree") and root in ("os", "shutil"))
            if sql_call and first is not None:
                hit = (SQL, first)
            elif fname in SHELL_FUNCS and root == "os" and first is not None:
                hit = (CMD, first)
            elif fname in SUBPROCESS_FUNCS and root == "subprocess" and first is not None:
                shell = kw.get("shell")
                if fname in ("getoutput", "getstatusoutput") or (isinstance(shell, ast.Constant) and shell.value):
                    hit = (CMD, first)
            elif isinstance(node.func, ast.Name) and fname in ("eval", "exec") and first is not None:
                hit = (CODE, first)
            elif fname in PICKLE_FUNCS and root in PICKLE_MODULES and first is not None:
                hit = (DESERIALIZE, first)
            elif root == "yaml" and fname in ("load", "load_all", "unsafe_load", "unsafe_load_all") \
                    and first is not None and not _safe_yaml_loader(
                        kw.get("Loader") or (node.args[1] if len(node.args) > 1 else None)):
                hit = (YAML_LOAD, first)
            elif fname == "save" and isinstance(node.func, ast.Attribute) and first is not None:
                hit = (UPLOAD, first)  # FileStorage.save(dst) / storage.save(name, content)
            elif mongo and fname in MONGO_METHODS and isinstance(node.func, ast.Attribute) and first is not None:
                part = self._mongo_filter(first)
                if part is not None:
                    hit = (NOSQL, part)
            elif file_call and first is not None:
                hit = (PATH, first)
            elif fname in HTTP_FUNCS and root in HTTP_MODULES and (first is not None or "url" in kw):
                target = kw.get("url") or (node.args[1] if fname == "request" and len(node.args) > 1 else first)
                hit = (SSRF, target)
            elif fname in ("render_template_string", "Template") and first is not None:
                hit = (SSTI, first)
            elif fname == "redirect" and isinstance(node.func, ast.Name) and first is not None:
                hit = (REDIRECT, first)
            if hit is None:
                continue
            sink, arg = hit
            origin = self.source(arg)
            if origin and not _guarded(self.func, node):
                yield sink, node, origin, self.chain(arg)


VALIDATORS = {"startswith", "endswith", "fullmatch", "match", "isdigit", "isalnum", "isidentifier", "is_safe_url",
              "url_has_allowed_host_and_scheme", "is_relative_to", "_safe_next", "safe_next", "validate"}


def _is_validation(test) -> bool:
    """A condition that checks the value (allow-list membership, prefix/regex checks, URL safety helpers)."""
    for n in ast.walk(test):
        if isinstance(n, ast.Call) and _name(n.func) in VALIDATORS:
            return True
        if isinstance(n, ast.Compare) and any(isinstance(op, ast.In) for op in n.ops):
            return True
    return False


def _guarded(func, call) -> bool:
    """Whether ``call`` sits inside an ``if`` whose condition validates input (see ``_is_validation``)."""
    for node in ast.walk(func):
        if isinstance(node, ast.If) and _is_validation(node.test) and any(c is call for b in node.body
                                                                              for c in ast.walk(b)):
            return True
    return False


def _safe_yaml_loader(loader) -> bool:
    """``Loader=yaml.SafeLoader`` (or FullLoader, which refuses arbitrary Python objects since PyYAML 5.4)."""
    return loader is not None and _name(loader) in SAFE_YAML_LOADERS


def _has_request_attr(node) -> bool:
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        if isinstance(node, ast.Attribute) and node.attr in REQUEST_ATTRS:
            return True
        node = node.func if isinstance(node, ast.Call) else node.value
    return False


def _first_request_attr(node) -> str:
    attrs = []
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        if isinstance(node, ast.Attribute):
            attrs.append(node.attr)
        node = node.func if isinstance(node, ast.Call) else node.value
    known = [a for a in reversed(attrs) if a in REQUEST_ATTRS]
    return known[0] if known else (attrs[-1] if attrs else "")


def _route_params(func) -> dict[str, int]:
    """Handler parameters that carry request data (path/query values), excluding typed numerics and DI."""
    routed = any(isinstance(d, ast.Call) and _name(d.func) in ROUTE_DECORATORS for d in func.decorator_list)
    if not routed:
        return {}
    out = {}
    args = func.args
    defaults = dict(zip([a.arg for a in args.args[len(args.args) - len(args.defaults):]], args.defaults,
                        strict=False))
    for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        ann = ast.unparse(a.annotation) if a.annotation else ""
        default = defaults.get(a.arg)
        if a.arg in ("self", "cls", "request", "db", "session") or ann.split(".")[-1] in SAFE_PARAM_TYPES:
            continue
        if any(x in ann for x in ("Request", "Session", "Depends", "BackgroundTasks", "Response")):
            continue
        if isinstance(default, ast.Call) and _name(default.func) in ("Depends", "Security"):
            continue
        out[a.arg] = func.lineno
    return out


@register
class TaintAnalyzer(Analyzer):
    name = "taint"
    title = "Request data flow (taint analysis)"
    categories = (Category.SECURITY,)
    languages = ("python",)

    def run(self, ctx: AnalyzerContext):
        findings = []
        mongo = "mongodb" in ctx.profile.datastores  # NoSQL sinks only where MongoDB is the data store
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
                analysis = _Function(func)
                analysis.propagate(_route_params(func))
                if not analysis.tainted and not any(_root(n) == "request" for n in ast.walk(func)
                                                    if isinstance(n, ast.Attribute)):
                    continue
                for sink, call, (origin, src_line), chain in analysis.sinks(mongo):
                    via = " → ".join(dict.fromkeys(chain)) if chain else "directly"
                    trace = f"{origin} (line {src_line}) → {via} → {_name(call.func)}() (line {call.lineno})"
                    findings.append(self.finding(
                        ctx, rule=sink.rule, title=sink.title, category=Category.SECURITY, severity=sink.severity,
                        confidence=Confidence.HIGH, kind=FindingKind.CONFIRMED,
                        description=f"Data flow in {func.name}(): {trace}. The value reaches the sink without "
                        f"passing through a recognized sanitizer ({sink.cwe}).",
                        remediation=sink.remediation, file_path=rel, line=call.lineno,
                        evidence=f"Flow: {trace}\n{ctx.snippet(rel, call.lineno, context=1)}",
                        references=[f"https://cwe.mitre.org/data/definitions/{sink.cwe[4:]}.html"]))
        return findings
