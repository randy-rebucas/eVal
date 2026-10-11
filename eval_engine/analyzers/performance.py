"""Performance and scalability risks found statically: blocking calls, missing timeouts, network calls repeated
in loops, nested-loop lookups (O(n·m) joins), inefficient serialization, memory-heavy reads, unbounded caches,
process-local state, in-memory session stores and local-disk uploads.

Nothing is executed or measured. Every finding here is a **static risk** (kind=estimate) unless it is a concrete
misconfiguration such as a missing timeout. Measured performance (benchmarks, load tests, profiling) is not
assessed, and reports say so.

Database access patterns (N+1 queries, unbounded queries, missing pagination) are reported by the database
analyzer, which resolves queries against the schema."""

from __future__ import annotations

import ast
import bisect
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

HTTP_FUNCS = {"get", "post", "put", "patch", "delete", "head", "request", "options"}
HTTP_MODULES = {"requests", "httpx"}
HTTP_CLIENT_FACTORIES = {"requests.Session": "sync", "requests.session": "sync", "httpx.Client": "sync",
                         "httpx.AsyncClient": "async", "aiohttp.ClientSession": "async", "urllib3.PoolManager": "sync"}
RETRY_NAMES = re.compile(r"(?i)^(_+|attempts?|retr(y|ies)|tries|tr(y|ial)|backoff)$")
MAX_RETRY_RANGE = 10
COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
JS_LOOP_START = re.compile(r"\bfor\s*(?:await\s*)?\(|\.(forEach|map|flatMap|reduce|filter|some|every|find)\s*\(")
JS_FETCH_AWAITED = re.compile(r"\bawait\s+(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|ky(?:\.\w+)?|\$fetch|ofetch|"
                              r"superagent\.\w+|needle|undici\.request)\s*\(")
JS_FETCH_ANY = re.compile(r"(?<![\w.$])(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|ky(?:\.\w+)?|\$fetch|ofetch)\s*\(")
JS_INNER_LOOKUP = re.compile(r"([\w$][\w$.\[\]]*)\.(find|filter|findIndex|findLast|findLastIndex|some|every)\(\s*"
                             r"(?:async\s*)?\(?\s*([\w$]+)")
JS_DECL_NAMES = re.compile(r"\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[\w$]+)")
JS_ARROW_PARAMS = re.compile(r"^\s*(?:async\s*)?(?:\(([^)]*)\)|([\w$]+))\s*=>|^\s*(?:async\s+)?function\s*[\w$]*\s*"
                             r"\(([^)]*)\)")
JS_STRING_OR_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/|'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`",
                                  re.S)
JS_BODY_LIMIT = re.compile(r"""\blimit\s*:\s*['"](\d+(?:\.\d+)?)\s*(mb|gb)['"]""", re.I)
FASTIFY_BODY_LIMIT = re.compile(r"\bbodyLimit\s*:\s*([\d_]+(?:\s*\*\s*[\d_]+)*)")
LARGE_BODY_MB = 10
BLOCKING_IN_ASYNC = {"time.sleep", "requests.get", "requests.post", "requests.put", "requests.delete",
                     "requests.request", "urllib.request.urlopen", "subprocess.run", "subprocess.call"}
# Names that suggest data, not configuration: module-level containers with these names written by request handlers.
STATE_NAME = re.compile(r"(?i)(cache|session|store|state|users|items|data|db|records|counter|count|queue|jobs|tokens|"
                        r"carts?|orders|visits|memory|registry|buffer|pending|seen|results|messages|rooms|clients)")
MUTABLE_FACTORIES = {"dict", "list", "set", "defaultdict", "OrderedDict", "Counter", "deque"}
MUTATORS = {"append", "add", "update", "setdefault", "extend", "insert", "__setitem__", "appendleft"}
JS_STATE_DECL = re.compile(r"^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:\{\s*\}|\[\s*\]|new\s+"
                           r"(?:Map|Set)\s*(?:<[^>]*>)?\(\s*\))\s*;?\s*$")


def _call_name(node: ast.Call) -> str:
    parts = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def _is_route(func: ast.AST) -> bool:
    return any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
               and d.func.attr in {"route", "get", "post", "put", "patch", "delete"}
               for d in getattr(func, "decorator_list", []))


def _names(node: ast.AST | None) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} if node is not None else set()


def _loops(tree: ast.AST):
    """(loop, iteration variable names, iterable, body nodes) for every for-loop and comprehension under ``tree``.
    While-loops are left out: they are usually polling, pagination or retries, where repetition is the point."""
    for node in ast.walk(tree):
        if isinstance(node, ast.For | ast.AsyncFor):
            yield node, _names(node.target), node.iter, node.body
        elif isinstance(node, COMPREHENSIONS):
            gens = node.generators
            body = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            body += [c for g in gens for c in g.ifs] + [g.iter for g in gens[1:]]
            yield node, set().union(*(_names(g.target) for g in gens)), gens[0].iter, body


def _is_retry_loop(names: set[str], iterable: ast.AST) -> bool:
    if names and all(RETRY_NAMES.match(n) for n in names):
        return True
    if not (isinstance(iterable, ast.Call) and _call_name(iterable) == "range" and iterable.args):
        return False
    bounds = [a.value for a in iterable.args if isinstance(a, ast.Constant) and isinstance(a.value, int)]
    return len(bounds) == len(iterable.args) and max(bounds) <= MAX_RETRY_RANGE


def _http_clients(tree: ast.AST) -> dict[str, str]:
    """Expressions bound to an HTTP client/session ("session", "self.client") -> "sync" | "async"."""
    clients = {}
    for node in ast.walk(tree):
        pairs = []
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            pairs = [(t, node.value) for t in node.targets]
        elif isinstance(node, ast.With | ast.AsyncWith):
            pairs = [(i.optional_vars, i.context_expr) for i in node.items
                     if i.optional_vars is not None and isinstance(i.context_expr, ast.Call)]
        for target, call in pairs:
            mode = HTTP_CLIENT_FACTORIES.get(_call_name(call))
            if mode and isinstance(target, ast.Name | ast.Attribute):
                clients[ast.unparse(target)] = mode
    return clients


def _blank_js(text: str) -> str:
    """Replace string literals and comments with spaces (newlines kept) so brackets inside them are ignored."""
    return JS_STRING_OR_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _matching(text: str, open_at: int) -> int:
    """Index of the bracket closing the one at ``open_at`` (len(text) if unbalanced)."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = []
    for i in range(open_at, len(text)):
        ch = text[i]
        if ch in pairs:
            stack.append(pairs[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
            if not stack:
                return i
    return len(text)


def _js_params(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_$][\w$]*", text)) - {"const", "let", "var", "of", "in", "await", "async"}


def _js_loop_regions(blank: str):
    """(kind, body start, body end, loop variable names) for for-loops and array-iteration callbacks."""
    for m in JS_LOOP_START.finditer(blank):
        paren = m.end() - 1
        close = _matching(blank, paren)
        if m.group(1) is None:  # for (...) statement
            header = blank[paren + 1:close]
            names = set()
            for decl in JS_DECL_NAMES.finditer(header):
                names |= _js_params(decl.group(1))
            after = close + 1
            while after < len(blank) and blank[after].isspace():
                after += 1
            end = _matching(blank, after) if after < len(blank) and blank[after] == "{" else blank.find("\n", after)
            yield "for", after, len(blank) if end < 0 else end, names
        else:
            body = blank[paren + 1:close]
            params = JS_ARROW_PARAMS.match(body)
            names = _js_params(next((g for g in params.groups() if g), "")) if params else set()
            yield m.group(1), paren + 1, close, names


@register
class PerformanceAnalyzer(Analyzer):
    name = "performance"
    title = "Performance & scalability (static)"
    categories = (Category.PERFORMANCE,)
    languages = ("python", "javascript", "typescript")

    def run(self, ctx: AnalyzerContext):
        findings = []
        for rel in ctx.python_files():
            if is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is not None:
                findings.extend(self._python(ctx, rel, tree))
        for rel in ctx.files_with_suffix(".js", ".ts", ".mjs", ".cjs"):
            if is_test_path(rel):
                continue
            findings.extend(self._js(ctx, rel))
        return findings

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line):
        return self.finding(ctx, rule=rule, title=title, category=Category.PERFORMANCE, severity=sev,
                            confidence=conf, kind=kind, description=desc, remediation=fix, file_path=rel, line=line)

    def _in_process_state(self, ctx, rel, tree):
        """Module-level mutable containers that request handlers write to: per-process state that is lost on
        restart, diverges between workers/replicas, and grows without bound."""
        containers: dict[str, int] = {}
        for stmt in tree.body:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] if isinstance(
                stmt, ast.AnnAssign) else []
            value = getattr(stmt, "value", None)
            mutable = isinstance(value, ast.Dict | ast.List | ast.Set) or (
                isinstance(value, ast.Call) and _call_name(value).rpartition(".")[2] in MUTABLE_FACTORIES)
            for t in targets:
                if mutable and isinstance(t, ast.Name) and STATE_NAME.search(t.id):
                    containers[t.id] = stmt.lineno
        if not containers:
            return []
        out = []
        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            if not _is_route(func):
                continue
            for node in ast.walk(func):
                written = None
                if isinstance(node, ast.Assign | ast.AugAssign):
                    for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                            written = t.value.id
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(
                        node.func.value, ast.Name) and node.func.attr in MUTATORS:
                    written = node.func.value.id
                if written in containers:
                    out.append(self._f(ctx, "performance.in-process-state", f"Request handler stores state in "
                                       f"module-level `{written}`", Severity.MEDIUM, Confidence.MEDIUM,
                                       FindingKind.ESTIMATE,
                                       f"`{written}` (line {containers.pop(written)}) is a process-local container "
                                       f"written by `{func.name}()`. It is lost on restart, each worker/replica sees "
                                       "different data, and it grows without bound — the app cannot scale "
                                       "horizontally. (Static estimate.)",
                                       "Move shared state to a database or cache (Redis, Memcached) with expiry, "
                                       "or use a bounded cache (functools.lru_cache, cachetools.TTLCache) if it is "
                                       "only a per-process cache.", rel, node.lineno))
                    if not containers:
                        return out
        return out

    def _local_uploads(self, ctx, rel, tree):
        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            if not _is_route(func) or "request.files" not in ast.unparse(func):
                continue
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and _call_name(node).endswith(".save"):
                    return [self._f(ctx, "performance.local-file-storage", "Uploaded files saved to the local "
                                    "filesystem", Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                    "Files written to the web server's disk are invisible to other replicas and "
                                    "are lost when the container is replaced, which blocks horizontal scaling. "
                                    "(Fine for a single persistent server.)",
                                    "Store uploads in object storage (S3, GCS, Azure Blob) or a shared volume.",
                                    rel, node.lineno)]
        return []

    def _network_in_loops(self, ctx, rel, tree):
        """HTTP calls made once per item of a collection: N sequential round trips (repeated / excessive API
        calls). Retry loops and un-awaited async calls (gathered concurrently) are left out."""
        clients = _http_clients(tree)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        out, seen = [], set()
        for _, names, iterable, body in _loops(tree):
            if _is_retry_loop(names, iterable):
                continue
            for node in (n for stmt in body for n in ast.walk(stmt)):
                if not isinstance(node, ast.Call) or node.lineno in seen:
                    continue
                name = _call_name(node)
                root, _, attr = name.rpartition(".")
                module_call = (root in HTTP_MODULES and attr in HTTP_FUNCS) or name in ("urllib.request.urlopen",
                                                                                       "urlopen")
                mode = clients.get(root) if attr in HTTP_FUNCS else None
                if not module_call and (mode is None or (mode == "async" and not isinstance(parents.get(node),
                                                                                             ast.Await))):
                    continue
                seen.add(node.lineno)
                it = ast.unparse(iterable)[:60]
                out.append(self._f(ctx, "performance.network-call-in-loop", f"{name}() called once per item of "
                                   f"`{it}`", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                   f"This HTTP call runs inside a loop over `{it}`, so N items cost N sequential "
                                   "round trips. Latency grows linearly with the data, and the remote API sees a "
                                   "burst of calls that can hit rate limits. (Static estimate.)",
                                   "Use a batch/bulk endpoint, cache repeated lookups, or run the calls concurrently "
                                   "with a bounded pool (asyncio.gather with a semaphore, ThreadPoolExecutor).",
                                   rel, node.lineno))
        return out

    def _nested_lookups(self, ctx, rel, tree):
        """Expensive loops: an inner loop scans a second collection for every outer item, matching on a key
        (an O(n·m) join), or tests membership in a list that is rebuilt or searched linearly each time."""
        out, seen = [], set()
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

        def runs_once(node):  # a loop inside `return`/`raise` runs once, not per outer item
            while node in parents:
                node = parents[node]
                if isinstance(node, ast.Return | ast.Raise):
                    return True
                if isinstance(node, ast.stmt):
                    return False
            return False

        def key_access(expr):  # u.id, order["user_id"], getattr-free field reads
            return isinstance(expr, ast.Attribute | ast.Subscript)

        for outer, outer_names, _, outer_body in _loops(tree):
            for inner, inner_names, inner_iter, inner_body in (x for stmt in outer_body for x in _loops(stmt)):
                own = inner_names - outer_names
                if inner is outer or inner.lineno in seen or not own or _names(inner_iter) & outer_names \
                        or (isinstance(inner_iter, ast.Call) and _call_name(inner_iter) == "range") \
                        or runs_once(inner):
                    continue  # child collections, index arithmetic and one-off scans are not joins
                for cmp in (n for part in inner_body for n in ast.walk(part) if isinstance(n, ast.Compare)):
                    if len(cmp.ops) != 1 or not isinstance(cmp.ops[0], ast.Eq | ast.Is):
                        continue
                    pair = (cmp.left, cmp.comparators[0])
                    sides = [_names(s) for s in pair]
                    if all(key_access(s) for s in pair) and any(s & own and not s & outer_names for s in sides) \
                            and any(s & outer_names and not s & own for s in sides):
                        seen.add(inner.lineno)
                        out.append(self._f(ctx, "performance.nested-loop-lookup", "Nested loop searches "
                                           f"`{ast.unparse(inner_iter)[:60]}` for every outer item",
                                           Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                           "For each item of the outer loop, the inner loop scans the whole second "
                                           "collection to find matching keys. Cost is O(n·m): fine for tens of "
                                           "items, slow for thousands. (Static estimate.)",
                                           "Index the inner collection once by key (a dict or "
                                           "collections.defaultdict(list)) and look items up in O(1).",
                                           rel, inner.lineno))
                        break
        for func in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)):
            built = {t.id for n in ast.walk(func) if isinstance(n, ast.Assign) and (
                isinstance(n.value, ast.ListComp) or (isinstance(n.value, ast.Call) and _call_name(n.value) == "list"))
                for t in n.targets if isinstance(t, ast.Name)}
            for _, _, _, body in _loops(func):
                grown = {n.func.value.id for part in body for n in ast.walk(part) if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                         and n.func.attr in ("append", "extend", "insert")}
                for cmp in (n for part in body for n in ast.walk(part) if isinstance(n, ast.Compare)):
                    if cmp.lineno in seen or not any(isinstance(op, ast.In | ast.NotIn) for op in cmp.ops):
                        continue
                    right = cmp.comparators[-1]
                    # A list grown inside the loop is an order-preserving dedupe; only flag fixed lists.
                    if isinstance(right, ast.ListComp) or (isinstance(right, ast.Name) and right.id in built
                                                           and right.id not in grown):
                        seen.add(cmp.lineno)
                        out.append(self._f(ctx, "performance.list-membership-in-loop", "Membership test against a "
                                           f"list inside a loop (`{ast.unparse(right)[:60]}`)", Severity.LOW,
                                           Confidence.MEDIUM, FindingKind.ESTIMATE,
                                           "`x in list` scans the list on every iteration"
                                           + (", and this list is rebuilt each time" if isinstance(right, ast.ListComp)
                                              else "") + ", so the loop costs O(n·m). (Static estimate.)",
                                           "Build a set once before the loop and test membership against it.",
                                           rel, cmp.lineno))
        return out

    def _serialization(self, ctx, rel, tree):
        out, seen = [], set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in ("json.loads", "pickle.loads") and node.args \
                    and isinstance(node.args[0], ast.Call) and _call_name(node.args[0]) in ("json.dumps",
                                                                                         "pickle.dumps"):
                out.append(self._f(ctx, "performance.serialization-roundtrip", f"{_call_name(node)}("
                                   f"{_call_name(node.args[0])}(...)) round trip", Severity.LOW, Confidence.HIGH,
                                   FindingKind.ESTIMATE,
                                   "Serializing an object only to parse it back (usually to copy it) encodes and "
                                   "decodes the whole structure, allocates it twice, and silently changes types "
                                   "(tuples become lists, datetimes fail). (Static estimate.)",
                                   "Use copy.deepcopy, a shallow copy, or avoid the copy; if the goal is JSON-safe "
                                   "data, convert it explicitly once.", rel, node.lineno))
        for _, names, iterable, body in _loops(tree):
            if _is_retry_loop(names, iterable):
                continue
            for node in (n for stmt in body for n in ast.walk(stmt)):
                if isinstance(node, ast.Call) and _call_name(node) in ("copy.deepcopy", "deepcopy") and \
                        node.lineno not in seen:
                    seen.add(node.lineno)
                    out.append(self._f(ctx, "performance.deepcopy-in-loop", "copy.deepcopy() inside a loop",
                                       Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                       "deepcopy walks and reallocates the entire object graph on every iteration; "
                                       "it is one of the slowest ways to copy data in Python. (Static estimate.)",
                                       "Copy only what changes (dict(x), list(x), dataclasses.replace) or restructure "
                                       "to avoid copying per item.", rel, node.lineno))
        return out

    def _memory(self, ctx, rel, tree):
        """Memory-heavy operations: whole files or request bodies loaded at once, caches that never evict."""
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "readlines" \
                    and not node.args and not node.keywords:
                out.append(self._f(ctx, "performance.readlines", ".readlines() loads the whole file into memory",
                                   Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                   "readlines() builds a list of every line before processing starts, so memory "
                                   "grows with the file size. (Static estimate: harmless for small files.)",
                                   "Iterate over the file object directly (`for line in f:`) to stream it.",
                                   rel, node.lineno))
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                params = [a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                          if a.arg not in ("self", "cls")]
                for dec in node.decorator_list:
                    name = _call_name(dec) if isinstance(dec, ast.Call) else ast.unparse(dec)
                    unbounded = name in ("cache", "functools.cache") or (
                        isinstance(dec, ast.Call) and name in ("lru_cache", "functools.lru_cache") and any(
                            k.arg == "maxsize" and isinstance(k.value, ast.Constant) and k.value.value is None
                            for k in dec.keywords))
                    if unbounded and (params or node.args.vararg or node.args.kwarg):
                        out.append(self._f(ctx, "performance.unbounded-cache", f"Unbounded cache on "
                                           f"`{node.name}()`", Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                           "@cache / @lru_cache(maxsize=None) keeps every distinct argument "
                                           "combination forever. With request-derived arguments the process memory "
                                           "grows without limit. (Static estimate.)",
                                           "Set a maxsize (e.g. @lru_cache(maxsize=1024)) or use a TTL cache.",
                                           rel, dec.lineno))
                if _is_route(node):
                    for call in ast.walk(node):
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and \
                                call.func.attr == "read" and not call.args and not call.keywords and \
                                re.search(r"(?i)file|upload|request|stream|body", ast.unparse(call.func.value)):
                            out.append(self._f(ctx, "performance.whole-upload-in-memory", "Request handler reads "
                                               "an entire upload/body into memory", Severity.LOW, Confidence.MEDIUM,
                                               FindingKind.ESTIMATE,
                                               f"`{ast.unparse(call)[:60]}` loads the whole payload at once; a few "
                                               "concurrent large uploads can exhaust worker memory. (Static "
                                               "estimate.)",
                                               "Enforce a maximum upload size and stream the data in chunks "
                                               "(read(65536) in a loop, or stream directly to object storage).",
                                               rel, call.lineno))
        return out

    def _python(self, ctx, rel, tree):
        out = self._in_process_state(ctx, rel, tree) + self._local_uploads(ctx, rel, tree)
        out += self._network_in_loops(ctx, rel, tree) + self._nested_lookups(ctx, rel, tree)
        out += self._serialization(ctx, rel, tree) + self._memory(ctx, rel, tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                root, _, attr = name.rpartition(".")
                if root in ("requests", "httpx") and attr in HTTP_FUNCS and not any(
                        k.arg == "timeout" for k in node.keywords):
                    out.append(self._f(ctx, "performance.http-without-timeout", f"{name}() without a timeout",
                                       Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "Outbound HTTP calls without a timeout can hang a worker indefinitely when "
                                       "the remote end stalls, exhausting the pool under load."
                                       + (" (httpx has a 5s default; set it explicitly.)" if root == "httpx" else ""),
                                       "Pass an explicit timeout (connect, read) and handle timeouts.",
                                       rel, node.lineno))
            if isinstance(node, ast.AsyncFunctionDef):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call) and _call_name(inner) in BLOCKING_IN_ASYNC:
                        out.append(self._f(ctx, "performance.blocking-call-in-async", f"Blocking call "
                                           f"{_call_name(inner)}() inside async function", Severity.MEDIUM,
                                           Confidence.HIGH, FindingKind.CONFIRMED,
                                           "A synchronous call blocks the event loop, stalling every concurrent "
                                           "request on that worker.",
                                           "Use the async equivalent (asyncio.sleep, httpx.AsyncClient) or run it in "
                                           "a thread executor.", rel, inner.lineno))
        return out

    def _js(self, ctx, rel):
        out = []
        text = ctx.read(rel) or ""
        lines = ctx.lines(rel)
        is_server = bool(re.search(r"\b(app|router)\.(get|post|put|patch|delete)\(", text))
        containers = {m.group(1): i for i, ln in enumerate(lines, start=1) if (m := JS_STATE_DECL.match(ln))
                      and STATE_NAME.search(m.group(1))} if is_server else {}
        for i, line in enumerate(lines, start=1):
            if is_server and re.search(r"\b(readFileSync|writeFileSync|execSync|pbkdf2Sync|scryptSync)\(", line):
                out.append(self._f(ctx, "performance.sync-io-in-server", "Synchronous I/O in a server module",
                                   Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                   "Sync APIs block Node's single event loop; if called per request, all clients "
                                   "wait. (Static estimate — it may only run at startup.)",
                                   "Use the async/promise API inside request paths.", rel, i))
            for name in list(containers):
                if i > containers[name] and re.search(rf"\b{re.escape(name)}(\[[^\]]+\]\s*=[^=]|\.(push|set|add)\()",
                                                      line):
                    out.append(self._f(ctx, "performance.in-process-state", f"Server stores state in module-level "
                                       f"`{name}`", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                       f"`{name}` (line {containers[name]}) is process-local. It is lost on restart, "
                                       "differs between cluster workers/replicas, and grows without bound — the app "
                                       "cannot scale horizontally. (Static estimate.)",
                                       "Keep shared state in a database or cache (Redis) with expiry, or use a "
                                       "bounded LRU cache if it is only a per-process cache.", rel, i))
                    del containers[name]
        if re.search(r"""require\(\s*["']express-session["']\s*\)|from\s+["']express-session["']""", text) and \
                re.search(r"\bsession\(\s*\{", text) and not re.search(r"\bstore\s*:", text):
            line = next((i for i, ln in enumerate(lines, 1) if re.search(r"\bsession\(\s*\{", ln)), None)
            out.append(self._f(ctx, "performance.memory-session-store", "express-session uses the default "
                               "in-memory store", Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                               "MemoryStore leaks memory, is not shared between processes, and loses every session "
                               "on restart; express-session documents it as unsuitable for production.",
                               "Configure a shared store (connect-redis, connect-pg-simple, …).", rel, line))
        if re.search(r"\bmulter\(\s*\{\s*dest\s*:|multer\.diskStorage\(", text):
            line = next((i for i, ln in enumerate(lines, 1) if re.search(r"multer\(\s*\{\s*dest|diskStorage", ln)),
                        None)
            out.append(self._f(ctx, "performance.local-file-storage", "Uploaded files saved to the local "
                               "filesystem", Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                               "Uploads written to the server's disk are invisible to other replicas and lost when "
                               "the container is replaced.",
                               "Stream uploads to object storage (S3, GCS, Azure Blob) or a shared volume.", rel, line))
        out += self._js_loops(ctx, rel, text)
        out += self._js_memory(ctx, rel, text, lines, is_server)
        return out

    def _js_loops(self, ctx, rel, text):
        """Network calls per loop item, nested-loop lookups, and JSON round trips."""
        out, seen = [], set()
        blank = _blank_js(text)
        starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]

        def line_of(offset):
            return bisect.bisect_right(starts, offset)

        for kind, start, end, names in _js_loop_regions(blank):
            body = blank[start:end]
            lead = JS_ARROW_PARAMS.match(body) if kind != "for" else None
            own_start = lead.end() if lead else 0
            if kind in ("for", "forEach"):
                pattern = JS_FETCH_AWAITED if kind == "for" else JS_FETCH_ANY
                for m in pattern.finditer(body):
                    line = line_of(start + m.start())
                    if ("net", line) in seen or re.search(r"=>|\bfunction\b|addEventListener\(|setTimeout\(|"
                                                          r"setInterval\(", body[own_start:m.start()]):
                        continue  # inside a nested function or handler: runs later, not once per item
                    seen.add(("net", line))
                    out.append(self._f(ctx, "performance.network-call-in-loop", "HTTP request made once per loop "
                                       "item", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                                       ("Each iteration awaits its own request, so N items cost N sequential round "
                                        "trips." if kind == "for" else
                                        "forEach fires one request per item without awaiting them: N concurrent "
                                        "untracked requests, unhandled rejections, and no back-pressure.")
                                       + " The remote API sees a burst of calls that can hit rate limits. "
                                       "(Static estimate.)",
                                       "Use a batch endpoint or cache, or run requests with bounded concurrency "
                                       "(Promise.all over chunks, p-limit).", rel, line))
            if not names:
                continue
            for m in JS_INNER_LOOKUP.finditer(body):
                receiver, inner = m.group(1), m.group(3)
                root = re.split(r"[.\[]", receiver, maxsplit=1)[0]
                line = line_of(start + m.start())
                if root in names or inner in names or ("lookup", line) in seen:
                    continue
                call_end = _matching(blank, start + m.end(2))
                callback = blank[start + m.end(2):call_end]
                if re.search(r"[!=]==?", callback) and re.search(rf"\b{re.escape(inner)}\b", callback) and any(
                        re.search(rf"(?<![\w$.]){re.escape(n)}\b", callback) for n in names):
                    seen.add(("lookup", line))
                    out.append(self._f(ctx, "performance.nested-loop-lookup", f"`{receiver}.{m.group(2)}()` scans "
                                       "a collection for every outer item", Severity.LOW, Confidence.MEDIUM,
                                       FindingKind.ESTIMATE,
                                       f"Inside a loop, `{receiver}.{m.group(2)}()` searches the whole array to "
                                       "match keys of the current item. Cost is O(n·m): fine for tens of items, "
                                       "slow for thousands. (Static estimate.)",
                                       "Index the inner array once (new Map(arr.map(x => [x.key, x])) or a "
                                       "group-by object) and look items up in O(1).", rel, line))
        for m in re.finditer(r"\bJSON\.parse\(\s*JSON\.stringify\(", blank):
            out.append(self._f(ctx, "performance.serialization-roundtrip", "JSON.parse(JSON.stringify(...)) deep "
                               "copy", Severity.LOW, Confidence.HIGH, FindingKind.ESTIMATE,
                               "Copying through JSON serializes and re-parses the whole object, and silently drops "
                               "or changes values (Dates become strings, undefined/Map/Set are lost). "
                               "(Static estimate.)",
                               "Use structuredClone(), a spread copy for shallow data, or avoid the copy.",
                               rel, line_of(m.start())))
        return out

    def _js_memory(self, ctx, rel, text, lines, is_server):
        out = []
        for i, ln in enumerate(lines, start=1):
            m = JS_BODY_LIMIT.search(ln)
            mb = (float(m.group(1)) * (1024 if m.group(2).lower() == "gb" else 1)) if m else 0
            if not m and (fm := FASTIFY_BODY_LIMIT.search(ln)):
                value = 1
                for part in fm.group(1).replace("_", "").split("*"):
                    value *= int(part.strip() or 1)
                mb = value / (1024 * 1024)
            if mb >= LARGE_BODY_MB and re.search(r"(?i)json|urlencoded|raw|text|bodyParser|bodyLimit", ln):
                out.append(self._f(ctx, "performance.large-body-limit", f"Request body limit raised to "
                                   f"{mb:g} MB", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                   "Body parsers buffer the whole body in memory before the handler runs. A large "
                                   "limit lets a handful of concurrent requests exhaust the process's memory.",
                                   "Keep JSON/form limits small (the default 100kb–1MB) and stream large uploads "
                                   "(multipart streaming to object storage) instead.", rel, i))
        if is_server and not re.search(r"(?i)maxBytes|max_?(?:body_?)?size|(?:byteLength|length|size|received)\s*>",
                                       text):
            for i, ln in enumerate(lines, start=1):
                if re.search(r"""\.on\(\s*['"]data['"]""", ln) and re.search(
                        r"\.push\(\s*chunk|\+=\s*chunk|Buffer\.concat", text):
                    out.append(self._f(ctx, "performance.request-buffered-in-memory", "Request body buffered in "
                                       "memory without a size limit", Severity.MEDIUM, Confidence.MEDIUM,
                                       FindingKind.ESTIMATE,
                                       "Chunks are accumulated until the request ends, with no maximum size: one "
                                       "large or slow request can consume unbounded memory. (Static estimate.)",
                                       "Enforce a maximum size and abort the request when it is exceeded, or use a "
                                       "body parser with a limit / stream the data to its destination.", rel, i))
                    break
        return out
