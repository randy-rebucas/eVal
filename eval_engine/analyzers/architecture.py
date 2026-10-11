"""Architecture: the module import graph (Python + relative JS/TS imports) and what it says about structure.

Checks, all static:

* dependency cycles between modules and between packages, excessive fan-out (coupling);
* dependency direction: lower layers (data access, services) importing request handlers or higher layers;
* service boundaries: deployable units (directories with their own manifest) importing each other's code, and
  feature packages reaching into another feature's route handlers or repositories;
* request handlers that hold business logic or talk to the database directly, files that mix HTTP routes with
  persistence models, and an application with handlers but no service layer (separation of concerns);
* database access scattered across many modules outside the data and service layers;
* oversized modules and packages, and a flat project layout;
* the same business logic implemented more than once (Python functions with an identical structure once
  variable names are ignored; verbatim copies are reported by the maintainability analyzer);
* configuration read ad hoc across the codebase, or around a central settings module.

Layers are inferred: a *controller* is a file that defines HTTP routes; *service* and *data* layers come from file
and directory names (``services/``, ``user_service.py``, ``repositories/``, ``models.py``…). The import graph is
also exposed via ``build_import_graph`` for future knowledge-graph features.
"""

from __future__ import annotations

import ast
import hashlib
import posixpath
import re
from collections import defaultdict

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .maintainability import cyclomatic_complexity
from .registry import register

FAN_OUT_LIMIT = 25
CONFIG_SPRAWL_FILES = 12
CONFIG_BYPASS_FILES = 5           # env reads outside an existing central settings module
OVERSIZED_DEFINITIONS = 40        # top-level functions/classes (Python) or exports (JS/TS) in one module
OVERSIZED_PACKAGE_FILES = 40      # source files directly inside one directory
FLAT_ROOT_FILES = 15              # source files at the repository root
HANDLER_COMPLEXITY = 10
HANDLER_STATEMENTS = 40
HANDLER_JS_LINES = 60
NO_SERVICE_LAYER_HANDLERS = 4     # controller modules that query the database, with no service layer anywhere
SCATTERED_DATA_ACCESS_FILES = 6
SCATTERED_DATA_ACCESS_DIRS = 3
DUPLICATE_MIN_STATEMENTS = 6
MAX_PER_RULE = 30

JS_IMPORT = re.compile(
    r"""(?:import\s[^'"]*?from\s*|import\s*\(\s*|require\s*\(\s*|export\s[^'"]*?from\s*)"""
    r"""["'](\.{1,2}/[^"']+)["']"""
)
JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
SOURCE_EXTS = (".py", *JS_EXTS)
SQL_IN_HANDLER = re.compile(
    r"(?is)\b(execute|raw|query)\s*\(\s*[fFrRbB]?[\"'`](\s*select|\s*insert|\s*update|\s*delete)"
)

# --------------------------------------------------------------------------------------------- what a file does
ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}
PY_ROUTE = re.compile(r"^\s*@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\(", re.M)
DJANGO_VIEW = re.compile(r"^\s*(?:async\s+)?def\s+\w+\(\s*request\b|^class\s+\w+\([^)]*(?:View|ViewSet|APIView)\b",
                         re.M)
JS_ROUTE = re.compile(r"\b(?:app|router|server|api|\w+Router)\.(?:get|post|put|patch|delete|all)\(\s*[\"'`]/")
JS_INLINE_HANDLER = re.compile(
    r"\b(?:app|router|server|api|\w+Router)\.(get|post|put|patch|delete|all)\(\s*[\"'`]([^\"'`\n]+)[\"'`]"
    r"[^\n]*?(?:=>|function\s*\w*\s*\([^)]*\))\s*\{")
NEST_CONTROLLER = re.compile(r"@Controller\(")
NEXT_HANDLER = re.compile(r"^export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|"
                          r"^export\s+default\s+(?:async\s+)?function\s+handler\b", re.M)
JS_DECISIONS = re.compile(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?\?|\?(?![.?:])")

PY_DATA_ACCESS = re.compile(
    r"\bdb\.session\.\w+|\bsession\.(?:query|execute|add|add_all|delete|commit|scalars?|get)\(|"
    r"\b[A-Z]\w*\.query\.(?:filter|filter_by|get|get_or_404|all|first|order_by|join)\b|"
    r"\.objects\.(?:filter|get|all|create|exclude|update|delete|raw|aggregate|annotate|get_or_create|"
    r"update_or_create|select_related|prefetch_related|values|bulk_create)\(|"
    r"\bcursor\.execute|\b(?:conn|connection|engine)\.execute\(|"
    r"\b\w+\.(?:find_one|insert_one|insert_many|update_one|update_many|delete_one|delete_many)\(")
JS_DATA_ACCESS = re.compile(
    r"\bprisma\.\w+\.(?:find\w*|create\w*|update\w*|delete\w*|upsert|count|aggregate|groupBy)\(|"
    r"\bprisma\.\$(?:queryRaw|executeRaw)|"
    r"\b(?:pool|db|client|connection|knex|sql|pg)\.(?:query|execute)\(|\bknex\(\s*[\"'`]\w+|"
    r"\bgetRepository\(|\.createQueryBuilder\(|\bsupabase\.from\(|"
    r"\b(?!(?:Object|Array|Promise|Reflect|Math|JSON|Date|Map|Set|WeakMap|Symbol|Number|String|Boolean|Buffer|URL|"
    r"Error|React|Intl)\b)[A-Z]\w*\.(?:find|findOne|findById|findAll|findByPk|findOneAndUpdate|findByIdAndUpdate|"
    r"updateOne|updateMany|deleteOne|deleteMany|countDocuments|bulkCreate)\(")
PY_MODEL_CLASS = re.compile(r"^class\s+\w+\(\s*(?:db\.Model|models\.Model|Base\s*[,)]|DeclarativeBase|"
                            r"SQLModel\b[^)]*table\s*=\s*True|(?:me\.|mongoengine\.)?Document\s*[,)])", re.M)
JS_MODEL = re.compile(r"\bmongoose\.model\(|\bnew\s+(?:mongoose\.)?Schema\(|\bsequelize\.define\(|@Entity\(")
ENV_READ = re.compile(r"os\.environ|os\.getenv|process\.env|import\.meta\.env")

# --------------------------------------------------------------------------------------------- naming conventions
SERVICE_NAMES = {"service", "services", "domain", "usecase", "usecases", "interactor", "interactors", "business",
                 "logic"}
DATA_NAMES = {"repository", "repositories", "repo", "repos", "dal", "dao", "daos", "persistence", "persist", "db",
              "database", "models", "model", "entities", "entity"}
REPOSITORY_NAMES = DATA_NAMES - {"models", "model", "entities", "entity"}
# "repository" also names source-code repositories (GitHub, git): only the repository *pattern* is a data layer.
AMBIGUOUS_DATA_NAMES = {"repository", "repositories", "repo", "repos"}
REPOSITORY_PATTERN = re.compile(r"\b(?:class|const|let|var)\s+\w*(?:Repository|Repo|Dao|DAO)\b")
CONFIG_NAMES = {"config", "configuration", "settings", "env", "conf", "environment"}
SHARED_NAMES = {"common", "shared", "utils", "util", "lib", "libs", "core", "helpers", "support", "base",
                "components", "types", "config", "settings"}
EXEMPT_DIRS = {"migrations", "alembic", "scripts", "bin", "seeds", "seed", "management", "fixtures"}
UNIT_MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "setup.py", "go.mod", "Dockerfile"}
LAYER_RANK = {"data": 0, "service": 1, "controller": 2}


def _tokens(name: str) -> list[str]:
    """``userService`` / ``user_service`` / ``user.service`` → ``['user', 'service']``."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [t for t in re.split(r"[._\-]+", name.lower()) if t]


def _stem(rel: str) -> str:
    name = rel.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[0] if "." in name else name


def _dirs(rel: str) -> list[str]:
    return rel.split("/")[:-1]


def _named(rel: str, names: set[str]) -> bool:
    """File name tokens first, then the enclosing directories, nearest first."""
    if any(t in names for t in _tokens(_stem(rel))):
        return True
    return any(d.lower() in names for d in reversed(_dirs(rel)))


def _is_exempt(rel: str) -> bool:
    return is_test_path(rel) or any(d.lower() in EXEMPT_DIRS for d in _dirs(rel))


def _ancestor(a: str, b: str) -> bool:
    """True when directory ``a`` is ``b`` or contains it ('' is the repository root)."""
    return a == b or a == "" or b.startswith(a + "/")


# --------------------------------------------------------------------------------------------- import graph
def _python_module_map(files: list[str]) -> dict[str, list[str]]:
    """Map dotted module names to the files that could provide them.

    A file's import name starts at its top-most enclosing *package* (directories with ``__init__.py``), so
    ``src/app/models.py`` with ``src/app/__init__.py`` is ``app.models``. Top-level scripts map to their own
    name. The full path form is also registered for repos that run from the root. A name can map to several
    files (two services that each have an ``app`` package); ``_resolve`` picks the one nearest the importer.
    """
    file_set = set(files)
    mapping: dict[str, list[str]] = defaultdict(list)
    for rel in files:
        if not rel.endswith(".py"):
            continue
        parts = rel[:-3].split("/")
        start = len(parts) - 1
        while start > 0 and "/".join(parts[:start]) + "/__init__.py" in file_set:
            start -= 1
        names = [parts[start:], parts]
        for name_parts in names:
            if name_parts and name_parts[-1] == "__init__":
                name_parts = name_parts[:-1]
            if name_parts and rel not in mapping[".".join(name_parts)]:
                mapping[".".join(name_parts)].append(rel)
    return mapping


def _shared_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a.split("/"), b.split("/"), strict=False):
        if x != y:
            break
        n += 1
    return n


def _resolve(modmap: dict[str, list[str]], name: str, importer: str) -> str | None:
    candidates = modmap.get(name)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    return max(candidates, key=lambda c: _shared_prefix(c, importer))


def _resolve_relative(rel: str, module: str | None, level: int) -> str:
    pkg = rel[:-3].split("/")
    pkg = pkg[:-1] if pkg[-1] != "__init__" else pkg[:-1]
    base = pkg[: len(pkg) - (level - 1)] if level > 1 else pkg
    return ".".join([*base, *(module.split(".") if module else [])])


def build_import_graph(ctx: AnalyzerContext) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    py_files = [f for f in ctx.python_files() if not is_test_path(f)]
    modmap = _python_module_map(py_files)
    for rel in py_files:
        tree = ctx.python_ast(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = _resolve_relative(rel, node.module, node.level) if node.level else (node.module or "")
                # `from pkg import mod` imports the submodule when one exists; otherwise a name from pkg, which is
                # an edge to pkg itself. (Counting pkg/__init__.py for submodule imports too would turn every
                # package that re-exports its modules into a cycle with any module importing a sibling.)
                names_from_base = False
                for a in node.names:
                    sub = _resolve(modmap, f"{base}.{a.name}", rel) if a.name != "*" else None
                    if sub is None:
                        names_from_base = True
                    else:
                        targets.append(f"{base}.{a.name}")
                if names_from_base:
                    targets.append(base)
            for t in targets:
                dest = _resolve(modmap, t, rel)
                if dest and dest != rel:
                    graph[rel].add(dest)
    js_files = [f for f in ctx.files_with_suffix(*JS_EXTS) if not is_test_path(f)]
    js_set = set(js_files)
    for rel in js_files:
        for m in JS_IMPORT.finditer(ctx.read(rel) or ""):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), m.group(1)))
            candidates = [target] + [target + e for e in JS_EXTS] + [f"{target}/index{e}" for e in JS_EXTS]
            for c in candidates:
                if c in js_set and c != rel:
                    graph[rel].add(c)
                    break
    return graph


def strongly_connected(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan's algorithm (iterative). Returns components with more than one node."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    nodes = set(graph) | {d for deps in graph.values() for d in deps}
    for root in sorted(nodes):
        if root in index:
            continue
        work = [(root, iter(sorted(graph.get(root, ()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(sorted(graph.get(nxt, ())))))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                if len(comp) > 1:
                    result.append(sorted(comp))
    return result


# --------------------------------------------------------------------------------------------- helpers
def _js_block(text: str, start: int, limit: int = 20000) -> str | None:
    """The ``{...}`` block opening at ``text[start]``, skipping strings and comments (best effort)."""
    depth, i, quote = 0, start, None
    end = min(len(text), start + limit)
    while i < end:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = end if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = end if j < 0 else j + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return None


def _is_route_handler(func: ast.FunctionDef | ast.AsyncFunctionDef, django_views: bool) -> bool:
    for d in func.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_METHODS and isinstance(d, ast.Call):
            return True
    if django_views:
        args = [a.arg for a in func.args.args]
        return bool(args) and (args[0] == "request" or (args[0] == "self" and args[1:2] == ["request"]))
    return False


class _Anonymize(ast.NodeTransformer):
    """Drop local names so ``total = price * qty`` and ``amount = cost * n`` compare equal."""

    def visit_Name(self, node):
        return ast.copy_location(ast.Name(id="_", ctx=node.ctx), node)

    def visit_arg(self, node):
        node.arg, node.annotation = "_", None
        return node


_LOGIC = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.BinOp, ast.Compare, ast.BoolOp)


def _body(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = func.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]  # docstring
    return body


@register
class ArchitectureAnalyzer(Analyzer):
    name = "architecture"
    title = "Architecture & module structure"
    categories = (Category.ARCHITECTURE,)

    def applicable(self, ctx: AnalyzerContext):
        if not (ctx.languages.has("python") or any(ctx.languages.has(x) for x in ("javascript", "typescript"))):
            return "import-graph analysis supports Python and JavaScript/TypeScript"
        return None

    def run(self, ctx: AnalyzerContext):
        graph = build_import_graph(ctx)
        sources = [f for f in ctx.files_with_suffix(*SOURCE_EXTS) if not is_test_path(f)]
        controllers = {f for f in sources if self._is_controller(ctx, f)}
        layers = {f: self._layer(ctx, f, controllers) for f in sources}
        findings = []
        module_cycles = strongly_connected(graph)
        findings.extend(self._cycles(ctx, module_cycles))
        findings.extend(self._package_cycles(ctx, graph, module_cycles))
        findings.extend(self._fan_out(ctx, graph))
        findings.extend(self._direction(ctx, graph, layers))
        findings.extend(self._boundaries(ctx, graph, layers, controllers))
        findings.extend(self._handlers(ctx, sources, controllers, layers))
        findings.extend(self._scattered_data_access(ctx, sources, layers))
        findings.extend(self._oversized(ctx, sources))
        findings.extend(self._duplicated_logic(ctx))
        findings.extend(self._config(ctx))
        return findings

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel="", line=None, evidence=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.ARCHITECTURE, severity=sev,
                            confidence=conf, kind=kind, description=desc, remediation=fix, file_path=rel, line=line,
                            evidence=evidence)

    # ------------------------------------------------------------------ layers
    @staticmethod
    def _is_controller(ctx, rel: str) -> bool:
        text = ctx.read(rel) or ""
        if rel.endswith(".py"):
            if PY_ROUTE.search(text):
                return True
            return (_stem(rel) == "views" or "views" in _dirs(rel)) and bool(DJANGO_VIEW.search(text))
        if JS_ROUTE.search(text) or NEST_CONTROLLER.search(text):
            return True
        is_next_route = _stem(rel) == "route" or "/pages/api/" in f"/{rel}"
        return is_next_route and bool(NEXT_HANDLER.search(text))

    @staticmethod
    def _layer(ctx, rel: str, controllers: set[str]) -> str:
        if rel in controllers:
            return "controller"
        names = _tokens(_stem(rel)) + [d.lower() for d in reversed(_dirs(rel))]
        for name in names:
            if name in SERVICE_NAMES:
                return "service"
            if name in DATA_NAMES:
                if name in AMBIGUOUS_DATA_NAMES and not REPOSITORY_PATTERN.search(ctx.read(rel) or ""):
                    continue
                return "data"
        return ""

    # ------------------------------------------------------------------ coupling and cycles
    def _cycles(self, ctx, cycles):
        return [self._f(
            ctx, "architecture.import-cycle", f"Circular dependency between {len(comp)} modules",
            Severity.MEDIUM if len(comp) > 2 else Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
            "These modules import each other (directly or transitively): " + " → ".join(comp[:12])
            + ". Cycles couple modules so they cannot be understood, tested, or changed independently, and in "
            "Python can cause partially-initialized-module import errors.",
            "Move shared code into a lower-level module, invert the dependency with an interface, or merge modules "
            "that are not truly separate.", comp[0], evidence="cycle: " + ", ".join(comp[:12]))
            for comp in cycles[:MAX_PER_RULE]]

    def _package_cycles(self, ctx, graph, module_cycles):
        """Directories that depend on each other although no single module cycle explains it."""
        dir_graph: dict[str, set[str]] = defaultdict(set)
        examples: dict[tuple[str, str], tuple[str, str]] = {}
        for src, deps in graph.items():
            a = posixpath.dirname(src)
            for dest in deps:
                b = posixpath.dirname(dest)
                if _ancestor(a, b) or _ancestor(b, a):
                    continue  # a package and its own sub-packages
                dir_graph[a].add(b)
                examples.setdefault((a, b), (src, dest))
        explained = {frozenset(posixpath.dirname(m) for m in comp) for comp in module_cycles}
        out = []
        for comp in strongly_connected(dir_graph):
            if frozenset(comp) in explained:
                continue
            edges = [f"{s} → {d}" for (a, b), (s, d) in sorted(examples.items()) if a in comp and b in comp]
            out.append(self._f(
                ctx, "architecture.package-cycle", f"Packages depend on each other: {', '.join(comp[:4])}",
                Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                f"The packages {', '.join(comp[:8])} import from each other, so dependencies between them run in "
                "both directions. Neither can be reused, tested, or extracted without the other, and the module-"
                "level graph is one refactor away from an import cycle.",
                "Decide which package is lower-level and move the code the other one needs into it (or into a "
                "shared package), so dependencies point one way.", examples[next(
                    k for k in sorted(examples) if k[0] in comp and k[1] in comp)][0],
                evidence="; ".join(edges[:8])))
            if len(out) >= MAX_PER_RULE:
                break
        return out

    def _fan_out(self, ctx, graph):
        return [self._f(
            ctx, "architecture.high-fan-out", f"Module depends on {len(deps)} internal modules", Severity.LOW,
            Confidence.HIGH, FindingKind.CONFIRMED,
            f"{rel} imports {len(deps)} other project modules (limit {FAN_OUT_LIMIT}); it is likely a 'god module' "
            "that changes for many reasons.", "Split responsibilities; depend on narrower interfaces.", rel)
            for rel, deps in sorted(graph.items()) if len(deps) > FAN_OUT_LIMIT]

    # ------------------------------------------------------------------ dependency direction
    def _direction(self, ctx, graph, layers):
        out = []
        for src, deps in sorted(graph.items()):
            src_layer = layers.get(src, "")
            if src_layer not in ("data", "service"):
                continue
            upward = sorted(d for d in deps if layers.get(d) and LAYER_RANK[layers[d]] > LAYER_RANK[src_layer])
            if not upward:
                continue
            to_controller = any(layers[d] == "controller" for d in upward)
            names = ", ".join(f"{d} ({layers[d]})" for d in upward[:6])
            out.append(self._f(
                ctx, "architecture.dependency-direction",
                f"{src_layer.capitalize()}-layer module imports a higher layer", Severity.MEDIUM if to_controller
                else Severity.LOW, Confidence.MEDIUM, FindingKind.CONFIRMED,
                f"{src} is in the {src_layer} layer but imports {names}. Dependencies should point from request "
                "handlers to services to data access, never back up: otherwise the lower layer cannot be used (or "
                "tested) without the web framework and the modules above it.",
                "Move the shared code down into the lower layer, or pass what the lower layer needs in as an "
                "argument or callback instead of importing it.", src,
                evidence=f"{src} → " + ", ".join(upward[:6])))
            if len(out) >= MAX_PER_RULE:
                break
        return out

    # ------------------------------------------------------------------ service boundaries
    def _boundaries(self, ctx, graph, layers, controllers):
        units = sorted({posixpath.dirname(f) for f in ctx.files_named(*UNIT_MANIFESTS)} - {""},
                       key=len, reverse=True)

        def unit_of(rel):
            return next((u for u in units if rel.startswith(u + "/")), "")

        service_files = [f for f, layer in layers.items() if layer == "service"]
        out, seen = [], set()
        for src, deps in sorted(graph.items()):
            for dest in sorted(deps):
                ua, ub = unit_of(src), unit_of(dest)
                if ua and ub and ua != ub and not (_ancestor(ua, ub) or _ancestor(ub, ua)):
                    if (src, ub) in seen:
                        continue
                    seen.add((src, ub))
                    out.append(self._f(
                        ctx, "architecture.cross-service-import", f"{ua} imports code from the {ub} service",
                        Severity.MEDIUM, Confidence.MEDIUM, FindingKind.CONFIRMED,
                        f"{ua} and {ub} each have their own manifest, so they are built and deployed separately, "
                        f"but {src} imports {dest} by path. The two services now share code and must be released "
                        "together, and a change inside one silently breaks the other.",
                        "Talk to the other service through its API, or move the shared code into a versioned "
                        "package that both declare as a dependency.", src, evidence=f"{src} → {dest}"))
                    continue
                da, db = _dirs(src), _dirs(dest)
                i = _shared_prefix("/".join(da), "/".join(db)) if da and db else 0
                if not (len(da) > i and len(db) > i):
                    continue  # same package, or one contains the other
                fa, fb = da[i], db[i]
                if fa.lower() in SHARED_NAMES or fb.lower() in SHARED_NAMES:
                    continue
                feature = "/".join(db[:i + 1])
                if dest in controllers:
                    why = (f"{dest} holds the {fb} feature's HTTP route handlers. Importing it from {fa} couples "
                           "the two features through their transport layer.")
                elif (layers.get(dest) == "data" and any(t in REPOSITORY_NAMES for t in _tokens(_stem(dest)))
                      and any(f.startswith(feature + "/") for f in service_files)):
                    why = (f"{dest} is the {fb} feature's data access. {fb} has a service layer, and {src} "
                           "bypasses it, so the rules that service enforces are skipped.")
                else:
                    continue
                if (src, feature) in seen:
                    continue
                seen.add((src, feature))
                out.append(self._f(
                    ctx, "architecture.boundary-violation", f"{fa} reaches into the internals of {fb}",
                    Severity.LOW, Confidence.MEDIUM, FindingKind.CONFIRMED, why,
                    f"Depend on {fb}'s service (public) API instead, or move what both features need into a shared "
                    "module.", src, evidence=f"{src} → {dest}"))
            if len(out) >= MAX_PER_RULE:
                break
        return out[:MAX_PER_RULE]

    # ------------------------------------------------------------------ handlers and separation of concerns
    def _handlers(self, ctx, sources, controllers, layers):
        out, querying = [], []
        fat = 0
        for rel in sorted(controllers):
            text = ctx.read(rel) or ""
            if rel.endswith(".py"):
                fat_found = self._fat_python_handlers(ctx, rel)
            else:
                fat_found = self._fat_js_handlers(ctx, rel, text)
            for f in fat_found:
                if fat < MAX_PER_RULE:
                    out.append(f)
                    fat += 1
            access = self._data_access(rel, text)
            if access:
                querying.append(rel)
                rule, title = (("architecture.sql-in-handlers", "Raw SQL inside request handler module")
                               if access[0] == "sql" else
                               ("architecture.data-access-in-handlers", "Request handler module queries the "
                                "database directly"))
                out.append(self._f(
                    ctx, rule, title, Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    "HTTP route definitions and database queries live in the same module, coupling transport, "
                    "business logic, and persistence: the logic cannot be reused from a job or CLI, and testing it "
                    "needs both an HTTP client and a database.",
                    "Move data access into a repository/service layer that handlers call.", rel, access[1]))
            m = (PY_MODEL_CLASS if rel.endswith(".py") else JS_MODEL).search(text)
            if m:
                out.append(self._f(
                    ctx, "architecture.mixed-concerns", "Route handlers and database models in the same module",
                    Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                    f"{rel} defines HTTP routes and persistence models together. The data model cannot be imported "
                    "by jobs, scripts, or other features without also importing (and registering) the web routes.",
                    "Move the models into a models/data module and import them from the routes.", rel,
                    text[: m.start()].count("\n") + 1))
        has_service_layer = any(layer == "service" for layer in layers.values())
        if len(querying) >= NO_SERVICE_LAYER_HANDLERS and not has_service_layer:
            out.append(self._f(
                ctx, "architecture.no-service-layer", f"No service layer: {len(querying)} handler modules query "
                "the database", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                "Request handlers talk to the database directly and no service or use-case layer exists, so "
                "business rules are spread across HTTP handlers and duplicated wherever they are needed again.",
                "Introduce a service layer (e.g. services/ or <feature>/services.py) that owns the business rules "
                "and data access, and keep handlers to parsing input and shaping responses.", querying[0],
                evidence=", ".join(querying[:10])))
        return out

    def _fat_python_handlers(self, ctx, rel):
        tree = ctx.python_ast(rel)
        if tree is None:
            return []
        django = _stem(rel) == "views" or "views" in _dirs(rel)
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or not _is_route_handler(node, django):
                continue
            cc = cyclomatic_complexity(node)
            statements = sum(isinstance(n, ast.stmt) for n in ast.walk(node)) - 1
            if cc >= HANDLER_COMPLEXITY or statements >= HANDLER_STATEMENTS:
                out.append(self._fat(ctx, rel, node.name, node.lineno, f"complexity {cc}, {statements} statements"))
        return out

    def _fat_js_handlers(self, ctx, rel, text):
        out = []
        for m in JS_INLINE_HANDLER.finditer(text):
            block = _js_block(text, m.end() - 1)
            if not block:
                continue
            cc = 1 + len(JS_DECISIONS.findall(block))
            lines = len([ln for ln in block.splitlines() if ln.strip()])
            if cc >= HANDLER_COMPLEXITY or lines >= HANDLER_JS_LINES:
                line = text[: m.start()].count("\n") + 1
                out.append(self._fat(ctx, rel, f"{m.group(1).upper()} {m.group(2)}", line,
                                     f"complexity {cc}, {lines} lines"))
        return out

    def _fat(self, ctx, rel, name, line, measure):
        return self._f(
            ctx, "architecture.fat-controller", f"Business logic inside route handler {name}", Severity.LOW,
            Confidence.MEDIUM, FindingKind.CONFIRMED,
            f"The handler {name} ({measure}) does more than translate an HTTP request into a call and a response. "
            "Business rules written inside handlers cannot be reused by jobs, CLIs, or other endpoints and are "
            "only testable through HTTP.",
            "Move the decision-making into a service function that takes plain arguments; keep the handler to "
            "input parsing, one service call, and response shaping.", rel, line,
            evidence=f"{rel}:{line} {name}: {measure}")

    @staticmethod
    def _data_access(rel: str, text: str) -> tuple[str, int] | None:
        m = SQL_IN_HANDLER.search(text)
        kind = "sql"
        if not m:
            m = (PY_DATA_ACCESS if rel.endswith(".py") else JS_DATA_ACCESS).search(text)
            kind = "orm"
        return (kind, text[: m.start()].count("\n") + 1) if m else None

    def _scattered_data_access(self, ctx, sources, layers):
        """Direct database access outside the data and service layers (handlers, utils, tasks, …)."""
        hits = []
        for rel in sources:
            if layers.get(rel) in ("data", "service") or _is_exempt(rel) or _named(rel, CONFIG_NAMES):
                continue
            access = self._data_access(rel, ctx.read(rel) or "")
            if access:
                hits.append((rel, access[1]))
        dirs = {posixpath.dirname(rel) for rel, _ in hits}
        if len(hits) < SCATTERED_DATA_ACCESS_FILES or len(dirs) < SCATTERED_DATA_ACCESS_DIRS:
            return []
        return [self._f(
            ctx, "architecture.scattered-data-access",
            f"Database accessed directly from {len(hits)} modules in {len(dirs)} packages", Severity.LOW,
            Confidence.MEDIUM, FindingKind.POTENTIAL,
            "Queries are issued from modules outside any data-access or service layer. Schema changes, query "
            "tuning, tenancy filters, and transactions have no single owner, and each call site must be found and "
            "changed by hand.",
            "Route data access through repositories or services that own each table/collection; let other modules "
            "call those.", hits[0][0], hits[0][1],
            evidence=", ".join(f"{r}:{ln}" for r, ln in hits[:12]))]

    # ------------------------------------------------------------------ size and layout
    def _oversized(self, ctx, sources):
        out = []
        for rel in sources:
            if _is_exempt(rel):
                continue
            if rel.endswith(".py"):
                tree = ctx.python_ast(rel)
                if tree is None:
                    continue
                count = sum(isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) for n in tree.body)
                what = "top-level functions and classes"
            else:
                count = len(re.findall(r"^export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var|"
                                       r"interface|type|enum)\b", ctx.read(rel) or "", re.M))
                what = "exports"
            if count >= OVERSIZED_DEFINITIONS:
                out.append(self._f(
                    ctx, "architecture.oversized-module", f"Module defines {count} {what}", Severity.LOW,
                    Confidence.HIGH, FindingKind.CONFIRMED,
                    f"{rel} defines {count} {what} (limit {OVERSIZED_DEFINITIONS}). A module this broad has many "
                    "unrelated reasons to change, and everything that imports any part of it depends on all of it.",
                    "Split it into cohesive modules grouped by responsibility, and re-export from a package if "
                    "callers need a stable import path.", rel, evidence=f"{rel}: {count} {what}"))
        per_dir: dict[str, list[str]] = defaultdict(list)
        for rel in sources:
            if not _is_exempt(rel):
                per_dir[posixpath.dirname(rel)].append(rel)
        root = per_dir.pop("", [])
        if len(root) >= FLAT_ROOT_FILES:
            out.append(self._f(
                ctx, "architecture.flat-structure", f"{len(root)} source files at the repository root",
                Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                "Application code sits directly at the repository root instead of in packages, so there is no "
                "visible structure: entry points, features, and shared code are indistinguishable.",
                "Group the code into a package (or src/ directory) with sub-packages per feature or layer.",
                root[0], evidence=", ".join(sorted(root)[:12])))
        for d, files in sorted(per_dir.items()):
            if len(files) >= OVERSIZED_PACKAGE_FILES:
                out.append(self._f(
                    ctx, "architecture.oversized-package", f"Package {d} holds {len(files)} source files",
                    Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                    f"{d}/ contains {len(files)} source files with no sub-packages (limit "
                    f"{OVERSIZED_PACKAGE_FILES}), so related modules are not grouped and the package has no "
                    "internal structure.", "Split it into sub-packages by feature or responsibility.", files[0],
                    evidence=f"{d}/: {len(files)} files"))
        return out[:MAX_PER_RULE * 2]

    # ------------------------------------------------------------------ duplicated business logic
    def _duplicated_logic(self, ctx):
        groups: dict[str, list[tuple[str, int, str, str]]] = defaultdict(list)
        for rel in ctx.python_files():
            if _is_exempt(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or node.name.startswith("__"):
                    continue
                body = _body(node)
                statements = sum(isinstance(n, ast.stmt) for s in body for n in ast.walk(s))
                if statements < DUPLICATE_MIN_STATEMENTS or not any(
                        isinstance(n, _LOGIC) for s in body for n in ast.walk(s)):
                    continue
                module = ast.Module(body=body, type_ignores=[])
                raw = ast.dump(module)
                shape = ast.dump(_Anonymize().visit(ast.parse(ast.unparse(module))))
                digest = hashlib.sha1(shape.encode(), usedforsecurity=False).hexdigest()
                groups[digest].append((rel, node.lineno, node.name, raw))
        out = []
        for locs in groups.values():
            if len({rel for rel, *_ in locs}) < 2:
                continue
            (rel, line, name, _), others = locs[0], locs[1:]
            renamed = len({raw for *_, raw in locs}) > 1
            out.append(self._f(
                ctx, "architecture.duplicated-logic",
                f"Same logic implemented {len(locs)} times ({', '.join(sorted({n for _, _, n, _ in locs})[:3])})",
                Severity.LOW, Confidence.MEDIUM, FindingKind.CONFIRMED,
                f"{name}() in {rel} has the same structure as "
                + ", ".join(f"{n}() in {r}:{ln}" for r, ln, n, _ in others[:4])
                + (" once variable names are ignored" if renamed else "")
                + ". A business rule implemented in several places drifts: a fix or a policy change lands in one "
                "copy and not the others.",
                "Keep one implementation in the module that owns the rule and call it from the others.", rel, line,
                evidence="; ".join(f"{r}:{ln} {n}()" for r, ln, n, _ in locs[:6])))
            if len(out) >= MAX_PER_RULE:
                break
        return out

    # ------------------------------------------------------------------ configuration management
    @staticmethod
    def _env_reads(ctx, rel) -> int:
        """Environment variable reads in code (not in strings or comments, for Python)."""
        if not rel.endswith(".py"):
            return len(ENV_READ.findall(ctx.read(rel) or ""))
        tree = ctx.python_ast(rel)
        if tree is None:
            return 0
        return sum(isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv") and isinstance(n.value, ast.Name)
                   and n.value.id == "os" for n in ast.walk(tree))

    def _config(self, ctx):
        reads = {f: self._env_reads(ctx, f) for f in ctx.files_with_suffix(*SOURCE_EXTS) if not _is_exempt(f)}
        readers = [f for f, n in reads.items() if n]
        central = [f for f in readers if _named(f, CONFIG_NAMES) and reads[f] >= 3]
        outside = [f for f in readers if f not in central]
        if len(readers) >= CONFIG_SPRAWL_FILES and len(outside) >= CONFIG_SPRAWL_FILES // 2:
            return [self._f(
                ctx, "architecture.config-sprawl", f"Environment variables read in {len(readers)} files",
                Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                "Configuration is read ad hoc across many modules, so required settings are undocumented and not "
                "validated at startup.",
                "Centralize configuration in one module that validates all settings at boot.",
                (outside or readers)[0], evidence=", ".join((outside or readers)[:10]))]
        # A settings module only governs its own top-level package (a separate library may read its own env vars).
        top = lambda rel: rel.split("/", 1)[0] if "/" in rel else ""  # noqa: E731
        out = []
        for settings in sorted({next(c for c in central if top(c) == t) for t in {top(c) for c in central}}):
            bypass = [f for f in outside if top(f) == top(settings)]
            if len(bypass) < CONFIG_BYPASS_FILES:
                continue
            out.append(self._f(
                ctx, "architecture.config-bypass",
                f"{len(bypass)} modules read the environment around {settings}", Severity.LOW,
                Confidence.HIGH, FindingKind.CONFIRMED,
                f"The project has a settings module ({settings}), but {len(bypass)} other modules beside it read "
                "environment variables directly. Those settings skip its defaults and validation, and the settings "
                "module no longer lists everything the application needs.",
                f"Read these values through {settings} and import them from there.", bypass[0],
                evidence=", ".join(bypass[:10])))
        return out
