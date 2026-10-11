"""Query-level database checks: N+1 queries, lazy relationship loads in loops, unbounded queries and list endpoints
without pagination, lookups on unindexed columns, transaction handling and race conditions.

Queries are recognised structurally, never by "a method called ``get``": SQLAlchemy (``Model.query…``,
``session.query(Model)…``, ``session.scalars(select(Model)…)``), Django (``Model.objects…``), PyMongo
(``db.collection.find…``) and DB-API SQL strings in Python; Prisma, Mongoose, Sequelize, the MongoDB driver and SQL
strings in JavaScript/TypeScript. A query's model is resolved against the schema model, so the checks can tell a
unique-key lookup (bounded) from a scan, an eager-loaded relationship from a lazy one, and a constrained column
from an unconstrained one.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..findings import Confidence, FindingKind, Severity
from .architecture import _is_exempt, _is_route_handler, _js_block
from .base import is_test_path
from .db_migrations import _paren_body
from .db_model import EAGER_LAZY, Model, Schema, top_level_entries, type_family

MAX_PER_RULE = 30
MAX_LISTED = 8

# Bounded reference data: listing every row is the point (a country picker), and the table does not grow with use.
REFERENCE_MODEL = re.compile(
    r"(?i)^(?:countr(?:y|ies)|currenc(?:y|ies)|languages?|locales?|time_?zones?|roles?|permissions?|settings?|"
    r"config(?:uration)?s?|feature_?flags?|features?|plans?|regions?|provinces?|states?|statuses|status|units?|"
    r"\w*types?|\w*kinds?|\w*categor(?:y|ies)|\w*choices?|\w*enums?)$")
PAGE_PARAMS = r"page|per_page|perpage|page_size|pagesize|pageSize|perPage|limit|offset|cursor|after|before|skip|take"
PY_PAGINATION = re.compile(
    rf"""(?:args|GET|query_params|values|query)\.get\(\s*['"](?:{PAGE_PARAMS})['"]|"""
    rf"""(?:args|GET|query_params)\[\s*['"](?:{PAGE_PARAMS})['"]|\bPaginator\(|\.paginate\(|paginate_queryset\(|"""
    rf"""Pagination\b|\[\s*\w*(?:offset|start|skip)\w*\s*:|\.limit\(|\.offset\(|\bfetchmany\(""")
JS_PAGINATION = re.compile(
    rf"""\b(?:req|request|ctx)\.query\.(?:{PAGE_PARAMS})\b|query\[['"](?:{PAGE_PARAMS})['"]\]|"""
    rf"""searchParams\.get\(\s*['"`](?:{PAGE_PARAMS})['"`]|@Query\(\s*['"`](?:{PAGE_PARAMS})['"`]|"""
    rf"""\{{[^}}]*\b(?:{PAGE_PARAMS})\b[^}}]*\}}\s*=\s*(?:req|request|ctx)\.query|\bpaginate\(""")
PY_SIDE_EFFECT = re.compile(r"^(?:requests|httpx|urllib\.request|stripe|boto3|smtplib)\.|(?:^|\.)(?:urlopen|send_mail|"
                            r"send_mass_mail|send_email|send_task|delay|apply_async|publish|send_message|"
                            r"post_message|notify)$")
JS_SIDE_EFFECT = re.compile(r"\bfetch\(|\baxios(?:\.\w+)?\(|\bstripe\.\w+|\bsendMail\(|\.sendEmail\(|\bresend\.|"
                            r"\bsgMail\.|\b\w*[qQ]ueue\.add\(|\.publish\(|\bsqs\.|\bsns\.|producer\.send\(")
BROAD_DB_ERRORS = {"Exception", "BaseException", "SQLAlchemyError", "IntegrityError", "DatabaseError",
                   "OperationalError", "DBAPIError", "Error", "PyMongoError"}
SESSION_RECEIVER = re.compile(r"(?:^|\.)(?:session|db_session|dbsession|sess|conn|connection|cnx|con|db|tx|uow)$")


@dataclass
class Issue:
    rule: str
    title: str
    severity: str
    confidence: str
    kind: str
    description: str
    remediation: str
    file: str = ""
    line: int | None = None
    evidence: str | None = None


@dataclass
class Query:
    node: object
    orm: str                     # sqlalchemy | django | pymongo | sql | prisma | mongoose | sequelize | mongodb
    model: str | None
    line: int
    file: str = ""
    method: str = ""
    eq_cols: list[str] = field(default_factory=list)
    order_cols: list[str] = field(default_factory=list)
    eager: set[str] = field(default_factory=set)
    single: bool = False
    limited: bool = False
    paginated: bool = False
    streaming: bool = False
    write: bool = False
    lock: bool = False
    filtered: bool = False
    materialized: bool = False
    in_tx_option: bool = False   # sequelize ``{ transaction: t }``
    start: int = 0               # JS: offsets in the file
    end: int = 0
    text: str = ""

    @property
    def bounded(self) -> bool:
        return self.single or self.limited or self.paginated


class Collector:
    """Issues from every file, plus unindexed lookups grouped by (model, column) across the codebase."""

    def __init__(self, schema: Schema, profile) -> None:
        self.schema = schema
        self.profile = profile
        self.issues: list[Issue] = []
        self.lookups: dict[tuple[str, str], list[tuple[str, int, str]]] = defaultdict(list)
        self.counts: dict[str, int] = defaultdict(int)
        self.dialects = profile.production_sql_dialects if profile else set()

    def add(self, issue: Issue) -> None:
        if self.counts[issue.rule] < MAX_PER_RULE:
            self.counts[issue.rule] += 1
            self.issues.append(issue)

    # ------------------------------------------------------------------ shared judgements
    def model(self, q: Query) -> Model | None:
        return self.schema.find(q.model) if q.model else None

    def reference(self, q: Query) -> bool:
        m = self.model(q)
        name = m.name if m else q.model or ""
        return bool(REFERENCE_MODEL.match(name) or (m and REFERENCE_MODEL.match(m.table)))

    def unique_lookup(self, q: Query) -> bool:
        """The equality filter pins at most one row (primary key, unique column, or a whole unique set)."""
        m = self.model(q)
        if q.orm == "mongoose" and "_id" in q.eq_cols:
            return True
        if not m:
            return any(c in ("id", "pk", "_id") for c in q.eq_cols)
        cols = set()
        for c in q.eq_cols:
            if c == "pk":
                cols |= {p.db_name for p in m.pk}
                continue
            col = m.column(c) or m.column(f"{c}_id")
            if col:
                cols.add(col.db_name)
        return any(s and s <= cols for s in m.unique_sets())

    def record_lookup(self, q: Query) -> None:
        """Remember equality filters that no index serves (the finding is built once all files are read)."""
        m = self.model(q)
        if not m or self.reference(q) or not (q.eq_cols or (q.order_cols and q.limited)):
            return
        cols = [m.column(c) or m.column(f"{c}_id") for c in (q.eq_cols or q.order_cols) if c != "pk"]
        if not cols or any(c is None for c in cols):
            return  # an unknown column (inherited from code eVal could not read, or a typo): do not guess
        if any(m.is_indexed(c) for c in cols) or not m.complete:
            return
        if any(c.fk for c in cols) and m.orm != "mongoose":
            return  # a foreign key: InnoDB indexes it itself, elsewhere database.fk-without-index reports it
        cols = [c for c in cols if type_family(c.type) != "bool"]
        if not cols:
            return  # low-selectivity flag columns: a plain index rarely helps
        kind = "filter" if q.eq_cols else "sort"
        self.lookups[(m.name, cols[0].name)].append((q.file, q.line, kind))

    def lookup_issues(self) -> list[Issue]:
        out = []
        for (model_name, col_name), sites in sorted(self.lookups.items(), key=lambda kv: -len(kv[1])):
            m = self.schema.find(model_name)
            col = m.column(col_name)
            mongo = m.orm == "mongoose"
            where = ", ".join(f"{f}:{ln}" for f, ln, _ in sites[:MAX_LISTED])
            sort_only = all(k == "sort" for *_, k in sites)
            impact = ("a collection scan (COLLSCAN) of every document" if mongo else
                      "a full table scan" + (" and a sort" if sort_only else ""))
            how = f"schema.index({{ {col.db_name}: 1 }})" if mongo else "index=True / @@index / CREATE INDEX"
            fix = (f"Add an index on `{col.db_name}` ({how}), or a composite index that starts with it if queries "
                   "also filter on other columns. Confirm with EXPLAIN on production-sized data first.")
            out.append(Issue(
                "database.missing-index", f"`{m.table}.{col.db_name}` is queried without an index",
                Severity.LOW if len(sites) == 1 else Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                f"{len(sites)} quer{'y' if len(sites) == 1 else 'ies'} {'sort' if sort_only else 'filter'} {m.name} "
                f"by `{col.name}`, which is not a key, not unique, and does not lead any index declared in the "
                f"model or created by a migration. Each such query is {impact}, which grows with the table. "
                "(Static estimate: an index created outside the repository would not be visible.)",
                fix, sites[0][0], sites[0][1],
                evidence=f"{m.file}:{col.line or m.line} {col.name}; queried at {where}"))
        return out[:MAX_PER_RULE]


# ============================================================================================ Python
SA_SINGLE = {"first", "one", "one_or_none", "scalar", "scalar_one", "scalar_one_or_none", "get", "get_or_404",
             "first_or_404", "one_or_404", "count", "exists"}
SA_LIMIT = {"limit", "slice", "fetchmany", "fetchone", "top"}
SA_MULTI = {"all", "fetchall", "partitions", "unique"}
SA_STREAM = {"yield_per", "stream", "stream_scalars", "partitions", "enable_eagerloads"}
SA_EAGER = {"joinedload", "selectinload", "subqueryload", "contains_eager", "immediateload", "defaultload"}
DJ_SINGLE = {"get", "first", "last", "latest", "earliest", "count", "exists", "aggregate", "in_bulk", "contains",
             "get_or_create", "update_or_create", "aget", "afirst", "acount", "aexists"}
DJ_WRITE = {"create", "bulk_create", "update", "delete", "get_or_create", "update_or_create", "bulk_update",
            "acreate", "aupdate", "adelete", "aget_or_create", "aupdate_or_create"}
DJ_PATTERN_LOOKUPS = {"contains", "icontains", "regex", "iregex", "search", "endswith", "iendswith", "trigram_similar",
                      "unaccent"}
MONGO_READ = {"find", "find_one", "count_documents", "aggregate", "distinct", "estimated_document_count"}
MONGO_WRITE = {"insert_one", "insert_many", "update_one", "update_many", "replace_one", "delete_one", "delete_many",
               "find_one_and_update", "find_one_and_delete", "find_one_and_replace", "bulk_write"}
SQL_EXEC = {"execute", "executemany", "exec_driver_sql"}


def _flatten(node):
    steps, cur = [], node
    while True:
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            steps.append((cur.func.attr, cur))
            cur = cur.func.value
        elif isinstance(cur, ast.Subscript):
            steps.append(("[]", cur))
            cur = cur.value
        elif isinstance(cur, ast.Attribute):
            steps.append(("." + cur.attr, cur))
            cur = cur.value
        else:
            break
    steps.reverse()
    return cur, steps


def _name_of(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id  # Model.column → Model
    return None


def _sql_text(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute | ast.Name) and node.args and (
            getattr(node.func, "attr", None) == "text" or getattr(node.func, "id", None) == "text"):
        return _sql_text(node.args[0])
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "?" for v in node.values)
    return None


SQL_VERB = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b", re.I)


def parse_sql_query(text: str) -> dict | None:
    m = SQL_VERB.match(text or "")
    if not m:
        return None
    verb = m.group(1).upper()
    low = " ".join(text.split())
    table = re.search(r"\b(?:FROM|INTO|UPDATE)\s+[`\"\[]?(\w+)", low, re.I)
    where = re.search(r"\bWHERE\b(.*?)(?:\bGROUP\b|\bORDER\b|\bLIMIT\b|\bOFFSET\b|$)", low, re.I)
    eq = re.findall(r"(?:WHERE|AND)\s+(?:\w+\.)?[`\"]?(\w+)[`\"]?\s*(?:=|IN\b|>=?|<=?)", where.group(0), re.I) \
        if where else []
    order = re.search(r"\bORDER\s+BY\s+(?:\w+\.)?[`\"]?(\w+)", low, re.I)
    return {"verb": verb, "table": table.group(1).lower() if table else None, "where": bool(where),
            "eq": [c.lower() for c in eq], "limit": bool(re.search(r"\bLIMIT\b|\bTOP\s*\(?\d|\bFETCH\s+FIRST\b", low,
                                                                    re.I)),
            "join": bool(re.search(r"\bJOIN\b", low, re.I)), "order": [order.group(1).lower()] if order else [],
            "aggregate": bool(re.match(r"\s*SELECT\s+(?:COUNT|SUM|AVG|MIN|MAX|EXISTS)\s*\(", low, re.I)),
            "for_update": bool(re.search(r"\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b", low, re.I))}


def _sa_cond_cols(nodes, model: str) -> list[str]:
    cols = []
    for root in nodes:
        for n in ast.walk(root):
            if isinstance(n, ast.Compare) and isinstance(n.ops[0], ast.Eq | ast.In | ast.Is | ast.Gt | ast.GtE
                                                          | ast.Lt | ast.LtE):
                for side in (n.left, *n.comparators):
                    if isinstance(side, ast.Attribute) and isinstance(side.value, ast.Name) and side.value.id == model:
                        cols.append(side.attr)
                        break
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in (
                    "in_", "between", "is_", "startswith") and isinstance(n.func.value, ast.Attribute) and isinstance(
                    n.func.value.value, ast.Name) and n.func.value.value.id == model:
                cols.append(n.func.value.attr)
    return cols


def _dj_lookups(call: ast.Call) -> list[str]:
    cols = []
    kws = [k for k in call.keywords if k.arg and k.arg != "defaults"]
    for n in call.args:
        for q in ast.walk(n):
            if isinstance(q, ast.Call) and getattr(q.func, "id", getattr(q.func, "attr", "")) == "Q":
                kws += [k for k in q.keywords if k.arg]
    for k in kws:
        parts = k.arg.split("__")
        if parts[-1] in DJ_PATTERN_LOOKUPS:
            continue
        if len(parts) > 2 or (len(parts) == 2 and parts[1] not in {"exact", "iexact", "in", "gt", "gte", "lt", "lte",
                                                                    "range", "isnull", "startswith", "istartswith",
                                                                    "date", "year", "id", "pk"}):
            cols.append("pk")  # traverses a relation: the join uses the (indexed) key
            continue
        cols.append(parts[0])
    return cols


def parse_python_query(node, rel: str, mongo: bool) -> Query | None:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in (
            "get_object_or_404", "get_list_or_404", "aget_object_or_404") and node.args:
        return Query(node, "django", _name_of(node.args[0]), node.lineno, rel, node.func.id,
                     eq_cols=_dj_lookups(node), filtered=True, single=node.func.id != "get_list_or_404")
    base, steps = _flatten(node)
    if not steps:
        return None
    q: Query | None = None
    start = 0
    if isinstance(base, ast.Name) and base.id[:1].isupper() and steps[0][0] == ".query":
        q, start = Query(node, "sqlalchemy", base.id, node.lineno, rel), 1
    elif isinstance(base, ast.Name) and base.id[:1].isupper() and steps[0][0] in (".objects", "._default_manager",
                                                                                   ".all_objects"):
        q, start = Query(node, "django", base.id, node.lineno, rel), 1
    else:
        for i, (m, call) in enumerate(steps):
            if not isinstance(call, ast.Call):
                continue
            receiver = ast.unparse(call.func.value) if isinstance(call.func, ast.Attribute) else ""
            if m == "query" and SESSION_RECEIVER.search(receiver) and call.args and _name_of(call.args[0]):
                q, start = Query(node, "sqlalchemy", _name_of(call.args[0]), node.lineno, rel), i + 1
                break
            if m == "get" and SESSION_RECEIVER.search(receiver) and call.args and isinstance(
                    call.args[0], ast.Name) and call.args[0].id[:1].isupper():
                return Query(node, "sqlalchemy", call.args[0].id, node.lineno, rel, "get", eq_cols=["pk"],
                             single=True, filtered=True)
            if m in ("execute", "scalars", "scalar", "paginate", "get_or_404") and call.args:
                inner = call.args[0]
                ib, isteps = _flatten(inner)
                sel = ib if isinstance(ib, ast.Call) and getattr(ib.func, "id", "") == "select" else None
                for k, (sm, sc) in enumerate(isteps):  # `db.select(User)` / `sa.select(User)`: a chain step
                    if sel is None and sm == "select" and isinstance(sc, ast.Call):
                        sel, isteps = sc, isteps[k + 1:]
                if sel is not None and sel.args:
                    q = Query(node, "sqlalchemy", _name_of(sel.args[0]), node.lineno, rel)
                    _sa_steps(q, isteps)
                    if m == "paginate":
                        q.paginated = True
                    elif m == "scalar" or m == "get_or_404":
                        q.single = True
                    start = i + 1
                    break
                sql = _sql_text(inner) if m in SQL_EXEC else None
                info = parse_sql_query(sql) if sql else None
                if info:
                    q = Query(node, "sql", info["table"], node.lineno, rel, info["verb"].lower(),
                              eq_cols=info["eq"], order_cols=info["order"], filtered=info["where"],
                              limited=info["limit"], single=info["aggregate"], write=info["verb"] in (
                                  "INSERT", "UPDATE", "DELETE"), lock=info["for_update"])
                    q.materialized = any(s[0] == "fetchall" for s in steps[i + 1:])
                    q.single = q.single or any(s[0] in ("fetchone", "scalar", "first", "one") for s in steps[i + 1:])
                    if info["join"]:
                        q.eq_cols = []  # multi-table: columns cannot be attributed to one table
                    return q
            if mongo and (m in MONGO_READ or m in MONGO_WRITE):
                recv = call.func.value
                coll = None
                if isinstance(recv, ast.Attribute):
                    coll = recv.attr
                elif isinstance(recv, ast.Subscript) and isinstance(recv.slice, ast.Constant):
                    coll = str(recv.slice.value)
                if coll and coll not in ("objects", "query", "session"):
                    q = Query(node, "pymongo", coll, node.lineno, rel, m, write=m in MONGO_WRITE,
                              single=m in ("find_one", "count_documents", "estimated_document_count",
                                           "find_one_and_update", "find_one_and_delete", "find_one_and_replace"))
                    flt = call.args[0] if call.args else _kwv(call, "filter")
                    if isinstance(flt, ast.Dict):
                        q.eq_cols = [str(k.value) for k in flt.keys if isinstance(k, ast.Constant) and isinstance(
                            k.value, str) and not k.value.startswith("$") and "." not in k.value]
                        q.filtered = bool(flt.keys)
                    for m2, _ in steps[i + 1:]:
                        q.limited |= m2 == "limit"
                    q.materialized = m == "find"
                    return q
        if q is None:
            return None
    if q.orm == "sqlalchemy":
        _sa_steps(q, steps[start:])
    else:
        _dj_steps(q, steps[start:])
    q.method = next((m for m, _ in reversed(steps) if not m.startswith(".")), q.method)
    return q


def _kwv(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _sa_steps(q: Query, steps) -> None:
    for m, call in steps:
        if m.startswith(".") or m == "[]":
            if m == "[]":
                q.limited = True
            continue
        if m == "filter_by":
            q.eq_cols += [k.arg for k in call.keywords if k.arg]
            q.filtered = True
        elif m in ("filter", "where"):
            q.eq_cols += _sa_cond_cols(call.args, q.model or "")
            q.filtered = True
        elif m == "order_by":
            q.order_cols += _sa_cond_cols([a.func.value if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)
                                           else a for a in call.args], q.model or "") + [
                a.attr for a in call.args if isinstance(a, ast.Attribute) and _name_of(a) == q.model]
        elif m in SA_LIMIT:
            q.limited = True
        elif m == "paginate":
            q.paginated = True
        elif m in SA_SINGLE:
            q.single = True
        elif m in SA_MULTI:
            q.materialized = True
        elif m in SA_STREAM or (m == "execution_options" and _kwv(call, "yield_per") is not None):
            q.streaming = True
        elif m == "with_for_update":
            q.lock = True
        elif m in ("delete", "update", "insert"):
            q.write = True
        elif m == "options":
            for n in ast.walk(call):
                if isinstance(n, ast.Call) and (getattr(n.func, "id", None) in SA_EAGER or getattr(
                        n.func, "attr", None) in SA_EAGER):
                    for a in n.args:
                        if isinstance(a, ast.Attribute):
                            q.eager.add(a.attr)
                        elif isinstance(a, ast.Constant) and isinstance(a.value, str):
                            q.eager.add(a.value.split(".")[0])


def _dj_steps(q: Query, steps) -> None:
    q.materialized = True  # querysets are lazy, but one that is built is (almost always) evaluated
    for m, call in steps:
        if m == "[]":
            q.single |= not isinstance(call.slice, ast.Slice)
            q.limited = True
            continue
        if m.startswith("."):
            continue
        if m in ("filter", "exclude", "get", "get_or_create", "update_or_create", "aget", "aget_or_create"):
            q.eq_cols += _dj_lookups(call)
            q.filtered = True
        elif m == "order_by":
            q.order_cols += [str(a.value).lstrip("-") for a in call.args if isinstance(a, ast.Constant)
                             and "__" not in str(a.value) and a.value != "?"]
        elif m in ("select_related", "prefetch_related"):
            for a in call.args:
                name = a.value if isinstance(a, ast.Constant) else _const_first(a)
                if isinstance(name, str):
                    q.eager.add(name.split("__")[0])
                    q.eager.add(name)
        elif m == "select_for_update":
            q.lock = True
        elif m in ("iterator", "aiterator"):
            q.streaming = True
        if m in DJ_SINGLE:
            q.single = True
        if m in DJ_WRITE:
            q.write = True


def _const_first(node):
    if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
        return node.args[0].value  # Prefetch("comments", ...)
    return None


def _own_nodes(func):
    """Nodes of ``func`` without the bodies of nested functions, lambdas and classes (analysed on their own)."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            continue
        stack.extend(ast.iter_child_nodes(n))


def _decorated_atomic(func) -> bool:
    return any(re.search(r"\batomic\b|transactional|\bin_transaction", ast.unparse(d)) for d in func.decorator_list)


def _with_atomic(item) -> bool:
    src = ast.unparse(item.context_expr)
    return bool(re.search(r"\batomic\(|\.begin(?:_nested)?\(\)|\btransaction\(|start_session|with_transaction", src))


class PythonChecks:
    def __init__(self, ctx, col: Collector) -> None:
        self.ctx, self.col, self.schema = ctx, col, col.schema
        profile = col.profile
        self.django = bool(profile and "django" in profile.web_frameworks) or any(
            m.orm == "django" for m in self.schema.unique_models())
        self.mongo = bool(profile and "mongodb" in profile.datastores)
        settings = "\n".join(ctx.read(f) or "" for f in ctx.python_files() if "settings" in f.rsplit("/", 1)[-1])
        self.atomic_requests = bool(re.search(r"""['"]ATOMIC_REQUESTS['"]\s*:\s*True""", settings))
        self.drf_default_pagination = bool(re.search(r"DEFAULT_PAGINATION_CLASS", settings))

    def run(self) -> None:
        for rel in self.ctx.python_files():
            if is_test_path(rel) or _is_exempt(rel):
                continue
            text = self.ctx.read(rel) or ""
            if not re.search(r"\.query\b|\.objects\b|session|\.execute\(|\.find(?:_one)?\(|select\(|cursor|"
                             r"get_object_or_404|transaction", text):
                continue
            tree = self.ctx.python_ast(rel)
            if tree is None:
                continue
            classes = {}
            for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
                for item in cls.body:
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                        classes[item] = cls
                self._drf_list_view(rel, cls)
            django_views = rel.rsplit("/", 1)[-1] == "views.py" or "/views/" in rel
            raw_conn = bool(re.search(r"\b(?:sqlite3|psycopg2?|pymysql|MySQLdb|mysql\.connector)\.connect\(", text))
            for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
                self._function(rel, func, classes.get(func), django_views, raw_conn, text)

    # ------------------------------------------------------------------ per function
    def _function(self, rel, func, cls, django_views, raw_conn, file_text) -> None:
        nodes = list(_own_nodes(func))
        parents = {}
        for p in [func, *nodes]:
            for c in ast.iter_child_nodes(p):
                parents[c] = p
        queries: list[Query] = []
        consumed: set[int] = set()
        # Outermost first: a chain and the calls inside it start at the same place, the chain ends later.
        for n in sorted((n for n in nodes if isinstance(n, ast.Call | ast.Subscript)),
                        key=lambda n: (n.lineno, n.col_offset, -n.end_lineno, -n.end_col_offset)):
            if id(n) in consumed:
                continue
            q = parse_python_query(n, rel, self.mongo)
            if q:
                queries.append(q)
                consumed.update(id(x) for x in ast.walk(n) if isinstance(x, ast.Call | ast.Subscript))
        assigned: dict[str, list[tuple[int, Query]]] = defaultdict(list)
        by_node = {id(q.node): q for q in queries}
        for n in nodes:
            if isinstance(n, ast.Assign | ast.AnnAssign) and isinstance(getattr(n, "value", None), ast.AST):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                value = n.value.value if isinstance(n.value, ast.Await) else n.value
                if id(value) in by_node and len(targets) == 1 and isinstance(targets[0], ast.Name):
                    assigned[targets[0].id].append((n.lineno, by_node[id(value)]))
        atomic_nodes = self._atomic_nodes(func, nodes)
        handler = _is_route_handler(func, django_views) or self._cbv_handler(func, cls)
        for q in queries:
            self.col.record_lookup(q)
        self._loops(rel, func, nodes, queries, assigned, parents)
        self._unbounded(rel, func, queries, handler, parents, assigned)
        self._transactions(rel, func, nodes, queries, handler, atomic_nodes, raw_conn, file_text, parents)
        self._races(rel, func, nodes, queries, assigned, handler, atomic_nodes)

    @staticmethod
    def _cbv_handler(func, cls) -> bool:
        if cls is None or func.name not in ("get", "post", "put", "patch", "delete", "list", "retrieve", "create",
                                            "update", "destroy", "get_queryset", "get_context_data"):
            return False
        return any(re.search(r"View|ViewSet|Resource|Handler|Endpoint", ast.unparse(b)) for b in cls.bases)

    def _atomic_nodes(self, func, nodes) -> set[int]:
        if _decorated_atomic(func):
            return {id(n) for n in nodes}
        out: set[int] = set()
        for n in nodes:
            if isinstance(n, ast.With | ast.AsyncWith) and any(_with_atomic(i) for i in n.items):
                for stmt in n.body:
                    out.update(id(x) for x in ast.walk(stmt))
        return out

    # ------------------------------------------------------------------ N+1
    def _loops(self, rel, func, nodes, queries, assigned, parents) -> None:
        loops = []
        for n in nodes:
            if isinstance(n, ast.For | ast.AsyncFor):
                loops.append((n, n.target, n.iter, n.body))
            elif isinstance(n, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
                gen = n.generators[0]
                body = [n.elt] if not isinstance(n, ast.DictComp) else [n.key, n.value]
                loops.append((n, gen.target, gen.iter, body + list(gen.ifs) + [g.iter for g in n.generators[1:]]))
        reported_loops: set[int] = set()
        for loop, target, iterable, body in loops:
            if isinstance(iterable, ast.List | ast.Tuple | ast.Set) and all(isinstance(e, ast.Constant)
                                                                            for e in iterable.elts):
                continue
            if isinstance(iterable, ast.Call) and getattr(iterable.func, "id", "") == "range" and all(
                    isinstance(a, ast.Constant) for a in iterable.args):
                continue
            loop_vars = {t.id for t in ast.walk(target) if isinstance(t, ast.Name)}
            body_ids = {id(x) for b in body for x in ast.walk(b)}
            source_q = self._iter_query(iterable, assigned, loop.lineno, queries)
            row_loop = source_q is not None
            for q in queries:
                if id(q.node) not in body_ids or id(loop) in reported_loops:
                    continue
                uses = {x.id for x in ast.walk(q.node) if isinstance(x, ast.Name)} & loop_vars
                if not uses:
                    continue
                reported_loops.add(id(loop))
                what = "write" if q.write else "query"
                fix = ("Collect the rows first and write them in one statement (bulk_create / bulk_update / "
                       "update() with a filter, session.execute(insert(...), rows))." if q.write else
                       "Load the related rows in one query before the loop (an IN (...) filter on the collected ids, "
                       "joinedload/selectinload, select_related/prefetch_related) and look them up in a dict.")
                self.col.add(Issue(
                    "database.n-plus-one", f"Database {what} inside a loop (N+1)",
                    Severity.LOW if q.write else Severity.MEDIUM,
                    Confidence.HIGH if row_loop else Confidence.MEDIUM, FindingKind.ESTIMATE,
                    f"`{ast.unparse(q.node)[:100]}` runs once per iteration of the loop at line {loop.lineno} "
                    f"(it uses the loop variable `{sorted(uses)[0]}`)"
                    + (", and the loop itself iterates over query results" if row_loop else "")
                    + ". N rows cost N+1 round trips, so latency grows linearly with the data."
                    + (" (session.get() answers from the identity map for ids already loaded, so only distinct ids "
                       "cost a query.)" if q.orm == "sqlalchemy" and q.method == "get" else "")
                    + " (Static estimate.)",
                    fix, rel, q.line))
            if row_loop and id(loop) not in reported_loops:
                self._lazy_loads(rel, loop, target, body, source_q, reported_loops)
            if id(loop) not in reported_loops:
                self._writes_in_loop(rel, loop, body, loop_vars, reported_loops)

    def _iter_query(self, iterable, assigned, line, queries) -> Query | None:
        node = iterable.value if isinstance(iterable, ast.Await) else iterable
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("list", "enumerate", "sorted", "reversed",
                                                                          "tuple") and node.args:
            node = node.args[0]
        for q in queries:
            if q.node is node:
                return q
        if isinstance(node, ast.Name) and assigned.get(node.id):
            before = [q for ln, q in assigned[node.id] if ln <= line]
            return before[-1] if before else None
        return None

    def _lazy_loads(self, rel, loop, target, body, q: Query, reported) -> None:
        m = self.col.model(q)
        if m is None or q.single:
            return
        item = target.elts[-1] if isinstance(target, ast.Tuple) and target.elts else target
        if not isinstance(item, ast.Name):
            return
        for b in body:
            for n in ast.walk(b):
                if not (isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == item.id):
                    continue
                rel_obj = m.relations.get(n.attr)
                if rel_obj is None or n.attr in q.eager or rel_obj.kind in ("ref", "generic"):
                    continue
                if rel_obj.lazy in EAGER_LAZY:
                    continue
                reported.add(id(loop))
                eager = ("select_related" if rel_obj.kind in ("fk", "o2o") else "prefetch_related") \
                    if m.orm == "django" else "selectinload/joinedload"
                self.col.add(Issue(
                    "database.n-plus-one", f"Lazy-loaded relationship `{n.attr}` accessed in a loop (N+1)",
                    Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                    f"The loop at line {loop.lineno} iterates over {m.name} rows from the query at line {q.line} and "
                    f"reads `{item.id}.{n.attr}`. The relationship is loaded lazily (no {eager} on the query"
                    + (f", lazy='{rel_obj.lazy}'" if rel_obj.lazy else "") + "), so each iteration issues one more "
                    "query. (Static estimate: rows already in the session identity map do not trigger a load.)",
                    f"Eager-load it on the query, e.g. `.options({eager.split('/')[0]}({m.name}.{n.attr}))`"
                    if m.orm != "django" else f"Add `.{eager}('{n.attr}')` to the queryset.",
                    rel, n.lineno))
                return

    def _writes_in_loop(self, rel, loop, body, loop_vars, reported) -> None:
        for b in body:
            for n in ast.walk(b):
                if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
                    continue
                recv = n.func.value
                if self.django and n.func.attr in ("save", "delete") and isinstance(recv, ast.Name) and \
                        recv.id in loop_vars:
                    reported.add(id(loop))
                    self.col.add(Issue(
                        "database.n-plus-one", f"`{recv.id}.{n.func.attr}()` inside a loop (one write per row)",
                        Severity.LOW, Confidence.MEDIUM, FindingKind.ESTIMATE,
                        f"Each iteration of the loop at line {loop.lineno} issues its own {n.func.attr.upper()} "
                        "statement (and its own transaction in autocommit mode).",
                        "Use bulk_update(objs, fields) / bulk_create, or a single queryset update()/delete().",
                        rel, n.lineno))
                    return
                if n.func.attr == "commit" and SESSION_RECEIVER.search(ast.unparse(recv)):
                    reported.add(id(loop))
                    self.col.add(Issue(
                        "database.multiple-commits", "Transaction committed inside a loop",
                        Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                        f"`{ast.unparse(n)}` runs on every iteration of the loop at line {loop.lineno}: one "
                        "transaction (and one durable flush to disk) per item, and a failure half-way leaves the "
                        "earlier items committed and the rest not. Fine if every item is deliberately independent "
                        "(a job that must make progress); otherwise it is slow and leaves partial results.",
                        "Commit once after the loop, or in fixed-size batches with a resumable checkpoint.", rel,
                        n.lineno))
                    return

    # ------------------------------------------------------------------ unbounded / pagination
    def _unbounded(self, rel, func, queries, handler, parents, assigned) -> None:
        src = ast.unparse(func)
        if handler and PY_PAGINATION.search(src):
            return
        args = {a.arg for a in func.args.args + func.args.kwonlyargs}
        if handler and args & set(PAGE_PARAMS.split("|")):
            return
        # A query that runs once per loop iteration is the N+1 problem, reported as such; paging it is not the fix.
        loop_types = ast.For | ast.AsyncFor | ast.While | ast.comprehension
        in_loops = {id(x) for n in ast.walk(func) if isinstance(n, loop_types)
                    for part in (n.body if not isinstance(n, ast.comprehension) else n.ifs) for x in ast.walk(part)}
        in_loops |= {id(x) for n in ast.walk(func) if isinstance(n, ast.ListComp | ast.SetComp | ast.GeneratorExp)
                     for x in ast.walk(n.elt)}
        for q in queries:
            if q.write or q.bounded or q.streaming or self.col.reference(q) or self.col.unique_lookup(q):
                continue
            if id(q.node) in in_loops:
                continue
            if q.orm in ("sql",) and (q.model is None or not q.materialized):
                continue
            if not self._materialized(q, parents, assigned):
                continue
            target = q.model or "rows"
            if handler:
                self.col.add(Issue(
                    "database.missing-pagination", f"Request handler returns every matching {target} row",
                    Severity.LOW if q.filtered else Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                    f"`{func.name}` loads `{ast.unparse(q.node)[:100]}` with no LIMIT, slice or pagination, and the "
                    "handler reads no page/limit/cursor parameter. Response size, memory and latency grow with the "
                    "table" + (" (filtered, but a filter does not bound the result)" if q.filtered else "")
                    + ". (Static estimate.)",
                    "Paginate: accept a limit (with a server-side maximum) and a cursor or page, and apply them "
                    "(`.limit()`/`.paginate()`, Paginator / DRF pagination, keyset pagination for large tables).",
                    rel, q.line))
            elif not q.filtered:
                self.col.add(Issue(
                    "database.unbounded-query", f"Query loads the whole {target} table", Severity.LOW,
                    Confidence.MEDIUM, FindingKind.ESTIMATE,
                    f"`{ast.unparse(q.node)[:100]}` has no filter and no limit, so it materializes every row in "
                    "memory at once. Memory and run time grow with the table. (Static estimate.)",
                    "Stream in chunks (yield_per / .iterator(chunk_size=...) / server-side cursors) or process in "
                    "keyset-paginated batches.", rel, q.line))

    @staticmethod
    def _materialized(q: Query, parents, assigned) -> bool:
        if q.orm == "django" or q.materialized:
            parent = parents.get(q.node)
            # Used as a subquery (`filter(id__in=qs)`) or as a value for another query: not materialized itself.
            return not (isinstance(parent, ast.keyword) or isinstance(parent, ast.Call) and isinstance(
                parent.func, ast.Attribute) and parent.func.attr in ("filter", "exclude", "in_", "where"))
        parent = parents.get(q.node)
        if isinstance(parent, ast.For | ast.AsyncFor | ast.comprehension) and parent.iter is q.node:
            return True
        if isinstance(parent, ast.Call) and getattr(parent.func, "id", "") in ("list", "tuple", "sorted", "set"):
            return True
        return isinstance(parent, ast.Return)

    def _drf_list_view(self, rel, cls) -> None:
        bases = " ".join(ast.unparse(b) for b in cls.bases)
        if not re.search(r"\b(?:ListAPIView|ListCreateAPIView|ModelViewSet|ReadOnlyModelViewSet)\b|"
                         r"ListModelMixin", bases):
            return
        attrs = {t.id: s.value for s in cls.body if isinstance(s, ast.Assign) for t in s.targets
                 if isinstance(t, ast.Name)}
        if "pagination_class" in attrs or self.drf_default_pagination:
            return
        qs = attrs.get("queryset")
        model = _flatten(qs)[0].id if qs is not None and isinstance(_flatten(qs)[0], ast.Name) else None
        if model and REFERENCE_MODEL.match(model):
            return
        self.col.add(Issue(
            "database.missing-pagination", f"{cls.name} lists {model or 'objects'} without pagination",
            Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
            f"{cls.name} is a Django REST Framework list view, but it sets no pagination_class and the REST_FRAMEWORK "
            "settings define no DEFAULT_PAGINATION_CLASS, so the list endpoint serializes the entire queryset on "
            "every request.",
            "Set DEFAULT_PAGINATION_CLASS (and PAGE_SIZE) in REST_FRAMEWORK settings, or pagination_class on the "
            "view (CursorPagination for large or frequently-written tables).", rel, cls.lineno))

    # ------------------------------------------------------------------ transactions
    def _transactions(self, rel, func, nodes, queries, handler, atomic, raw_conn, file_text, parents) -> None:
        calls = [n for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        commits = [c for c in calls if c.func.attr == "commit" and SESSION_RECEIVER.search(ast.unparse(c.func.value))]
        loop_ids = {id(x) for n in nodes if isinstance(n, ast.For | ast.AsyncFor | ast.While)
                    for b in n.body for x in ast.walk(b)}
        # Django: several writes in autocommit mode.
        if self.django and not (handler and self.atomic_requests):
            writes = [(q.line, f"{q.model}.objects.{q.method}()") for q in queries if q.write and q.orm == "django"
                      and id(q.node) not in atomic]
            # .save()/.delete() only on objects known to be model instances (cache.delete(), image.save() are not).
            instances = set(self._instances(nodes))
            writes += [(c.lineno, ast.unparse(c)[:60]) for c in calls if c.func.attr in ("save", "delete")
                       and isinstance(c.func.value, ast.Name) and c.func.value.id in instances and id(c) not in atomic]
            writes = sorted(set(writes))
            if len(writes) >= 2 and func.name not in ("save", "delete", "create", "update"):
                self.col.add(Issue(
                    "database.non-atomic-writes", f"`{func.name}` makes {len(writes)} writes outside a transaction",
                    Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    "Django runs in autocommit mode: each write commits on its own. If a later write fails "
                    "(validation, constraint, crash, timeout) the earlier ones stay committed and the data is left "
                    "half-updated. "
                    "Writes: " + "; ".join(f"line {ln}: {w}" for ln, w in writes[:6])
                    + ". (Unless every caller already wraps this in transaction.atomic().)",
                    "Wrap the related writes in `with transaction.atomic():` (or decorate the function), or enable "
                    "ATOMIC_REQUESTS for views.", rel, writes[0][0]))
        # SQLAlchemy / DB-API: one request path that commits, writes more, and commits again. Commits in exclusive
        # branches (if/else, try/except) or before an early return are separate paths, and background jobs that
        # commit progress states ("running", then "done") do so deliberately, so neither counts.
        pair = self._split_unit_of_work(nodes, commits, loop_ids, parents) if handler else None
        if pair:
            first, second = pair
            self.col.add(Issue(
                "database.multiple-commits", f"`{func.name}` commits twice on one request path",
                Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                f"The commit at line {first.lineno} ends a transaction, more changes follow, and line "
                f"{second.lineno} commits again. If anything between them fails, the first part stays saved and "
                "the request leaves the data half-updated.",
                "Commit once at the end of the unit of work (use flush() when you need generated ids earlier), or "
                "use `with session.begin():`.", rel, second.lineno))
        self._rollback(rel, nodes)
        self._side_effects(rel, func, nodes, calls, atomic, commits, queries)
        if raw_conn:
            self._uncommitted(rel, func, nodes, queries, commits, file_text)

    @staticmethod
    def _branch_path(node, parents) -> dict[int, str]:
        path, cur = {}, node
        while cur in parents:
            parent = parents[cur]
            if isinstance(parent, ast.If):
                path[id(parent)] = "body" if any(cur is s for s in parent.body) else (
                    "orelse" if any(cur is s for s in parent.orelse) else "test")
            elif isinstance(parent, ast.Try):
                for tag, block in (("body", parent.body), ("orelse", parent.orelse), ("final", parent.finalbody)):
                    if any(cur is s for s in block):
                        path[id(parent)] = tag
                if isinstance(cur, ast.ExceptHandler):
                    path[id(parent)] = f"handler{parent.handlers.index(cur)}"
            cur = parent
        return path

    @staticmethod
    def _exits_between(node, until: int, parents) -> bool:
        """After ``node`` and before line ``until``, its block (or an enclosing one) returns, raises or jumps."""
        cur = node
        while cur in parents and not isinstance(cur, ast.stmt):
            cur = parents[cur]
        while cur in parents:
            parent = parents[cur]
            for block in (getattr(parent, "body", []), getattr(parent, "orelse", []), getattr(parent, "handlers", []),
                          getattr(parent, "finalbody", [])):
                if isinstance(block, list) and any(cur is s for s in block):
                    rest = block[[i for i, s in enumerate(block) if s is cur][0] + 1:]
                    if any(isinstance(s, ast.Return | ast.Raise | ast.Continue | ast.Break) and s.lineno < until
                           for s in rest):
                        return True
            if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef | ast.For | ast.While):
                return False
            cur = parent
        return False

    def _split_unit_of_work(self, nodes, commits, loop_ids, parents):
        commits = sorted((c for c in commits if id(c) not in loop_ids), key=lambda c: c.lineno)
        writes = [n.lineno for n in nodes if isinstance(n, ast.Assign | ast.AugAssign) and any(
            isinstance(t, ast.Attribute) for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
        writes += [n.lineno for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr in ("add", "add_all", "delete", "merge", "execute")
                   and SESSION_RECEIVER.search(ast.unparse(n.func.value))]
        for i, a in enumerate(commits):
            pa = self._branch_path(a, parents)
            for b in commits[i + 1:]:
                if self._exits_between(a, b.lineno, parents):
                    continue  # `commit(); return` — the second commit is on another path
                pb = self._branch_path(b, parents)
                if any(pa[k] != pb[k] for k in pa.keys() & pb.keys()):
                    continue  # exclusive branches
                if any(a.lineno < w < b.lineno for w in writes):
                    return a, b
        return None

    def _instances(self, nodes):
        """Names bound to model instances: from a single-row query, a model constructor, a form or serializer."""
        for n in nodes:
            if not (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)):
                continue
            name, value = n.targets[0].id, n.value
            constructor = isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and bool(
                self.schema.find(value.func.id))
            if re.search(r"(?:form|serializer)$", name, re.I) or constructor:
                yield name
            elif isinstance(value, ast.Call):
                q = parse_python_query(value, "", self.mongo)
                if q and q.single:
                    yield name

    def _rollback(self, rel, nodes) -> None:
        for t in [n for n in nodes if isinstance(n, ast.Try)]:
            body_calls = [c for s in t.body for c in ast.walk(s) if isinstance(c, ast.Call)
                          and isinstance(c.func, ast.Attribute) and c.func.attr in ("commit", "flush")
                          and SESSION_RECEIVER.search(ast.unparse(c.func.value))]
            if not body_calls:
                continue
            if any(isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "rollback"
                   for s in t.finalbody for c in ast.walk(s)):
                continue
            for h in t.handlers:
                names = {x.id if isinstance(x, ast.Name) else getattr(x, "attr", "")
                         for x in ([h.type] if not isinstance(h.type, ast.Tuple) else h.type.elts) if x is not None}
                if h.type is not None and not names & BROAD_DB_ERRORS:
                    continue
                inner = [x for s in h.body for x in ast.walk(s)]
                if any(isinstance(x, ast.Raise) for x in inner) or any(
                        isinstance(x, ast.Call) and getattr(x.func, "attr", "") == "rollback" for x in inner):
                    continue
                self.col.add(Issue(
                    "database.missing-rollback", "Database error swallowed without a rollback",
                    Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    f"The `except` at line {h.lineno} catches the failure of `{ast.unparse(body_calls[0])}` but "
                    "neither rolls back nor re-raises. After a failed flush/commit the SQLAlchemy session refuses all "
                    "further work (PendingRollbackError) until rollback() is called, so later queries in the same "
                    "request or job fail too, and the caller is told nothing went wrong.",
                    "Call `session.rollback()` in the handler (or use `with session.begin():`), and log or re-raise "
                    "the error.", rel, h.lineno))
                break

    def _side_effects(self, rel, func, nodes, calls, atomic, commits, queries) -> None:
        last_commit = max((c.lineno for c in commits), default=0)
        first_write = min([q.line for q in queries if q.write] + [c.lineno for c in calls if c.func.attr in (
            "add", "add_all", "merge", "delete") and SESSION_RECEIVER.search(ast.unparse(c.func.value))],
                          default=0)
        for n in nodes:
            if not isinstance(n, ast.Call):
                continue
            name = ast.unparse(n.func)
            if not PY_SIDE_EFFECT.search(name):
                continue
            inside_atomic = id(n) in atomic
            before_commit = bool(first_write and first_write < n.lineno < last_commit)
            if not (inside_atomic or before_commit):
                continue
            task = name.endswith(("delay", "apply_async", "send_task"))
            self.col.add(Issue(
                "database.side-effect-in-transaction", f"`{name}()` runs before the transaction commits",
                Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                (f"`{name}()` is called inside an open transaction" if inside_atomic else
                 f"`{name}()` is called after writes (line {first_write}) but before the commit at line "
                 f"{last_commit}") + ". "
                + ("A worker can pick the task up before the commit is visible (it reads stale or missing rows), "
                   "and if the transaction rolls back the task still runs." if task else
                   "If the transaction later rolls back, the external effect (request, e-mail, charge) has already "
                   "happened and cannot be undone; a slow remote call also holds row locks open."),
                "Run it after the commit: `transaction.on_commit(lambda: ...)` in Django, an `after_commit` session "
                "event or simply after `commit()` in SQLAlchemy, or an outbox table processed by a worker.",
                rel, n.lineno))
            return

    def _uncommitted(self, rel, func, nodes, queries, commits, file_text) -> None:
        writes = [q for q in queries if q.orm == "sql" and q.write]
        if not writes or commits or "autocommit" in file_text or "isolation_level=None" in file_text:
            return
        if any(isinstance(n, ast.With) for n in nodes):
            return  # `with conn:` commits on exit (sqlite3, psycopg)
        self.col.add(Issue(
            "database.uncommitted-writes", f"`{func.name}` writes through a DB-API connection but never commits",
            Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
            "sqlite3, psycopg and PyMySQL open a transaction implicitly; without `connection.commit()` (or a "
            "`with connection:` block) the INSERT/UPDATE/DELETE is rolled back when the connection closes. "
            "(Unless the caller commits.)",
            "Commit after the writes (`conn.commit()`), or use `with conn:` so success commits and errors roll back.",
            rel, writes[0].line))

    # ------------------------------------------------------------------ races
    def _races(self, rel, func, nodes, queries, assigned, handler, atomic) -> None:
        self._lost_updates(rel, func, nodes, assigned)
        self._check_then_insert(rel, func, nodes, queries, assigned)
        for q in queries:
            if not q.lock:
                continue
            if self.col.dialects == {"sqlite"}:
                self.col.add(Issue(
                    "database.row-lock-unsupported", "Row lock requested on SQLite, which ignores it",
                    Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    "SQLite has no SELECT ... FOR UPDATE: Django's select_for_update() and SQLAlchemy's "
                    "with_for_update() are silently dropped. Concurrency safety relies on SQLite's database-wide "
                    "write lock instead, and the read itself takes no lock.",
                    "Use an atomic UPDATE ... WHERE (compare-and-set) or BEGIN IMMEDIATE for read-modify-write on "
                    "SQLite; the row lock works once you run on PostgreSQL or MySQL.", rel, q.line))
            elif q.orm == "django" and id(q.node) not in atomic and not (handler and self.atomic_requests):
                self.col.add(Issue(
                    "database.lock-outside-transaction", "select_for_update() outside transaction.atomic()",
                    Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    "In autocommit mode a row lock is released as soon as the SELECT finishes, so Django raises "
                    "TransactionManagementError when this queryset is evaluated (unless a caller already opened a "
                    "transaction). The lock cannot protect the read-modify-write that follows.",
                    "Evaluate it inside `with transaction.atomic():` together with the update it protects.",
                    rel, q.line))

    def _lost_updates(self, rel, func, nodes, assigned) -> None:
        saves = [n for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr in ("save", "commit", "flush", "asave")]
        for n in nodes:
            target = attr = None
            if isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add | ast.Sub | ast.Mult) and isinstance(
                    n.target, ast.Attribute) and isinstance(n.target.value, ast.Name):
                target, attr = n.target.value.id, n.target.attr
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Attribute) and \
                    isinstance(n.targets[0].value, ast.Name) and isinstance(n.value, ast.BinOp):
                t = n.targets[0]
                if any(isinstance(x, ast.Attribute) and x.attr == t.attr and isinstance(x.value, ast.Name)
                       and x.value.id == t.value.id for x in ast.walk(n.value)):
                    target, attr = t.value.id, t.attr
            if not target or not assigned.get(target):
                continue
            reads = [q for ln, q in assigned[target] if ln <= n.lineno and q.single and not q.write]
            if not reads or reads[-1].lock:
                continue
            q = reads[-1]
            m = self.col.model(q)
            col = m.column(attr) if m else None
            if m and (col is None or type_family(col.type) in ("string", "json", "bool")):
                continue  # not a stored column (a property, a relation) or not arithmetic
            if not any(s.lineno >= n.lineno for s in saves):
                continue
            self.col.add(Issue(
                "database.lost-update", f"Read-modify-write on `{target}.{attr}` can lose concurrent updates",
                Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                f"`{target}` is read at line {q.line} and `{attr}` is recomputed in Python at line {n.lineno} before "
                "being saved. Two concurrent requests both read the old value and the second write overwrites the "
                "first (a lost update: double-spent balance, oversold stock, missed counter increments). A "
                "transaction alone does not prevent this at READ COMMITTED (the PostgreSQL and SQL Server default) "
                "or REPEATABLE READ in MySQL.",
                "Let the database do the arithmetic atomically (`F('balance') - amount` in Django, "
                f"`update({m.name if m else 'Model'}).values({attr}={m.name if m else 'Model'}.{attr} - x)` in "
                "SQLAlchemy, `$inc` in MongoDB), or lock the row first (select_for_update / with_for_update) inside "
                "a transaction, or use optimistic locking with a version column.", rel, n.lineno))

    def _check_then_insert(self, rel, func, nodes, queries, assigned) -> None:
        creates = []
        for n in nodes:
            if isinstance(n, ast.Call):
                callee = n.func
                if isinstance(callee, ast.Name) and self.schema.find(callee.id) and callee.id[:1].isupper():
                    creates.append((n.lineno, callee.id))
        creates += [(q.line, q.model) for q in queries if q.write and q.method in ("create", "acreate", "insert_one")]
        for q in queries:
            if q.write and q.method in ("get_or_create", "update_or_create", "aget_or_create") and q.eq_cols and \
                    not self.col.unique_lookup(q) and self.col.model(q):
                self.col.add(self._race_issue(rel, q, q.line, f"{q.method}()", "Django documents that "
                                              f"{q.method}() is only race-free when the lookup fields are unique"))
        for n in nodes:
            if not isinstance(n, ast.If):
                continue
            probe = None
            for x in ast.walk(n.test):
                for q in queries:
                    if q.node is x and q.single and not q.write:
                        probe = q
                if isinstance(x, ast.Name) and assigned.get(x.id):
                    before = [q for ln, q in assigned[x.id] if ln <= n.lineno and q.single and not q.write]
                    probe = probe or (before[-1] if before else None)
            if probe is None or not probe.eq_cols or self.col.model(probe) is None:
                continue
            model = self.col.model(probe)
            if self.col.unique_lookup(probe):
                continue
            later = [ln for ln, name in creates if ln > n.test.lineno and self.schema.find(name) is model]
            if later:
                self.col.add(self._race_issue(rel, probe, later[0], "check-then-insert",
                                              f"line {probe.line} checks for an existing {model.name} and line "
                                              f"{later[0]} inserts one when none was found"))

    def _race_issue(self, rel, q: Query, line: int, what: str, detail: str) -> Issue:
        m = self.col.model(q)
        cols = ", ".join(q.eq_cols)
        return Issue(
            "database.check-then-insert", f"{what} on {m.name}({cols}) without a unique constraint",
            Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
            f"{detail}. Nothing in the schema makes ({cols}) unique on {m.table}, so two concurrent requests can both "
            "see 'not found' and both insert, creating duplicates that later break .get()/.one() lookups.",
            f"Add a unique constraint on ({cols}) and handle the IntegrityError (or use INSERT ... ON CONFLICT / "
            "upsert); the existence check is then only an optimization.", rel, line)


# ============================================================================================ JavaScript / TypeScript
PRISMA_CALL = re.compile(r"\b(?:this\.)?(?:prisma|db|tx|trx|client|prismaClient|ctx\.prisma)\.(\w+)\.(findMany|"
                         r"findFirst|findFirstOrThrow|findUnique|findUniqueOrThrow|count|aggregate|groupBy|create|"
                         r"createMany|createManyAndReturn|update|updateMany|upsert|delete|deleteMany)\s*\(")
MODEL_CALL = re.compile(r"\b([A-Z]\w*)\.(find|findOne|findById|findByPk|findAll|findAndCountAll|countDocuments|count|"
                        r"estimatedDocumentCount|exists|create|insertMany|bulkCreate|updateOne|updateMany|update|"
                        r"replaceOne|findOneAndUpdate|findByIdAndUpdate|findOneAndDelete|findByIdAndDelete|deleteOne|"
                        r"deleteMany|destroy|aggregate|increment|decrement|upsert|findOrCreate)\s*\(")
MONGO_DRIVER = re.compile(r"\.collection\(\s*['\"`](\w+)['\"`]\s*\)\s*\.(find|findOne|insertOne|insertMany|updateOne|"
                          r"updateMany|deleteOne|deleteMany|countDocuments|aggregate|findOneAndUpdate)\s*\(")
JS_SQL = re.compile(r"\b([\w$]+)\.(query|execute|unsafe)\(\s*([`'\"])((?:(?!\3)[\s\S])*?)\3")
SEQ_MODEL = re.compile(r"(?:sequelize|db)\.define\(\s*['\"`](\w+)['\"`]|class\s+(\w+)\s+extends\s+Model\b")
JS_FUNC_HEAD = re.compile(
    r"(?:\basync\s+)?\bfunction\b\s*\*?\s*\w*\s*\([^)]*\)\s*(?::\s*[^{=;]+)?\{"
    r"|(?:\basync\s+)?(?:\([^()]*(?:\([^()]*\)[^()]*)*\)|\b\w+)\s*(?::\s*[^=;{]+?)?=>\s*\{"
    r"|^[ \t]*(?:(?:public|private|protected|static|async|override|readonly)\s+)*"
    r"(?!(?:if|for|while|switch|catch|function|return|else|do|try|with)\b)\w+\s*\([^)]*\)\s*(?::\s*[^{;]+)?\{",
    re.M)
JS_FOR_OF = re.compile(r"\bfor\s*(?:await\s*)?\(\s*(?:const|let|var)\s+(\w+|\{[^}]*\}|\[[^\]]*\])\s+(?:of|in)\s+"
                       r"([^)]+)\)\s*\{")
JS_FOR_I = re.compile(r"\bfor\s*\(\s*(?:let|var)\s+(\w+)\s*=[^;]*;[^;]*;[^)]*\)\s*\{")
JS_ITER_CB = re.compile(r"\.(forEach|map|flatMap|reduce|some|every|filter)\(\s*(?:async\s*)?(?:\(\s*([^)]*?)\s*\)|"
                        r"(\w+))\s*(?::\s*[^=]+)?=>\s*")
JS_HANDLER_REF = re.compile(r"\b(?:app|router|server|api|\w+Router)\.(get|post|put|patch|delete|all)\(\s*['\"`][^'\"`]+"
                            r"['\"`]\s*,\s*(?:[\w.]+\s*,\s*)*([A-Za-z_]\w*)\s*\)")
JS_LITERAL_ARRAY = re.compile(r"\[\s*(?:(?:'[^']*'|\"[^\"]*\"|`[^`$]*`|-?\d+(?:\.\d+)?|true|false|null)\s*,?\s*)*\]")
JS_ROUTE_CALL = re.compile(r"\b(?:app|router|server|api|\w+Router)\.(get|post|put|patch|delete|all)\(\s*(?=['\"`])")
NEXT_HANDLER = re.compile(r"^export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(", re.M)
NEST_ROUTE = re.compile(r"@(Get|Post|Put|Patch|Delete)\([^)]*\)\s*(?:@\w+\([^)]*\)\s*)*")
JS_WRITE = {"create", "createMany", "createManyAndReturn", "update", "updateMany", "upsert", "delete", "deleteMany",
            "insertMany", "bulkCreate", "updateOne", "replaceOne", "findOneAndUpdate", "findByIdAndUpdate",
            "findOneAndDelete", "findByIdAndDelete", "deleteOne", "destroy", "increment", "decrement", "insertOne",
            "findOrCreate"}
JS_SINGLE = {"findFirst", "findFirstOrThrow", "findUnique", "findUniqueOrThrow", "count", "aggregate", "groupBy",
             "findOne", "findById", "findByPk", "countDocuments", "estimatedDocumentCount", "exists"}


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _first_object(args: str) -> str | None:
    s = args.lstrip()
    if not s.startswith("{"):
        return None
    start = len(args) - len(s)
    return _js_block(args, start)


def _entries(obj: str | None) -> dict[str, str]:
    return {k: v for k, v, _ in top_level_entries(obj)} if obj else {}


def _chained(text: str, pos: int) -> tuple[list[str], int]:
    """Methods chained after a call that ends at ``pos`` (``.limit(10).populate('x')``)."""
    methods = []
    while True:
        m = re.match(r"\s*\.\s*(\w+)\s*\(", text[pos:])
        if not m:
            return methods, pos
        methods.append(m.group(1))
        body = _paren_body(text, pos + m.end() - 1)
        if body is None:
            return methods, pos
        pos = pos + m.end() + len(body) + 1


class JsChecks:
    def __init__(self, ctx, col: Collector) -> None:
        self.ctx, self.col, self.schema = ctx, col, col.schema
        self.models = {m.name for m in self.schema.unique_models() if m.orm == "mongoose"}

    def run(self) -> None:
        files = [f for f in self.ctx.files_with_suffix(".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
                 if not is_test_path(f) and not _is_exempt(f) and "node_modules/" not in f
                 and not re.search(r"(?:^|/)migrations?/", f)]
        for rel in files:
            for m in SEQ_MODEL.finditer(self.ctx.read(rel) or ""):
                self.models.add(m.group(1) or m.group(2))
        for rel in files:
            text = self.ctx.read(rel) or ""
            if not re.search(r"prisma|mongoose|sequelize|\.query\(|\.collection\(|\.find\w*\(|\.create\(", text):
                continue
            self._file(rel, text)

    def _queries(self, rel: str, text: str) -> list[Query]:
        out = []
        for m in PRISMA_CALL.finditer(text):
            if m.group(1).startswith("$"):
                continue
            args = _paren_body(text, m.end() - 1) or ""
            end = m.end() + len(args) + 1
            method = m.group(2)
            q = Query(None, "prisma", m.group(1), _line(text, m.start()), rel, method, start=m.start(), end=end,
                      text=text[m.start():end], write=method in JS_WRITE, single=method in JS_SINGLE)
            opts = _entries(_first_object(args))
            where = _entries(_first_object(opts.get("where", "")))
            model = self.schema.find(m.group(1))
            rels = model.relations if model else {}
            q.eq_cols = [k for k in where if k not in ("AND", "OR", "NOT") and k not in rels]
            q.filtered = bool(where)
            q.limited = "take" in opts
            q.paginated = "cursor" in opts and "take" in opts
            q.eager = set(_entries(_first_object(opts.get("include", "")))) | {
                k for k, v in _entries(_first_object(opts.get("select", ""))).items() if v.startswith("{")}
            ob = opts.get("orderBy", "")
            q.order_cols = re.findall(r"(\w+)\s*:\s*['\"`]?(?:asc|desc)", ob)
            out.append(q)
        for m in MODEL_CALL.finditer(text):
            if m.group(1) not in self.models:
                continue
            args = _paren_body(text, m.end() - 1) or ""
            end = m.end() + len(args) + 1
            chain, end2 = _chained(text, end)
            method = m.group(2)
            model = self.schema.find(m.group(1))
            orm = "mongoose" if model and model.orm == "mongoose" else "sequelize"
            q = Query(None, orm, m.group(1), _line(text, m.start()), rel, method, start=m.start(), end=end2,
                      text=text[m.start():end2], write=method in JS_WRITE, single=method in JS_SINGLE)
            first = _entries(_first_object(args))
            if orm == "sequelize":
                where = _entries(_first_object(first.get("where", "")))
                q.eq_cols, q.filtered = list(where), bool(where)
                q.limited = "limit" in first
                q.eager = {"include"} if "include" in first else set()
                q.in_tx_option = "transaction" in first or bool(re.search(r"\btransaction\s*[:,}]", args))
            else:
                q.eq_cols = [k for k in first if not k.startswith("$") and "." not in k]
                q.filtered = bool(first) or method in ("findById", "findByIdAndUpdate", "findByIdAndDelete")
                if method in ("findById", "findByIdAndUpdate", "findByIdAndDelete"):
                    q.eq_cols = ["_id"]
                q.limited = "limit" in chain
                q.streaming = "cursor" in chain
                q.eager = {"populate"} if "populate" in chain else set()
                q.in_tx_option = "session" in chain or bool(re.search(r"\bsession\s*[:,}]", args))
            out.append(q)
        for m in MONGO_DRIVER.finditer(text):
            args = _paren_body(text, m.end() - 1) or ""
            end = m.end() + len(args) + 1
            chain, end2 = _chained(text, end)
            method = m.group(2)
            first = _entries(_first_object(args))
            out.append(Query(None, "mongodb", m.group(1), _line(text, m.start()), rel, method, start=m.start(),
                             end=end2, text=text[m.start():end2], write=method in JS_WRITE,
                             single=method in JS_SINGLE, eq_cols=[k for k in first if not k.startswith("$")],
                             filtered=bool(first), limited="limit" in chain, streaming="stream" in chain))
        for m in JS_SQL.finditer(text):
            info = parse_sql_query(m.group(4))
            if not info:
                continue
            end = m.end()
            out.append(Query(None, "sql", info["table"], _line(text, m.start()), rel, m.group(1), start=m.start(),
                             end=end, text=text[m.start():end], write=info["verb"] in ("INSERT", "UPDATE", "DELETE"),
                             single=info["aggregate"], limited=info["limit"], filtered=info["where"],
                             eq_cols=[] if info["join"] else info["eq"], lock=info["for_update"]))
        return out

    def _scopes(self, text: str) -> list[tuple[int, int, int]]:
        """(head start, body start, body end) of every function-like block."""
        out = []
        for m in JS_FUNC_HEAD.finditer(text):
            block = _js_block(text, m.end() - 1)
            if block:
                out.append((m.start(), m.end() - 1, m.end() - 1 + len(block)))
        return out

    @staticmethod
    def _scope_of(scopes, pos):
        inner = [s for s in scopes if s[1] <= pos < s[2]]
        return max(inner, key=lambda s: s[1]) if inner else (0, 0, 10 ** 9)

    def _handlers(self, rel: str, text: str, scopes) -> list[tuple[int, int, str]]:
        """Request handlers as (start, end, HTTP method)."""
        out = []
        for m in JS_ROUTE_CALL.finditer(text):
            args = _paren_body(text, m.end() - 1)  # path, middleware and an inline handler (block or expression)
            if args is not None:
                out.append((m.end(), m.end() + len(args), m.group(1).upper()))
        for m in JS_HANDLER_REF.finditer(text):
            name = re.escape(m.group(2))
            decl = re.search(rf"(?:function\s+{name}\s*\(|(?:const|let|var)\s+{name}\s*=)", text)
            if decl:
                s = next((s for s in scopes if s[0] >= decl.start()), None)
                if s:
                    out.append((s[1], s[2], m.group(1).upper()))
        for m in list(NEXT_HANDLER.finditer(text)) + list(NEST_ROUTE.finditer(text)):
            s = next((s for s in scopes if s[0] >= m.start()), None)
            if s:
                out.append((s[1], s[2], m.group(1).upper()))
        return out

    def _file(self, rel: str, text: str) -> None:
        queries = self._queries(rel, text)
        if not queries and not re.search(r"\bBEGIN\b", text, re.I):
            return
        scopes = self._scopes(text)
        handlers = self._handlers(rel, text, scopes)
        for q in queries:
            self.col.record_lookup(q)
        self._loops(rel, text, queries)
        self._unbounded(rel, text, queries, handlers)
        self._transactions(rel, text, queries, scopes)
        self._races(rel, text, queries, scopes)

    # ------------------------------------------------------------------ N+1
    def _loops(self, rel, text, queries) -> None:
        loops = []
        for m in JS_FOR_OF.finditer(text):
            body = _js_block(text, m.end() - 1)
            literal = JS_LITERAL_ARRAY.fullmatch(m.group(2).strip())
            if body and not literal:
                loops.append((m.start(), m.end() - 1, m.end() - 1 + len(body), set(re.findall(r"\w+", m.group(1)))
                              - {"const", "let", "var"}, False))
        for m in JS_FOR_I.finditer(text):
            body = _js_block(text, m.end() - 1)
            if body:
                loops.append((m.start(), m.end() - 1, m.end() - 1 + len(body), {m.group(1)}, False))
        for m in JS_ITER_CB.finditer(text):
            params = m.group(2) if m.group(2) is not None else m.group(3) or ""
            names = [p.split("=")[0].strip(" {}[]:") for p in re.split(r",", params) if p.strip()]
            if m.group(1) == "reduce":
                names = names[1:2]
            vars_ = {w for n in names for w in re.findall(r"\w+", n)}
            if not vars_:
                continue
            if text[m.end():m.end() + 1] == "{":
                body = _js_block(text, m.end())
                start, end = m.end(), m.end() + len(body or "")
            else:
                args = _paren_body(text, m.start() + len(m.group(1)) + 1)
                start, end = m.end(), m.start() + len(m.group(1)) + 2 + len(args or "")
            parallel = bool(re.search(r"Promise\.(?:all|allSettled)\(\s*[\w.]*$", text[max(0, m.start() - 80):
                                                                                        m.start()]))
            loops.append((m.start(), start, end, vars_, parallel))
        reported = set()
        for start, body_start, body_end, vars_, parallel in loops:
            if start in reported:
                continue
            for q in queries:
                if not (body_start <= q.start < body_end):
                    continue
                used = [v for v in vars_ if re.search(rf"(?<![\w.$]){re.escape(v)}\b", q.text)]
                if not used:
                    continue
                reported.add(start)
                self.col.add(Issue(
                    "database.n-plus-one", f"Database {'write' if q.write else 'query'} inside a loop (N+1)",
                    Severity.LOW if q.write else Severity.MEDIUM, Confidence.HIGH, FindingKind.ESTIMATE,
                    f"`{' '.join(q.text.split())[:100]}` runs once per element of the loop at line "
                    f"{_line(text, start)} (it uses `{used[0]}`)"
                    + (", in parallel through Promise.all: N concurrent queries also exhaust the connection pool"
                       if parallel else "") + ". N items cost N+1 round trips. (Static estimate.)",
                    "Query once for all items (`where: { id: { in: ids } }` / `{ _id: { $in: ids } }` / "
                    "`include`/`populate` on the parent query) and look results up in a Map; use createMany / "
                    "insertMany / bulkCreate for writes.", rel, q.line))
                break
            if start in reported:
                continue
            body = text[body_start:body_end]
            for v in vars_:
                lazy = re.search(rf"(?<![\w.$]){re.escape(v)}\.get[A-Z]\w*\(", body)
                if lazy:
                    reported.add(start)
                    self.col.add(Issue(
                        "database.n-plus-one", "Lazy association getter called in a loop (N+1)", Severity.MEDIUM,
                        Confidence.MEDIUM, FindingKind.ESTIMATE,
                        f"`{lazy.group(0)})` is a Sequelize association getter: each call issues a query, once per "
                        f"element of the loop at line {_line(text, start)}.",
                        "Load the association with `include` on the parent query.", rel,
                        _line(text, body_start + lazy.start())))
                    break

    # ------------------------------------------------------------------ unbounded / pagination
    def _unbounded(self, rel, text, queries, handlers) -> None:
        for q in queries:
            if q.write or q.bounded or q.streaming or self.col.reference(q) or self.col.unique_lookup(q):
                continue
            if q.orm == "sql" and not q.model:
                continue
            handler = next((h for h in handlers if h[0] <= q.start < h[1]), None)
            if handler:
                if handler[2] not in ("GET", "ALL") or JS_PAGINATION.search(text[handler[0]:handler[1]]):
                    continue
                self.col.add(Issue(
                    "database.missing-pagination", f"GET handler returns every matching {q.model} row",
                    Severity.LOW if q.filtered else Severity.MEDIUM, Confidence.MEDIUM, FindingKind.ESTIMATE,
                    f"`{' '.join(q.text.split())[:100]}` has no take/limit and the handler reads no page, limit or "
                    "cursor parameter, so the response grows with the collection"
                    + (" (the filter narrows it but does not bound it)" if q.filtered else "") + ". (Static estimate.)",
                    "Accept `limit` (with a server-side maximum) and a cursor, and pass them as take/skip/cursor "
                    "(Prisma), .limit()/.skip() or a range on an indexed key (MongoDB), limit/offset (Sequelize).",
                    rel, q.line))
            elif not q.filtered:
                self.col.add(Issue(
                    "database.unbounded-query", f"Query loads the whole {q.model} collection", Severity.LOW,
                    Confidence.MEDIUM, FindingKind.ESTIMATE,
                    f"`{' '.join(q.text.split())[:100]}` has no filter and no limit, so every row is loaded into "
                    "memory at once. (Static estimate.)",
                    "Process in batches (cursor-based take/skip, Mongoose `.cursor()`, Sequelize limit/offset).",
                    rel, q.line))

    # ------------------------------------------------------------------ transactions
    def _tx_regions(self, text: str) -> list[tuple[int, int]]:
        regions = []
        for m in re.finditer(r"\.\$transaction\(|\.transaction\(|\.withTransaction\(", text):
            args = _paren_body(text, m.end() - 1)
            if args is not None:
                regions.append((m.end(), m.end() + len(args)))
        return regions

    def _transactions(self, rel, text, queries, scopes) -> None:
        for m in re.finditer(r"\b(\w*[pP]ool\w*)\.query\(\s*['\"`]\s*BEGIN\b", text, re.I):
            self.col.add(Issue(
                "database.transaction-on-pool", "Transaction started with pool.query('BEGIN')", Severity.HIGH,
                Confidence.HIGH, FindingKind.CONFIRMED,
                f"`{m.group(1)}.query()` takes any free connection from the pool for each call, so BEGIN, the "
                "statements and COMMIT can run on different connections: the statements are not in the transaction, "
                "and the connection left inside BEGIN is handed to another request.",
                "Check out one client (`const client = await pool.connect()`), run BEGIN / statements / COMMIT or "
                "ROLLBACK on it, and `client.release()` in a finally block.", rel, _line(text, m.start())))
        regions = self._tx_regions(text)
        by_scope: dict[tuple, list[Query]] = defaultdict(list)
        for q in queries:
            if not q.write or q.in_tx_option or any(a <= q.start < b for a, b in regions):
                continue
            by_scope[self._scope_of(scopes, q.start)].append(q)
        for scope, writes in by_scope.items():
            body = text[scope[1]:scope[2]] if scope[2] < 10 ** 9 else text
            if re.search(r"startTransaction\(|\bBEGIN\b", body):
                continue
            if len(writes) < 2:
                continue
            mongo = all(w.orm in ("mongoose", "mongodb") for w in writes)
            models = sorted({w.model or "" for w in writes})
            if mongo and len(models) < 2:
                continue  # several writes to one collection: usually independent documents
            self.col.add(Issue(
                "database.non-atomic-writes", f"{len(writes)} related writes without a transaction",
                Severity.LOW if mongo else Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                "These writes in one function run as separate statements: if a later one fails, the earlier ones stay "
                "committed and the data is left half-updated ("
                + "; ".join(f"line {w.line}: {w.model}.{w.method}" for w in writes[:6]) + ")."
                + (" MongoDB multi-document transactions need a replica set or sharded cluster." if mongo else ""),
                "Run them in one transaction: `prisma.$transaction([...])` or an interactive `$transaction(async "
                "(tx) => ...)`, `sequelize.transaction(async (t) => ...)` passing `{ transaction: t }`, or "
                "`session.withTransaction()` in MongoDB; or use a nested write.", rel, writes[1].line))
        for a, b in regions:
            side = JS_SIDE_EFFECT.search(text, a, b)
            if side:
                self.col.add(Issue(
                    "database.side-effect-in-transaction", f"`{side.group(0).rstrip('(')}` called inside a transaction",
                    Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    "The external call runs while the transaction is open: if the transaction rolls back, the call "
                    "(payment, e-mail, queued job, webhook) has already happened; a slow remote call also holds the "
                    "transaction and its locks open (Prisma aborts interactive transactions after 5 s by default).",
                    "Do the external call after the transaction commits, or record it in an outbox table inside the "
                    "transaction and send it from a worker.", rel, _line(text, side.start())))

    # ------------------------------------------------------------------ races
    def _races(self, rel, text, queries, scopes) -> None:
        reads = re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+([^;\n]+)", text)
        by_start = {q.start: q for q in queries}
        for m in reads:
            var = m.group(1)
            q = next((by_start[s] for s in by_start if m.start(2) <= s < m.start(2) + 5), None)
            if q is None or q.write and q.method not in ("findOneAndUpdate", "updateOne") or q.lock:
                continue
            scope = self._scope_of(scopes, m.start())
            after = text[q.end:scope[2]] if scope[2] < 10 ** 9 else text[q.end:]
            v = re.escape(var)
            if q.single and not q.write:
                arith = re.search(rf"(?<![\w.]){v}\.(\w+)\s*(?:\+=|-=|\+\+|--)|"
                                  rf"(?<![\w.]){v}\.(\w+)\s*=\s*{v}\.\2\s*[-+]", after)
                prisma_arith = re.search(rf"\.{re.escape(q.model or '')}\.update\(\s*\{{[\s\S]{{0,400}}?"
                                         rf"(?<![\w.]){v}\.(\w+)\s*[-+]", after) if q.orm == "prisma" else None
                hit = prisma_arith or (arith if re.search(rf"(?<![\w.]){v}\.save\(", after) else None)
                if hit:
                    field_name = next(g for g in hit.groups() if g)
                    self.col.add(Issue(
                        "database.lost-update",
                        f"Read-modify-write on `{var}.{field_name}` can lose concurrent updates",
                        Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
                        f"`{var}` is read at line {q.line} and `{field_name}` is recomputed in application code before "
                        "being written back. Two concurrent requests both read the old value; the second write "
                        "silently overwrites the first.",
                        "Use an atomic update: Prisma `{ " + field_name + ": { increment: n } }`, MongoDB `$inc`, "
                        "Sequelize `increment()`; or a conditional update on a version column.",
                        rel, _line(text, q.end + hit.start())))
                    continue
            if q.single and not q.write and q.method in ("findFirst", "findFirstOrThrow", "findOne", "exists",
                                                         "count", "countDocuments"):
                if not q.eq_cols or self.col.unique_lookup(q) or not self.col.model(q):
                    continue
                guard = re.search(rf"\bif\s*\(\s*!?\s*{v}\b", after)
                create = re.search(rf"\.{re.escape(q.model)}\.create\(|\b{re.escape(q.model)}\.create\(|"
                                   rf"\bnew\s+{re.escape(q.model)}\(", after) if q.model else None
                if guard and create and guard.start() < create.start():
                    self._race(rel, q, _line(text, q.end + create.start()), "check-then-insert",
                               f"line {q.line} looks for an existing {q.model} and line "
                               f"{_line(text, q.end + create.start())} creates one when none was found")
        for q in queries:
            if q.method in ("findOneAndUpdate", "updateOne", "updateMany", "upsert") and re.search(
                    r"\bupsert\s*:\s*true", q.text) and q.eq_cols and self.col.model(q) and \
                    not self.col.unique_lookup(q):
                self._race(rel, q, q.line, "upsert", "MongoDB documents that concurrent upserts on a filter without a "
                                                     "unique index can insert duplicates")

    def _race(self, rel, q: Query, line: int, what: str, detail: str) -> None:
        m = self.col.model(q)
        cols = ", ".join(q.eq_cols)
        self.col.add(Issue(
            "database.check-then-insert", f"{what} on {m.name}({cols}) without a unique constraint",
            Severity.MEDIUM, Confidence.MEDIUM, FindingKind.POTENTIAL,
            f"{detail}. Nothing in the schema makes ({cols}) unique, so concurrent requests can both see 'not found' "
            "and both insert.",
            f"Add a unique constraint/index on ({cols}) (@unique / @@unique, `unique: true` index) and handle the "
            "duplicate-key error, or use an upsert on that unique key.", rel, line))


def run_query_checks(ctx, schema: Schema, profile) -> list[Issue]:
    col = Collector(schema, profile)
    PythonChecks(ctx, col).run()
    JsChecks(ctx, col).run()
    return col.issues + col.lookup_issues()
