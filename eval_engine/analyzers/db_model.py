"""The database schema as the application defines it, read statically into one model.

Sources: SQLAlchemy declarative models and Core ``Table`` objects, Django models, Prisma schemas, Mongoose schemas,
and SQL DDL — schema files and every forward migration (SQL, Alembic, Django, knex, Sequelize) replayed in order.
Migrations matter because indexes and foreign keys are often created there and never declared on the ORM model;
treating the ORM model as the whole truth would report indexes that exist.

Column names in indexes and keys are database names (lower case); ``Model.column(attr)`` resolves the attribute
names queries use. Nothing here decides whether something is a problem: that is the checks' job.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from . import db_migrations as mig
from .base import is_test_path

MODEL_BASE = re.compile(r"(?:\w+\.)*(?:Model|\w*Base|DeclarativeBase|AsyncAttrs|SQLModel)")
SA_COLUMN_FUNCS = ("Column", "mapped_column")
EAGER_LAZY = {"joined", "selectin", "subquery", "immediate", "raise", "raise_on_sql", "noload", "write_only"}


@dataclass
class Column:
    name: str                 # attribute / field name used in code
    db_name: str              # column name in the database (lower case)
    type: str = ""
    primary_key: bool = False
    unique: bool = False
    indexed: bool = False
    nullable: bool | None = None
    fk: str | None = None     # referenced "table.column", "table" or "Model.attr" (resolved via Schema.fk_target)
    on_delete: str | None = None
    line: int | None = None


@dataclass
class Relation:
    name: str
    target: str               # model name as written (resolved via Schema.find)
    kind: str                 # relationship | backref | fk | o2o | m2m | reverse | ref | generic
    line: int | None = None
    back_populates: str | None = None
    backref: str | None = None
    lazy: str | None = None
    secondary: bool = False
    explicit_join: bool = False
    related_name: str | None = None
    uselist: bool | None = None
    column: str | None = None  # db column holding the key, for fk / o2o / ref
    backref_lazy: str | None = None


@dataclass
class Model:
    name: str
    table: str
    orm: str                  # sqlalchemy | django | prisma | mongoose | sql
    file: str
    line: int
    columns: dict[str, Column] = field(default_factory=dict)       # by attribute name
    relations: dict[str, Relation] = field(default_factory=dict)
    indexes: list[tuple[tuple[str, ...], bool]] = field(default_factory=list)  # (db column names, unique)
    complete: bool = True     # False when a base class contributes columns eVal could not read
    bind: str | None = None
    app: str = ""

    def column(self, name: str) -> Column | None:
        name_l = name.lower()
        return self.columns.get(name) or next(
            (c for c in self.columns.values() if c.db_name == name_l or c.name.lower() == name_l), None)

    def by_db(self, db_name: str) -> Column | None:
        return next((c for c in self.columns.values() if c.db_name == db_name.lower()), None)

    @property
    def pk(self) -> list[Column]:
        return [c for c in self.columns.values() if c.primary_key]

    def is_indexed(self, col: Column) -> bool:
        """A b-tree lookup on ``col`` can use an index: key, unique, indexed, or the leading column of an index."""
        if col.primary_key and len(self.pk) == 1 or col.unique or col.indexed:
            return True
        if col.primary_key and self.pk and self.pk[0] is col:
            return True
        return any(cols and cols[0] == col.db_name for cols, _ in self.indexes)

    def unique_sets(self) -> list[set[str]]:
        """Column sets (db names) the database keeps unique."""
        sets = [{c.db_name} for c in self.columns.values() if c.unique]
        if self.pk:
            sets.append({c.db_name for c in self.pk})
        sets += [set(cols) for cols, unique in self.indexes if unique]
        return sets


@dataclass
class Schema:
    models: dict[str, Model] = field(default_factory=dict)
    migrations: list[mig.Migration] = field(default_factory=list)
    prisma_relation_mode: str | None = None
    prisma_provider: str | None = None

    def unique_models(self) -> list[Model]:
        """Each model once (single-table-inheritance subclasses share their parent's Model)."""
        return list({id(m): m for m in self.models.values()}.values())

    def find(self, name: str | None) -> Model | None:
        """By model name, then table name, case-insensitively (Prisma's ``prisma.orderItem`` → ``OrderItem``)."""
        if not name:
            return None
        if name in self.models:
            return self.models[name]
        low = name.lower()
        for m in self.models.values():
            if m.name.lower() == low or m.table == low:
                return m
        return None

    def fk_target(self, fk: str | None) -> tuple[Model | None, Column | None]:
        if not fk:
            return None, None
        table, _, col = fk.partition(".")
        model = self.find(table)
        if model is None:
            return None, None
        if col:
            return model, model.column(col)
        return model, model.pk[0] if len(model.pk) == 1 else None


def snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", name).lower()


def type_family(t: str | None) -> str:
    """Comparable type families: int16/int32/int64, uuid, string, bool, number, datetime, json, objectid…"""
    t = (t or "").lower().strip()
    t = re.sub(r"^(?:(?:db|sa|sqlalchemy|types|models|postgresql|mysql|sqlite|pg|dialects)\.)+", "", t)
    t = re.sub(r"^mapped\[(?:optional\[)?|\]+$", "", t)
    if not t or t in ("fk", "auto"):
        return ""
    if re.match(r"(?:big\w*|int8|bigserial)\b|bigautofield|positivebigintegerfield", t):
        return "int64"
    if re.match(r"(?:small\w*|int2|tinyint|smallserial)\b|positivesmallintegerfield", t):
        return "int16"
    if re.match(r"(?:int|integer|int4|serial|mediumint|autofield|integerfield|positiveintegerfield)\b", t):
        return "int32"
    if "uuid" in t:
        return "uuid"
    if "objectid" in t:
        return "objectid"
    if re.match(r"(?:str|string|varchar|char|text|nvarchar|nchar|unicode\w*|citext|character|charfield|textfield|"
                r"emailfield|slugfield|urlfield|enum)\b", t):
        return "string"
    if re.match(r"(?:bool|boolean|booleanfield|nullbooleanfield)\b", t):
        return "bool"
    if re.match(r"(?:numeric|decimal|float|double|real|money|number|decimalfield|floatfield)\b", t):
        return "number"
    if re.match(r"(?:date|time|timestamp|datetime|interval)", t):
        return "datetime"
    if "json" in t:
        return "json"
    return t.split("(")[0]


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _call_name(node) -> str:
    if not isinstance(node, ast.Call):
        return ""
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _ref_name(node) -> str:
    """``"app.Post"`` / ``Post`` / ``models.Post`` → ``Post``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.rsplit(".", 1)[-1]
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


# ============================================================================================ SQLAlchemy
@dataclass
class _Cls:
    node: ast.ClassDef
    file: str
    bases: list[str]
    text: str


def _class_body(cls: ast.ClassDef):
    for stmt in cls.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            yield stmt.target.id, stmt.value, ast.unparse(stmt.annotation), stmt.lineno
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            yield stmt.targets[0].id, stmt.value, "", stmt.lineno


def _is_sa_class(cls: ast.ClassDef, helpers=()) -> bool:
    for name, value, _, _ in _class_body(cls):
        if name in ("__tablename__", "__table__"):
            return True
        if isinstance(value, ast.Call) and (_call_name(value) in (*SA_COLUMN_FUNCS, "relationship")
                                            or _call_name(value) in helpers):
            return True
    return False


def _mapped_inner(annotation: str) -> str:
    m = re.match(r"Mapped\[(.*)\]$", annotation.replace(" ", ""))
    return m.group(1) if m else ""


def _sa_attr_column(attr: str, call: ast.Call, annotation: str, line: int) -> Column:
    d = mig.sa_column(call) or {}
    inner = _mapped_inner(annotation)
    optional = inner.startswith(("Optional[", "typing.Optional[")) or inner.endswith("|None") or "None|" in inner
    col_type = d.get("type") or re.sub(r"^(?:typing\.)?Optional\[|\]$|\|None|None\|", "", inner)
    nullable_node = _kw(call, "nullable")
    if nullable_node is not None and isinstance(_const(nullable_node), bool):
        nullable = _const(nullable_node)
    elif d.get("primary_key"):
        nullable = False
    elif _call_name(call) == "mapped_column" and inner:
        nullable = optional
    else:
        nullable = True
    return Column(attr, (d.get("name") or attr).lower(), col_type, d.get("primary_key", False), d.get("unique", False),
                  d.get("index", False), nullable, d.get("fk"), d.get("on_delete"), line)


def _sa_relation(attr: str, call: ast.Call, annotation: str, line: int) -> Relation:
    target = _ref_name(call.args[0]) if call.args else ""
    if not target:
        inner = _mapped_inner(annotation)
        target = re.sub(r"^(?:list|List|set|Set|Optional|typing\.\w+)\[|\]$|[\"']", "", inner).rsplit(".", 1)[-1]
    backref = _kw(call, "backref")
    backref_name, backref_lazy = None, None
    if isinstance(backref, ast.Constant):
        backref_name = backref.value
    elif isinstance(backref, ast.Call) and backref.args:
        backref_name = _const(backref.args[0])
        backref_lazy = _const(_kw(backref, "lazy"))
    return Relation(attr, target, "relationship", line, back_populates=_const(_kw(call, "back_populates")),
                    backref=backref_name, lazy=_const(_kw(call, "lazy")),
                    secondary=_kw(call, "secondary") is not None,
                    explicit_join=_kw(call, "primaryjoin") is not None or _kw(call, "foreign_keys") is not None,
                    uselist=_const(_kw(call, "uselist")), backref_lazy=backref_lazy)


def _table_args(cls: ast.ClassDef, model: Model) -> None:
    for name, value, _, _ in _class_body(cls):
        if name != "__table_args__" or value is None:
            continue
        for node in ast.walk(value):
            if not isinstance(node, ast.Call):
                continue
            fname = _call_name(node)
            if fname in ("Index", "UniqueConstraint", "PrimaryKeyConstraint"):
                args = node.args[1:] if fname == "Index" else node.args
                cols = tuple(c for c in (_col_ref(model, a) for a in args) if c)
                if cols:
                    unique = fname != "Index" or _const(_kw(node, "unique")) is True
                    model.indexes.append((cols, unique))
            elif fname == "ForeignKeyConstraint" and len(node.args) >= 2:
                locs, refs = mig._strs(node.args[0]), mig._strs(node.args[1])
                for loc, ref in zip(locs, refs, strict=False):
                    col = model.by_db(loc) or model.column(loc)
                    if col:
                        col.fk = ref


def _col_ref(model: Model, node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        col = model.column(node.value)
        return col.db_name if col else node.value.lower()
    if isinstance(node, ast.Attribute | ast.Name):
        name = node.attr if isinstance(node, ast.Attribute) else node.id
        col = model.column(name)
        return col.db_name if col else None
    return None


SCALAR_ANNOTATION = re.compile(r"^(?:Optional\[)?(?:str|int|float|bool|bytes|dict|list\[\w+\]|Decimal|decimal\."
                               r"Decimal|uuid\.UUID|UUID|datetime(?:\.\w+)?|date|time|timedelta|Any|JSON\w*)\]?$|"
                               r"\|None$")


def column_helpers(trees) -> dict[str, ast.Call]:
    """Functions that build columns (``def org_fk(): return mapped_column(ForeignKey(...), index=True)``): models
    that call them get the column the helper returns."""
    helpers = {}
    for _, tree in trees:
        for fn in tree.body:
            if not isinstance(fn, ast.FunctionDef):
                continue
            for ret in [n for n in ast.walk(fn) if isinstance(n, ast.Return)]:
                if isinstance(ret.value, ast.Call) and _call_name(ret.value) in SA_COLUMN_FUNCS:
                    helpers[fn.name] = ret.value
                    break
    return helpers


def _sqlalchemy(classes: dict[str, _Cls], schema: Schema, helpers: dict[str, ast.Call]) -> None:
    sa = {n: c for n, c in classes.items() if _is_sa_class(c.node, helpers)}

    def tablename(c: _Cls) -> str | None:
        for name, value, _, _ in _class_body(c.node):
            if name == "__tablename__" and isinstance(_const(value), str):
                return _const(value).lower()
            if name == "__tablename__":
                return ""  # declared_attr / computed
        return None

    def abstract(c: _Cls) -> bool:
        return any(n == "__abstract__" and _const(v) is True for n, v, _, _ in _class_body(c.node))

    def concrete(c: _Cls) -> bool:
        return not abstract(c) and (tablename(c) is not None or any(MODEL_BASE.fullmatch(b) for b in c.bases))

    models: dict[str, Model] = {}
    for name, c in sa.items():
        if not concrete(c):
            continue
        parent = next((b for b in c.bases if b in sa and concrete(sa[b])), None)
        if parent and tablename(c) is None:
            continue  # single-table inheritance: the subclass adds columns to its parent's table (handled below)
        table = tablename(c) or snake(name)
        models[name] = Model(name, table, "sqlalchemy", c.file, c.node.lineno)

    def contribute(model: Model, c: _Cls, seen: set[str]) -> None:
        for base in c.bases:
            short = base.rsplit(".", 1)[-1]
            if short in seen:
                continue
            if short in sa and short not in models:
                seen.add(short)
                contribute(model, sa[short], seen)
            elif short in classes:
                continue  # a visible class without columns (plain mixin) contributes nothing to the table
            elif not (MODEL_BASE.fullmatch(base) or short in models or base in ("object", "Generic")):
                model.complete = False  # e.g. a mixin from an installed package: its columns are unknown
        for attr, value, annotation, line in _class_body(c.node):
            if attr.startswith("__"):
                continue
            if value is None and annotation.startswith("Mapped[") and SCALAR_ANNOTATION.search(
                    _mapped_inner(annotation)):
                inner = _mapped_inner(annotation)
                optional = inner.startswith("Optional[") or inner.endswith("|None")
                model.columns[attr] = Column(attr, attr.lower(), re.sub(r"^Optional\[|\]$|\|None$", "", inner),
                                             nullable=optional, line=line)  # SQLAlchemy 2.0: annotation only
                continue
            if not isinstance(value, ast.Call):
                continue
            fname = _call_name(value)
            if fname in helpers and isinstance(value.func, ast.Name):
                model.columns[attr] = _sa_attr_column(attr, helpers[fname], annotation, line)
            elif fname in SA_COLUMN_FUNCS:
                model.columns[attr] = _sa_attr_column(attr, value, annotation, line)
            elif fname == "relationship":
                model.relations[attr] = _sa_relation(attr, value, annotation, line)
        for attr, value, _, _ in _class_body(c.node):
            if attr == "__bind_key__":
                model.bind = _const(value)

    for name, model in models.items():
        contribute(model, sa[name], {name})
        _table_args(sa[name].node, model)
    for name, c in sa.items():  # single-table inheritance children
        parent = next((b for b in c.bases if b in models), None)
        if parent and name not in models and tablename(c) is None:
            contribute(models[parent], c, {name})
            models[name] = models[parent]
    schema.models.update(models)


def _sqlalchemy_core(rel: str, tree: ast.Module, schema: Schema) -> None:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _call_name(node) == "Table" and node.args
                and isinstance(_const(node.args[0]), str)):
            continue
        table = _const(node.args[0]).lower()
        model = Model(table, table, "sqlalchemy", rel, node.lineno)
        for a in node.args[1:]:
            if isinstance(a, ast.Call) and _call_name(a) in SA_COLUMN_FUNCS:
                d = mig.sa_column(a) or {}
                if d.get("name"):
                    model.columns[d["name"]] = Column(d["name"], d["name"], d["type"], d["primary_key"],
                                                      d["unique"], d["index"], not d["not_null"], d["fk"],
                                                      d["on_delete"], a.lineno)
            elif isinstance(a, ast.Call) and _call_name(a) in ("Index", "UniqueConstraint", "PrimaryKeyConstraint"):
                args = a.args[1:] if _call_name(a) == "Index" else a.args
                cols = tuple(str(_const(x)).lower() for x in args if isinstance(_const(x), str))
                if cols:
                    model.indexes.append((cols, _call_name(a) != "Index" or _const(_kw(a, "unique")) is True))
        schema.models.setdefault(table, model)


def _module_indexes(tree: ast.Module, schema: Schema) -> None:
    """``Index("ix_users_email", User.email)`` declared at module level, outside the class."""
    for node in tree.body:
        call = node.value if isinstance(node, ast.Expr | ast.Assign) else None
        if not (isinstance(call, ast.Call) and _call_name(call) == "Index"):
            continue
        attrs = [a for a in call.args[1:] if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name)]
        if attrs and (model := schema.models.get(attrs[0].value.id)):
            cols = tuple(c for c in (_col_ref(model, a) for a in attrs) if c)
            model.indexes.append((cols, _const(_kw(call, "unique")) is True))


# ============================================================================================ Django
DJANGO_REL = {"ForeignKey": "fk", "OneToOneField": "o2o", "ManyToManyField": "m2m", "ParentalKey": "fk"}


def _django_app(rel: str) -> str:
    parts = rel.split("/")
    if parts[-1] == "models.py" and len(parts) >= 2:
        return parts[-2]
    if len(parts) >= 3 and parts[-2] == "models":
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else ""


def _django(classes: dict[str, _Cls], schema: Schema) -> None:
    names = {n for n, c in classes.items() if any(b in ("models.Model", "Model") for b in c.bases)
             and ("django" in c.text)}
    changed = True
    while changed:
        changed = False
        for n, c in classes.items():
            if n not in names and any(b.rsplit(".", 1)[-1] in names for b in c.bases):
                names.add(n)
                changed = True
    built: dict[str, Model] = {}

    def meta(c: _Cls) -> ast.ClassDef | None:
        return next((s for s in c.node.body if isinstance(s, ast.ClassDef) and s.name == "Meta"), None)

    def meta_value(c: _Cls, key: str):
        m = meta(c)
        for stmt in m.body if m else []:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == key:
                return stmt.value
        return None

    def build(n: str) -> Model:
        if n in built:
            return built[n]
        c = classes[n]
        app = str(_const(meta_value(c, "app_label")) or _django_app(c.file))
        table = str(_const(meta_value(c, "db_table")) or f"{app}_{n.lower()}").lower()
        model = Model(n, table, "django", c.file, c.node.lineno, app=app)
        for b in c.bases:
            short = b.rsplit(".", 1)[-1]
            if short in names and short != n:
                parent = build(short)
                if _const(meta_value(classes[short], "abstract")) is True:
                    model.columns.update({k: Column(**vars(v)) for k, v in parent.columns.items()
                                          if not (v.primary_key and v.name == "id")})
                    model.relations.update(parent.relations)
                    model.indexes += parent.indexes
                    model.complete = model.complete and parent.complete
            elif short not in ("Model",) and b not in ("models.Model",):
                model.complete = False
        for attr, value, _, line in _class_body(c.node):
            if not isinstance(value, ast.Call):
                continue
            ftype = _call_name(value)
            if ftype in DJANGO_REL:
                target = value.args[0] if value.args else _kw(value, "to")
                tname = _ref_name(target) if target is not None else ""
                if tname == "self":
                    tname = n
                if isinstance(target, ast.Attribute) and target.attr == "AUTH_USER_MODEL" or _call_name(
                        target) == "get_user_model":
                    tname = "User"
                kind = DJANGO_REL[ftype]
                rn = _const(_kw(value, "related_name"))
                rel_obj = Relation(attr, tname, kind, line, related_name=rn)
                if kind != "m2m":
                    db_col = str(_const(_kw(value, "db_column")) or f"{attr}_id").lower()
                    on_delete = _kw(value, "on_delete") or (value.args[1] if len(value.args) > 1 else None)
                    model.columns[f"{attr}_id"] = Column(
                        f"{attr}_id", db_col, "fk", unique=kind == "o2o",
                        indexed=_const(_kw(value, "db_index")) is not False,
                        nullable=_const(_kw(value, "null")) is True, fk=tname,
                        on_delete=ast.unparse(on_delete).rsplit(".", 1)[-1] if on_delete is not None else None,
                        line=line)
                    rel_obj.column = db_col
                else:
                    rel_obj.secondary = _kw(value, "through") is not None
                model.relations[attr] = rel_obj
            elif ftype in ("GenericForeignKey",):
                model.relations[attr] = Relation(attr, "", "generic", line)
            elif ftype.endswith("Field"):
                db_col = str(_const(_kw(value, "db_column")) or attr).lower()
                model.columns[attr] = Column(attr, db_col, ftype.lower(), _const(_kw(value, "primary_key")) is True,
                                             _const(_kw(value, "unique")) is True,
                                             _const(_kw(value, "db_index")) is True,
                                             _const(_kw(value, "null")) is True, None, None, line)
        if not any(col.primary_key for col in model.columns.values()):
            model.columns["id"] = Column("id", "id", "auto", primary_key=True, nullable=False)

        def field_cols(node) -> tuple[str, ...]:
            out = []
            for f in mig._strs(node):
                f = f.lstrip("-")
                rel_ = model.relations.get(f)
                out.append(rel_.column if rel_ and rel_.column else (model.column(f).db_name if model.column(f)
                                                                     else f))
            return tuple(out)

        for key, unique in (("unique_together", True), ("index_together", False)):
            v = meta_value(c, key)
            groups = v.elts if isinstance(v, ast.List | ast.Tuple) else []
            if groups and all(isinstance(g, ast.Constant) for g in groups):
                groups = [v]
            for g in groups:
                model.indexes.append((field_cols(g), unique))
        for key in ("indexes", "constraints"):
            v = meta_value(c, key)
            for call in v.elts if isinstance(v, ast.List | ast.Tuple) else []:
                if isinstance(call, ast.Call) and _kw(call, "fields") is not None:
                    unique = _call_name(call) == "UniqueConstraint" and _kw(call, "condition") is None
                    if _call_name(call) in ("Index", "UniqueConstraint"):
                        model.indexes.append((field_cols(_kw(call, "fields")), unique))
        built[n] = model
        return model

    for n in names:
        c = classes[n]
        model = build(n)
        abstract = _const(meta_value(c, "abstract")) is True
        if not abstract and _const(meta_value(c, "proxy")) is not True:
            schema.models[n] = model


# ============================================================================================ Prisma
PRISMA_SCALARS = {"String", "Int", "BigInt", "Float", "Decimal", "Boolean", "DateTime", "Json", "Bytes",
                  "Unsupported"}


def _prisma(rel: str, text: str, schema: Schema) -> None:
    clean = re.sub(r"//[^\n]*", "", text)
    ds = re.search(r"datasource\s+\w+\s*\{([^}]*)\}", clean)
    if ds:
        if m := re.search(r'provider\s*=\s*"(\w+)"', ds.group(1)):
            schema.prisma_provider = m.group(1)
        if m := re.search(r'(?:relationMode|referentialIntegrity)\s*=\s*"(\w+)"', ds.group(1)):
            schema.prisma_relation_mode = m.group(1)
    blocks = list(re.finditer(r"^\s*(model|view)\s+(\w+)\s*\{", text, re.M))
    model_names = {b.group(2) for b in blocks}
    enums = set(re.findall(r"^\s*enum\s+(\w+)\s*\{", text, re.M))
    mongo = schema.prisma_provider == "mongodb"
    for b in blocks:
        name = b.group(2)
        start_line = text.count("\n", 0, b.start()) + 1
        end = text.find("\n}", b.end())
        body = text[b.end(): end if end >= 0 else len(text)]
        model = Model(name, name.lower(), "prisma", rel, start_line)
        relations = []
        for i, raw in enumerate(body.split("\n")):
            line = raw.split("//", 1)[0].strip()
            lineno = start_line + i
            if not line:
                continue
            if line.startswith("@@"):
                if m := re.match(r'@@map\(\s*"([^"]+)"', line):
                    model.table = m.group(1).lower()
                elif m := re.match(r"@@(index|unique|id)\(\s*(?:fields\s*:\s*)?\[([^\]]*)\]", line):
                    cols = tuple(re.split(r"[\s(]", c.strip(), maxsplit=1)[0] for c in m.group(2).split(",")
                                 if c.strip())
                    model.indexes.append((cols, m.group(1) != "index"))
                    if m.group(1) == "id":
                        for c in cols:
                            if c in model.columns:
                                model.columns[c].primary_key = True
                continue
            f = re.match(r"(\w+)\s+(\w+)(\[\])?(\?)?\s*(.*)$", line)
            if not f:
                continue
            fname, ftype, is_list, optional, attrs = f.groups()
            if ftype in model_names and ftype not in PRISMA_SCALARS:
                rel_m = re.search(r"@relation\(([^)]*)\)", attrs)
                fields_m = re.search(r"fields\s*:\s*\[([^\]]*)\]", rel_m.group(1)) if rel_m else None
                refs_m = re.search(r"references\s*:\s*\[([^\]]*)\]", rel_m.group(1)) if rel_m else None
                od = re.search(r"onDelete\s*:\s*(\w+)", rel_m.group(1)) if rel_m else None
                kind = "reverse" if is_list or not fields_m else ("ref" if mongo else "fk")
                relations.append((Relation(fname, ftype, kind, lineno, uselist=bool(is_list)),
                                  [x.strip() for x in fields_m.group(1).split(",")] if fields_m else [],
                                  [x.strip() for x in refs_m.group(1).split(",")] if refs_m else [],
                                  od.group(1) if od else None))
                continue
            db_name = re.search(r'@map\(\s*"([^"]+)"', attrs)
            native = re.search(r"@db\.(\w+)", attrs)
            col_type = (native.group(1) if native else ftype) if ftype not in enums else "enum"
            model.columns[fname] = Column(
                fname, (db_name.group(1) if db_name else fname).lower(), col_type,
                primary_key="@id" in attrs, unique="@unique" in attrs, nullable=bool(optional), line=lineno)
        for rel_obj, fields, refs, on_delete in relations:
            model.relations[rel_obj.name] = rel_obj
            for local, remote in zip(fields, refs or ["id"] * len(fields), strict=False):
                col = model.columns.get(local)
                if col:
                    col.fk = f"{rel_obj.target}.{remote}"
                    col.on_delete = on_delete
                    rel_obj.column = col.db_name
        # Indexes list Prisma field names; store database names.
        model.indexes = [(tuple(model.columns[c].db_name if c in model.columns else c.lower() for c in cols), u)
                         for cols, u in model.indexes]
        schema.models[name] = model


# ============================================================================================ Mongoose
SCHEMA_DECL = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*new\s+(?:mongoose\.)?Schema\s*(?:<[^>]*>)?\(\s*\{")
MODEL_DECL = re.compile(r"""\b(?:mongoose\.)?model\s*(?:<[^>]*>)?\(\s*["'`](\w+)["'`]\s*,\s*(\w+)""")
SCHEMA_INDEX = re.compile(r"(\w+)\.index\(\s*\{([^}]*)\}\s*(?:,\s*\{([^}]*)\})?")


def top_level_entries(block: str) -> list[tuple[str, str, int]]:
    """``{ a: 1, b: { c: 2 }, 'd': [x] }`` → [(key, value text, offset)] for the outermost object only."""
    inner = block[1:-1] if block.startswith("{") else block
    entries, depth, start, quote = [], 0, 0, None
    for i, ch in enumerate(inner + ","):
        if quote:
            if ch == quote and inner[i - 1:i] != "\\":
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        elif ch == "," and depth == 0:
            part = inner[start:i]
            m = re.match(r"\s*(?:\.\.\.\w+|['\"`]?([\w$.-]+)['\"`]?\s*:\s*(.*))", part, re.S)
            if m and m.group(1):
                entries.append((m.group(1), m.group(2).strip(), start + 1 + (len(part) - len(part.lstrip()))))
            elif re.fullmatch(r"\s*(\w+)\s*", part):  # shorthand { email }
                name = part.strip()
                entries.append((name, name, start + 1))
            start = i + 1
    return entries


def _mongoose(rel: str, text: str, schema: Schema) -> None:
    from .architecture import _js_block

    var_to_model = {m.group(2): m.group(1) for m in MODEL_DECL.finditer(text)}
    for decl in SCHEMA_DECL.finditer(text):
        var = decl.group(1)
        block = _js_block(text, decl.end() - 1)
        if not block:
            continue
        name = var_to_model.get(var) or re.sub(r"Schema$", "", var)[:1].upper() + re.sub(r"Schema$", "", var)[1:]
        model = Model(name, name.lower(), "mongoose", rel, text.count("\n", 0, decl.start()) + 1)
        model.columns["_id"] = Column("_id", "_id", "objectid", primary_key=True, nullable=False)
        base = decl.end() - 1
        for key, value, off in top_level_entries(block):
            line = text.count("\n", 0, base + off) + 1
            opts = value
            is_array = value.startswith("[")
            if is_array:
                opts = value[1:].strip()
            col_type = (re.search(r"\btype\s*:\s*([\w.]+)", opts) or re.match(r"([\w.]+)", opts))
            ref = re.search(r"\bref\s*:\s*['\"`](\w+)['\"`]", opts)
            column = Column(key, key.lower(), (col_type.group(1) if col_type else "mixed").lower(),
                            unique=bool(re.search(r"\bunique\s*:\s*true", opts)),
                            indexed=bool(re.search(r"\bindex\s*:\s*true", opts)),
                            nullable=not re.search(r"\brequired\s*:\s*(?:true|\[)", opts), line=line)
            if ref:
                column.fk = ref.group(1)
                model.relations[key] = Relation(key, ref.group(1), "ref", line, uselist=is_array, column=key.lower())
            model.columns[key] = column
        for ix in SCHEMA_INDEX.finditer(text):
            if ix.group(1) == var:
                cols = tuple(k.strip().strip("'\"`").lower() for k in re.findall(r"([\w.'\"`]+)\s*:", ix.group(2)))
                model.indexes.append((cols, bool(ix.group(3) and re.search(r"unique\s*:\s*true", ix.group(3)))))
        schema.models.setdefault(name, model)


# ============================================================================================ SQL replay
@dataclass
class _Table:
    columns: dict[str, Column]
    indexes: list[tuple[tuple[str, ...], bool]]
    file: str
    line: int


def _replay(migrations: list[mig.Migration], schema_files: list[tuple[str, list[mig.Op]]]) -> dict[str, _Table]:
    tables: dict[str, _Table] = {}
    named: dict[str, tuple[str, tuple[str, ...]]] = {}

    def table(name: str, rel: str, line: int) -> _Table:
        return tables.setdefault(name, _Table({}, [], rel, line))

    def col_from(d: dict, line: int) -> Column:
        return Column(d["name"], d["name"], d.get("type", ""), d.get("primary_key", False), d.get("unique", False),
                      d.get("index", False) or d.get("indexed", False), not d.get("not_null", False), d.get("fk"),
                      d.get("on_delete"), line)

    sources = [(rel, ops) for rel, ops in schema_files] + [(m.file, m.ops) for m in migrations if m.tool != "django"]
    for rel, ops in sources:
        for op in ops:
            if not op.table and op.kind != "drop_index":
                continue
            if op.kind == "create_table":
                t = tables[op.table] = _Table({}, [], rel, op.line)
                for d in op.detail.get("columns", []):
                    if d.get("name"):
                        t.columns[d["name"]] = col_from(d, op.line)
                for c in op.detail.get("pk", []):
                    if c in t.columns:
                        t.columns[c].primary_key = True
                if len(op.detail.get("pk", [])) > 1:
                    t.indexes.append((tuple(op.detail["pk"]), True))
                t.indexes += [(tuple(u), True) for u in op.detail.get("uniques", [])]
                t.indexes += [(tuple(ix), False) for ix in op.detail.get("indexes", [])]
                for locs, ref, on_delete in op.detail.get("fks", []):
                    for c in locs:
                        if c in t.columns:
                            t.columns[c].fk, t.columns[c].on_delete = ref, on_delete
            elif op.kind == "drop_table":
                tables.pop(op.table, None)
            elif op.kind == "rename_table" and op.table in tables and op.detail.get("to"):
                tables[op.detail["to"]] = tables.pop(op.table)
            elif op.kind == "add_column" and op.column:
                table(op.table, rel, op.line).columns[op.column] = col_from({**op.detail, "name": op.column}, op.line)
            elif op.kind == "drop_column" and op.table in tables:
                t = tables[op.table]
                t.columns.pop(op.column, None)
                t.indexes = [(cols, u) for cols, u in t.indexes if op.column not in cols]
            elif op.kind == "rename_column" and op.table in tables and op.column in tables[op.table].columns:
                t, new = tables[op.table], op.detail.get("to", "")
                col = t.columns.pop(op.column)
                col.name = col.db_name = new
                t.columns[new] = col
                t.indexes = [(tuple(new if c == op.column else c for c in cols), u) for cols, u in t.indexes]
            elif op.kind == "alter_type" and op.table in tables and op.column in tables[op.table].columns:
                tables[op.table].columns[op.column].type = op.detail.get("type", "")
            elif op.kind == "add_fk":
                t = table(op.table, rel, op.line)
                for c in op.columns:
                    t.columns.setdefault(c, Column(c, c, line=op.line)).fk = op.detail.get("ref") or None
                    t.columns[c].on_delete = op.detail.get("on_delete")
            elif op.kind in ("add_unique", "add_pk", "create_index") and op.columns:
                table(op.table, rel, op.line).indexes.append((op.columns, op.kind != "create_index"
                                                              or op.detail.get("unique", False)))
                if op.detail.get("name"):
                    named[op.detail["name"].lower()] = (op.table, op.columns)
            elif op.kind == "drop_index" and op.detail.get("name", "").lower() in named:
                tname, cols = named.pop(op.detail["name"].lower())
                if tname in tables:
                    t = tables[tname]
                    for i, (c, _) in enumerate(t.indexes):
                        if c == cols:
                            del t.indexes[i]
                            break
    return tables


def _merge(schema: Schema, tables: dict[str, _Table]) -> None:
    by_table: dict[str, Model] = {}
    for m in schema.models.values():
        by_table.setdefault(m.table, m)
    for name, t in tables.items():
        model = by_table.get(name)
        if model is None:
            if not t.columns:
                continue
            model = Model(name, name, "sql", t.file, t.line, columns={c.name: c for c in t.columns.values()},
                          indexes=list(t.indexes))
            schema.models.setdefault(name, model)
            continue
        model.indexes += [ix for ix in t.indexes if ix not in model.indexes]
        for c in t.columns.values():
            mine = model.by_db(c.db_name)
            if mine and c.fk and not mine.fk:
                mine.fk, mine.on_delete = c.fk, mine.on_delete or c.on_delete
            if mine and c.unique:
                mine.unique = True


def _finalize(schema: Schema) -> None:
    """Reverse accessors: SQLAlchemy backrefs and Django reverse relations become relations on the target."""
    for model in schema.unique_models():
        for rel in list(model.relations.values()):
            target = schema.find(rel.target)
            if target is None:
                continue
            if rel.kind == "relationship" and rel.backref and rel.backref not in target.relations:
                target.relations[rel.backref] = Relation(rel.backref, model.name, "backref", rel.line,
                                                         lazy=rel.backref_lazy, back_populates=rel.name)
            elif model.orm == "django" and rel.kind in ("fk", "o2o", "m2m"):
                if rel.related_name and rel.related_name.endswith("+"):
                    continue
                accessor = rel.related_name or (model.name.lower() if rel.kind == "o2o"
                                                else f"{model.name.lower()}_set")
                target.relations.setdefault(accessor, Relation(accessor, model.name, "reverse", rel.line,
                                                               uselist=rel.kind != "o2o"))


# ============================================================================================ entry point
def _table_resolver(schema: Schema):
    def table_of(app: str, model_name: str) -> str:
        m = schema.models.get(model_name)
        if m is None:
            m = next((x for x in schema.models.values() if x.orm == "django" and x.name.lower() == model_name.lower()
                      and (not app or x.app == app)), None)
        return m.table if m else f"{app}_{model_name.lower()}"
    return table_of


def build_schema(ctx) -> Schema:
    schema = Schema()
    classes: dict[str, _Cls] = {}
    trees = []
    for rel in ctx.python_files():
        if is_test_path(rel) or "/migrations/" in f"/{rel}" or "/versions/" in f"/{rel}":
            continue
        text = ctx.read(rel) or ""
        if not re.search(r"Column\(|mapped_column\(|models\.Model|django\.db|Table\(|relationship\(|\bModel\b",
                         text):
            continue
        tree = ctx.python_ast(rel)
        if tree is None:
            continue
        trees.append((rel, tree))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.setdefault(node.name, _Cls(node, rel, [ast.unparse(b) for b in node.bases], text))
    _django(classes, schema)
    _sqlalchemy({n: c for n, c in classes.items() if n not in schema.models}, schema, column_helpers(trees))
    for rel, tree in trees:
        _sqlalchemy_core(rel, tree, schema)
        _module_indexes(tree, schema)
    for rel in ctx.files_with_suffix(".prisma"):
        _prisma(rel, ctx.read(rel) or "", schema)
    for rel in ctx.files_with_suffix(".js", ".ts", ".mjs", ".cjs"):
        if is_test_path(rel) or "node_modules/" in rel:
            continue
        text = ctx.read(rel) or ""
        if "Schema(" in text and "mongoose" in text:
            _mongoose(rel, text, schema)
    schema.migrations = mig.discover(ctx, _table_resolver(schema))
    schema_files = [(rel, mig.parse_sql(ctx.read(rel) or "")) for rel in ctx.files_with_suffix(".sql")
                    if not is_test_path(rel) and not mig.is_sql_migration(rel) and not mig.DOWN_MIGRATION.search(rel)]
    _merge(schema, _replay(schema.migrations, schema_files))
    _finalize(schema)
    return schema
