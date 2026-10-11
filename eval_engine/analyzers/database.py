"""Database design and data-access safety, for PostgreSQL, MySQL, SQLite and (where it is used) MongoDB.

* SQL built from strings; missing primary keys, money stored as floating point, natural keys without a unique
  constraint; ORM models without migrations (this module).
* Schema: foreign keys without an index, columns that reference another table without a foreign key, inconsistent
  relationships (asymmetric back_populates, no join path, mismatched key types, SET NULL on NOT NULL, Django
  accessor clashes, unknown Mongoose refs), and duplicated data (copied columns, counter caches) — ``db_checks``.
* Migrations: destructive operations, operations that lock or break a live database (per engine), and migrations
  that cannot be reversed — ``db_checks``.
* Queries: N+1 queries and lazy loads in loops, unbounded queries, list endpoints without pagination, filters on
  unindexed columns, non-atomic multi-write operations, commits and rollbacks, side effects inside transactions,
  lost updates, check-then-insert races and misused row locks — ``db_queries``.

The schema comes from ORM models and every forward migration (``db_model``), and the engine from the application
profile, so a check only fires where it is true for the engine in use (InnoDB indexes foreign keys itself; only
PostgreSQL blocks writes during a plain CREATE INDEX; SQLite ignores FOR UPDATE).
"""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .db_checks import migration_checks, schema_checks
from .db_model import build_schema
from .db_queries import run_query_checks
from .registry import register

SQL_KEYWORDS = re.compile(r"(?is)^\s*(select|insert|update|delete|with|create|alter|drop|merge|replace)\b")
EXEC_METHODS = {"execute", "executemany", "executescript", "raw", "text", "exec_driver_sql", "mogrify", "query"}
JS_SQL_TEMPLATE = re.compile(
    r"""\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*`[^`]*\b(select|insert|update|"""
    r"""delete)\b[^`]*\$\{""", re.I)
JS_SQL_CONCAT = re.compile(
    r"""\.(?:query|execute|raw)\s*\(\s*["'][^"']*\b(select|insert|update|delete)\b[^"']*["']\s*\+""", re.I)
MODEL_BASE = re.compile(r"(db\.)?Model|Base|\w*Base")
MONEY_TOKENS = {"price", "prices", "amount", "cost", "costs", "total", "subtotal", "balance", "fee", "fees", "salary",
                "wage", "payment", "revenue", "tax", "discount", "charge", "refund", "budget", "money", "usd", "eur"}
NOT_MONEY_TOKENS = {"rate", "ratio", "percent", "percentage", "pct", "count", "weight", "score", "factor"}
NATURAL_KEY = re.compile(r"(?i)email|e_mail|username|user_name|login|slug|sku|handle")
PERSON_MODEL = re.compile(r"(?i)\w*(user|account|member|customer|person|profile|admin|staff|employee|subscriber)s?$")


def is_money_name(name: str) -> bool:
    tokens = {t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", name)}
    return bool(tokens & MONEY_TOKENS) and not tokens & NOT_MONEY_TOKENS


def _call_attr(node: ast.Call) -> str:
    return node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")


def _kw_true(node: ast.Call, name: str) -> bool:
    return any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)


def _is_dynamic_sql(node: ast.AST) -> str | None:
    """Return how a SQL string is built dynamically, or None if it is a constant/parameterized string."""
    if isinstance(node, ast.JoinedStr):
        consts = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        if SQL_KEYWORDS.match(consts) and any(isinstance(v, ast.FormattedValue) for v in node.values):
            return "f-string"
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str) and SQL_KEYWORDS.match(node.left.value)):
        return "%-formatting"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = node.left
        while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
            left = left.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str) and SQL_KEYWORDS.match(left.value):
            return "string concatenation"
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
            and SQL_KEYWORDS.match(node.func.value.value)):
        return "str.format()"
    return None


@register
class DatabaseAnalyzer(Analyzer):
    name = "database"
    title = "Database design & data access"
    categories = (Category.DATABASE,)

    def applicable(self, ctx: AnalyzerContext):
        if not (ctx.languages.has("python") or ctx.languages.has("javascript") or ctx.languages.has("typescript")
                or ctx.languages.has("sql")):
            return "no Python, JavaScript/TypeScript, or SQL files detected"
        return None

    def run(self, ctx: AnalyzerContext):
        findings = []
        uses_sqlalchemy_models = False
        for rel in ctx.python_files():
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            text = ctx.read(rel) or ""
            if re.search(r"\b(db\.Model|DeclarativeBase|declarative_base\(\))", text):
                uses_sqlalchemy_models = True
            if re.search(r"\b(db\.Model|DeclarativeBase|declarative_base\(\)|models\.Model)\b", text) and not \
                    is_test_path(rel):
                findings.extend(self._schema_design(ctx, rel, tree))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute | ast.Name)):
                    continue
                fname = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
                if fname not in EXEC_METHODS or not node.args:
                    continue
                how = _is_dynamic_sql(node.args[0])
                if how:
                    findings.append(self._sqli(ctx, rel, node.lineno, how, is_test_path(rel)))

        for rel in ctx.files_with_suffix(".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
            for i, line in enumerate(ctx.lines(rel), start=1):
                if JS_SQL_TEMPLATE.search(line) or JS_SQL_CONCAT.search(line):
                    findings.append(self._sqli(ctx, rel, i, "template literal / concatenation", is_test_path(rel)))

        for rel in ctx.files_with_suffix(".prisma"):
            findings.extend(self._prisma_design(ctx, rel))
        findings.extend(self._migrations(ctx, uses_sqlalchemy_models))

        schema = build_schema(ctx)
        dialects = ctx.profile.production_sql_dialects
        issues = schema_checks(schema, dialects) + migration_checks(schema, dialects) + run_query_checks(
            ctx, schema, ctx.profile)
        findings.extend(self.finding(
            ctx, rule=i.rule, title=i.title, category=Category.DATABASE, severity=i.severity, confidence=i.confidence,
            kind=i.kind, description=i.description, remediation=i.remediation, file_path=i.file, line=i.line,
            evidence=i.evidence) for i in issues)
        return findings

    # ------------------------------------------------------------------------------------- schema design
    def _schema_design(self, ctx, rel, tree):
        """Model-level design problems: tables without a primary key, money stored as binary floating point, and
        natural keys (email, username, slug) without a uniqueness guarantee."""
        out = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            bases = [ast.unparse(b) for b in cls.bases]
            django = any(b in ("models.Model", "Model") for b in bases) and "models.Model" in (ctx.read(rel) or "")
            sqlalchemy = any(MODEL_BASE.fullmatch(b) for b in bases) and not django
            # Mixins and parent models can contribute columns (often the primary key) that are not visible here.
            only_model_bases = all(MODEL_BASE.fullmatch(b) for b in bases)
            if not (django or sqlalchemy):
                continue
            class_names = {t.id for s in cls.body if isinstance(s, ast.Assign) for t in s.targets
                           if isinstance(t, ast.Name)}
            if class_names & {"__abstract__", "__table__"} or any(
                    isinstance(s, ast.ClassDef) and s.name == "Meta" and "abstract" in ast.unparse(s)
                    for s in cls.body):
                continue
            unique_cols = self._table_args_unique_columns(cls)
            columns = []
            for stmt in cls.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    name, value, annotation = stmt.target.id, stmt.value, ast.unparse(stmt.annotation)
                elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    name, value, annotation = stmt.targets[0].id, stmt.value, ""
                else:
                    continue
                if isinstance(value, ast.Call):
                    columns.append((name, value, stmt.lineno, annotation))
            sa_columns = [c for _, c, _, _ in columns if _call_attr(c) in ("Column", "mapped_column")]
            if sqlalchemy and only_model_bases and sa_columns and not any(_kw_true(c, "primary_key")
                                                                          for c in sa_columns):
                out.append(self._design(ctx, "database.no-primary-key", f"Model {cls.name} has no primary key",
                                        Severity.MEDIUM, Confidence.MEDIUM, FindingKind.CONFIRMED,
                                        "No column is marked primary_key=True. SQLAlchemy cannot map a table without "
                                        "a primary key, and rows cannot be updated or deleted reliably.",
                                        "Add a surrogate primary key (e.g. `id = mapped_column(Integer, "
                                        "primary_key=True)`) or a composite key.", rel, cls.lineno))
            for name, call, line, annotation in columns:
                kind = _call_attr(call)
                if kind in ("Column", "mapped_column"):
                    type_src = " ".join(ast.unparse(a) for a in call.args[:2]) + " " + annotation
                else:
                    type_src = kind
                if is_money_name(name) and re.search(r"\b(Float|REAL|Double|DOUBLE_PRECISION|FloatField|float)\b",
                                                     type_src):
                    out.append(self._design(ctx, "database.money-as-float", f"Monetary column `{name}` stored as "
                                            "floating point", Severity.MEDIUM, Confidence.MEDIUM,
                                            FindingKind.CONFIRMED,
                                            "Binary floating point cannot represent most decimal amounts exactly "
                                            "(0.1 + 0.2 != 0.3), so totals, taxes and balances drift and fail "
                                            "reconciliation.",
                                            "Use a fixed-point type (Numeric/DECIMAL with explicit precision and "
                                            "scale, Django DecimalField) or store integer minor units (cents).",
                                            rel, line, ["https://cwe.mitre.org/data/definitions/1339.html"]))
                natural = NATURAL_KEY.fullmatch(name)
                if natural and (name.lower() != "email" or PERSON_MODEL.search(cls.name)) \
                        and kind in ("Column", "mapped_column", "CharField", "EmailField", "SlugField") \
                        and not _kw_true(call, "unique") and not _kw_true(call, "primary_key") \
                        and name not in unique_cols and not self._unique_together(cls, name):
                    out.append(self._design(ctx, "database.missing-unique-constraint", f"`{cls.name}.{name}` has no "
                                            "unique constraint", Severity.LOW, Confidence.LOW, FindingKind.POTENTIAL,
                                            f"`{name}` looks like a natural key, but the database does not enforce "
                                            "uniqueness. Application-level 'check then insert' races under "
                                            "concurrency and produces duplicate accounts or records.",
                                            "Add `unique=True` (or a unique index/constraint, case-insensitive for "
                                            "emails) and handle the integrity error.", rel, line))
        return out

    @staticmethod
    def _table_args_unique_columns(cls: ast.ClassDef) -> set[str]:
        """Columns covered by a UniqueConstraint or unique Index in ``__table_args__`` (composite ones included:
        a slug unique per organization is a deliberate design)."""
        cols: set[str] = set()
        for stmt in cls.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__table_args__"
                                                    for t in stmt.targets):
                for node in ast.walk(stmt.value):
                    if isinstance(node, ast.Call) and (_call_attr(node) == "UniqueConstraint" or (
                            _call_attr(node) == "Index" and _kw_true(node, "unique"))):
                        cols.update(a.value for a in node.args if isinstance(a, ast.Constant)
                                    and isinstance(a.value, str))
        return cols

    @staticmethod
    def _unique_together(cls: ast.ClassDef, column: str) -> bool:
        for stmt in cls.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == "Meta":
                src = ast.unparse(stmt)
                if ("unique_together" in src or "UniqueConstraint" in src) and f"'{column}'" in src:
                    return True
        return False

    def _prisma_design(self, ctx, rel):
        out = []
        model, block_attrs = None, ""
        lines = ctx.lines(rel)
        for i, raw in enumerate(lines, start=1):
            line = raw.split("//", 1)[0].strip()
            m = re.match(r"model\s+(\w+)\s*\{", line)
            if m:
                model = m.group(1)
                end = next((j for j in range(i, len(lines)) if lines[j].strip() == "}"), len(lines))
                block_attrs = "\n".join(ln for ln in lines[i:end] if ln.strip().startswith("@@"))
                continue
            if line == "}":
                model = None
                continue
            field = re.match(r"(\w+)\s+(\w+)(\??)\s*(.*)$", line)
            if not model or not field or line.startswith("@@"):
                continue
            name, ftype, attrs = field.group(1), field.group(2), field.group(4)
            if is_money_name(name) and ftype == "Float":
                out.append(self._design(ctx, "database.money-as-float", f"Monetary field `{model}.{name}` stored as "
                                        "Float", Severity.MEDIUM, Confidence.MEDIUM, FindingKind.CONFIRMED,
                                        "Prisma's Float is binary floating point; decimal amounts drift and fail "
                                        "reconciliation.", "Use `Decimal` (with @db.Decimal(p, s)) or integer cents.",
                                        rel, i, ["https://cwe.mitre.org/data/definitions/1339.html"]))
            if NATURAL_KEY.fullmatch(name) and ftype == "String" and "@unique" not in attrs and "@id" not in attrs \
                    and (name.lower() != "email" or PERSON_MODEL.search(model)) \
                    and not re.search(rf"@@(unique|id)\(\[\s*{name}\s*\]", block_attrs):
                out.append(self._design(ctx, "database.missing-unique-constraint", f"`{model}.{name}` has no unique "
                                        "constraint", Severity.LOW, Confidence.LOW, FindingKind.POTENTIAL,
                                        f"`{name}` looks like a natural key but is not @unique; concurrent writes can "
                                        "create duplicates.", "Add `@unique` and handle the constraint error.",
                                        rel, i))
        return out

    def _design(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line, refs=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.DATABASE, severity=sev, confidence=conf,
                            kind=kind, description=desc, remediation=fix, file_path=rel, line=line, references=refs)

    def _sqli(self, ctx, rel, line, how, in_tests):
        return self.finding(
            ctx, rule="database.sql-string-formatting", title=f"SQL statement built with {how}",
            category=Category.DATABASE, severity=Severity.LOW if in_tests else Severity.HIGH,
            confidence=Confidence.MEDIUM, kind=FindingKind.POTENTIAL,
            description="A SQL statement is assembled from runtime values instead of bound parameters. If any "
            "interpolated value can be influenced by a user, this is SQL injection. eVal did not trace data flow, "
            "so verify whether inputs are attacker-controlled.",
            remediation="Use parameterized queries (e.g. `text('... WHERE id = :id')` with params, `cursor.execute("
            "sql, (value,))`, or the ORM query API). Never interpolate identifiers from user input; allow-list them.",
            file_path=rel, line=line, references=["https://cwe.mitre.org/data/definitions/89.html"])

    def _migrations(self, ctx: AnalyzerContext, uses_sqlalchemy_models: bool):
        has_alembic = any(f.endswith(("alembic.ini", "/env.py")) and ("alembic" in f or "migrations" in f)
                          for f in ctx.files) or any("/versions/" in f and "migrations" in f for f in ctx.files)
        has_prisma_migrations = any(f.startswith("prisma/migrations/") for f in ctx.files)
        has_other = any(re.search(r"(^|/)(migrations|db/migrate|migrate)/", f) for f in ctx.files)
        out = []
        if uses_sqlalchemy_models and not (has_alembic or has_other):
            out.append(self.finding(
                ctx, rule="database.no-migrations", title="ORM models without schema migrations",
                category=Category.DATABASE, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                kind=FindingKind.POTENTIAL,
                description="SQLAlchemy models are defined but no migration tool (Alembic/Flask-Migrate) was found. "
                "Schemas created with create_all() cannot be evolved safely in production.",
                remediation="Adopt Alembic (or Flask-Migrate) and generate versioned, reviewed migrations."))
        if ctx.exists("prisma/schema.prisma") and not has_prisma_migrations:
            out.append(self.finding(
                ctx, rule="database.prisma-no-migrations", title="Prisma schema without committed migrations",
                category=Category.DATABASE, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                kind=FindingKind.POTENTIAL,
                description="prisma/schema.prisma exists but prisma/migrations is absent; `db push` is not safe for "
                "production schema changes.", remediation="Use `prisma migrate dev` and commit migrations.",
                file_path="prisma/schema.prisma"))
        return out
