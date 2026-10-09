"""Database design and data-access safety: string-built SQL, migrations, unindexed foreign keys."""

from __future__ import annotations

import ast
import re

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, is_test_path
from .registry import register

SQL_KEYWORDS = re.compile(r"(?is)^\s*(select|insert|update|delete|with|create|alter|drop|merge|replace)\b")
EXEC_METHODS = {"execute", "executemany", "executescript", "raw", "text", "exec_driver_sql", "mogrify", "query"}
JS_SQL_TEMPLATE = re.compile(
    r"""\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*`[^`]*\b(select|insert|update|"""
    r"""delete)\b[^`]*\$\{""", re.I)
JS_SQL_CONCAT = re.compile(
    r"""\.(?:query|execute|raw)\s*\(\s*["'][^"']*\b(select|insert|update|delete)\b[^"']*["']\s*\+""", re.I)


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
                findings.extend(self._unindexed_fks(ctx, rel, tree))
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

        findings.extend(self._migrations(ctx, uses_sqlalchemy_models))
        return findings

    def _sqli(self, ctx, rel, line, how, in_tests):
        return self.finding(
            ctx, rule="database.sql-string-formatting", title=f"SQL statement built with {how}",
            category=Category.DATABASE, severity=Severity.LOW if in_tests else Severity.HIGH,
            confidence=Confidence.MEDIUM, kind=FindingKind.CONFIRMED,
            description="A SQL statement is assembled from runtime values instead of bound parameters. If any "
            "interpolated value can be influenced by a user, this is SQL injection. eVal did not trace data flow, "
            "so verify whether inputs are attacker-controlled.",
            remediation="Use parameterized queries (e.g. `text('... WHERE id = :id')` with params, `cursor.execute("
            "sql, (value,))`, or the ORM query API). Never interpolate identifiers from user input; allow-list them.",
            file_path=rel, line=line, references=["https://cwe.mitre.org/data/definitions/89.html"])

    @staticmethod
    def _table_args_leading_columns(cls: ast.ClassDef) -> set[str]:
        """Columns that lead a composite Index/UniqueConstraint/PrimaryKeyConstraint in ``__table_args__``
        (such an index serves lookups and cascades on that column)."""
        leading: set[str] = set()
        for stmt in cls.body:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] if isinstance(
                stmt, ast.AnnAssign) else []
            if not any(isinstance(t, ast.Name) and t.id == "__table_args__" for t in targets) or stmt.value is None:
                continue
            for node in ast.walk(stmt.value):
                if not isinstance(node, ast.Call):
                    continue
                fname = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if fname not in ("Index", "UniqueConstraint", "PrimaryKeyConstraint"):
                    continue
                cols = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if fname == "Index":
                    cols = cols[1:]  # first positional argument is the index name
                if cols:
                    leading.add(cols[0])
        return leading

    def _unindexed_fks(self, ctx, rel, tree):
        out = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            leading = self._table_args_leading_columns(cls)
            for stmt in cls.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    name, value = stmt.target.id, stmt.value
                elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    name, value = stmt.targets[0].id, stmt.value
                else:
                    continue
                if name not in leading and value is not None:
                    out.extend(self._check_fk_column(ctx, rel, value))
        # Core tables: Table("name", metadata, Column(..., ForeignKey(...)), ..., Index(...))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (getattr(node.func, "attr", None) == "Table"
                                               or getattr(node.func, "id", None) == "Table"):
                for arg in node.args:
                    out.extend(self._check_fk_column(ctx, rel, arg))
        return out

    def _check_fk_column(self, ctx, rel, node):
        out = []
        if isinstance(node, ast.Call):
            fname = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if fname not in ("Column", "mapped_column"):
                return out
            has_fk = any(isinstance(a, ast.Call) and (getattr(a.func, "attr", None) == "ForeignKey"
                                                     or getattr(a.func, "id", None) == "ForeignKey")
                         for a in node.args)
            if not has_fk:
                return out
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            indexed = any(isinstance(kw.get(k), ast.Constant) and kw[k].value is True
                          for k in ("index", "primary_key", "unique"))
            if not indexed:
                out.append(self.finding(
                    ctx, rule="database.fk-without-index", title="Foreign key column without an index",
                    category=Category.DATABASE, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    kind=FindingKind.ESTIMATE,
                    description="PostgreSQL and SQLite do not index foreign key columns automatically. Joins and "
                    "cascading deletes on this column will scan the table as it grows. (Static estimate: an index "
                    "may exist in a migration or __table_args__.)",
                    remediation="Add `index=True` or a composite index that starts with this column.",
                    file_path=rel, line=node.lineno))
        return out

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
