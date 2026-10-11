"""Schema migrations, read statically: SQL files (plain, Flyway, Prisma, golang-migrate…), Alembic revisions,
Django migrations, and knex / Sequelize migrations are turned into one list of operations each.

The operations feed two consumers: the schema model replays them to learn which tables, foreign keys and indexes
exist in the database (not only in the ORM models), and the migration checks classify them. Only the forward
direction is read: ``downgrade()`` bodies and ``*.down.sql`` files are destructive by design.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .base import is_test_path

IDENT = r'(?:[`"\[]?[\w$]+[`"\]]?\s*\.\s*)?[`"\[]?[\w$]+[`"\]]?'
SQL_MIGRATION_PATH = re.compile(r"(?:^|/)(?:migrations?|migrate|db/migrate|schema_migrations|flyway|changelog)/|"
                                r"(?:^|/)V\d+(?:[._]\d+)*__\w+\.sql$|\.up\.sql$", re.I)
DOWN_MIGRATION = re.compile(r"\.down\.sql$|(?:^|/)down\.sql$|(?:^|/)U\d+(?:[._]\d+)*__\w+\.sql$", re.I)


@dataclass
class Op:
    """One schema or data operation. ``kind`` is one of: create_table, drop_table, rename_table, add_column,
    drop_column, rename_column, alter_type, set_not_null, add_fk, add_unique, add_pk, add_check, create_index,
    drop_index, truncate, delete, update, insert, run_python, run_sql_opaque."""

    kind: str
    table: str
    line: int
    column: str = ""
    columns: tuple[str, ...] = ()
    detail: dict = field(default_factory=dict)
    source: str = ""          # short human-readable form, used as evidence


@dataclass
class Migration:
    file: str
    tool: str                 # sql | alembic | django | knex | sequelize
    ops: list[Op]
    order: tuple = ()         # sort key within the tool
    downgrade: str = ""       # alembic: "missing" | "empty" | "" (implemented)
    atomic: bool = True
    app: str = ""             # django app label

    @property
    def created_tables(self) -> set[str]:
        return {o.table for o in self.ops if o.kind == "create_table"}


def norm_ident(name: str) -> str:
    """``"public"."Users"`` → ``users``: unquoted, schema dropped, lower-cased (SQL folds unquoted names)."""
    name = name.strip().strip(";")
    name = re.split(r"\s*\.\s*", name)[-1]
    return name.strip('`"[] ').lower()


# ============================================================================================ SQL
def split_sql(text: str) -> list[tuple[str, int]]:
    """Split a SQL script into statements (with 1-based start lines). Comments are blanked; quotes and PostgreSQL
    dollar-quoted bodies are respected so a ``;`` inside a function body does not end the statement."""
    out, i, n, start = [], 0, len(text), 0
    buf = list(text)
    quote = None
    dollar = None
    while i < n:
        c = text[i]
        if dollar:
            if text.startswith(dollar, i):
                i += len(dollar)
                dollar = None
                continue
            i += 1
            continue
        if quote:
            if c == quote:
                if i + 1 < n and text[i + 1] == quote:  # '' escape
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if text.startswith("--", i) or c == "#" and (i == 0 or text[i - 1] == "\n"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                buf[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if buf[k] != "\n":
                    buf[k] = " "
            i = j
            continue
        if c in "'\"`":
            quote = c
        elif c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", text[i:])
            if m:
                dollar = m.group(0)
                i += len(dollar)
                continue
        elif c == ";":
            out.append(("".join(buf[start:i]), start))
            start = i + 1
        i += 1
    out.append(("".join(buf[start:]), start))
    result = []
    for stmt, pos in out:
        stripped = stmt.strip()
        if stripped:
            lead = len(stmt) - len(stmt.lstrip())
            result.append((" ".join(stripped.split()), text.count("\n", 0, pos + lead) + 1))
    return result


def _split_top(text: str, sep: str = ",") -> list[str]:
    parts, depth, cur, quote = [], 0, [], None
    for c in text:
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
            continue
        if c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _paren_body(text: str, open_pos: int) -> str | None:
    depth, quote = 0, None
    for i in range(open_pos, len(text)):
        c = text[i]
        if quote:
            if c == quote:
                quote = None
            continue
        if c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i]
    return None


def _cols(text: str) -> tuple[str, ...]:
    """``(a, "b" DESC, lower(c))`` → ``('a', 'b', 'lower(c)')``."""
    out = []
    for part in _split_top(text):
        part = part.strip()
        if re.fullmatch(IDENT + r"(?:\s+(?:ASC|DESC|NULLS\s+\w+|COLLATE\s+\S+|\w+_ops))*(?:\s*\(\d+\))?", part, re.I):
            out.append(norm_ident(re.split(r"\s|\(", part, maxsplit=1)[0]))
        else:
            out.append(re.sub(r"\s+", "", part.lower()))
    return tuple(out)


COLUMN_STOP = re.compile(r"\b(?:NOT|NULL|PRIMARY|UNIQUE|REFERENCES|DEFAULT|CHECK|CONSTRAINT|GENERATED|"
                         r"AUTO_INCREMENT|AUTOINCREMENT|COLLATE|COMMENT|ON|IDENTITY)\b", re.I)
REFERENCES = re.compile(r"\bREFERENCES\s+(" + IDENT + r")\s*(?:\(([^)]*)\))?([^,]*)", re.I)


def parse_column_def(text: str) -> dict | None:
    m = re.match(r"\s*(" + IDENT + r")\s+(.*)$", text, re.S)
    if not m:
        return None
    name, rest = norm_ident(m.group(1)), m.group(2)
    stop = COLUMN_STOP.search(rest)
    col_type = (rest[: stop.start()] if stop else rest).strip().lower()
    upper = rest.upper()
    ref = REFERENCES.search(rest)
    return {
        "name": name, "type": col_type,
        "primary_key": "PRIMARY KEY" in upper, "unique": bool(re.search(r"\bUNIQUE\b", upper)),
        "not_null": "NOT NULL" in upper or "PRIMARY KEY" in upper,
        "default": bool(re.search(r"\bDEFAULT\b|\bGENERATED\b|AUTO_INCREMENT|AUTOINCREMENT|\bSERIAL\b|IDENTITY",
                                  upper + " " + col_type.upper())),
        "fk": (norm_ident(ref.group(1)) + ("." + _cols(ref.group(2))[0] if ref.group(2) else "")) if ref else None,
        "on_delete": (re.search(r"ON\s+DELETE\s+(SET\s+NULL|CASCADE|RESTRICT|NO\s+ACTION|SET\s+DEFAULT)",
                                ref.group(3), re.I).group(1).upper()
                      if ref and re.search(r"ON\s+DELETE", ref.group(3), re.I) else None),
    }


CREATE_TABLE = re.compile(r"^CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?(?:TEMP(?:ORARY)?\s+)?"
                          r"(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(" + IDENT + r")\s*\(", re.I)
CREATE_TABLE_AS = re.compile(r"^CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+.*\bAS\s+SELECT\b", re.I)
CREATE_INDEX = re.compile(r"^CREATE\s+(UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(" + IDENT +
                          r")?\s*ON\s+(?:ONLY\s+)?(" + IDENT + r")\s*(?:USING\s+\w+\s*)?\(", re.I)
ALTER_TABLE = re.compile(r"^ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?(" + IDENT + r")\s+(.*)$", re.I | re.S)
DROP_TABLE = re.compile(r"^DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(.+?)(?:\s+(?:CASCADE|RESTRICT))?$", re.I)
DROP_INDEX = re.compile(r"^DROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(" + IDENT + r")", re.I)
TRUNCATE = re.compile(r"^TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(" + IDENT + r")", re.I)
DELETE = re.compile(r"^DELETE\s+FROM\s+(?:ONLY\s+)?(" + IDENT + r")(.*)$", re.I)
UPDATE = re.compile(r"^UPDATE\s+(?:ONLY\s+)?(" + IDENT + r")\s+SET\s+(.*)$", re.I)
INSERT = re.compile(r"^INSERT\s+INTO\s+(" + IDENT + r")(.*)$", re.I)
RENAME_TABLE = re.compile(r"^RENAME\s+TABLE\s+(" + IDENT + r")\s+TO\s+(" + IDENT + r")", re.I)


def parse_sql(text: str, base_line: int = 1) -> list[Op]:
    ops: list[Op] = []
    for stmt, line in split_sql(text):
        line += base_line - 1
        ops.extend(_parse_statement(stmt, line))
    return ops


def _parse_statement(stmt: str, line: int) -> list[Op]:
    short = stmt[:160]
    if CREATE_TABLE_AS.match(stmt):
        m = re.match(r"^CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(" + IDENT + ")", stmt, re.I)
        return [Op("create_table", norm_ident(m.group(1)), line, detail={"columns": [], "as_select": True},
                   source=short)] if m else []
    m = CREATE_TABLE.match(stmt)
    if m:
        body = _paren_body(stmt, m.end() - 1) or ""
        return [_create_table_op(norm_ident(m.group(1)), body, line, short)]
    m = CREATE_INDEX.match(stmt)
    if m:
        body = _paren_body(stmt, m.end() - 1) or ""
        return [Op("create_index", norm_ident(m.group(4)), line, columns=_cols(body),
                   detail={"unique": bool(m.group(1)), "concurrently": bool(m.group(2)),
                           "name": norm_ident(m.group(3)) if m.group(3) else ""}, source=short)]
    m = ALTER_TABLE.match(stmt)
    if m:
        table = norm_ident(m.group(1))
        return [op for action in _split_top(m.group(2)) for op in _alter_action(table, action, line, short)]
    m = RENAME_TABLE.match(stmt)
    if m:
        return [Op("rename_table", norm_ident(m.group(1)), line, detail={"to": norm_ident(m.group(2))}, source=short)]
    m = DROP_TABLE.match(stmt)
    if m:
        return [Op("drop_table", norm_ident(t), line, source=short) for t in _split_top(m.group(1))]
    m = DROP_INDEX.match(stmt)
    if m:
        return [Op("drop_index", "", line, detail={"name": norm_ident(m.group(1))}, source=short)]
    m = TRUNCATE.match(stmt)
    if m:
        return [Op("truncate", norm_ident(m.group(1)), line, source=short)]
    m = DELETE.match(stmt)
    if m:
        return [Op("delete", norm_ident(m.group(1)), line, detail={"where": bool(re.search(r"\bWHERE\b", m.group(2),
                                                                                          re.I))}, source=short)]
    m = UPDATE.match(stmt)
    if m:
        sets = [norm_ident(p.split("=", 1)[0]) for p in _split_top(re.split(r"\bWHERE\b|\bFROM\b", m.group(2),
                                                                             flags=re.I)[0]) if "=" in p]
        return [Op("update", norm_ident(m.group(1)), line, columns=tuple(sets),
                   detail={"where": bool(re.search(r"\bWHERE\b", m.group(2), re.I)),
                           "reads": set(re.findall(r"\b\w+\b", m.group(2).lower()))}, source=short)]
    m = INSERT.match(stmt)
    if m:
        return [Op("insert", norm_ident(m.group(1)), line,
                   detail={"select": bool(re.search(r"\bSELECT\b", m.group(2), re.I)),
                           "reads": set(re.findall(r"\b\w+\b", m.group(2).lower()))}, source=short)]
    return []


def _create_table_op(table: str, body: str, line: int, short: str) -> Op:
    columns, pk, uniques, fks, indexes = [], [], [], [], []
    for part in _split_top(body):
        upper = part.upper()
        con = re.sub(r"^CONSTRAINT\s+\S+\s+", "", part, flags=re.I)
        cu = con.upper()
        if cu.startswith("PRIMARY KEY"):
            pk = list(_cols(_paren_body(con, con.index("(")) or ""))
        elif cu.startswith("UNIQUE"):
            if "(" in con:
                uniques.append(_cols(_paren_body(con, con.index("(")) or ""))
        elif cu.startswith("FOREIGN KEY"):
            fk = re.match(r"FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+(" + IDENT + r")\s*(?:\(([^)]*)\))?(.*)", con,
                          re.I | re.S)
            if fk:
                fks.append((_cols(fk.group(1)), norm_ident(fk.group(2)) + ("." + _cols(fk.group(3))[0]
                                                                              if fk.group(3) else ""),
                            _on_delete(fk.group(4))))
        elif re.match(r"(?:KEY|INDEX|FULLTEXT|SPATIAL)\b", cu) and "(" in con:
            indexes.append(_cols(_paren_body(con, con.index("(")) or ""))
        elif cu.startswith(("CHECK", "EXCLUDE", "LIKE", "PERIOD")) or upper.startswith("CONSTRAINT"):
            continue
        else:
            col = parse_column_def(part)
            if col:
                columns.append(col)
    return Op("create_table", table, line, detail={"columns": columns, "pk": pk, "uniques": uniques, "fks": fks,
                                                   "indexes": indexes}, source=short)


def _on_delete(text: str) -> str | None:
    m = re.search(r"ON\s+DELETE\s+(SET\s+NULL|CASCADE|RESTRICT|NO\s+ACTION|SET\s+DEFAULT)", text or "", re.I)
    return " ".join(m.group(1).upper().split()) if m else None


def _alter_action(table: str, action: str, line: int, short: str) -> list[Op]:
    a = action.strip()
    au = a.upper()
    m = re.match(r"ADD\s+(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+(" + IDENT +
                 r")\s*(?:\(([^)]*)\))?(.*)$", a, re.I | re.S)
    if m:
        return [Op("add_fk", table, line, columns=_cols(m.group(1)),
                   detail={"ref": norm_ident(m.group(2)) + ("." + _cols(m.group(3))[0] if m.group(3) else ""),
                           "not_valid": "NOT VALID" in m.group(4).upper(), "on_delete": _on_delete(m.group(4))},
                   source=short)]
    m = re.match(r"ADD\s+(?:CONSTRAINT\s+(\S+)\s+)?(UNIQUE|PRIMARY\s+KEY)\s*(?:KEY|INDEX)?\s*\S*?\s*\(([^)]*)\)(.*)",
                 a, re.I | re.S)
    if m:
        kind = "add_unique" if m.group(2).upper() == "UNIQUE" else "add_pk"
        return [Op(kind, table, line, columns=_cols(m.group(3)),
                   detail={"using_index": "USING INDEX" in m.group(4).upper()}, source=short)]
    m = re.match(r"ADD\s+CONSTRAINT\s+\S+\s+UNIQUE\s+USING\s+INDEX", a, re.I)
    if m:
        return [Op("add_unique", table, line, detail={"using_index": True}, source=short)]
    m = re.match(r"ADD\s+(?:CONSTRAINT\s+\S+\s+)?CHECK\b(.*)", a, re.I | re.S)
    if m:
        return [Op("add_check", table, line, detail={"not_valid": "NOT VALID" in au}, source=short)]
    m = re.match(r"ADD\s+(UNIQUE\s+|FULLTEXT\s+|SPATIAL\s+)?(?:INDEX|KEY)\s+\S*\s*\(([^)]*)\)", a, re.I)
    if m:
        return [Op("create_index", table, line, columns=_cols(m.group(2)),
                   detail={"unique": bool(m.group(1) and "UNIQUE" in m.group(1).upper()), "concurrently": False,
                           "mysql": True}, source=short)]
    m = re.match(r"ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(.*)$", a, re.I | re.S)
    if m and not re.match(r"ADD\s+(?:CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK|INDEX|KEY)\b", a, re.I):
        col = parse_column_def(m.group(1))
        if col:
            return [Op("add_column", table, line, column=col["name"], detail=col, source=short)]
    m = re.match(r"DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(" + IDENT + r")", a, re.I)
    if m and not re.match(r"DROP\s+(?:CONSTRAINT|INDEX|KEY|PRIMARY|FOREIGN|DEFAULT|NOT)\b", a, re.I):
        return [Op("drop_column", table, line, column=norm_ident(m.group(1)), source=short)]
    m = re.match(r"RENAME\s+(?:COLUMN\s+)?(" + IDENT + r")\s+TO\s+(" + IDENT + r")", a, re.I)
    if m and not re.match(r"RENAME\s+TO\b", a, re.I):
        return [Op("rename_column", table, line, column=norm_ident(m.group(1)),
                   detail={"to": norm_ident(m.group(2))}, source=short)]
    m = re.match(r"RENAME\s+TO\s+(" + IDENT + r")", a, re.I)
    if m:
        return [Op("rename_table", table, line, detail={"to": norm_ident(m.group(1))}, source=short)]
    m = re.match(r"ALTER\s+(?:COLUMN\s+)?(" + IDENT + r")\s+(?:SET\s+DATA\s+)?TYPE\s+(.*)$", a, re.I | re.S)
    if m:
        return [Op("alter_type", table, line, column=norm_ident(m.group(1)),
                   detail={"type": m.group(2).strip().lower(), "using": "USING" in m.group(2).upper()},
                   source=short)]
    m = re.match(r"ALTER\s+(?:COLUMN\s+)?(" + IDENT + r")\s+SET\s+NOT\s+NULL", a, re.I)
    if m:
        return [Op("set_not_null", table, line, column=norm_ident(m.group(1)), source=short)]
    m = re.match(r"(?:MODIFY|CHANGE)\s+(?:COLUMN\s+)?(" + IDENT + r")\s+(?:(" + IDENT + r")\s+)?(.*)$", a, re.I | re.S)
    if m:  # MySQL rewrites the column definition: a type change and possibly NOT NULL.
        new = m.group(3) if au.startswith("MODIFY") else (m.group(3) or "")
        ops = [Op("alter_type", table, line, column=norm_ident(m.group(1)), detail={"type": new.lower(),
                                                                                   "mysql": True}, source=short)]
        if "NOT NULL" in new.upper():
            ops.append(Op("set_not_null", table, line, column=norm_ident(m.group(1)), detail={"mysql": True},
                          source=short))
        if au.startswith("CHANGE") and m.group(2) and norm_ident(m.group(2)) != norm_ident(m.group(1)):
            ops.append(Op("rename_column", table, line, column=norm_ident(m.group(1)),
                          detail={"to": norm_ident(m.group(2))}, source=short))
        return ops
    return []


# ============================================================================================ Alembic
ALEMBIC_TYPE_ARGS = {"type_", "existing_type"}


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _strs(node) -> tuple[str, ...]:
    if isinstance(node, ast.List | ast.Tuple):
        return tuple(str(e.value).lower() for e in node.elts if isinstance(e, ast.Constant))
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value.lower(),)
    return ()


def _arg(call: ast.Call, index: int, *names: str):
    for n in names:
        v = _kw(call, n)
        if v is not None:
            return v
    return call.args[index] if len(call.args) > index else None


def sa_column(call: ast.Call) -> dict | None:
    """``sa.Column('name', sa.String(20), sa.ForeignKey('t.id'), nullable=False)`` → column dict."""
    if _call_name(call) not in ("Column", "mapped_column"):
        return None
    name, col_type, fk, on_delete = "", "", None, None
    for i, a in enumerate(call.args):
        if i == 0 and isinstance(a, ast.Constant) and isinstance(a.value, str):
            name = a.value
        elif isinstance(a, ast.Call) and _call_name(a) == "ForeignKey":
            target = a.args[0] if a.args else _kw(a, "column")
            fk = (_const(target) if isinstance(target, ast.Constant) else ast.unparse(target)) if target else None
            od = _kw(a, "ondelete")
            on_delete = str(_const(od)).upper() if od is not None and _const(od) else None
        elif not col_type:
            col_type = ast.unparse(a)
    pk = _const(_kw(call, "primary_key")) is True
    nullable = _kw(call, "nullable")
    return {"name": name.lower(), "type": col_type, "fk": fk.lower() if isinstance(fk, str) else fk,
            "on_delete": on_delete, "primary_key": pk,
            "unique": _const(_kw(call, "unique")) is True, "index": _const(_kw(call, "index")) is True,
            "not_null": pk or (nullable is not None and _const(nullable) is False),
            "default": _kw(call, "server_default") is not None or _const(_kw(call, "autoincrement")) is True
            or (pk and re.search(r"int", col_type, re.I) is not None),
            "python_default": _kw(call, "default") is not None}


def _sql_text(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and _call_name(node) in ("text", "DDL") and node.args:
        return _sql_text(node.args[0])
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "x" for v in node.values)
    return None


def parse_alembic(rel: str, tree: ast.Module) -> Migration | None:
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    if "upgrade" not in funcs:
        return None
    rev = down = None
    for n in tree.body:
        if isinstance(n, ast.Assign | ast.AnnAssign):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "revision":
                    rev = _const(n.value)
                if isinstance(t, ast.Name) and t.id == "down_revision":
                    down = n.value
    ops: list[Op] = []
    _alembic_body(funcs["upgrade"].body, ops, batch_table=None)
    downgrade = "missing" if "downgrade" not in funcs else ("empty" if _trivial(funcs["downgrade"]) else "")
    mig = Migration(rel, "alembic", sorted(ops, key=lambda o: o.line), downgrade=downgrade)
    mig.order = (rev, ast.unparse(down) if down is not None else None)
    return mig


def _trivial(func: ast.FunctionDef) -> bool:
    body = [s for s in func.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
    return all(isinstance(s, ast.Pass) for s in body) or (
        len(body) == 1 and isinstance(body[0], ast.Raise))


def _alembic_body(stmts, ops: list[Op], batch_table: str | None, batch_var: str | None = None) -> None:
    for stmt in stmts:
        if isinstance(stmt, ast.With):
            for item in stmt.items:
                c = item.context_expr
                if isinstance(c, ast.Call) and _call_name(c) == "batch_alter_table":
                    var = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else None
                    name = _const(c.args[0]) if c.args else _const(_kw(c, "table_name"))
                    # A table chosen at runtime (a loop over table names) is unknown: "?" keeps batch mode
                    # but no check attributes the operations to a table.
                    _alembic_body(stmt.body, ops, str(name).lower() if isinstance(name, str) else "?", var)
                    break
            else:
                _alembic_body(stmt.body, ops, batch_table, batch_var)
            continue
        if isinstance(stmt, ast.If | ast.For | ast.Try):
            for block in (stmt.body, getattr(stmt, "orelse", []), getattr(stmt, "finalbody", [])):
                _alembic_body(block, ops, batch_table, batch_var)
            continue
        for node in ast.walk(stmt):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)):
                continue
            recv = node.func.value.id
            if recv == "op":
                ops.extend(_alembic_op(node, None))
            elif batch_table and recv == batch_var:
                ops.extend(_alembic_op(node, batch_table))


def _alembic_op(call: ast.Call, batch: str | None) -> list[Op]:
    name, line = call.func.attr, call.lineno
    src = ast.unparse(call)[:160]
    shift = 0 if batch else 1  # batch_op methods take no table argument

    def table(idx=0, *kw):
        if batch:
            return batch
        name = _const(_arg(call, idx, *kw))
        return name.lower() if isinstance(name, str) else "?"

    def col_arg(idx):
        name = _const(_arg(call, idx - (1 - shift), "column_name"))
        return name.lower() if isinstance(name, str) else "?"

    flags = {"batch": bool(batch)}
    if name == "create_table":
        tname = str(_const(call.args[0]) if call.args else _const(_kw(call, "table_name")) or "").lower()
        columns, pk, uniques, fks = [], [], [], []
        for a in call.args[1:]:
            if not isinstance(a, ast.Call):
                continue
            col = sa_column(a)
            if col:
                columns.append(col)
            elif _call_name(a) == "PrimaryKeyConstraint":
                pk = [str(_const(x)).lower() for x in a.args if isinstance(x, ast.Constant)]
            elif _call_name(a) == "UniqueConstraint":
                uniques.append(tuple(str(_const(x)).lower() for x in a.args if isinstance(x, ast.Constant)))
            elif _call_name(a) == "ForeignKeyConstraint" and len(a.args) >= 2:
                refs = _strs(a.args[1])
                od = _kw(a, "ondelete")
                fks.append((_strs(a.args[0]), refs[0] if refs else "", str(_const(od)).upper() if od else None))
        return [Op("create_table", tname, line, detail={"columns": columns, "pk": pk, "uniques": uniques,
                                                        "fks": fks, "indexes": []}, source=src)]
    if name == "drop_table":
        return [Op("drop_table", table(0, "table_name"), line, source=src)]
    if name == "rename_table":
        return [Op("rename_table", table(0, "old_table_name"), line,
                   detail={"to": str(_const(_arg(call, 1, "new_table_name")) or "").lower()}, source=src)]
    if name == "add_column":
        col_node = _arg(call, shift, "column")
        col = sa_column(col_node) if isinstance(col_node, ast.Call) else None
        if col:
            return [Op("add_column", table(0, "table_name"), line, column=col["name"], detail={**col, **flags},
                       source=src)]
        return []
    if name == "drop_column":
        return [Op("drop_column", table(0, "table_name"), line, column=col_arg(1), detail=flags, source=src)]
    if name == "alter_column":
        tname, cname = table(0, "table_name"), col_arg(1)
        out = []
        new_type, old_type = _kw(call, "type_"), _kw(call, "existing_type")
        if new_type is not None:
            out.append(Op("alter_type", tname, line, column=cname,
                          detail={"type": ast.unparse(new_type).lower(),
                                  "existing": ast.unparse(old_type).lower() if old_type is not None else "",
                                  "using": _kw(call, "postgresql_using") is not None, **flags}, source=src))
        if _const(_kw(call, "nullable")) is False:
            out.append(Op("set_not_null", tname, line, column=cname, detail=flags, source=src))
        if _kw(call, "new_column_name") is not None:
            out.append(Op("rename_column", tname, line, column=cname,
                          detail={"to": str(_const(_kw(call, "new_column_name"))).lower(), **flags}, source=src))
        return out
    if name == "create_index":
        cols = _strs(_arg(call, 2 - (1 - shift), "columns"))
        conc = _const(_kw(call, "postgresql_concurrently")) is True
        return [Op("create_index", table(1, "table_name"), line, columns=cols,
                   detail={"unique": _const(_kw(call, "unique")) is True, "concurrently": conc,
                           "name": str(_const(_arg(call, 0, "index_name")) or ""), **flags}, source=src)]
    if name == "drop_index":
        return [Op("drop_index", "", line, detail={"name": str(_const(_arg(call, 0, "index_name")) or "")},
                   source=src)]
    if name == "create_foreign_key":
        if batch:
            ref, local, remote = _arg(call, 1, "referent_table"), _arg(call, 2, "local_cols"), _arg(call, 3,
                                                                                                    "remote_cols")
            src_table = batch
        else:
            src_table = str(_const(_arg(call, 1, "source_table")) or "").lower()
            ref, local, remote = _arg(call, 2, "referent_table"), _arg(call, 3, "local_cols"), _arg(call, 4,
                                                                                                    "remote_cols")
        remote_cols = _strs(remote)
        od = _kw(call, "ondelete")
        return [Op("add_fk", src_table, line, columns=_strs(local),
                   detail={"ref": str(_const(ref) or "").lower() + ("." + remote_cols[0] if remote_cols else ""),
                           "not_valid": False, "on_delete": str(_const(od)).upper() if od else None, **flags},
                   source=src)]
    if name in ("create_unique_constraint", "create_primary_key"):
        tname = batch or str(_const(_arg(call, 1, "table_name")) or "").lower()
        cols = _strs(_arg(call, 1 if batch else 2, "columns"))
        return [Op("add_unique" if name == "create_unique_constraint" else "add_pk", tname, line, columns=cols,
                   detail=flags, source=src)]
    if name == "create_check_constraint":
        return [Op("add_check", batch or str(_const(_arg(call, 1, "table_name")) or "").lower(), line,
                   detail=flags, source=src)]
    if name == "drop_constraint":
        return [Op("drop_constraint", table(1, "table_name"), line, detail=flags, source=src)]
    if name == "execute" and call.args:
        sql = _sql_text(call.args[0])
        return parse_sql(sql, line) if sql else [Op("run_sql_opaque", "", line, source=src)]
    if name == "bulk_insert":
        return [Op("insert", "", line, source=src)]
    return []


# ============================================================================================ Django
DJANGO_INDEXED_FIELDS = ("ForeignKey", "OneToOneField")


def parse_django(rel: str, tree: ast.Module, table_of) -> Migration | None:
    """``table_of(app, model_name)`` resolves a model to its table (honouring Meta.db_table when known)."""
    parts = rel.split("/")
    app = parts[-3] if len(parts) >= 3 else ""
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Migration"), None)
    if cls is None:
        return None
    atomic, ops_node = True, None
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
            if stmt.targets[0].id == "operations":
                ops_node = stmt.value
            if stmt.targets[0].id == "atomic":
                atomic = _const(stmt.value) is not False
    if not isinstance(ops_node, ast.List | ast.Tuple):
        return Migration(rel, "django", [], atomic=atomic, app=app)
    ops: list[Op] = []
    for call in ops_node.elts:
        if isinstance(call, ast.Call):
            ops.extend(_django_op(call, app, table_of))
    num = re.match(r"(\d+)", parts[-1])
    return Migration(rel, "django", ops, order=(app, int(num.group(1)) if num else 0), atomic=atomic, app=app)


def _django_op(call: ast.Call, app: str, table_of) -> list[Op]:
    name, line, src = _call_name(call), call.lineno, ast.unparse(call)[:160]

    def model(*kw, idx=0):
        v = _arg(call, idx, *kw)
        return str(_const(v) or "")

    if name == "CreateModel":
        mname = model("name")
        fields = _arg(call, 1, "fields")
        columns = []
        for f in fields.elts if isinstance(fields, ast.List | ast.Tuple) else []:
            if isinstance(f, ast.Tuple) and len(f.elts) == 2 and isinstance(f.elts[1], ast.Call):
                columns.append({"name": str(_const(f.elts[0]) or "").lower(), "type": _call_name(f.elts[1]).lower()})
        return [Op("create_table", table_of(app, mname), line, detail={"columns": columns, "model": mname},
                   source=src)]
    if name == "DeleteModel":
        return [Op("drop_table", table_of(app, model("name")), line, source=src)]
    if name == "RenameModel":
        return [Op("rename_table", table_of(app, model("old_name")), line, detail={"to": model("new_name", idx=1)},
                   source=src)]
    if name == "RemoveField":
        return [Op("drop_column", table_of(app, model("model_name")), line, column=model("name", idx=1).lower(),
                   source=src)]
    if name == "RenameField":
        return [Op("rename_column", table_of(app, model("model_name")), line, column=model("old_name", idx=1).lower(),
                   detail={"to": model("new_name", idx=2).lower()}, source=src)]
    if name == "AddField":
        f = _arg(call, 2, "field")
        fname = model("name", idx=1).lower()
        ftype = _call_name(f) if isinstance(f, ast.Call) else ""
        indexed = isinstance(f, ast.Call) and (
            (ftype in DJANGO_INDEXED_FIELDS and _const(_kw(f, "db_index")) is not False)
            or _const(_kw(f, "db_index")) is True or _const(_kw(f, "unique")) is True)
        return [Op("add_column", table_of(app, model("model_name")), line, column=fname,
                   detail={"django": True, "type": ftype.lower(), "indexed": indexed,
                           "fk": ftype in DJANGO_INDEXED_FIELDS}, source=src)]
    if name in ("AddIndex", "AddIndexConcurrently"):
        idx = _arg(call, 1, "index")
        cols = _strs(_kw(idx, "fields")) if isinstance(idx, ast.Call) else ()
        return [Op("create_index", table_of(app, model("model_name")), line,
                   columns=tuple(c.lstrip("-") for c in cols),
                   detail={"concurrently": name == "AddIndexConcurrently", "django": True}, source=src)]
    if name == "RunSQL":
        sql = _arg(call, 0, "sql")
        texts = [t for t in (_sql_text(e) for e in (sql.elts if isinstance(sql, ast.List | ast.Tuple) else [sql]))
                 if t]
        reverse = _arg(call, 1, "reverse_sql")
        out = [op for t in texts for op in parse_sql(t, line)] or [Op("run_sql_opaque", "", line, source=src)]
        for op in out:
            op.detail["irreversible"] = reverse is None
        return out
    if name == "RunPython":
        return [Op("run_python", "", line, detail={"irreversible": _arg(call, 1, "reverse_code") is None},
                   source=src)]
    return []


# ============================================================================================ knex / Sequelize
KNEX_UP = re.compile(r"(?:exports\.up|export\s+(?:async\s+)?function\s+up|up\s*[:=]\s*(?:async\s*)?(?:function)?)"
                     r"[^{]*\{")
KNEX_TABLE = re.compile(r"\.(createTable|alterTable|table)\(\s*['\"`](\w+)['\"`]")
KNEX_SIMPLE = re.compile(r"\.(dropTable|dropTableIfExists|renameTable)\(\s*['\"`](\w+)['\"`](?:\s*,\s*['\"`](\w+))?")
SEQ_CALL = re.compile(r"\b(?:queryInterface|qi|queryinterface)\.(createTable|dropTable|renameTable|addColumn|"
                      r"removeColumn|renameColumn|changeColumn|addIndex|addConstraint|bulkDelete)\(\s*['\"`](\w+)['\"`]"
                      r"(?:\s*,\s*['\"`](\w+)['\"`])?(?:\s*,\s*['\"`](\w+)['\"`])?", re.I)
RAW_SQL_JS = re.compile(r"\.(?:raw|query)\(\s*(['\"`])((?:(?!\1).)*)\1", re.S)


def parse_js_migration(rel: str, text: str) -> Migration | None:
    from .architecture import _js_block

    m = KNEX_UP.search(text)
    if not m:
        return None
    body = _js_block(text, m.end() - 1) or ""
    base = text[: m.end()].count("\n")
    ops: list[Op] = []
    tool = "sequelize" if re.search(r"queryInterface|Sequelize", text) else "knex"

    def line_at(pos):
        return base + body.count("\n", 0, pos) + 1

    for mm in KNEX_TABLE.finditer(body):
        kind, table = mm.group(1), mm.group(2).lower()
        block_start = body.find("{", mm.end())
        block = _js_block(body, block_start) if block_start >= 0 else ""
        if kind == "createTable":
            ops.append(Op("create_table", table, line_at(mm.start()), source=mm.group(0)))
            continue
        for c in re.finditer(r"\.dropColumns?\(\s*['\"`](\w+)", block or ""):
            ops.append(Op("drop_column", table, line_at(block_start + c.start()), column=c.group(1).lower(),
                          source=c.group(0)))
        for c in re.finditer(r"\.renameColumn\(\s*['\"`](\w+)['\"`]\s*,\s*['\"`](\w+)", block or ""):
            ops.append(Op("rename_column", table, line_at(block_start + c.start()), column=c.group(1).lower(),
                          detail={"to": c.group(2).lower()}, source=c.group(0)))
        for stmt in re.finditer(r"\b\w+\.(\w+)\(\s*['\"`](\w+)['\"`][^;\n]*", block or ""):
            chain = stmt.group(0)
            if stmt.group(1) in ("index", "unique", "foreign", "dropColumn", "dropColumns", "renameColumn",
                                 "dropIndex", "dropForeign", "primary"):
                if stmt.group(1) in ("index", "unique"):
                    ops.append(Op("create_index", table, line_at(block_start + stmt.start()),
                                  columns=(stmt.group(2).lower(),), detail={"unique": stmt.group(1) == "unique"},
                                  source=chain[:120]))
                continue
            if ".alter()" in chain:
                ops.append(Op("alter_type", table, line_at(block_start + stmt.start()), column=stmt.group(2).lower(),
                              source=chain[:120]))
                if ".notNullable()" in chain:
                    ops.append(Op("set_not_null", table, line_at(block_start + stmt.start()),
                                  column=stmt.group(2).lower(), source=chain[:120]))
            elif ".notNullable()" in chain and ".defaultTo(" not in chain and stmt.group(1) not in ("increments",
                                                                                                  "bigIncrements"):
                ops.append(Op("add_column", table, line_at(block_start + stmt.start()), column=stmt.group(2).lower(),
                              detail={"not_null": True, "default": False}, source=chain[:120]))
            if ".references(" in chain or ".foreign(" in chain:
                ops.append(Op("add_fk", table, line_at(block_start + stmt.start()), columns=(stmt.group(2).lower(),),
                              detail={"ref": ""}, source=chain[:120]))
    for mm in KNEX_SIMPLE.finditer(body):
        kind = {"dropTable": "drop_table", "dropTableIfExists": "drop_table",
                "renameTable": "rename_table"}[mm.group(1)]
        ops.append(Op(kind, mm.group(2).lower(), line_at(mm.start()), detail={"to": (mm.group(3) or "").lower()},
                      source=mm.group(0)))
    for mm in SEQ_CALL.finditer(body):
        verb, table, a, b = mm.group(1), mm.group(2).lower(), (mm.group(3) or "").lower(), (mm.group(4) or "").lower()
        line = line_at(mm.start())
        tail = body[mm.end(): mm.end() + 400]
        if verb == "createTable":
            ops.append(Op("create_table", table, line, source=mm.group(0)))
        elif verb == "dropTable":
            ops.append(Op("drop_table", table, line, source=mm.group(0)))
        elif verb == "renameTable":
            ops.append(Op("rename_table", table, line, detail={"to": a}, source=mm.group(0)))
        elif verb == "removeColumn":
            ops.append(Op("drop_column", table, line, column=a, source=mm.group(0)))
        elif verb == "renameColumn":
            ops.append(Op("rename_column", table, line, column=a, detail={"to": b}, source=mm.group(0)))
        elif verb == "changeColumn":
            ops.append(Op("alter_type", table, line, column=a, source=mm.group(0)))
            if re.match(r"[^)]*allowNull\s*:\s*false", tail):
                ops.append(Op("set_not_null", table, line, column=a, source=mm.group(0)))
        elif verb == "addColumn":
            opts = re.match(r"\s*,\s*\{", tail)
            body_opts = (_js_block(tail, opts.end() - 1) or "") if opts else ""
            ops.append(Op("add_column", table, line, column=a,
                          detail={"not_null": bool(re.search(r"allowNull\s*:\s*false", body_opts)),
                                  "default": "defaultValue" in body_opts,
                                  "fk": "references" in body_opts}, source=mm.group(0)))
        elif verb == "addIndex":
            cols = re.match(r"\s*,\s*\[([^\]]*)\]", tail)
            ops.append(Op("create_index", table, line,
                          columns=tuple(c.strip(" '\"`").lower() for c in cols.group(1).split(",")) if cols else (),
                          detail={"concurrently": "concurrently: true" in tail[:300]}, source=mm.group(0)))
        elif verb == "addConstraint" and re.search(r"type\s*:\s*['\"`]foreign key", tail[:400], re.I):
            ops.append(Op("add_fk", table, line, detail={"ref": ""}, source=mm.group(0)))
        elif verb == "bulkDelete":
            ops.append(Op("delete", table, line, detail={"where": not re.match(r"\s*,\s*(?:null|\{\s*\})", tail)},
                          source=mm.group(0)))
    for mm in RAW_SQL_JS.finditer(body):
        ops.extend(parse_sql(mm.group(2), line_at(mm.start())))
    return Migration(rel, tool, sorted(ops, key=lambda o: o.line), order=(rel,))


# ============================================================================================ discovery
def _natural(path: str) -> tuple:
    return tuple(int(t) if t.isdigit() else t for t in re.split(r"(\d+)", path))


def is_sql_migration(rel: str) -> bool:
    return rel.lower().endswith(".sql") and bool(SQL_MIGRATION_PATH.search(rel)) and not DOWN_MIGRATION.search(rel)


def discover(ctx, table_of) -> list[Migration]:
    """All forward migrations in the repository, each tool's files in application order."""
    out: list[Migration] = []
    for rel in ctx.files:
        if is_test_path(rel) and "migrations/" not in rel:
            continue
        low = rel.lower()
        if is_sql_migration(rel):
            ops = parse_sql(ctx.read(rel) or "")
            out.append(Migration(rel, "sql", ops, order=_natural(rel)))
        elif low.endswith(".py") and ("/versions/" in f"/{low}" or "/migrations/" in f"/{low}"):
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            text = ctx.read(rel) or ""
            if "def upgrade" in text and ("alembic" in text or "revision" in text):
                mig = parse_alembic(rel, tree)
            elif "migrations.Migration" in text:
                mig = parse_django(rel, tree, table_of)
            else:
                mig = None
            if mig:
                out.append(mig)
        elif low.endswith((".js", ".ts", ".cjs", ".mjs")) and re.search(r"(?:^|/)migrations?/", low):
            mig = parse_js_migration(rel, ctx.read(rel) or "")
            if mig:
                out.append(mig)
    return _ordered(out)


def _ordered(migs: list[Migration]) -> list[Migration]:
    alembic = [m for m in migs if m.tool == "alembic"]
    rest = sorted((m for m in migs if m.tool != "alembic"), key=lambda m: (m.tool, m.order or (m.file,)))
    # Alembic: follow down_revision links from the base; files that are not on a chain keep file order.
    children: dict = {}
    for m in alembic:
        parent = m.order[1] if m.order else None
        children.setdefault(parent, []).append(m)
    ordered, seen = [], set()
    stack = sorted(children.get("None", []) + children.get(None, []), key=lambda m: m.file, reverse=True)
    while stack:
        m = stack.pop()
        if id(m) in seen:
            continue
        seen.add(id(m))
        ordered.append(m)
        rev = m.order[0] if m.order else None
        stack.extend(sorted(children.get(repr(rev), []), key=lambda x: x.file, reverse=True))
    ordered += sorted((m for m in alembic if id(m) not in seen), key=lambda m: m.file)
    return ordered + rest
