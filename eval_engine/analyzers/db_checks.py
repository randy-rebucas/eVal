"""Schema and migration checks over the schema model: foreign-key indexes, missing and inconsistent foreign keys and
relationships, duplicated data, and destructive, unsafe or irreversible migrations.

Each check states which engines it applies to. ``dialects`` is the set of production SQL engines from the app
profile; an empty set means none was identified, so a risk that exists on any of PostgreSQL, MySQL or SQLite is
reported (and the description says which engine it concerns).
"""

from __future__ import annotations

import re

from ..findings import Confidence, FindingKind, Severity
from .db_migrations import Migration, Op
from .db_model import Column, Model, Schema, snake, type_family
from .db_queries import MAX_PER_RULE, Issue

LOG_MODEL = re.compile(r"(?i)audit|log$|logs$|event|history|activity|snapshot|archive|outbox|journal|trail")
SNAPSHOT_MODEL = re.compile(r"(?i)order|invoice|receipt|payment|transaction|shipment|line_?item|booking|reservation|"
                            r"audit|log|history|event|snapshot|archive|ledger|quote|contract|statement|charge|refund")
EXTERNAL_PREFIX = re.compile(r"(?i)^(?:external|stripe|paypal|github|gitlab|google|apple|facebook|twitter|slack|"
                             r"provider|remote|session|request|trace|correlation|idempotency|transaction|message|"
                             r"object|entity|resource|client|device|installation|tenant_external)$")
PLURAL = (lambda p: {p, p + "s", p + "es", p[:-1] + "ies" if p.endswith("y") else p})  # noqa: E731


def _issue(rule, title, sev, conf, kind, desc, fix, file, line, evidence=None) -> Issue:
    return Issue(rule, title, sev, conf, kind, desc, fix, file, line, evidence)


def _sql_models(schema: Schema) -> list[Model]:
    mongo_prisma = schema.prisma_provider == "mongodb"
    return [m for m in schema.unique_models() if m.orm in ("sqlalchemy", "django", "sql")
            or m.orm == "prisma" and not mongo_prisma]


def _engines(dialects: set[str]) -> str:
    return ", ".join(sorted(dialects)) if dialects else "no engine identified"


# ============================================================================================ schema
def schema_checks(schema: Schema, dialects: set[str]) -> list[Issue]:
    out: list[Issue] = []
    out += _fk_indexes(schema, dialects)
    out += _missing_fks(schema)
    out += _inconsistent(schema, dialects)
    out += _duplicated(schema)
    return out


def _fk_indexes(schema: Schema, dialects: set[str]) -> list[Issue]:
    out = []
    prisma_emulated = schema.prisma_relation_mode == "prisma"
    for m in _sql_models(schema):
        if m.orm == "django":
            continue  # Django creates an index for every ForeignKey unless db_index=False is chosen explicitly
        emulated = m.orm == "prisma" and prisma_emulated
        if dialects == {"mysql"} and not emulated:
            continue  # InnoDB requires and creates an index for every foreign key constraint
        for col in m.columns.values():
            if not col.fk or m.is_indexed(col):
                continue
            why = ("relationMode = \"prisma\" emulates relations without database foreign keys, so nothing indexes "
                   "the relation scalar; Prisma's documentation asks for an explicit @@index." if emulated else
                   "PostgreSQL and SQLite do not index foreign key columns automatically (MySQL/InnoDB does)"
                   + (f"; this application uses {_engines(dialects)}" if dialects else "")
                   + ". Joins on this column and ON DELETE checks on the parent table scan the child table as it "
                   "grows.")
            out.append(_issue(
                "database.fk-without-index", "Foreign key column without an index", Severity.LOW, Confidence.MEDIUM,
                FindingKind.ESTIMATE,
                f"{m.name}.{col.name} references {col.fk}. {why} (Static estimate: no index on it was found in the "
                "model or in any migration.)",
                "Add `index=True`, `@@index([" + col.name + "])`, or a composite index that starts with this column.",
                m.file, col.line or m.line))
    return out[:MAX_PER_RULE]


def _resolve_prefix(schema: Schema, prefix: str) -> Model | None:
    for cand in PLURAL(prefix.lower()):
        for m in schema.unique_models():
            if snake(m.name) == cand or m.name.lower() == cand or m.table == cand:
                return m
    return None


def _fk_syntax(m: Model, col: Column, target: Model, tpk: Column | None) -> str:
    key = tpk.db_name if tpk else "id"
    if m.orm == "sqlalchemy":
        return f"ForeignKey('{target.table}.{key}')"
    if m.orm == "django":
        return f"models.ForeignKey({target.name}, on_delete=...)"
    if m.orm == "prisma":
        return f"@relation(fields: [{col.name}], references: [{tpk.name if tpk else 'id'}])"
    return f"REFERENCES {target.table}({key})"


def _missing_fks(schema: Schema) -> list[Issue]:
    emulated = schema.prisma_relation_mode == "prisma"
    out = []
    for m in _sql_models(schema):
        if m.orm == "prisma" and emulated:
            continue
        names = {c.name.lower() for c in m.columns.values()}
        generic = any(r.kind == "generic" for r in m.relations.values())
        for col in m.columns.values():
            if col.fk or col.primary_key:
                continue
            match = re.fullmatch(r"([a-z][a-z0-9_]*?)_id", col.name) or re.fullmatch(r"([a-z][A-Za-z0-9]*?)(?:Id|ID)",
                                                                                     col.name)
            if not match or EXTERNAL_PREFIX.match(match.group(1)):
                continue
            prefix = snake(match.group(1))
            if generic or {f"{prefix}_type", f"{prefix}type", f"{prefix}_model", f"{prefix}_kind",
                           f"{prefix}_table", f"{prefix}_class"} & names:
                continue  # polymorphic association: a foreign key cannot point at several tables
            target = _resolve_prefix(schema, prefix)
            if target is None or (target.orm != m.orm and "sql" not in (target.orm, m.orm)):
                continue
            if m.bind != target.bind:
                continue  # different databases: a foreign key is impossible
            tpk = target.pk[0] if len(target.pk) == 1 else None
            fam_a, fam_b = type_family(col.type), type_family(tpk.type if tpk else "")
            if fam_a and fam_b and fam_a != fam_b and not {fam_a, fam_b} <= {"int16", "int32", "int64"}:
                continue  # e.g. a string id: probably an identifier from another system, not this table's key
            log = bool(LOG_MODEL.search(m.name) or LOG_MODEL.search(m.table))
            out.append(_issue(
                "database.missing-foreign-key", f"`{m.name}.{col.name}` looks like a reference to {target.name} but "
                "has no foreign key", Severity.LOW if log else Severity.MEDIUM, Confidence.MEDIUM,
                FindingKind.POTENTIAL,
                f"{col.name} holds {target.name} ids ({target.table}), but no foreign key constraint is declared in "
                "the model or created by a migration. The database will accept ids that do not exist and keep "
                "orphans when a parent row is deleted; joins silently drop or duplicate rows."
                + (f" {m.name} looks like a log/history table: if rows must outlive the referenced {target.name}, "
                   "an FK with ON DELETE SET NULL still validates inserts." if log else ""),
                f"Declare it as a foreign key ({_fk_syntax(m, col, target, tpk)}) and backfill or delete orphaned "
                "rows first (the constraint cannot be added while they exist).",
                m.file, col.line or m.line))
    return out[:MAX_PER_RULE]


def _inconsistent(schema: Schema, dialects: set[str]) -> list[Issue]:
    out: list[Issue] = []
    models = schema.unique_models()

    def add(title, desc, fix, m: Model, line, sev=Severity.MEDIUM, conf=Confidence.HIGH, kind=FindingKind.CONFIRMED):
        out.append(_issue("database.inconsistent-relationship", title, sev, conf, kind, desc, fix, m.file,
                          line or m.line))

    for m in models:
        for rel in m.relations.values():
            target = schema.find(rel.target)
            # SQLAlchemy back_populates must name a relationship on the target that points back.
            if m.orm == "sqlalchemy" and rel.kind == "relationship" and rel.back_populates and target:
                other = target.relations.get(rel.back_populates)
                if other is None and target.complete:
                    add(f"{m.name}.{rel.name} back_populates a missing {target.name}.{rel.back_populates}",
                        f"relationship({rel.target!r}, back_populates={rel.back_populates!r}) requires "
                        f"{target.name}.{rel.back_populates} to exist; SQLAlchemy raises InvalidRequestError when "
                        "the mappers are configured (on the first query), so the application fails at runtime.",
                        f"Add `{rel.back_populates} = relationship('{m.name}', back_populates='{rel.name}')` to "
                        f"{target.name}, or fix the name.", m, rel.line)
                elif other is not None and other.kind == "relationship" and (
                        other.back_populates != rel.name or schema.find(other.target) is not m):
                    add(f"{m.name}.{rel.name} and {target.name}.{other.name} do not point at each other",
                        f"{m.name}.{rel.name} says back_populates={rel.back_populates!r}, but "
                        f"{target.name}.{other.name} targets {other.target!r} with back_populates="
                        f"{other.back_populates!r}. The two sides go out of sync in the session (an object appended "
                        "on one side is not reflected on the other) or the mapper fails to configure.",
                        "Make each side name the other: back_populates must be symmetric.", m, rel.line)
            # A relationship needs a foreign key path between the two tables.
            if m.orm == "sqlalchemy" and rel.kind == "relationship" and target and not rel.secondary and \
                    not rel.explicit_join and m.complete and target.complete:
                linked = any(schema.fk_target(c.fk)[0] is target for c in m.columns.values()) or any(
                    schema.fk_target(c.fk)[0] is m for c in target.columns.values())
                if not linked:
                    add(f"{m.name}.{rel.name} has no foreign key path to {target.name}",
                        f"Neither {m.table} nor {target.table} has a foreign key to the other, and the "
                        "relationship gives no secondary table, primaryjoin or foreign_keys. SQLAlchemy cannot work "
                        "out the join and raises NoForeignKeysError when the mappers are configured.",
                        "Add the ForeignKey column on the child table, or pass primaryjoin/foreign_keys (or "
                        "secondary= for many-to-many).", m, rel.line)
            # One-to-one on a key that is not unique.
            if m.orm == "sqlalchemy" and rel.kind == "relationship" and rel.uselist is False and target:
                back_fk = [c for c in target.columns.values() if schema.fk_target(c.fk)[0] is m]
                if back_fk and not any(target.is_indexed(c) and (c.unique or {c.db_name} in target.unique_sets())
                                       for c in back_fk):
                    add(f"{m.name}.{rel.name} is one-to-one but {target.table}.{back_fk[0].db_name} is not unique",
                        f"uselist=False promises at most one {target.name} per {m.name}, but nothing stops a second "
                        f"row with the same {back_fk[0].db_name}; SQLAlchemy then warns and returns an arbitrary one.",
                        f"Add unique=True to {target.name}.{back_fk[0].name} (or drop uselist=False).",
                        m, rel.line, sev=Severity.LOW, conf=Confidence.MEDIUM, kind=FindingKind.POTENTIAL)
            # Mongoose refs must name a registered model.
            if m.orm == "mongoose" and rel.kind == "ref" and target is None:
                add(f"{m.name}.{rel.name} refs unknown model '{rel.target}'",
                    f"`ref: '{rel.target}'` does not match any model registered with mongoose.model() in the "
                    "repository; populate() on this path throws MissingSchemaError.",
                    "Use the exact model name passed to mongoose.model().", m, rel.line, conf=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL)
        # Foreign key types must match the referenced key.
        if m.orm in ("sqlalchemy", "sql", "prisma") and schema.prisma_provider != "mongodb":
            for col in m.columns.values():
                tm, tc = schema.fk_target(col.fk)
                if not (tm and tc):
                    continue
                a, b = type_family(col.type), type_family(tc.type)
                if not a or not b or a == b:
                    continue
                ints = {a, b} <= {"int16", "int32", "int64"}
                engine_note = ("MySQL refuses to create the constraint" if not dialects or "mysql" in dialects
                               else "")
                add(f"{m.name}.{col.name} ({a}) references {tm.table}.{tc.db_name} ({b})",
                    "The foreign key column and the key it references have different types. "
                    + ("A narrower column cannot hold ids once the parent table passes its range (2,147,483,647 "
                       "for 32-bit integers), and inserts start failing" if ints else
                       "Values cannot be compared without casts; PostgreSQL rejects the constraint as incompatible")
                    + (f"; {engine_note}." if engine_note else "."),
                    f"Give {col.name} exactly the type of {tm.table}.{tc.db_name}.", m, col.line,
                    sev=Severity.MEDIUM if ints else Severity.HIGH)
        # ON DELETE SET NULL on a NOT NULL column.
        for col in m.columns.values():
            od = (col.on_delete or "").upper().replace("_", " ")
            if od in ("SET NULL", "SETNULL") and col.nullable is False:
                add(f"{m.name}.{col.name} is NOT NULL but ON DELETE SET NULL",
                    "Deleting the referenced row makes the database set this column to NULL, which its NOT NULL "
                    "constraint forbids, so the delete fails"
                    + (" (Django refuses to start: fields.E320)" if m.orm == "django" else "") + ".",
                    "Make the column nullable, or use CASCADE / RESTRICT.", m, col.line)
        # Django: two relations to the same model without distinct related_name clash (fields.E304).
        if m.orm == "django":
            by_target: dict[str, list] = {}
            for rel in m.relations.values():
                if rel.kind in ("fk", "o2o", "m2m"):
                    by_target.setdefault(rel.target, []).append(rel)
            for target_name, rels in by_target.items():
                unnamed = [r for r in rels if not r.related_name]
                if len(unnamed) >= 2:
                    add(f"{m.name} has {len(unnamed)} relations to {target_name} without related_name",
                        f"{', '.join(r.name for r in unnamed)} all create the reverse accessor "
                        f"`{m.name.lower()}_set` on {target_name}; Django's system checks fail with fields.E304 and "
                        "manage.py refuses to run.",
                        "Give each relation its own related_name.", m, unnamed[1].line)
    # Two classes mapped to the same table.
    seen: dict[str, Model] = {}
    for m in models:
        if m.orm != "sqlalchemy":
            continue
        if m.table in seen and seen[m.table] is not m:
            add(f"{seen[m.table].name} and {m.name} both map table `{m.table}`",
                "Two declarative classes define the same __tablename__ in one metadata; SQLAlchemy raises "
                "'Table is already defined' (or, with extend_existing, silently merges two column sets).",
                "Map the table once; use inheritance or a second mapper on the same Table explicitly.", m, m.line)
        seen.setdefault(m.table, m)
    return out[:MAX_PER_RULE]


def _duplicated(schema: Schema) -> list[Issue]:
    out = []
    models = _sql_models(schema)
    for m in models:
        snapshot = bool(SNAPSHOT_MODEL.search(m.name))
        refs = []
        for col in m.columns.values():
            tm, _ = schema.fk_target(col.fk)
            if tm is None and col.fk:
                tm = schema.find(col.fk.split(".")[0])
            if tm is not None and tm is not m:
                prefix = re.sub(r"_?id$|Id$", "", col.name)
                refs.append((snake(prefix), tm))
        for prefix, tm in refs:
            for col in m.columns.values():
                if col.fk or col.primary_key:
                    continue
                # Only `<relation>_<column>` (customer_email next to customer_id) counts: a column that merely shares
                # a name with one on the referenced table (an identity provider's own `email`) is not a copy.
                copied = None
                if col.name.lower().startswith(prefix + "_") and not snapshot:
                    tc = tm.column(col.name[len(prefix) + 1:])
                    if tc and not tc.primary_key and not tc.fk:
                        copied = tc
                if copied is None:
                    continue
                out.append(_issue(
                    "database.duplicated-data", f"`{m.name}.{col.name}` copies `{tm.name}.{copied.name}`",
                    Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    f"{m.name} references {tm.name} and also stores {col.name}, a copy of {tm.name}.{copied.name}. "
                    f"When the {tm.name} changes, every copy must be updated in the same transaction, or the two "
                    "disagree and reports, searches and notifications use stale data.",
                    "Read it through the relationship (join or select_related) instead of copying it. If the copy "
                    "is a deliberate point-in-time snapshot, name it so (e.g. `" + col.name + "_at_signup`) and "
                    "document that it is not kept in sync.", m.file, col.line or m.line))
        # Counter caches: <children>_count next to a child table that references this one.
        for col in m.columns.values():
            cnt = re.fullmatch(r"(\w+?)_count|num_(\w+)|(\w+?)Count", col.name)
            if not cnt:
                continue
            what = snake(next(g for g in cnt.groups() if g))
            child = next((c for c in models if c is not m and what in PLURAL(snake(c.name)) | {c.table}
                          and any(schema.fk_target(x.fk)[0] is m for x in c.columns.values())), None)
            if child:
                out.append(_issue(
                    "database.duplicated-data", f"`{m.name}.{col.name}` duplicates COUNT of {child.name}",
                    Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                    f"{col.name} stores a value the database can compute (the number of {child.name} rows that "
                    f"reference this {m.name}). It drifts whenever a row is added or removed without updating it in "
                    "the same transaction, and `count = count + 1` done in application code loses increments "
                    "under concurrency.",
                    "Compute it (COUNT with an index on the foreign key), or keep it with an atomic UPDATE ... SET "
                    "n = n + 1 in the same transaction as the insert/delete (or a database trigger), and reconcile "
                    "periodically.", m.file, col.line or m.line))
    return out[:MAX_PER_RULE]


# ============================================================================================ migrations
def migration_checks(schema: Schema, dialects: set[str]) -> list[Issue]:
    out: list[Issue] = []
    pg = not dialects or "postgresql" in dialects
    mysql = not dialects or "mysql" in dialects
    sqlite_only = dialects == {"sqlite"}
    migs = schema.migrations
    counts: dict[str, int] = {}

    def add(rule, mig: Migration, op: Op, title, sev, desc, fix, conf=Confidence.HIGH, kind=FindingKind.CONFIRMED):
        if counts.get(rule, 0) >= MAX_PER_RULE:
            return
        counts[rule] = counts.get(rule, 0) + 1
        out.append(_issue(rule, title, sev, conf, kind, desc, fix, mig.file, op.line, evidence=op.source or None))

    for i, mg in enumerate(migs):
        created = mg.created_tables
        later = [x for x in migs[i + 1:] if x.tool == mg.tool]
        for j, op in enumerate(mg.ops):
            if op.table in ("?", "") or op.column == "?":
                continue  # table or column computed at runtime: cannot be attributed
            new = op.table in created
            before = mg.ops[:j]
            where = f"`{op.table}.{op.column}`" if op.column else f"`{op.table}`"
            # ---------------------------------------------------------------- destructive
            if op.kind in ("drop_table", "drop_column", "truncate") or op.kind == "delete" and not op.detail.get(
                    "where"):
                if new:
                    continue
                name = op.column or op.table
                copied = any(b.kind in ("insert", "update") and name in b.detail.get("reads", set()) for b in before) \
                    or any(b.kind == "run_python" for b in before)
                still_used = _still_declared(schema, op, later)
                verb = {"drop_table": "drops table", "drop_column": "drops column", "truncate": "truncates",
                        "delete": "deletes every row of"}[op.kind]
                sev = Severity.HIGH if still_used else Severity.LOW if copied else Severity.MEDIUM
                desc = (f"This migration {verb} {where}: the data is gone once it runs, and rolling back the "
                        "deployment does not bring it back.")
                if still_used:
                    desc += (f" The current {still_used} still declares it and no later migration re-creates it, so "
                             "the application will query a column/table that no longer exists.")
                elif copied:
                    desc += " An earlier statement in the same migration appears to copy the data first."
                else:
                    desc += (" If code that is still deployed reads it during a rolling deploy, those requests fail "
                             "until every instance runs the new version.")
                add("database.destructive-migration", mg, op, f"Migration {verb} {where}", sev, desc,
                    "Use expand/contract: stop reading and writing it in one release, drop it in a later one; back "
                    "the data up (or copy it to its new place in the same migration) before dropping.")
                continue
            if new:
                continue
            # ---------------------------------------------------------------- SQLite cannot ALTER this
            if sqlite_only and mg.tool == "alembic" and not op.detail.get("batch") and op.kind in (
                    "alter_type", "set_not_null", "add_fk", "add_unique", "drop_constraint", "add_check"):
                add("database.unsafe-migration", mg, op, f"Alembic `{op.kind}` on SQLite outside batch mode",
                    Severity.MEDIUM,
                    "SQLite's ALTER TABLE cannot change a column's type or nullability or add/drop constraints; "
                    "Alembic raises NotImplementedError unless the operation runs inside `op.batch_alter_table()`, "
                    "which recreates the table.", "Wrap the operation in `with op.batch_alter_table('"
                    + op.table + "') as batch_op:` (and render_as_batch=True in env.py for autogenerate).")
                continue
            # ---------------------------------------------------------------- locking / breaking
            if op.kind in ("rename_column", "rename_table"):
                add("database.unsafe-migration", mg, op, f"Migration renames {where}", Severity.MEDIUM,
                    "Instances still running the previous release query the old name until they are replaced, so "
                    "a rolling or blue/green deploy fails requests in between (and a rollback breaks the new name). "
                    "Safe only with downtime.",
                    "Add the new column, write to both, backfill, switch reads, then drop the old one in a later "
                    "release (or use a view/alias during the transition).", Confidence.MEDIUM, FindingKind.POTENTIAL)
            elif op.kind == "add_column" and op.detail.get("not_null") and not op.detail.get("default") and \
                    not op.detail.get("django"):
                fails = pg or not dialects or "sqlite" in dialects
                client = " (`default=` is a client-side Python default and does not apply to existing rows)" \
                    if op.detail.get("python_default") else ""
                add("database.unsafe-migration", mg, op, f"NOT NULL column {where} added without a default",
                    Severity.MEDIUM if fails else Severity.LOW,
                    ("PostgreSQL and SQLite reject adding a NOT NULL column without a default to a table that has "
                     "rows, so the migration fails in every environment with data" if fails else
                     "MySQL fills existing rows with the type's implicit default (0, '' or the zero date), which "
                     "silently stores meaningless values") + client + ".",
                    "Add it as nullable (or with a server_default), backfill, then set NOT NULL in a later step.")
            elif op.kind == "add_column" and op.detail.get("django") and op.detail.get("indexed") and pg:
                add("database.unsafe-migration", mg, op, f"AddField {where} builds an index while blocking writes",
                    Severity.LOW,
                    "On PostgreSQL Django creates the index for a ForeignKey/db_index/unique field with a plain "
                    "CREATE INDEX, which blocks inserts, updates and deletes on the table for the whole build.",
                    "Add the field with db_index=False, then add the index with AddIndexConcurrently in a "
                    "non-atomic migration (atomic = False).", Confidence.MEDIUM, FindingKind.POTENTIAL)
            elif op.kind == "create_index" and not op.detail.get("concurrently") and pg and not op.detail.get(
                    "mysql"):
                add("database.unsafe-migration", mg, op, f"Index on {where} built without CONCURRENTLY",
                    Severity.MEDIUM,
                    "On PostgreSQL a plain CREATE INDEX takes a SHARE lock: inserts, updates and deletes on the "
                    "table wait until the index is built, which takes minutes on a large table. (MySQL/InnoDB builds "
                    "secondary indexes online; this concerns PostgreSQL"
                    + ("" if dialects else ", which may not be your engine") + ".)",
                    "CREATE INDEX CONCURRENTLY outside a transaction: `postgresql_concurrently=True` inside "
                    "`op.get_context().autocommit_block()` (Alembic), AddIndexConcurrently with atomic = False "
                    "(Django), `concurrently: true` (Sequelize).", Confidence.MEDIUM, FindingKind.POTENTIAL)
            elif op.kind == "alter_type":
                if _widening(op):
                    continue
                engines = [e for e, on in (("PostgreSQL rewrites the table and its indexes under an ACCESS "
                                            "EXCLUSIVE lock (no reads or writes)", pg),
                                           ("MySQL copies the table (ALGORITHM=COPY) and blocks writes", mysql))
                           if on]
                if engines:
                    add("database.unsafe-migration", mg, op, f"Column type change on {where}", Severity.MEDIUM,
                        "Changing a column's type on a table with data: " + "; ".join(engines) + ". The lock lasts as "
                        "long as the rewrite. Values that do not convert make the migration fail half-way.",
                        "Add a new column of the new type, backfill in batches, switch reads and writes, then drop "
                        "the old column. (Widening varchar(n) to a larger n or to text is safe on PostgreSQL.)",
                        Confidence.MEDIUM, FindingKind.POTENTIAL)
            elif op.kind == "set_not_null":
                backfilled = any(b.kind == "update" and op.column in b.columns and b.table == op.table
                                 for b in before)
                add("database.unsafe-migration", mg, op, f"SET NOT NULL on existing column {where}",
                    Severity.LOW if backfilled else Severity.MEDIUM,
                    ("" if backfilled else "If any existing row is NULL the migration fails. ")
                    + ("PostgreSQL scans the whole table under an ACCESS EXCLUSIVE lock to verify it; MySQL "
                       "rebuilds the table." if pg or mysql else "SQLite has to recreate the table."),
                    "Backfill NULLs first; on PostgreSQL 12+ add `CHECK (col IS NOT NULL) NOT VALID`, VALIDATE it, "
                    "then SET NOT NULL (which then skips the scan).", Confidence.MEDIUM, FindingKind.POTENTIAL)
            elif op.kind == "add_fk" and not op.detail.get("not_valid"):
                if pg:
                    add("database.unsafe-migration", mg, op, f"Foreign key on {where} added and validated at once",
                        Severity.MEDIUM,
                        "On PostgreSQL ADD FOREIGN KEY checks every existing row while holding a SHARE ROW EXCLUSIVE "
                        "lock on both tables, blocking writes to them for the duration; it fails outright if an "
                        "orphaned row exists.",
                        "Add it with NOT VALID (immediate, checks new rows only), then run VALIDATE CONSTRAINT in a "
                        "separate step, which does not block writes.", Confidence.MEDIUM, FindingKind.POTENTIAL)
                elif mysql:
                    add("database.unsafe-migration", mg, op, f"Foreign key on {where} added to an existing table",
                        Severity.LOW,
                        "MySQL copies the table to add a foreign key unless foreign_key_checks is disabled for the "
                        "session, blocking writes during the copy.",
                        "Run it with foreign_key_checks=0 (online, INPLACE) after verifying there are no orphans, or "
                        "with an online schema-change tool (gh-ost, pt-online-schema-change).", Confidence.MEDIUM,
                        FindingKind.POTENTIAL)
            elif op.kind == "add_unique" and pg and not op.detail.get("using_index"):
                add("database.unsafe-migration", mg, op, f"Unique constraint on {where} built while blocking writes",
                    Severity.MEDIUM,
                    "On PostgreSQL ADD CONSTRAINT ... UNIQUE builds its index under a lock that blocks writes, and "
                    "fails if duplicates exist.",
                    "CREATE UNIQUE INDEX CONCURRENTLY first, then ADD CONSTRAINT ... UNIQUE USING INDEX.",
                    Confidence.MEDIUM, FindingKind.POTENTIAL)
            elif op.kind == "update":
                add("database.unsafe-migration", mg, op, f"Data backfill of {where} inside a schema migration",
                    Severity.LOW,
                    "The UPDATE runs in the migration's transaction" + ("" if op.detail.get("where") else
                                                                         " over every row")
                    + ": all touched rows stay locked until the migration commits, blocking concurrent writes to "
                    "them, and on PostgreSQL each updated row leaves a dead tuple (table bloat).",
                    "Backfill in batches (e.g. 1,000 rows per transaction) from a separate data migration or job.",
                    Confidence.MEDIUM, FindingKind.POTENTIAL)
        # ---------------------------------------------------------------- irreversible
        if mg.tool == "alembic" and mg.ops and mg.downgrade in ("missing", "empty"):
            add("database.irreversible-migration", mg, mg.ops[0], "Alembic migration has no downgrade",
                Severity.LOW, f"upgrade() changes the schema but downgrade() is {mg.downgrade}, so "
                "`alembic downgrade` silently does nothing and a failed release cannot be rolled back with the "
                "migration tool.", "Implement downgrade() (or raise an explicit error explaining why it is "
                "impossible, so a rollback stops instead of pretending to succeed).", Confidence.HIGH,
                FindingKind.CONFIRMED)
        for op in mg.ops:
            if op.detail.get("irreversible"):
                kind = "RunPython" if op.kind == "run_python" else "RunSQL"
                add("database.irreversible-migration", mg, op, f"{kind} without a reverse operation",
                    Severity.LOW, f"The {kind} operation has no reverse_code/reverse_sql, so the whole migration "
                    "cannot be unapplied (`migrate <app> <previous>` raises IrreversibleError).",
                    f"Pass reverse_{'code' if kind == 'RunPython' else 'sql'} (migrations.RunPython.noop when there "
                    "is genuinely nothing to undo).", Confidence.HIGH, FindingKind.CONFIRMED)
                break
    return out


def _still_declared(schema: Schema, op: Op, later: list[Migration]) -> str | None:
    """The ORM model still declares what this migration drops, and no later migration adds it back."""
    model = schema.find(op.table)
    if model is None or model.orm == "sql":
        return None
    for mg in later:
        for o in mg.ops:
            if o.table == op.table and (op.kind == "drop_table" and o.kind == "create_table"
                                        or op.kind == "drop_column" and o.kind in ("add_column", "create_table")
                                        and (o.column == op.column or o.kind == "create_table")):
                return None
            if o.kind == "rename_column" and o.table == op.table and o.detail.get("to") == op.column:
                return None
    if op.kind == "drop_table":
        return f"model {model.name} ({model.file})"
    col: Column | None = model.by_db(op.column) if op.column else None
    return f"model {model.name} ({model.file})" if col else None


def _widening(op: Op) -> bool:
    """varchar(n) → varchar(m ≥ n) or text: a metadata-only change on PostgreSQL."""
    old, new = op.detail.get("existing", ""), op.detail.get("type", "")
    if type_family(old) != "string" or type_family(new) != "string":
        return False
    n_old = re.search(r"\((\d+)", old)
    n_new = re.search(r"\((\d+)", new)
    if re.search(r"\btext\b|unicodetext", new):
        return True
    return bool(n_old and n_new and int(n_new.group(1)) >= int(n_old.group(1)))
