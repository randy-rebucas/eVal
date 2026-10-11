"""Database analyzer: engine detection, schema model, indexes, N+1, pagination, migrations, relationships,
duplicated data, transactions and races. Each rule has a positive and a negative case, and engine-specific rules
are tested on the engines where they do and do not apply."""

from __future__ import annotations

from eval_engine.analyzers import registry
from eval_engine.analyzers.base import AnalyzerContext
from eval_engine.languages import detect
from eval_engine.pipeline import run_analyzer
from eval_engine.workspace import iter_files


def write(root, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def ctx(root):
    files = list(iter_files(root))
    return AnalyzerContext(root=root, files=files, languages=detect(root, files), timeout=120)


def run(root):
    outcome = run_analyzer(registry.get(["database"])[0], ctx(root))
    assert outcome.status == "ok", outcome.reason
    return outcome.findings


def by_rule(root, rule):
    return [f for f in run(root) if f.rule_id == f"eval:database.{rule}"]


PG = {"requirements.txt": "flask\nflask-sqlalchemy\npsycopg2-binary\n"}
MYSQL = {"requirements.txt": "flask\nflask-sqlalchemy\npymysql\n"}
SQLITE = {"requirements.txt": "flask\nflask-sqlalchemy\n", "config.py": "URL = 'sqlite:///app.db'\n"}
HEAD = ("from flask_sqlalchemy import SQLAlchemy\nfrom flask import Flask, request\ndb = SQLAlchemy()\n"
        "app = Flask(__name__)\n")
USER = ("class User(db.Model):\n    __tablename__ = 'users'\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    email = db.Column(db.String(255))\n    active = db.Column(db.Boolean)\n")
POST = ("class Post(db.Model):\n    __tablename__ = 'posts'\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)\n"
        "    author = db.relationship('User')\n")


# ------------------------------------------------------------------------------------------ engines
def test_server_engine_wins_over_sqlite_fallback(tmp_path):
    write(tmp_path, {**PG, "config.py": "import os\nURL = os.getenv('DATABASE_URL', 'sqlite:///dev.db')\n"})
    profile = ctx(tmp_path).profile
    assert set(profile.sql_dialects) == {"postgresql", "sqlite"}
    assert profile.production_sql_dialects == {"postgresql"}


def test_engine_from_compose_image_and_prisma_provider(tmp_path):
    write(tmp_path, {"docker-compose.yml": "services:\n  db:\n    image: mysql:8.0\n",
                     "prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n}\n'})
    assert ctx(tmp_path).profile.production_sql_dialects == {"mysql", "postgresql"}


# ------------------------------------------------------------------------------------------ fk indexes
def test_fk_index_created_by_migration_counts(tmp_path):
    models = HEAD + USER + "class Post(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n" \
                           "    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))\n"
    write(tmp_path, {**PG, "app/models.py": models})
    assert len(by_rule(tmp_path, "fk-without-index")) == 1
    write(tmp_path, {"migrations/versions/1_ix.py": "from alembic import op\nrevision = '1'\ndown_revision = None\n"
                     "def upgrade():\n    op.create_index('ix_post_author', 'post', ['author_id'])\n"
                     "def downgrade():\n    op.drop_index('ix_post_author')\n"})
    assert not by_rule(tmp_path, "fk-without-index")


def test_fk_index_not_reported_on_mysql_unless_relations_are_emulated(tmp_path):
    models = HEAD + USER + "class Post(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n" \
                           "    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))\n"
    write(tmp_path, {**MYSQL, "app/models.py": models})
    assert not by_rule(tmp_path, "fk-without-index")  # InnoDB indexes foreign keys itself
    write(tmp_path, {"package.json": '{"dependencies": {"@prisma/client": "5"}}', "prisma/schema.prisma": (
        'datasource db {\n  provider = "mysql"\n  relationMode = "prisma"\n}\n'
        "model Account {\n  id Int @id\n  posts Article[]\n}\n"
        "model Article {\n  id Int @id\n  accountId Int\n  account Account @relation(fields: [accountId], "
        "references: [id])\n}\n")})
    found = by_rule(tmp_path, "fk-without-index")
    assert [f.file_path for f in found] == ["prisma/schema.prisma"] and "relationMode" in found[0].description


def test_django_foreign_keys_are_indexed_by_django(tmp_path):
    write(tmp_path, {"shop/models.py": "from django.db import models\nclass Customer(models.Model):\n"
                     "    name = models.CharField(max_length=20)\nclass Order(models.Model):\n"
                     "    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)\n"})
    assert not by_rule(tmp_path, "fk-without-index")


# ------------------------------------------------------------------------------------------ missing index
def test_unindexed_filter_column(tmp_path):
    code = HEAD + USER + ("def by_email(e):\n    return User.query.filter_by(email=e).first()\n"
                          "def again(e):\n"
                          "    return db.session.scalars(db.select(User).where(User.email == e)).first()\n"
                          "def actives():\n    return User.query.filter_by(active=True).count()\n")
    write(tmp_path, {**PG, "app.py": code})
    found = by_rule(tmp_path, "missing-index")
    assert len(found) == 1 and "users.email" in found[0].title and found[0].severity == "medium"
    write(tmp_path, {"app.py": code.replace("db.String(255))", "db.String(255), index=True)")})
    assert not by_rule(tmp_path, "missing-index")


def test_django_lookups_respect_meta_indexes_and_pattern_lookups(tmp_path):
    models = ("from django.db import models\nclass Ticket(models.Model):\n    status = models.CharField(max_length=9)\n"
              "    title = models.CharField(max_length=99)\n    class Meta:\n"
              "        indexes = [models.Index(fields=['status'])]\n")
    write(tmp_path, {"desk/models.py": models, "desk/views.py": (
        "from .models import Ticket\ndef open_count():\n    return Ticket.objects.filter(status='open').count()\n"
        "def search(q):\n    return Ticket.objects.filter(title__icontains=q).count()\n")})
    assert not by_rule(tmp_path, "missing-index")  # status is indexed; icontains cannot use a b-tree index anyway


def test_mongoose_unindexed_query(tmp_path):
    schema = ("const mongoose = require('mongoose');\nconst userSchema = new mongoose.Schema({\n"
              "  email: { type: String },\n  name: String,\n});\nconst User = mongoose.model('User', userSchema);\n"
              "async function find(e) { return User.findOne({ email: e }); }\n")
    write(tmp_path, {"package.json": '{"dependencies": {"mongoose": "8"}}', "models/user.js": schema})
    found = by_rule(tmp_path, "missing-index")
    assert len(found) == 1 and "COLLSCAN" in found[0].description
    write(tmp_path, {"models/user.js": schema.replace("{ type: String }", "{ type: String, unique: true }")})
    assert not by_rule(tmp_path, "missing-index")


# ------------------------------------------------------------------------------------------ N+1
def test_query_in_loop_must_depend_on_loop_variable(tmp_path):
    write(tmp_path, {**PG, "jobs.py": HEAD + USER + POST + (
        "def report():\n    for u in User.query.all():\n        n = Post.query.filter_by(author_id=u.id).count()\n"
        "def constant():\n    for u in User.query.all():\n        total = Post.query.count()\n")})
    found = by_rule(tmp_path, "n-plus-one")
    assert [f.line_start for f in found] == [17] and found[0].confidence == "high"


def test_lazy_relationship_in_loop(tmp_path):
    loop = "def titles():\n    return [p.author.email for p in {q}]\n"
    write(tmp_path, {**PG, "jobs.py": HEAD + USER + POST + loop.format(q="Post.query.limit(50).all()")})
    found = by_rule(tmp_path, "n-plus-one")
    assert len(found) == 1 and "Lazy-loaded relationship `author`" in found[0].title
    eager = "Post.query.options(db.selectinload(Post.author)).limit(50).all()"
    write(tmp_path, {"jobs.py": HEAD + USER + POST + loop.format(q=eager)})
    assert not by_rule(tmp_path, "n-plus-one")
    joined = POST.replace("relationship('User')", "relationship('User', lazy='joined')")
    write(tmp_path, {"jobs.py": HEAD + USER + joined + loop.format(q="Post.query.limit(50).all()")})
    assert not by_rule(tmp_path, "n-plus-one")


def test_django_select_and_prefetch_related(tmp_path):
    models = ("from django.db import models\nclass Customer(models.Model):\n    email = models.EmailField()\n"
              "class Order(models.Model):\n    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, "
              "related_name='orders')\n")
    view = ("from .models import Customer, Order\n"
            "def a():\n    return [o.customer.email for o in Order.objects.all()[:50]]\n"
            "def b():\n    return [o.customer.email for o in Order.objects.select_related('customer')[:50]]\n"
            "def c():\n    return [len(c.orders.all()) for c in Customer.objects.all()[:50]]\n"
            "def d():\n    return [len(c.orders.all()) for c in Customer.objects.prefetch_related('orders')[:50]]\n")
    write(tmp_path, {"shop/models.py": models, "shop/report.py": view})
    assert sorted(f.line_start for f in by_rule(tmp_path, "n-plus-one")) == [3, 7]


def test_js_query_in_loop(tmp_path):
    write(tmp_path, {"src/report.ts": (
        "export async function report(users) {\n  for (const u of users) {\n"
        "    await prisma.post.count({ where: { authorId: u.id } });\n  }\n"
        "  await Promise.all(users.map(async (u) => prisma.post.findMany({ where: { authorId: u.id }, take: 5 })));\n"
        "  for (const s of ['a', 'b']) {\n    await prisma.setting.findFirst({ where: { key: s } });\n  }\n}\n")})
    found = by_rule(tmp_path, "n-plus-one")
    assert sorted(f.line_start for f in found) == [3, 5]
    assert "Promise.all" in next(f for f in found if f.line_start == 5).description


# ------------------------------------------------------------------------------------------ pagination
def test_list_handler_without_pagination(tmp_path):
    routes = HEAD + USER + ("@app.get('/users')\ndef users():\n    return {'u': [u.id for u in User.query.all()]}\n"
                            "@app.get('/paged')\ndef paged():\n    page = request.args.get('page', 1, type=int)\n"
                            "    return {'u': [u.id for u in User.query.paginate(page=page)]}\n"
                            "@app.get('/one')\ndef one():\n    return {'u': User.query.filter_by(id=1).all()}\n")
    write(tmp_path, {**PG, "app.py": routes})
    found = by_rule(tmp_path, "missing-pagination")
    assert [(f.line_start, f.severity) for f in found] == [(12, "medium")]


def test_reference_tables_and_unique_lookups_are_bounded(tmp_path):
    write(tmp_path, {**PG, "app.py": HEAD + USER.replace("db.String(255))", "db.String(255), unique=True)") + (
        "class Country(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "@app.get('/countries')\ndef countries():\n    return {'c': Country.query.all()}\n"
        "@app.get('/me')\ndef me():\n    return {'u': User.query.filter_by(email='x').all()}\n")})
    assert not by_rule(tmp_path, "missing-pagination")


def test_whole_table_load_outside_handlers(tmp_path):
    write(tmp_path, {**PG, "jobs.py": HEAD + USER + (
        "def export():\n    return [u.email for u in User.query.all()]\n"
        "def stream():\n    return [u.email for u in User.query.yield_per(500)]\n")})
    assert [f.line_start for f in by_rule(tmp_path, "unbounded-query")] == [11]


def test_drf_list_view_pagination(tmp_path):
    view = ("from rest_framework import generics\nfrom .models import Ticket\n"
            "class TicketList(generics.ListAPIView):\n    queryset = Ticket.objects.all()\n")
    write(tmp_path, {"desk/views.py": view, "desk/models.py": "from django.db import models\n"
                     "class Ticket(models.Model):\n    title = models.CharField(max_length=9)\n"})
    assert len(by_rule(tmp_path, "missing-pagination")) == 1
    write(tmp_path, {"proj/settings.py": "REST_FRAMEWORK = {'DEFAULT_PAGINATION_CLASS': 'x.Pager', 'PAGE_SIZE': 50}\n"})
    assert not by_rule(tmp_path, "missing-pagination")


# ------------------------------------------------------------------------------------------ migrations
ALEMBIC = ("from alembic import op\nimport sqlalchemy as sa\nrevision = '{rev}'\ndown_revision = {down}\n"
           "def upgrade():\n{body}\ndef downgrade():\n    op.execute('select 1')\n")


def alembic(rev, body, down="None"):
    return ALEMBIC.format(rev=rev, down=down, body="\n".join("    " + ln for ln in body.splitlines()))


def test_destructive_migration_severity_depends_on_context(tmp_path):
    write(tmp_path, {**PG, "app/models.py": HEAD + USER, "migrations/versions/1.py": alembic("1", (
        "op.drop_column('users', 'email')\nop.drop_column('users', 'legacy')\n"
        "op.execute('UPDATE users SET name = nickname')\nop.drop_column('users', 'nickname')"))})
    found = {f.title: f.severity for f in by_rule(tmp_path, "destructive-migration")}
    assert found == {"Migration drops column `users.email`": "high",       # the model still declares it
                     "Migration drops column `users.legacy`": "medium",
                     "Migration drops column `users.nickname`": "low"}     # copied first


def test_down_migrations_and_new_tables_are_not_flagged(tmp_path):
    write(tmp_path, {**PG, "db/migrations/001_init.up.sql": (
        "CREATE TABLE audit (id serial primary key, user_id int NOT NULL);\n"
        "CREATE INDEX ix_audit_user ON audit (user_id);\nALTER TABLE audit ADD COLUMN note text NOT NULL;\n"),
        "db/migrations/001_init.down.sql": "DROP TABLE audit;\n"})
    assert not by_rule(tmp_path, "destructive-migration") and not by_rule(tmp_path, "unsafe-migration")


def test_create_index_locking_is_postgresql_specific(tmp_path):
    files = {"db/migrations/002.sql": "CREATE INDEX ix_a ON accounts (email);\n"
                                      "CREATE INDEX CONCURRENTLY ix_b ON accounts (name);\n"}
    write(tmp_path, {**PG, **files})
    assert [f.line_start for f in by_rule(tmp_path, "unsafe-migration")] == [1]
    (tmp_path / "requirements.txt").write_text("pymysql\n")
    assert not by_rule(tmp_path, "unsafe-migration")


def test_not_null_column_without_default_by_engine(tmp_path):
    body = "op.add_column('users', sa.Column('plan', sa.String(9), nullable=False, default='free'))"
    write(tmp_path, {**PG, "migrations/versions/1.py": alembic("1", body)})
    found = by_rule(tmp_path, "unsafe-migration")
    assert found[0].severity == "medium" and "client-side" in found[0].description
    (tmp_path / "requirements.txt").write_text("pymysql\n")
    assert by_rule(tmp_path, "unsafe-migration")[0].severity == "low"  # MySQL fills implicit defaults
    write(tmp_path, {"migrations/versions/1.py": alembic("1", body.replace("default=", "server_default="))})
    assert not by_rule(tmp_path, "unsafe-migration")


def test_type_change_widening_is_safe(tmp_path):
    write(tmp_path, {**PG, "migrations/versions/1.py": alembic("1", (
        "op.alter_column('users', 'name', type_=sa.String(200), existing_type=sa.String(100))\n"
        "op.alter_column('users', 'id', type_=sa.BigInteger(), existing_type=sa.Integer())"))})
    assert [f.line_start for f in by_rule(tmp_path, "unsafe-migration")] == [7]


def test_sqlite_needs_batch_mode(tmp_path):
    body = "op.alter_column('users', 'name', nullable=False)"
    write(tmp_path, {**SQLITE, "migrations/versions/1.py": alembic("1", body)})
    assert "batch" in by_rule(tmp_path, "unsafe-migration")[0].title.lower()
    write(tmp_path, {"migrations/versions/1.py": alembic("1", "with op.batch_alter_table('users') as b:\n"
                                                                "    b.alter_column('name', nullable=False)")})
    assert not [f for f in by_rule(tmp_path, "unsafe-migration") if "batch" in f.title.lower()]


def test_foreign_key_not_valid_and_renames(tmp_path):
    write(tmp_path, {**PG, "db/migrations/003.sql": (
        "ALTER TABLE posts ADD CONSTRAINT fk_a FOREIGN KEY (author_id) REFERENCES users (id);\n"
        "ALTER TABLE posts ADD CONSTRAINT fk_b FOREIGN KEY (editor_id) REFERENCES users (id) NOT VALID;\n"
        "ALTER TABLE posts RENAME COLUMN body TO content;\n")})
    found = by_rule(tmp_path, "unsafe-migration")
    assert [(f.line_start, f.title.split()[0]) for f in found] == [(1, "Foreign"), (3, "Migration")]


def test_irreversible_migrations(tmp_path):
    write(tmp_path, {**PG, "migrations/versions/1.py": ALEMBIC.replace("op.execute('select 1')", "pass").format(
        rev="1", down="None", body="    op.add_column('users', sa.Column('x', sa.Integer()))"),
        "shop/migrations/0002_data.py": (
            "from django.db import migrations\ndef fwd(apps, schema_editor):\n    pass\n"
            "class Migration(migrations.Migration):\n    dependencies = []\n"
            "    operations = [migrations.RunPython(fwd)]\n"),
        "shop/migrations/0003_ok.py": (
            "from django.db import migrations\nclass Migration(migrations.Migration):\n"
            "    operations = [migrations.RunPython(fwd, migrations.RunPython.noop)]\n")})
    assert sorted(f.file_path for f in by_rule(tmp_path, "irreversible-migration")) == [
        "migrations/versions/1.py", "shop/migrations/0002_data.py"]


# ------------------------------------------------------------------------------------------ relationships
def test_missing_foreign_key_and_its_exceptions(tmp_path):
    write(tmp_path, {**PG, "app/models.py": HEAD + USER + (
        "class Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    user_id = db.Column(db.Integer)\n"                                     # flagged
        "    commentable_id = db.Column(db.Integer)\n    commentable_type = db.Column(db.String(20))\n"
        "    stripe_customer_id = db.Column(db.String(40))\n"
        "class Login(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    user_id = db.Column(db.String(64))\n"                                  # an external id: not ours
        "class AuditLog(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    user_id = db.Column(db.Integer)\n")})                                 # log table: low
    found = {(f.title.split("`")[1], f.severity) for f in by_rule(tmp_path, "missing-foreign-key")}
    assert found == {("Note.user_id", "medium"), ("AuditLog.user_id", "low")}


def test_inconsistent_relationships(tmp_path):
    write(tmp_path, {**PG, "app/models.py": HEAD + (
        "class User(db.Model):\n    __tablename__ = 'users'\n    id = db.Column(db.BigInteger, primary_key=True)\n"
        "    posts = db.relationship('Post', back_populates='writer')\n"
        "    tags = db.relationship('Tag')\n"
        "class Post(db.Model):\n    __tablename__ = 'posts'\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=False, "
        "index=True)\n    author = db.relationship('User', back_populates='posts')\n"
        "class Tag(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    label = db.Column(db.String(9))\n")})
    titles = sorted(f.title for f in by_rule(tmp_path, "inconsistent-relationship"))
    assert titles == [
        "Post.author and User.posts do not point at each other",  # posts says 'writer', author says 'posts'
        "Post.author_id (int32) references users.id (int64)",
        "Post.author_id is NOT NULL but ON DELETE SET NULL",
        "User.posts back_populates a missing Post.writer",
        "User.tags has no foreign key path to Tag",
    ]


def test_django_accessor_clash_and_mongoose_refs(tmp_path):
    write(tmp_path, {"app/models.py": (
        "from django.db import models\nclass User(models.Model):\n    name = models.CharField(max_length=9)\n"
        "class Transfer(models.Model):\n    sender = models.ForeignKey(User, on_delete=models.CASCADE)\n"
        "    receiver = models.ForeignKey(User, on_delete=models.CASCADE)\n"
        "class Ok(models.Model):\n    a = models.ForeignKey(User, on_delete=models.CASCADE, related_name='a_ok')\n"
        "    b = models.ForeignKey(User, on_delete=models.CASCADE, related_name='b_ok')\n"),
        "package.json": '{"dependencies": {"mongoose": "8"}}',
        "models/post.js": "const mongoose = require('mongoose');\nconst postSchema = new mongoose.Schema({\n"
                          "  author: { type: mongoose.Schema.Types.ObjectId, ref: 'Usr' },\n});\n"
                          "module.exports = mongoose.model('Post', postSchema);\n"})
    titles = sorted(f.title for f in by_rule(tmp_path, "inconsistent-relationship"))
    assert titles == ["Post.author refs unknown model 'Usr'", "Transfer has 2 relations to User without related_name"]


def test_duplicated_data(tmp_path):
    write(tmp_path, {**PG, "app/models.py": HEAD + (
        "class Customer(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    email = db.Column(db.String(99))\n    ticket_count = db.Column(db.Integer)\n"
        "class Ticket(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), index=True)\n"
        "    customer_email = db.Column(db.String(99))\n"
        "class Order(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), index=True)\n"
        "    customer_email = db.Column(db.String(99))\n")})       # an order snapshots the e-mail on purpose
    titles = sorted(f.title for f in by_rule(tmp_path, "duplicated-data"))
    assert titles == ["`Customer.ticket_count` duplicates COUNT of Ticket",
                      "`Ticket.customer_email` copies `Customer.email`"]


# ------------------------------------------------------------------------------------------ transactions
DJ_MODELS = ("from django.db import models\nclass Account(models.Model):\n    balance = models.IntegerField()\n"
             "    email = models.EmailField()\nclass Entry(models.Model):\n    amount = models.IntegerField()\n")


def test_django_writes_outside_atomic(tmp_path):
    svc = ("from django.db import transaction\nfrom .models import Account, Entry\n"
           "def pay(a, n):\n    Entry.objects.create(amount=n)\n    Account.objects.filter(pk=a).update(balance=n)\n"
           "def pay_atomic(a, n):\n    with transaction.atomic():\n        Entry.objects.create(amount=n)\n"
           "        Account.objects.filter(pk=a).update(balance=n)\n")
    write(tmp_path, {"bank/models.py": DJ_MODELS, "bank/services.py": svc})
    assert [f.line_start for f in by_rule(tmp_path, "non-atomic-writes")] == [4]


def test_side_effect_before_commit(tmp_path):
    write(tmp_path, {"bank/models.py": DJ_MODELS, "bank/services.py": (
        "from django.db import transaction\nfrom .models import Entry\nfrom .tasks import notify\n"
        "@transaction.atomic\ndef a(n):\n    e = Entry.objects.create(amount=n)\n    notify.delay(e.pk)\n"
        "@transaction.atomic\ndef b(n):\n    e = Entry.objects.create(amount=n)\n"
        "    transaction.on_commit(lambda: notify.delay(e.pk))\n")})
    assert [f.line_start for f in by_rule(tmp_path, "side-effect-in-transaction")] == [7]


def test_missing_rollback(tmp_path):
    write(tmp_path, {**PG, "svc.py": HEAD + USER + (
        "def a(u):\n    try:\n        db.session.add(u)\n        db.session.commit()\n    except Exception:\n"
        "        print('failed')\n"
        "def b(u):\n    try:\n        db.session.commit()\n    except Exception:\n        db.session.rollback()\n"
        "def c(u):\n    try:\n        db.session.commit()\n    except Exception:\n        raise\n")})
    assert [f.line_start for f in by_rule(tmp_path, "missing-rollback")] == [14]


def test_multiple_commits_only_on_one_path(tmp_path):
    write(tmp_path, {**PG, "app.py": HEAD + USER + (
        "@app.post('/a')\ndef a():\n    u = User(email='x')\n    db.session.add(u)\n    db.session.commit()\n"
        "    u.active = True\n    db.session.commit()\n    return ''\n"
        "@app.post('/b')\ndef b():\n    if request.form.get('x'):\n        db.session.add(User())\n"
        "        db.session.commit()\n    else:\n        db.session.add(User())\n        db.session.commit()\n"
        "    return ''\n")})
    assert [f.line_start for f in by_rule(tmp_path, "multiple-commits")] == [16]  # not /b: exclusive branches


def test_uncommitted_dbapi_writes(tmp_path):
    write(tmp_path, {"store.py": (
        "import sqlite3\ndef save(x):\n    conn = sqlite3.connect('a.db')\n"
        "    conn.execute('INSERT INTO t (x) VALUES (?)', (x,))\n"
        "def save_ok(x):\n    conn = sqlite3.connect('a.db')\n    conn.execute('INSERT INTO t (x) VALUES (?)', (x,))\n"
        "    conn.commit()\n")})
    assert [f.line_start for f in by_rule(tmp_path, "uncommitted-writes")] == [4]


def test_js_transactions(tmp_path):
    write(tmp_path, {"src/orders.ts": (
        "import { Pool } from 'pg';\nconst pool = new Pool();\n"
        "export async function place(o) {\n  await prisma.order.create({ data: o });\n"
        "  await prisma.stock.update({ where: { id: o.sku }, data: { qty: { decrement: 1 } } });\n}\n"
        "export async function placeTx(o) {\n  await prisma.$transaction(async (tx) => {\n"
        "    await tx.order.create({ data: o });\n    await tx.stock.update({ where: { id: o.sku }, data: {} });\n"
        "    await fetch('https://hooks.example.com', { method: 'POST' });\n  });\n}\n"
        "export async function legacy() {\n  await pool.query('BEGIN');\n}\n")})
    assert [f.line_start for f in by_rule(tmp_path, "non-atomic-writes")] == [5]
    assert [f.line_start for f in by_rule(tmp_path, "side-effect-in-transaction")] == [11]
    assert [f.severity for f in by_rule(tmp_path, "transaction-on-pool")] == ["high"]


# ------------------------------------------------------------------------------------------ races
def test_lost_update_and_its_fixes(tmp_path):
    write(tmp_path, {"bank/models.py": DJ_MODELS, "bank/services.py": (
        "from django.db import transaction\nfrom django.db.models import F\nfrom .models import Account\n"
        "def debit(pk, n):\n    acct = Account.objects.get(pk=pk)\n    acct.balance -= n\n    acct.save()\n"
        "def debit_f(pk, n):\n    Account.objects.filter(pk=pk).update(balance=F('balance') - n)\n"
        "@transaction.atomic\ndef debit_locked(pk, n):\n    acct = Account.objects.select_for_update().get(pk=pk)\n"
        "    acct.balance -= n\n    acct.save()\n"
        "def rename(pk):\n    acct = Account.objects.get(pk=pk)\n    acct.email = acct.email + '.old'\n"
        "    acct.save()\n")})
    found = run(tmp_path)
    assert [f.line_start for f in found if f.rule_id == "eval:database.lost-update"] == [6]
    assert not [f for f in found if f.rule_id == "eval:database.lock-outside-transaction"]


def test_select_for_update_outside_transaction(tmp_path):
    write(tmp_path, {"bank/models.py": DJ_MODELS, "bank/services.py": (
        "from .models import Account\ndef debit(pk):\n    return Account.objects.select_for_update().get(pk=pk)\n")})
    assert [f.line_start for f in by_rule(tmp_path, "lock-outside-transaction")] == [3]


def test_row_lock_on_sqlite(tmp_path):
    write(tmp_path, {**SQLITE, "svc.py": HEAD + USER + (
        "def lock(i):\n    return User.query.filter_by(id=i).with_for_update().first()\n")})
    assert len(by_rule(tmp_path, "row-lock-unsupported")) == 1


def test_check_then_insert(tmp_path):
    code = HEAD + USER + ("def signup(e):\n    if not User.query.filter_by(email=e).first():\n"
                          "        db.session.add(User(email=e))\n")
    write(tmp_path, {**PG, "svc.py": code})
    assert [f.line_start for f in by_rule(tmp_path, "check-then-insert")] == [12]
    write(tmp_path, {"svc.py": code.replace("db.String(255))", "db.String(255), unique=True)")})
    assert not by_rule(tmp_path, "check-then-insert")


def test_django_get_or_create_needs_unique_lookup(tmp_path):
    write(tmp_path, {"bank/models.py": DJ_MODELS, "bank/services.py": (
        "from .models import Account\ndef ensure(e):\n    return Account.objects.get_or_create(email=e)\n"
        "def ensure_pk(pk):\n    return Account.objects.get_or_create(pk=pk)\n")})
    assert [f.line_start for f in by_rule(tmp_path, "check-then-insert")] == [3]


def test_js_lost_update_and_check_then_insert(tmp_path):
    write(tmp_path, {"package.json": '{"dependencies": {"@prisma/client": "5"}}', "prisma/schema.prisma": (
        'datasource db {\n  provider = "postgresql"\n}\n'
        "model Wallet {\n  id Int @id\n  credits Int\n  owner String\n}\n"),
        "src/wallet.ts": (
            "export async function spend(id) {\n  const w = await prisma.wallet.findUnique({ where: { id } });\n"
            "  await prisma.wallet.update({ where: { id }, data: { credits: w.credits - 1 } });\n}\n"
            "export async function open(owner) {\n  const w = await prisma.wallet.findFirst({ where: { owner } });\n"
            "  if (!w) {\n    await prisma.wallet.create({ data: { owner, credits: 0 } });\n  }\n}\n"
            "export async function spendAtomic(id) {\n"
            "  await prisma.wallet.update({ where: { id }, data: { credits: { decrement: 1 } } });\n}\n")})
    found = run(tmp_path)
    assert [f.line_start for f in found if f.rule_id == "eval:database.lost-update"] == [3]
    assert [f.line_start for f in found if f.rule_id == "eval:database.check-then-insert"] == [8]
