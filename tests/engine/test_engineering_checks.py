"""Engineering-quality checks beyond classic security: object-level authorization, error handling, schema design,
scalability, observability, and undocumented configuration assumptions. Each rule has a positive and a negative
case so heuristics stay precise."""

from __future__ import annotations

from eval_engine.analyzers import registry
from eval_engine.analyzers.base import AnalyzerContext
from eval_engine.analyzers.database import is_money_name
from eval_engine.compliance import map_finding
from eval_engine.languages import detect
from eval_engine.pipeline import run_analyzer
from eval_engine.workspace import iter_files
from tests.conftest import FIXTURES


def write(root, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def run(name, root):
    files = list(iter_files(root))
    ctx = AnalyzerContext(root=root, files=files, languages=detect(root, files), timeout=120)
    outcome = run_analyzer(registry.get([name])[0], ctx)
    assert outcome.status == "ok", outcome.reason
    return outcome.findings


def rules(name, root):
    return {f.rule_id for f in run(name, root)}


FLASK_REQS = "flask\nflask-login\nflask-sqlalchemy\n"


# ------------------------------------------------------------------------------------------ authorization (IDOR)
def test_idor_flagged_for_authenticated_lookup_without_ownership(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK_REQS, "views.py": (
        "from flask_login import login_required\n"
        "@bp.route('/invoices/<int:invoice_id>')\n@login_required\n"
        "def show(invoice_id):\n    inv = Invoice.query.get_or_404(invoice_id)\n    return inv.to_dict()\n")})
    found = [f for f in run("api_security", tmp_path) if f.rule_id == "eval:api.idor-unscoped-lookup"]
    assert len(found) == 1 and found[0].line_start == 5 and found[0].category == "security"


def test_idor_not_flagged_when_scoped_to_current_user(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK_REQS, "views.py": (
        "from flask_login import login_required, current_user\n"
        "@bp.route('/invoices/<int:invoice_id>')\n@login_required\n"
        "def show(invoice_id):\n"
        "    inv = Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first_or_404()\n"
        "    return inv.to_dict()\n"
        "@bp.route('/public/<slug>')\ndef public(slug):\n    return Page.query.filter_by(slug=slug).first()\n")})
    assert "eval:api.idor-unscoped-lookup" not in rules("api_security", tmp_path)


def test_idor_fastapi_dependency_principal_counts_as_scoping(tmp_path):
    write(tmp_path, {"requirements.txt": "fastapi\n", "api.py": (
        "@router.get('/docs/{doc_id}')\n"
        "def get_doc(doc_id: int, user=Depends(get_current_user)):\n"
        "    return db.get(Doc, doc_id) if user.can_read(doc_id) else None\n"
        "@router.get('/notes/{note_id}')\n"
        "def get_note(note_id: int, user=Depends(get_current_user)):\n"
        "    return db.get(Note, note_id)\n")})
    found = [f for f in run("api_security", tmp_path) if f.rule_id == "eval:api.idor-unscoped-lookup"]
    assert [f.line_start for f in found] == [6]


def test_idor_express(tmp_path):
    write(tmp_path, {"package.json": '{"dependencies": {"express": "4.19.2"}}', "server.js": (
        "const express = require('express');\nconst app = express();\n"
        "app.get('/orders/:id', requireAuth, async (req, res) => {\n"
        "  const order = await Order.findById(req.params.id);\n  res.json(order);\n});\n"
        "app.get('/carts/:id', requireAuth, async (req, res) => {\n"
        "  const cart = await Cart.findOne({ _id: req.params.id, owner: req.user.id });\n  res.json(cart);\n});\n")})
    found = [f for f in run("api_security", tmp_path) if f.rule_id == "eval:api.idor-unscoped-lookup"]
    assert [f.line_start for f in found] == [4]


# ------------------------------------------------------------------------------------------------ error handling
def test_error_details_exposed_python(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK_REQS, "views.py": (
        "import traceback\n"
        "@app.route('/a')\ndef a():\n    try:\n        work()\n    except Exception as e:\n"
        "        return {'error': str(e)}, 500\n"
        "@app.route('/b')\ndef b():\n    try:\n        work()\n    except Exception:\n"
        "        return {'trace': traceback.format_exc()}, 500\n"
        "@app.route('/c')\ndef c():\n    try:\n        parse()\n    except ValueError as e:\n"
        "        return {'error': str(e)}, 400\n"
        "@app.errorhandler(Exception)\ndef boom(err):\n    return jsonify(error=str(err)), 500\n")})
    found = sorted(f.line_start for f in run("api_security", tmp_path) if f.rule_id == "eval:api.error-details-exposed")
    assert found == [7, 13, 22]  # validation errors (ValueError -> 400) are fine to echo


def test_error_details_exposed_js_stack(tmp_path):
    write(tmp_path, {"server.js": "app.use((err, req, res, next) => {\n  res.status(500).json({ stack: err.stack });\n"
                                  "});\n"})
    assert "eval:api.error-details-exposed" in rules("api_security", tmp_path)


def test_no_error_handler_express(tmp_path):
    routes = "".join(f"app.get('/r{i}', (req, res) => res.send('ok'));\n" for i in range(4))
    write(tmp_path, {"package.json": '{"dependencies": {"express": "4.19.2"}}', "server.js": routes})
    assert "eval:api.no-error-handler" in rules("api_security", tmp_path)
    write(tmp_path, {"server.js": routes + "app.use((err, req, res, next) => res.status(500).end());\n"})
    assert "eval:api.no-error-handler" not in rules("api_security", tmp_path)


def test_swallowed_exception_variants(tmp_path):
    write(tmp_path, {"svc.py": (
        "try:\n    import ujson\nexcept Exception:\n    pass\n"
        "def f():\n    for x in y:\n        try:\n            g(x)\n"
        "        except BaseException:\n            continue\n"
        "def h():\n    try:\n        g()\n    except KeyError:\n        pass\n"),
        "web/app.js": "try { run(); } catch (e) {}\nfetchIt().catch(() => {});\ntry { a() } catch (e) { log(e) }\n"})
    found = sorted((f.file_path, f.line_start) for f in run("maintainability", tmp_path)
                   if f.rule_id == "eval:maintainability.swallowed-exception")
    assert found == [("svc.py", 3), ("svc.py", 9), ("web/app.js", 1), ("web/app.js", 2)]


# ------------------------------------------------------------------------------------------------ schema design
def test_money_name_tokens():
    assert is_money_name("price") and is_money_name("unitPrice") and is_money_name("total_amount")
    assert not is_money_name("tax_rate") and not is_money_name("discount_percent") and not is_money_name("name")


def test_database_design_sqlalchemy(tmp_path):
    write(tmp_path, {"models.py": (
        "from flask_sqlalchemy import SQLAlchemy\ndb = SQLAlchemy()\n"
        "class User(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    email = db.Column(db.String(255))\n    balance = db.Column(db.Float)\n"
        "class Invite(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    email = db.Column(db.String(255))\n    price: Mapped[float] = mapped_column()\n"
        "class AuditRow(db.Model):\n    __tablename__ = 'audit_rows'\n    message = db.Column(db.Text)\n"
        "class Product(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    sku = db.Column(db.String(40), unique=True)\n    price = db.Column(db.Numeric(10, 2))\n"
        "class Base(db.Model):\n    __abstract__ = True\n    created = db.Column(db.DateTime)\n")})
    found = {(f.rule_id, f.line_start) for f in run("database", tmp_path)}
    assert ("eval:database.missing-unique-constraint", 5) in found  # User.email
    assert ("eval:database.money-as-float", 6) in found  # balance Float
    assert ("eval:database.money-as-float", 10) in found  # Mapped[float]
    assert ("eval:database.no-primary-key", 11) in found
    assert not any(line in (9, 16, 17, 18) for _, line in found)  # Invite.email, unique sku, Numeric, abstract


def test_database_design_respects_mixins_and_composite_uniqueness(tmp_path):
    write(tmp_path, {"models.py": (
        "from flask_sqlalchemy import SQLAlchemy\ndb = SQLAlchemy()\n"
        "class TenantMixin:\n    id = db.Column(db.Integer, primary_key=True)\n"
        "class Project(TenantMixin, db.Model):\n    org_id = db.Column(db.Integer)\n"
        "    slug = db.Column(db.String(80))\n"
        "    __table_args__ = (db.UniqueConstraint('org_id', 'slug'),)\n"
        "class UserIdentity(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
        "    email = db.Column(db.String(255))\n")})
    found = {f.rule_id for f in run("database", tmp_path)}
    assert not found & {"eval:database.no-primary-key", "eval:database.missing-unique-constraint"}


def test_database_design_django_and_prisma(tmp_path):
    write(tmp_path, {
        "shop/models.py": "from django.db import models\nclass Customer(models.Model):\n"
                          "    email = models.EmailField()\n    credit = models.FloatField()\n"
                          "    total_spent = models.FloatField()\n",
        "prisma/schema.prisma": "model User {\n  id Int @id\n  email String\n  amount Float\n}\n"
                                "model Shop {\n  id Int @id\n  slug String @unique\n}\n"})
    found = {(f.file_path, f.rule_id, f.line_start) for f in run("database", tmp_path)}
    assert ("shop/models.py", "eval:database.missing-unique-constraint", 3) in found
    assert ("shop/models.py", "eval:database.money-as-float", 5) in found
    assert ("shop/models.py", "eval:database.money-as-float", 4) not in found  # 'credit' is not a money token
    assert ("prisma/schema.prisma", "eval:database.missing-unique-constraint", 3) in found
    assert ("prisma/schema.prisma", "eval:database.money-as-float", 4) in found
    assert not any(line == 8 for _, _, line in found)


def test_vulnapp_order_total_is_float():
    from tests.engine.test_analyzers import rules_from

    _, found, _ = rules_from("database", "vulnapp")
    assert "eval:database.money-as-float" in found


# --------------------------------------------------------------------------------------------------- scalability
def test_in_process_state_python(tmp_path):
    write(tmp_path, {"app.py": (
        "SESSIONS = {}\nALLOWED = {'a', 'b'}\n"
        "@app.post('/login')\ndef login():\n    SESSIONS[token] = user\n    return 'ok'\n"
        "@app.get('/check')\ndef check():\n    return token in ALLOWED\n")})
    found = [f for f in run("performance", tmp_path) if f.rule_id == "eval:performance.in-process-state"]
    assert [f.line_start for f in found] == [5]


def test_scalability_js(tmp_path):
    write(tmp_path, {"server.js": (
        "const session = require('express-session');\nconst multer = require('multer');\n"
        "const carts = new Map();\nconst upload = multer({ dest: 'uploads/' });\n"
        "app.use(session({ secret: process.env.S }));\n"
        "app.post('/cart', (req, res) => { carts.set(req.user.id, req.body); res.end(); });\n"
        "app.get('/all', async (req, res) => res.json(await prisma.user.findMany()));\n"
        "app.get('/page', async (req, res) => res.json(await prisma.user.findMany({ take: 20 })));\n")})
    found = {(f.rule_id, f.line_start) for f in run("performance", tmp_path)}
    assert ("eval:performance.in-process-state", 6) in found
    assert ("eval:performance.memory-session-store", 5) in found
    assert ("eval:performance.local-file-storage", 4) in found
    db = {(f.rule_id, f.line_start) for f in run("database", tmp_path)}
    assert ("eval:database.missing-pagination", 7) in db
    assert ("eval:database.missing-pagination", 8) not in db


def test_session_store_configured_not_flagged(tmp_path):
    write(tmp_path, {"server.js": "const session = require('express-session');\n"
                                  "app.use(session({ store: new RedisStore({ client }), secret: s }));\n"
                                  "app.get('/', (req, res) => res.end());\n"})
    assert "eval:performance.memory-session-store" not in rules("performance", tmp_path)


def test_local_upload_python(tmp_path):
    write(tmp_path, {"app.py": "@app.post('/upload')\ndef up():\n    f = request.files['file']\n"
                               "    f.save('/srv/uploads/' + f.filename)\n    return 'ok'\n"})
    assert "eval:performance.local-file-storage" in rules("performance", tmp_path)


# ------------------------------------------------------------------------------------------------- observability
def test_observability_gaps_reported_for_web_service(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\n", "app.py": (
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.get('/health')\ndef health():\n    print('health check')\n    return 'ok'\n")})
    found = rules("devops", tmp_path)
    assert {"eval:devops.no-metrics", "eval:devops.no-tracing", "eval:devops.no-request-id",
            "eval:devops.print-logging"} <= found


def test_observability_satisfied(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\nsentry-sdk\nprometheus-client\n", "app.py": (
        "import logging\nfrom flask import Flask, request\napp = Flask(__name__)\nlog = logging.getLogger(__name__)\n"
        "@app.get('/health')\ndef health():\n"
        "    log.info('ok', extra={'request_id': request.headers.get('X-Request-ID')})\n"
        "    return 'ok'\n")})
    found = rules("devops", tmp_path)
    assert not found & {"eval:devops.no-metrics", "eval:devops.no-tracing", "eval:devops.no-request-id",
                        "eval:devops.print-logging"}


def test_console_logging_ok_when_logger_library_present(tmp_path):
    write(tmp_path, {"package.json": '{"dependencies": {"express": "4.19.2", "pino": "9.0.0"}}',
                     "server.js": "app.get('/x', (req, res) => { console.log('hit'); res.end(); });\n"})
    assert "eval:devops.print-logging" not in rules("devops", tmp_path)
    write(tmp_path, {"package.json": '{"dependencies": {"express": "4.19.2"}}'})
    assert "eval:devops.print-logging" in rules("devops", tmp_path)


# ------------------------------------------------------------------------------- configuration / assumptions
def test_env_vars_without_example_file(tmp_path):
    write(tmp_path, {"settings.py": (
        "import os\nDB = os.environ['DATABASE_URL']\nKEY = os.getenv('STRIPE_KEY')\nHOME = os.getenv('HOME')\n")})
    found = run("configuration", tmp_path)
    [f] = [f for f in found if f.rule_id == "eval:config.no-env-example"]
    assert "DATABASE_URL" in f.description and "STRIPE_KEY" in f.description and "HOME" not in f.description
    assert "Required (no default): DATABASE_URL" in f.description


def test_undocumented_env_var_with_example_file(tmp_path):
    write(tmp_path, {
        ".env.example": "DATABASE_URL=postgres://user:pass@localhost/app\n",
        "README.md": "Set `SENTRY_DSN` to report errors.\n",
        "settings.py": "import os\nDB = os.environ['DATABASE_URL']\nDSN = os.getenv('SENTRY_DSN')\n",
        "web/client.ts": "const url = process.env.API_BASE_URL ?? '';\nconst k = import.meta.env['VITE_KEY'];\n"})
    found = {(f.rule_id, f.title) for f in run("configuration", tmp_path)}
    titles = {t for r, t in found if r == "eval:config.undocumented-env-var"}
    assert titles == {"Environment variable API_BASE_URL is not documented",
                      "Environment variable VITE_KEY is not documented"}


def test_hardcoded_endpoints_and_paths(tmp_path):
    write(tmp_path, {
        ".env.example": "REDIS_URL=\n",
        "worker.py": "import os\nREDIS = os.getenv('REDIS_URL', 'redis://localhost:6379/0')\n"
                     "API = 'http://192.168.1.20:8080/api'\nDATA = '/home/alice/data/input.csv'\n",
        "ok.py": "PUBLIC = 'https://api.example.com'\nBIND = '0.0.0.0'\n",
        "web/api.js": "const base = 'http://localhost:3000/api';\nconst prod = process.env.API || 'http://localhost:3000';\n"})
    found = {(f.rule_id, f.file_path, f.line_start) for f in run("configuration", tmp_path)}
    assert ("eval:config.hardcoded-endpoint", "worker.py", 3) in found  # not line 2: env fallback is fine
    assert ("eval:config.machine-specific-path", "worker.py", 4) in found
    assert ("eval:config.hardcoded-endpoint", "web/api.js", 1) in found
    assert not any(path == "ok.py" for _, path, _ in found)


def test_undocumented_api(tmp_path):
    routes = "".join(f"@app.get('/r{i}')\ndef r{i}():\n    return 'ok'\n" for i in range(5))
    write(tmp_path, {"requirements.txt": "flask\n", "app.py": routes})
    assert "eval:config.undocumented-api" in rules("configuration", tmp_path)
    write(tmp_path, {"openapi.yaml": "openapi: 3.1.0\n"})
    assert "eval:config.undocumented-api" not in rules("configuration", tmp_path)


def test_clean_fixture_has_no_configuration_findings():
    files = list(iter_files(FIXTURES / "cleanapp"))
    ctx = AnalyzerContext(root=FIXTURES / "cleanapp", files=files, languages=detect(FIXTURES / "cleanapp", files))
    assert run_analyzer(registry.get(["configuration"])[0], ctx).findings == []


# ---------------------------------------------------------------------------------------------------- compliance
def test_new_rules_are_mapped_to_controls():
    assert map_finding("eval:api.idor-unscoped-lookup", "security")["owasp"] == ["A01:2021"]
    assert map_finding("eval:api.error-details-exposed", "security")["cwe"] == ["CWE-209"]
    assert "A09:2021" in map_finding("eval:devops.no-tracing", "devops")["owasp"]
    assert map_finding("eval:database.money-as-float", "database")["cwe"] == ["CWE-1339"]
    assert "A.8.9" in map_finding("eval:config.undocumented-env-var", "maintainability")["iso27001"]
