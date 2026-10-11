"""API design checks: input validation, status codes, idempotency, versioning, error-format consistency and API-wide
rate limiting. Each rule has a positive and a negative case so heuristics stay precise."""

from __future__ import annotations

from eval_engine.compliance import map_finding
from tests.engine.test_engineering_checks import rules, run, write

FLASK = "flask\n"
EXPRESS = '{"dependencies": {"express": "4.19.2"}}'


def found(root, rule):
    return sorted((f.file_path, f.line_start) for f in run("api_security", root) if f.rule_id == f"eval:api.{rule}")


# ------------------------------------------------------------------------------------------ input validation
def test_unvalidated_json_body_flagged_python(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK, "views.py": (
        "@app.post('/items')\ndef create():\n    data = request.get_json()\n    save(data['name'])\n"
        "    return {}, 201\n"
        "@app.post('/checked')\ndef checked():\n    data = ItemSchema().load(request.json)\n    return {}, 201\n"
        "@app.post('/manual')\ndef manual():\n    data = request.json\n    if 'name' not in data:\n"
        "        return {'error': 'name required'}, 400\n    return {}, 201\n"
        "@app.get('/read')\ndef read():\n    return request.json\n")})
    assert found(tmp_path, "missing-input-validation") == [("views.py", 3)]


def test_unvalidated_body_flagged_express(tmp_path):
    write(tmp_path, {"package.json": EXPRESS, "server.js": (
        "const express = require('express');\n"
        "app.post('/users', async (req, res) => {\n  const u = await db.save(req.body.name);\n  res.json(u);\n});\n"
        "app.post('/safe', validate(userSchema), async (req, res) => {\n  res.json(await db.save(req.body));\n});\n"
        "app.put('/z', (req, res) => {\n  const r = UserSchema.safeParse(req.body);\n  res.json(r);\n});\n")})
    assert found(tmp_path, "missing-input-validation") == [("server.js", 3)]


def test_spec_validator_suppresses_validation_check(tmp_path):
    write(tmp_path, {"package.json": EXPRESS, "server.js": (
        "const express = require('express');\napp.use(OpenApiValidator.middleware({ apiSpec: './api.yaml' }));\n"
        "app.post('/users', (req, res) => res.json(save(req.body)));\n")})
    assert found(tmp_path, "missing-input-validation") == []


# ------------------------------------------------------------------------------------------ status codes
def test_error_body_with_success_status_python(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK, "views.py": (
        "@app.get('/a')\ndef a():\n    return jsonify({'error': 'not found'})\n"
        "@app.get('/b')\ndef b():\n    return {'success': False, 'message': 'nope'}, 200\n"
        "@app.get('/c')\ndef c():\n    return jsonify(error='bad'), 400\n"
        "@app.get('/d')\ndef d():\n    return {'errors': [], 'items': []}\n"
        "def helper():\n    return {'error': 'x'}\n")})
    assert found(tmp_path, "error-status-200") == [("views.py", 3), ("views.py", 6)]


def test_error_body_with_success_status_express_and_next(tmp_path):
    write(tmp_path, {"package.json": EXPRESS, "server.js": (
        "const express = require('express');\n"
        "app.get('/a', (req, res) => {\n  return res.json({ error: 'missing' });\n});\n"
        "app.get('/b', (req, res) => {\n  res.status(404).json({ error: 'missing' });\n});\n"
        "app.get('/c', (req, res) => {\n  res.status(code);\n  res.json({ error: 'x' });\n});\n"),
        "app/api/items/route.ts": (
            "export async function GET() {\n  return NextResponse.json({ error: 'x' });\n}\n"
            "export async function POST() {\n  return NextResponse.json({ error: 'x' }, { status: 400 });\n}\n")})
    assert found(tmp_path, "error-status-200") == [("app/api/items/route.ts", 2), ("server.js", 3)]


# ------------------------------------------------------------------------------------------ idempotency
def test_payment_post_without_idempotency(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK, "pay.py": (
        "@app.post('/orders')\ndef create_order():\n    return {}, 201\n"
        "@app.post('/orders/search')\ndef search_orders():\n    return {}\n"
        "@app.post('/stripe/webhook')\ndef stripe_webhook():\n    return {}\n"
        "@app.post('/display')\ndef display():\n    return {}\n"
        "def charge(amount):\n    return stripe.PaymentIntent.create(amount=amount, currency='usd')\n")})
    assert found(tmp_path, "missing-idempotency") == [("pay.py", 2), ("pay.py", 14)]


def test_idempotency_key_handling_suppresses_route_check(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK, "pay.py": (
        "@app.post('/orders')\ndef create_order():\n    key = request.headers.get('Idempotency-Key')\n"
        "    return {}, 201\n"
        "def charge(amount, key):\n"
        "    return stripe.PaymentIntent.create(amount=amount, currency='usd', idempotency_key=key)\n")})
    assert found(tmp_path, "missing-idempotency") == []


def test_stripe_node_call_without_idempotency_key(tmp_path):
    write(tmp_path, {"package.json": EXPRESS, "billing.js": (
        "await stripe.paymentIntents.create({ amount, currency: 'usd' });\n"
        "await stripe.refunds.create({ payment_intent: id }, { idempotencyKey: key });\n")})
    assert found(tmp_path, "missing-idempotency") == [("billing.js", 1)]


# ------------------------------------------------------------------------------------------ versioning
def test_unversioned_api_flagged(tmp_path):
    routes = "".join(f"@app.get('/api/r{i}')\ndef r{i}():\n    return {{}}\n" for i in range(5))
    write(tmp_path, {"requirements.txt": FLASK, "api.py": routes})
    assert found(tmp_path, "unversioned") == [("api.py", 2)]


def test_versioned_by_blueprint_prefix(tmp_path):
    routes = "".join(f"@bp.get('/r{i}')\ndef r{i}():\n    return {{}}\n" for i in range(5))
    write(tmp_path, {"requirements.txt": FLASK, "api.py": "bp = Blueprint('api', __name__, url_prefix='/api/v1')\n"
                     + routes})
    assert found(tmp_path, "unversioned") == []


def test_unversioned_express_mount(tmp_path):
    routes = "".join(f"router.get('/r{i}', (req, res) => res.json({{}}));\n" for i in range(5))
    write(tmp_path, {"package.json": EXPRESS, "server.js": (
        "const express = require('express');\nconst router = express.Router();\n" + routes
        + "app.use('/api', router);\n")})
    assert found(tmp_path, "unversioned") == [("server.js", 8)]
    write(tmp_path, {"server.js": (
        "const express = require('express');\nconst router = express.Router();\n" + routes
        + "app.use('/api/v2', router);\n")})
    assert found(tmp_path, "unversioned") == []


# ------------------------------------------------------------------------------------------ error format
def test_inconsistent_error_format(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK, "views.py": (
        "@app.get('/a')\ndef a():\n    return jsonify(error='x'), 404\n"
        "@app.get('/b')\ndef b():\n    return jsonify(error='y'), 400\n"
        "@app.get('/c')\ndef c():\n    return jsonify(error='z'), 409\n"
        "@app.get('/d')\ndef d():\n    return {'message': 'gone'}, 410\n")})
    hits = [f for f in run("api_security", tmp_path) if f.rule_id == "eval:api.inconsistent-error-format"]
    assert len(hits) == 1 and (hits[0].file_path, hits[0].line_start) == ("views.py", 12)
    assert "{error} ×3" in hits[0].description and "{message} ×1" in hits[0].description


def test_consistent_error_format_not_flagged(tmp_path):
    write(tmp_path, {"requirements.txt": FLASK, "views.py": "".join(
        f"@app.get('/r{i}')\ndef r{i}():\n    return jsonify(error='x'), 40{i}\n" for i in range(5))})
    assert "eval:api.inconsistent-error-format" not in rules("api_security", tmp_path)


# ------------------------------------------------------------------------------------------ rate limiting
def test_api_wide_rate_limit_without_login_routes(tmp_path):
    routes = "".join(f"@app.get('/r{i}')\ndef r{i}():\n    return {{}}\n" for i in range(5))
    write(tmp_path, {"requirements.txt": FLASK, "api.py": routes})
    hits = [f for f in run("api_security", tmp_path) if f.rule_id == "eval:api.no-rate-limiting"]
    assert len(hits) == 1 and hits[0].severity == "info"
    write(tmp_path, {"requirements.txt": FLASK + "flask-limiter\n"})
    assert "eval:api.no-rate-limiting" not in rules("api_security", tmp_path)


def test_api_design_rules_have_compliance_mappings():
    assert map_finding("eval:api.missing-input-validation", "api")["cwe"] == ["CWE-20"]
    assert map_finding("eval:api.missing-input-validation", "api")["owasp"] == ["A03:2021"]
    assert map_finding("eval:api.missing-idempotency", "api")["cwe"] == ["CWE-837"]
    assert map_finding("eval:api.error-status-200", "api")["cwe"] == ["CWE-393"]
