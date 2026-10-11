"""Testing analyzer: test presence, kinds of tests, critical paths, error paths, assertion strength and duplicated
setup. Each rule has a positive and a negative case so heuristics stay precise."""

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


def run(root):
    files = list(iter_files(root))
    ctx = AnalyzerContext(root=root, files=files, languages=detect(root, files), timeout=120)
    outcome = run_analyzer(registry.get(["testing"])[0], ctx)
    assert outcome.status == "ok", outcome.reason
    return outcome.findings


def by_rule(root, rule):
    return [f for f in run(root) if f.rule_id == f"eval:testing.{rule}"]


FLASK_APP = (
    "from flask import Flask, abort, jsonify\nfrom flask_sqlalchemy import SQLAlchemy\n"
    "app = Flask(__name__)\ndb = SQLAlchemy(app)\n\n"
    "@app.get('/items/<int:item_id>')\ndef item(item_id):\n    return jsonify(id=item_id)\n\n"
    "@app.post('/login')\ndef login():\n    return jsonify(ok=True)\n"
)
FILLER = "".join(f"def helper_{i}(x):\n    return x + {i}\n\n" for i in range(120))  # pushes source past size gates


# ------------------------------------------------------------------------------------------ presence
def test_language_without_tests(tmp_path):
    write(tmp_path, {"app.py": "def f():\n    return 1\n", "tests/test_app.py": "from app import f\n\n"
                     "def test_f():\n    assert f() == 1\n",
                     "web/main.js": "".join(f"export function f{i}(x) {{\n  return x + {i};\n}}\n"
                                            for i in range(200))})
    found = by_rule(tmp_path, "language-without-tests")
    assert [f.title for f in found] == ["No tests for the javascript code"]


def test_language_with_tests_is_not_flagged(tmp_path):
    write(tmp_path, {"web/main.js": "".join(f"export const f{i} = (x) => x + {i};\n" for i in range(600)),
                     "web/main.test.js": "import { f1 } from './main';\n"
                     "test('f1', () => {\n  expect(f1(1)).toBe(2);\n});\n"})
    assert not by_rule(tmp_path, "language-without-tests")


# ------------------------------------------------------------------------------------------ API tests
def test_routes_without_api_tests(tmp_path):
    write(tmp_path, {"app.py": FLASK_APP, "tests/test_unit.py": "def test_x():\n    assert 1 + 1 == 2\n"})
    found = by_rule(tmp_path, "missing-api-tests")
    assert len(found) == 1 and found[0].file_path == "app.py"


def test_api_tests_with_test_client_are_recognized(tmp_path):
    write(tmp_path, {"app.py": FLASK_APP, "tests/test_api.py": "from app import app\n\ndef test_item():\n"
                     "    r = app.test_client().get('/items/1')\n    assert r.status_code == 200\n"})
    assert not by_rule(tmp_path, "missing-api-tests")


# ------------------------------------------------------------------------------------------ integration tests
def test_datastore_without_integration_tests(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\nflask-sqlalchemy\n", "app.py": FLASK_APP + FILLER,
                     "tests/test_unit.py": "def test_x():\n    assert 1 + 1 == 2\n"})
    assert len(by_rule(tmp_path, "missing-integration-tests")) == 1


def test_database_fixture_counts_as_integration_test(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\nflask-sqlalchemy\n", "app.py": FLASK_APP + FILLER,
                     "tests/conftest.py": "import pytest\nfrom app import app, db\n\n@pytest.fixture\ndef client():\n"
                     "    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'\n    db.create_all()\n"
                     "    yield app.test_client()\n",
                     "tests/test_unit.py": "def test_x():\n    assert 1 + 1 == 2\n"})
    assert not by_rule(tmp_path, "missing-integration-tests")


def test_integration_directory_counts_as_integration_test(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\nflask-sqlalchemy\n", "app.py": FLASK_APP + FILLER,
                     "tests/integration/test_flow.py": "def test_x():\n    assert 1 + 1 == 2\n"})
    assert not by_rule(tmp_path, "missing-integration-tests")


# ------------------------------------------------------------------------------------------ critical paths
def test_untested_critical_module_and_endpoint(tmp_path):
    write(tmp_path, {"app.py": FLASK_APP, "payments.py": "def charge(amount):\n    return amount\n",
                     "tests/test_api.py": "from app import app\n\ndef test_item():\n"
                     "    r = app.test_client().get('/items/1')\n    assert r.status_code == 200\n"})
    found = by_rule(tmp_path, "untested-critical-paths")
    assert len(found) == 1
    assert "module payments.py" in found[0].evidence and "POST /login" in found[0].evidence
    assert "/items" not in found[0].evidence


def test_referenced_critical_paths_are_not_flagged(tmp_path):
    write(tmp_path, {"app.py": FLASK_APP, "payments.py": "def charge(amount):\n    return amount\n",
                     "tests/test_payments.py": "from payments import charge\n\ndef test_charge():\n"
                     "    assert charge(5) == 5\n",
                     "tests/test_api.py": "from app import app\n\ndef test_login():\n"
                     "    r = app.test_client().post('/login')\n    assert r.status_code == 200\n"})
    assert not by_rule(tmp_path, "untested-critical-paths")


API_TEST = "from app import app\nclient = app.test_client()\n\ndef test_api():\n    r = client.get({url})\n" \
           "    assert r.status_code == 200\n"


def critical_endpoints(root, app_py, test_call):
    write(root, {"app.py": app_py, "tests/test_api.py": API_TEST.format(url=test_call)})
    found = by_rule(root, "untested-critical-paths")
    return found[0].evidence if found else ""


def test_endpoint_reached_by_route_name_is_tested(tmp_path):
    app_py = "from flask import Flask\napp = Flask(__name__)\n\n@app.post('/signin')\ndef login():\n    return ''\n"
    assert critical_endpoints(tmp_path, app_py, "url_for('auth.login')") == ""


def test_endpoint_reached_by_built_url_is_tested(tmp_path):
    app_py = ("from flask import Flask\napp = Flask(__name__)\n\n@app.put('/users/<int:uid>/password')\n"
              "def change(uid):\n    return ''\n\n@app.get('/tokens/<tid>')\ndef show(tid):\n    return ''\n")
    assert "password" in critical_endpoints(tmp_path, app_py, "'/tokens/' + tid")
    assert critical_endpoints(tmp_path, app_py, "f'/users/{uid}/password') or client.get('/tokens/' + t") == ""
    # quotes inside an interpolation do not end the URL
    assert critical_endpoints(tmp_path, app_py, "f\"/o/{org['id']}/users/{u['id']}/password\") or "
                              "client.get(f'/tokens/{t}'") == ""


def test_endpoint_under_mount_prefix_matches_whole_segments(tmp_path):
    app_py = "from flask import Flask\napp = Flask(__name__)\n\n@app.post('/login')\ndef sign_in():\n    return ''\n"
    assert critical_endpoints(tmp_path, app_py, "'/auth/login'") == ""
    assert "/login" in critical_endpoints(tmp_path, app_py, "'/login_history'")


def test_django_urls_are_checked(tmp_path):
    write(tmp_path, {
        "shop/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [\n"
        "    path('checkout/', views.checkout, name='checkout'),\n"
        "    path('refunds/<int:pk>/', views.refund, name='refund'),\n]\n",
        "shop/views.py": "def checkout(request):\n    return None\n\ndef refund(request, pk):\n    return None\n",
        "shop/tests.py": "from django.test import TestCase\nfrom django.urls import reverse\n\n"
        "class T(TestCase):\n    def test_checkout(self):\n"
        "        self.assertEqual(self.client.get(reverse('shop:checkout')).status_code, 200)\n"})
    evidence = by_rule(tmp_path, "untested-critical-paths")[0].evidence
    assert "/refunds/<int:pk>/" in evidence and "checkout" not in evidence


def test_nest_controller_routes_are_checked(tmp_path):
    controller = ("import { Controller, Post } from '@nestjs/common';\n@Controller('auth')\n"
                  "export class AuthController {\n  @Post('login')\n  login() {}\n  @Post('logout')\n  out() {}\n}\n")
    write(tmp_path, {"src/auth.controller.ts": controller,
                     "test/auth.e2e-spec.ts": "import request from 'supertest';\nit('logs in', async () => {\n"
                     "  await request(app.getHttpServer()).post('/auth/login').expect(201);\n});\n"})
    evidence = by_rule(tmp_path, "untested-critical-paths")[0].evidence
    assert "POST /auth/logout" in evidence and "/auth/login" not in evidence


def test_next_file_routes_are_checked(tmp_path):
    route = "export async function POST(req) {\n  return Response.json({});\n}\n"
    write(tmp_path, {"app/api/auth/login/route.ts": route, "app/api/billing/route.ts": route,
                     "tests/login.test.ts": "import { POST } from '../app/api/auth/login/route';\n"
                     "test('login', async () => {\n"
                     "  const r = await POST(new Request('http://localhost/api/auth/login'));\n"
                     "  expect(r.status).toBe(200);\n});\n"})
    evidence = by_rule(tmp_path, "untested-critical-paths")[0].evidence
    assert "POST /api/billing" in evidence and "/api/auth/login" not in evidence


# ------------------------------------------------------------------------------------------ error paths
RAISING = ("def parse(x):\n    if not x:\n        raise ValueError('empty')\n    if len(x) > 9:\n"
           "        raise ValueError('long')\n    return x\n\n"
           "def load(k):\n    if k is None:\n        raise KeyError(k)\n    if k == '':\n        raise KeyError(k)\n"
           "    raise LookupError(k)\n")


def test_happy_path_only_suite(tmp_path):
    write(tmp_path, {"parser.py": RAISING, "tests/test_parser.py": "from parser import parse\n\n"
                     "def test_parse():\n    assert parse('a') == 'a'\n"})
    assert len(by_rule(tmp_path, "no-error-path-tests")) == 1
    assert not by_rule(tmp_path, "untested-error-paths")  # suite-level finding replaces the per-module ones


def test_module_whose_own_tests_skip_errors(tmp_path):
    write(tmp_path, {"parser.py": RAISING, "other.py": RAISING,
                     "tests/test_parser.py": "from parser import parse\n\ndef test_parse():\n"
                     "    assert parse('a') == 'a'\n",
                     "tests/test_other.py": "import pytest\nfrom other import parse\n\ndef test_empty():\n"
                     "    with pytest.raises(ValueError):\n        parse('')\n"})
    assert not by_rule(tmp_path, "no-error-path-tests")
    assert [f.file_path for f in by_rule(tmp_path, "untested-error-paths")] == ["parser.py"]


def test_package_init_is_not_matched_to_tests_init(tmp_path):
    write(tmp_path, {"pkg/__init__.py": RAISING, "tests/__init__.py": "", "other.py": RAISING,
                     "tests/test_other.py": "import pytest\nfrom other import parse\n\ndef test_empty():\n"
                     "    with pytest.raises(ValueError):\n        parse('')\n"})
    assert not by_rule(tmp_path, "untested-error-paths")


def test_js_error_checks_are_recognized(tmp_path):
    write(tmp_path, {"src/parse.js": "export function parse(x) {\n" + "  if (!x) throw new Error('e');\n" * 6 + "}\n",
                     "src/parse.test.js": "import { parse } from './parse';\ntest('empty', () => {\n"
                     "  expect(() => parse('')).toThrow();\n});\n"})
    assert not by_rule(tmp_path, "no-error-path-tests")
    assert not by_rule(tmp_path, "untested-error-paths")


# ------------------------------------------------------------------------------------------ assertions
def test_weak_python_assertions(tmp_path):
    write(tmp_path, {"app.py": "def f():\n    return [1]\n", "tests/test_app.py": "from app import f\n\n"
                     "def test_weak():\n    r = f()\n    assert r is not None\n    assert len(r) > 0\n\n"
                     "def test_mixed():\n    r = f()\n    assert r\n    assert r == [1]\n\n"
                     "def test_strong():\n    assert f() == [1]\n"})
    found = by_rule(tmp_path, "weak-assertions")
    assert len(found) == 1 and "test_weak" in found[0].description and "test_mixed" not in found[0].description


def test_weak_js_assertions(tmp_path):
    write(tmp_path, {"src/a.js": "export const a = () => 1;\n",
                     "src/a.test.js": "test('a', () => {\n  expect(a()).toBeDefined();\n  expect(a()).toBeTruthy();\n"
                     "  expect(a()).not.toBeNull();\n});\n",
                     "src/b.test.js": "test('b', () => {\n  expect(a()).toBeDefined();\n  expect(a()).toBe(1);\n});\n"})
    assert [f.file_path for f in by_rule(tmp_path, "weak-assertions")] == ["src/a.test.js"]


def test_assertionless_tests_still_detected(tmp_path):
    write(tmp_path, {"app.py": "def f():\n    return 1\n",
                     "tests/test_app.py": "def test_a():\n    f()\n\ndef test_b():\n    assert f() == 1\n"})
    found = by_rule(tmp_path, "tests-without-assertions")
    assert found and "test_a" in found[0].description


# ------------------------------------------------------------------------------------------ duplicated setup
SETUP = "    user = make_user('a')\n    order = make_order(user)\n    order.add('x', 2)\n"


def test_duplicated_python_setup(tmp_path):
    tests = "".join(f"def test_{i}():\n{SETUP}    assert order.total() == {i}\n\n" for i in range(3))
    write(tmp_path, {"app.py": "X = 1\n", "tests/test_orders.py": tests})
    found = by_rule(tmp_path, "duplicated-test-setup")
    assert len(found) == 1 and found[0].title == "Same setup repeated in 3 tests"
    assert "make_order(user)" in found[0].evidence


def test_setup_repeated_twice_or_varied_is_not_flagged(tmp_path):
    tests = "".join(f"def test_{i}():\n{SETUP}    assert order.total() == {i}\n\n" for i in range(2))
    tests += f"def test_other():\n    user = make_user('b')\n{SETUP[SETUP.index('    order'):]}    assert order\n"
    write(tmp_path, {"app.py": "X = 1\n", "tests/test_orders.py": tests})
    assert not by_rule(tmp_path, "duplicated-test-setup")


def test_duplicated_js_setup(tmp_path):
    block = ("  const user = makeUser('a');\n  const order = makeOrder(user);\n  order.add('x', 2);\n"
             "  expect(order.total()).toBe(2);\n")
    tests = "".join(f"it('case {i}', () => {{\n{block}}});\n" for i in range(3))
    write(tmp_path, {"src/o.js": "export const o = 1;\n", "src/o.test.js": tests})
    assert len(by_rule(tmp_path, "duplicated-test-setup")) == 1
