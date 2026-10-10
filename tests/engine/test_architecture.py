"""Architecture analyzer: structure, dependency direction, service boundaries, handlers, data access, size,
duplicated logic and configuration. Each rule has a positive and a negative case so heuristics stay precise."""

from __future__ import annotations

from eval_engine.analyzers import registry
from eval_engine.analyzers.architecture import _python_module_map, _resolve
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
    outcome = run_analyzer(registry.get(["architecture"])[0], ctx)
    assert outcome.status == "ok", outcome.reason
    return outcome.findings


def by_rule(root, rule):
    return [f for f in run(root) if f.rule_id == f"eval:architecture.{rule}"]


FLASK_ROUTE = ("from flask import Blueprint\nbp = Blueprint('x', __name__)\n\n@bp.get('/x')\ndef index():\n"
               "    return ''\n")


# ------------------------------------------------------------------------------------------ module resolution
def test_same_named_packages_resolve_to_the_nearest_file():
    files = ["svc_a/app/__init__.py", "svc_a/app/models.py", "svc_a/app/main.py",
             "svc_b/app/__init__.py", "svc_b/app/models.py", "svc_b/app/main.py"]
    modmap = _python_module_map(files)
    assert _resolve(modmap, "app.models", "svc_b/app/main.py") == "svc_b/app/models.py"
    assert _resolve(modmap, "app.models", "svc_a/app/main.py") == "svc_a/app/models.py"


def test_separate_services_with_same_package_name_are_not_coupled(tmp_path):
    for svc in ("orders", "billing"):
        write(tmp_path, {f"{svc}/requirements.txt": "flask\n", f"{svc}/app/__init__.py": "",
                         f"{svc}/app/models.py": "X = 1\n", f"{svc}/app/main.py": "from app import models\n"})
    assert not by_rule(tmp_path, "cross-service-import")


# ------------------------------------------------------------------------------------------ dependency direction
def test_service_importing_route_module_is_flagged(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/routes.py": FLASK_ROUTE + "HELPER = 1\n",
                     "app/services/__init__.py": "", "app/services/orders.py": "from app.routes import HELPER\n"})
    found = by_rule(tmp_path, "dependency-direction")
    assert [f.file_path for f in found] == ["app/services/orders.py"]
    assert found[0].severity == "medium"


def test_data_layer_importing_service_is_flagged_but_downward_imports_are_not(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/models.py": "from app.services import price\n",
                     "app/services.py": "from app import models\n\ndef price():\n    return 1\n"})
    found = by_rule(tmp_path, "dependency-direction")
    assert [f.file_path for f in found] == ["app/models.py"]


def test_git_repository_module_is_not_treated_as_data_layer(tmp_path):
    # "repositories" here means source-code repositories, not the repository pattern.
    write(tmp_path, {"app/__init__.py": "", "app/services.py": "def sync():\n    return 1\n",
                     "app/repositories.py": "from app.services import sync\n\ndef clone(url):\n    return sync()\n"})
    assert not by_rule(tmp_path, "dependency-direction")


def test_repository_pattern_module_is_data_layer(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/services.py": "def sync():\n    return 1\n",
                     "app/repositories.py": "from app.services import sync\n\nclass UserRepository:\n    pass\n"})
    assert [f.file_path for f in by_rule(tmp_path, "dependency-direction")] == ["app/repositories.py"]


def test_package_cycle_without_module_cycle(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/billing/__init__.py": "", "app/shipping/__init__.py": "",
                     "app/billing/a.py": "from app.shipping import b\n", "app/shipping/b.py": "X = 1\n",
                     "app/shipping/c.py": "from app.billing import d\n", "app/billing/d.py": "Y = 1\n"})
    assert not by_rule(tmp_path, "import-cycle")
    found = by_rule(tmp_path, "package-cycle")
    assert len(found) == 1 and "app/billing" in found[0].title and "app/shipping" in found[0].title


def test_one_way_package_dependency_is_not_a_cycle(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/billing/__init__.py": "", "app/shipping/__init__.py": "",
                     "app/billing/a.py": "from app.shipping import b\n", "app/shipping/b.py": "X = 1\n"})
    assert not by_rule(tmp_path, "package-cycle")


# ------------------------------------------------------------------------------------------ service boundaries
def test_cross_service_import_between_deployables(tmp_path):
    write(tmp_path, {"services/orders/package.json": "{}", "services/billing/package.json": "{}",
                     "services/orders/index.js": "const t = require('../billing/tax');\n",
                     "services/billing/tax.js": "module.exports = 1;\n"})
    found = by_rule(tmp_path, "cross-service-import")
    assert [f.file_path for f in found] == ["services/orders/index.js"]


def test_import_within_one_deployable_is_fine(tmp_path):
    write(tmp_path, {"services/orders/package.json": "{}", "services/orders/index.js": "require('./lib/tax');\n",
                     "services/orders/lib/tax.js": "module.exports = 1;\n"})
    assert not by_rule(tmp_path, "cross-service-import")


def test_feature_importing_another_features_routes(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/orders/__init__.py": "", "app/users/__init__.py": "",
                     "app/users/routes.py": FLASK_ROUTE + "def helper():\n    return 1\n",
                     "app/orders/services.py": "from app.users.routes import helper\n"})
    found = by_rule(tmp_path, "boundary-violation")
    assert [f.file_path for f in found] == ["app/orders/services.py"]


def test_feature_bypassing_another_features_service(tmp_path):
    files = {"app/__init__.py": "", "app/orders/__init__.py": "", "app/users/__init__.py": "",
             "app/users/repository.py": "class UserRepository:\n    pass\n",
             "app/orders/services.py": "from app.users.repository import UserRepository\n"}
    write(tmp_path, files)
    assert not by_rule(tmp_path, "boundary-violation")  # users has no service layer to bypass
    write(tmp_path, {"app/users/services.py": "from app.users.repository import UserRepository\n"})
    assert [f.file_path for f in by_rule(tmp_path, "boundary-violation")] == ["app/orders/services.py"]


def test_importing_another_features_service_or_shared_code_is_fine(tmp_path):
    write(tmp_path, {"app/__init__.py": "", "app/orders/__init__.py": "", "app/users/__init__.py": "",
                     "app/common/__init__.py": "", "app/common/routes.py": FLASK_ROUTE,
                     "app/users/services.py": "def get():\n    return 1\n",
                     "app/orders/services.py": "from app.users.services import get\nfrom app.common import routes\n"})
    assert not by_rule(tmp_path, "boundary-violation")


# ------------------------------------------------------------------------------------------ handlers
FAT_HANDLER = """from flask import Blueprint, request
bp = Blueprint('x', __name__)

@bp.post('/checkout')
def checkout():
    cart = request.json
    if not cart:
        return {'error': 'empty'}, 400
    total = 0
    for item in cart['items']:
        if item['qty'] > 10 and item.get('bulk'):
            total += item['price'] * item['qty'] * 0.9
        elif item['qty'] > 5:
            total += item['price'] * item['qty'] * 0.95
        else:
            total += item['price'] * item['qty']
    if cart.get('coupon') == 'VIP' or cart.get('vip'):
        total *= 0.8
    if total > 1000 and not cart.get('vip'):
        total -= 50
    return {'total': total}
"""


def test_business_logic_in_python_handler(tmp_path):
    write(tmp_path, {"app.py": FAT_HANDLER})
    found = by_rule(tmp_path, "fat-controller")
    assert len(found) == 1 and "checkout" in found[0].title and found[0].line_start == 5


def test_thin_handler_is_fine(tmp_path):
    write(tmp_path, {"app.py": FLASK_ROUTE})
    assert not by_rule(tmp_path, "fat-controller")


def test_business_logic_in_express_handler(tmp_path):
    branches = "\n".join(f"  if (req.body.k{i} && req.body.v{i}) {{ total += {i}; }}" for i in range(8))
    write(tmp_path, {"package.json": '{"dependencies": {"express": "4"}}',
                     "server.js": "const app = require('express')();\n"
                                  f"app.post('/checkout', async (req, res) => {{\n  let total = 0;\n{branches}\n"
                                  "  res.json({ total });\n});\n"
                                  "app.get('/health', (req, res) => { res.send('ok'); });\n"})
    found = by_rule(tmp_path, "fat-controller")
    assert len(found) == 1 and "POST /checkout" in found[0].title


def test_orm_access_in_handler_module(tmp_path):
    write(tmp_path, {"app.py": FLASK_ROUTE + "\n@bp.get('/u')\ndef users():\n    return User.query.filter_by(a=1)"
                               ".all()\n"})
    assert [f.line_start for f in by_rule(tmp_path, "data-access-in-handlers")] == [10]


def test_raw_sql_in_handler_keeps_its_rule(tmp_path):
    write(tmp_path, {"app.py": FLASK_ROUTE + "\ndef q(c):\n    return c.execute('SELECT 1')\n"})
    assert by_rule(tmp_path, "sql-in-handlers") and not by_rule(tmp_path, "data-access-in-handlers")


def test_handler_calling_a_service_is_fine(tmp_path):
    write(tmp_path, {"app.py": FLASK_ROUTE.replace("return ''", "return services.list_users()")})
    assert not by_rule(tmp_path, "data-access-in-handlers") and not by_rule(tmp_path, "sql-in-handlers")


def test_routes_and_models_in_one_module(tmp_path):
    write(tmp_path, {"app.py": FLASK_ROUTE + "\nclass User(db.Model):\n    id = 1\n"})
    assert [f.line_start for f in by_rule(tmp_path, "mixed-concerns")] == [8]
    write(tmp_path, {"app.py": FLASK_ROUTE, "models.py": "class User(db.Model):\n    id = 1\n"})
    assert not by_rule(tmp_path, "mixed-concerns")


def test_no_service_layer(tmp_path):
    files = {"app/__init__.py": ""}
    for name in ("users", "orders", "invoices", "reports"):
        files[f"app/{name}_routes.py"] = FLASK_ROUTE + "\ndef q():\n    return db.session.execute(x)\n"
    write(tmp_path, files)
    assert len(by_rule(tmp_path, "no-service-layer")) == 1
    write(tmp_path, {"app/services/__init__.py": "", "app/services/users.py": "def get():\n    return 1\n"})
    assert not by_rule(tmp_path, "no-service-layer")


# ------------------------------------------------------------------------------------------ scattered data access
def test_scattered_data_access(tmp_path):
    files = {}
    for i, pkg in enumerate(("billing", "reports", "notify", "billing", "reports", "notify")):
        files[f"app/{pkg}/m{i}.py"] = "def f(cursor):\n    cursor.execute('select 1')\n"
    write(tmp_path, files)
    found = by_rule(tmp_path, "scattered-data-access")
    assert len(found) == 1 and "6 modules in 3 packages" in found[0].title


def test_data_access_inside_data_and_service_layers_is_not_scattered(tmp_path):
    files = {}
    for i in range(4):
        files[f"app/repositories/r{i}.py"] = "def f(cursor):\n    cursor.execute('select 1')\n"
        files[f"app/services/s{i}.py"] = "def f(session):\n    return session.query(X)\n"
        files[f"migrations/versions/v{i}.py"] = "def up(conn):\n    conn.execute('alter table x')\n"
    write(tmp_path, files)
    assert not by_rule(tmp_path, "scattered-data-access")


# ------------------------------------------------------------------------------------------ size and layout
def test_oversized_module_and_package(tmp_path):
    files = {"app/__init__.py": "", "app/big.py": "".join(f"def f{i}():\n    return {i}\n" for i in range(45)),
             "app/small.py": "def f():\n    return 1\n"}
    files.update({f"app/many/m{i}.py": "X = 1\n" for i in range(41)})
    write(tmp_path, files)
    assert [f.file_path for f in by_rule(tmp_path, "oversized-module")] == ["app/big.py"]
    assert [f.title for f in by_rule(tmp_path, "oversized-package")] == ["Package app/many holds 41 source files"]


def test_flat_structure(tmp_path):
    write(tmp_path, {f"m{i}.py": "X = 1\n" for i in range(16)})
    assert len(by_rule(tmp_path, "flat-structure")) == 1
    write(tmp_path, {"pkg/__init__.py": ""})
    for i in range(16):
        (tmp_path / f"m{i}.py").rename(tmp_path / "pkg" / f"m{i}.py")
    assert not by_rule(tmp_path, "flat-structure")


# ------------------------------------------------------------------------------------------ duplicated logic
DISCOUNT = """def {name}({a}, {b}):
    {t} = 0
    for {x} in {a}:
        {t} += {x}.price * {x}.qty
    if {t} > 100:
        {t} = {t} * 0.9
    if {b}:
        {t} -= {b}
    return {t}
"""


def test_renamed_copy_of_business_logic_is_detected(tmp_path):
    write(tmp_path, {
        "app/orders.py": DISCOUNT.format(name="order_total", a="items", b="coupon", t="total", x="item"),
        "app/invoices.py": DISCOUNT.format(name="invoice_amount", a="lines", b="credit", t="amount", x="line"),
    })
    found = by_rule(tmp_path, "duplicated-logic")
    assert len(found) == 1 and "once variable names are ignored" in found[0].description


def test_different_logic_is_not_duplicated(tmp_path):
    write(tmp_path, {
        "app/orders.py": DISCOUNT.format(name="order_total", a="items", b="coupon", t="total", x="item"),
        "app/invoices.py": DISCOUNT.format(name="invoice_amount", a="lines", b="credit", t="amount", x="line")
        .replace("0.9", "0.85"),
    })
    assert not by_rule(tmp_path, "duplicated-logic")


# ------------------------------------------------------------------------------------------ configuration
SETTINGS = "import os\nA = os.environ['A']\nB = os.getenv('B')\nC = os.getenv('C')\n"


def test_settings_module_bypassed(tmp_path):
    files = {"app/__init__.py": "", "app/config.py": SETTINGS}
    files.update({f"app/m{i}.py": "import os\nX = os.getenv('X')\n" for i in range(5)})
    write(tmp_path, files)
    found = by_rule(tmp_path, "config-bypass")
    assert len(found) == 1 and "app/config.py" in found[0].title


def test_settings_module_used_and_other_package_ignored(tmp_path):
    files = {"app/__init__.py": "", "app/config.py": SETTINGS,
             "app/m.py": "from app.config import A\n", "app/n.py": "import os\nX = os.getenv('X')\n"}
    files.update({f"lib/m{i}.py": "import os\nX = os.getenv('X')\n" for i in range(5)})  # a separate package
    write(tmp_path, files)
    assert not by_rule(tmp_path, "config-bypass")


def test_env_names_in_strings_are_not_reads(tmp_path):
    write(tmp_path, {f"pkg/m{i}.py": "PATTERN = 'os.environ'\n" for i in range(14)})
    assert not by_rule(tmp_path, "config-sprawl")
    write(tmp_path, {f"pkg/m{i}.py": "import os\nX = os.environ['X']\n" for i in range(14)})
    assert len(by_rule(tmp_path, "config-sprawl")) == 1
