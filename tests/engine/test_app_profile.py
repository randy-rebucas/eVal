"""Application profile (framework, auth schemes, datastores, password schema) and the checks that depend on it."""

from __future__ import annotations

import json
import textwrap

from eval_engine.analyzers import registry
from eval_engine.analyzers.base import AnalyzerContext
from eval_engine.languages import detect
from eval_engine.pipeline import PipelineConfig, run_analyzer, run_pipeline
from eval_engine.reports import render_markdown
from eval_engine.workspace import iter_files


def _write(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def _ctx(root):
    files = list(iter_files(root))
    return AnalyzerContext(root=root, files=files, languages=detect(root, files), timeout=60)


def _applies(profile) -> dict[str, bool]:
    return {row["check"]: row["applies"] for row in profile.applicability()}


def _rules(root, analyzer="auth_security"):
    out = run_analyzer(registry.get([analyzer])[0], _ctx(root))
    assert out.status == "ok", out.reason
    return sorted((f.rule_id.split(":", 1)[1], f.file_path, f.line_start, str(f.kind)) for f in out.findings)


# ----------------------------------------------------------------------------------------------- profile
def test_bearer_api_profile_marks_csrf_not_applicable(tmp_path):
    _write(tmp_path, {
        "requirements.txt": "fastapi==0.110.0\npyjwt==2.8.0\npymongo==4.6.0\n",
        "main.py": """
            from fastapi.security import HTTPBearer
            bearer = HTTPBearer()
        """,
    })
    profile = _ctx(tmp_path).profile
    assert profile.web_frameworks == ["fastapi"]
    assert set(profile.auth) == {"jwt", "bearer-token"} and not profile.cookie_auth
    assert set(profile.datastores) == {"mongodb"}
    assert _applies(profile) == {"CSRF protection": False, "JWT weaknesses": True,
                                 "Password storage and comparison": False, "SQL injection": False,
                                 "NoSQL (MongoDB) operator injection": True, "File upload validation": False}
    csrf = next(r for r in profile.applicability() if r["check"] == "CSRF protection")
    assert "request headers (jwt, bearer-token)" in csrf["reason"]


def test_schema_dialects_and_what_does_not_count_as_a_password_column(tmp_path):
    _write(tmp_path, {
        "package.json": json.dumps({"dependencies": {"@prisma/client": "5.10.0", "express": "4.19.2"}}),
        "prisma/schema.prisma": """
            generator client {
              provider = "prisma-client-js"
            }
            datasource db {
              provider = "mongodb"
              url      = env("DATABASE_URL")
            }
            model User {
              id       String @id @map("_id")
              password String
            }
        """,
        "forms.py": """
            class LoginForm(FlaskForm):
                password = PasswordField("Password")
                pwd = forms.CharField()
        """,
        "models.py": """
            class Account(Base):
                password = Column(String(128))
                password_hash = Column(String(128))
        """,
        "migrations/001.sql": "CREATE TABLE users (\n  id int,\n  password varchar(64)\n);\n",
        "lint.py": 'PATTERN = re.compile(r"JWTAuthentication|APIKeyHeader")\n',
    })
    profile = _ctx(tmp_path).profile
    assert profile.datastores["mongodb"] == "Prisma (mongodb)"
    assert sorted(profile.password_columns) == [("migrations/001.sql", 3), ("models.py", 2),
                                                ("prisma/schema.prisma", 10)]
    assert "jwt" not in profile.auth and "api-key" not in profile.auth  # regex source is not usage


def test_utf8_bom_files_are_still_analyzed(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"\xef\xbb\xbfflask==3.0.0\n")
    (tmp_path / "app.py").write_bytes(b"\xef\xbb\xbfimport jwt\ntok = jwt.encode({'sub': 1}, 'hardcoded-key')\n")
    ctx = _ctx(tmp_path)
    assert ctx.languages.frameworks == ["flask"] and ctx.python_ast("app.py") is not None
    assert ("auth.jwt-hardcoded-secret", "app.py", 2, "confirmed") in _rules(tmp_path)


# ------------------------------------------------------------------------------------- gated checks
DJANGO_VIEWS = """
    from django.views.decorators.csrf import csrf_exempt

    @csrf_exempt
    def update_profile(request):
        return None

    @csrf_exempt
    def stripe_webhook(request):
        return None
"""


def test_django_csrf_checks_apply_only_with_session_cookies(tmp_path):
    cookie, bearer = tmp_path / "cookie", tmp_path / "bearer"
    _write(cookie, {"requirements.txt": "django==5.0.3\n", "views.py": DJANGO_VIEWS, "settings.py": """
        INSTALLED_APPS = ["django.contrib.sessions"]
        MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
    """})
    _write(bearer, {"requirements.txt": "django==5.0.3\ndjangorestframework-simplejwt==5.3\n", "views.py": DJANGO_VIEWS,
                    "settings.py": """
        INSTALLED_APPS = ["rest_framework"]
        MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
        AUTH = "rest_framework_simplejwt.authentication.JWTAuthentication"
    """})
    assert _rules(cookie) == [("auth.csrf-exempt", "views.py", 4, "potential"),
                              ("auth.django-csrf-middleware-missing", "settings.py", 2, "confirmed")]
    assert _rules(bearer) == []  # header-token API: CSRF does not apply


def test_express_cookie_app_without_csrf(tmp_path):
    route = "app.post('/transfer', (req, res) => res.send('ok'));\n"
    _write(tmp_path, {"package.json": json.dumps({"dependencies": {"express": "4", "express-session": "1"}}),
                      "server.js": route})
    assert _rules(tmp_path) == [("auth.express-no-csrf", "server.js", 1, "potential")]
    _write(tmp_path, {"server.js": "app.use(session({ cookie: { sameSite: 'lax' } }));\n" + route})
    assert _rules(tmp_path) == []


def test_jwt_weaknesses(tmp_path):
    _write(tmp_path, {
        "requirements.txt": "pyjwt==2.8.0\n",
        "auth.py": """
            import jwt
            JWT_SECRET_KEY = "super-secret"
            a = jwt.encode({"sub": uid}, "literal-key", algorithm="HS256")
            b = jwt.encode({"sub": uid, "exp": exp}, key, algorithm="HS256")
            c = jwt.decode(tok, key)
            d = jwt.decode(tok, key, algorithms=["HS256"])
            e = create_access_token(identity=uid, expires_delta=False)
        """,
        "auth.js": """
            const t = jwt.sign({ id: u.id }, process.env.KEY);
            const t2 = jwt.sign({ id: u.id }, process.env.KEY, { expiresIn: '15m' });
            jwt.verify(t, 'inline-secret');
            jwt.verify(t, key, { algorithms: ['RS256'] });
        """,
    })
    assert _rules(tmp_path) == [
        ("auth.jwt-algorithm-not-pinned", "auth.js", 3, "potential"),
        ("auth.jwt-algorithm-not-pinned", "auth.py", 5, "potential"),
        ("auth.jwt-hardcoded-secret", "auth.js", 3, "confirmed"),
        ("auth.jwt-hardcoded-secret", "auth.py", 2, "confirmed"),
        ("auth.jwt-hardcoded-secret", "auth.py", 3, "confirmed"),
        ("auth.jwt-no-expiry", "auth.js", 1, "potential"),
        ("auth.jwt-no-expiry", "auth.py", 3, "potential"),
        ("auth.jwt-no-expiry", "auth.py", 7, "confirmed"),
    ]


def test_password_storage_and_plaintext_comparison(tmp_path):
    _write(tmp_path, {
        "models.py": """
            class User(db.Model):
                password = db.Column(db.String(64))
        """,
        "views.py": """
            def login(user, form):
                if user.password == form["password"]:
                    return True
                if form["password"] != form["confirm_password"]:
                    return False
                return hmac.compare_digest(user.password, form.get("password"))
        """,
        "server.js": "if (user.password === req.body.password) ok();\n"
                     "if (req.body.password !== req.body.confirmPassword) bad();\n",
    })
    assert _rules(tmp_path) == [
        ("auth.password-stored-unhashed", "models.py", 2, "potential"),
        ("auth.plaintext-password-compare", "server.js", 1, "potential"),
        ("auth.plaintext-password-compare", "views.py", 2, "potential"),
        ("auth.plaintext-password-compare", "views.py", 6, "potential"),
    ]
    (tmp_path / "requirements.txt").write_text("bcrypt==4.1.2\n")
    assert [r for r in _rules(tmp_path) if r[0] == "auth.password-stored-unhashed"] == []


def test_nosql_injection_only_with_mongodb(tmp_path):
    js = "const u = await User.findOne({ email: req.body.email });\nawait User.find(req.query);\n"
    py = """
        from fastapi import FastAPI, Request
        app = FastAPI()

        @app.post("/search")
        async def search(request: Request):
            body = await request.json()
            users.find({"name": body["name"]})
            users.find({"name": str(body["name"])})
            users.find_one({"$where": request.query_params["q"]})
    """
    mongo, sql = tmp_path / "mongo", tmp_path / "sql"
    _write(mongo, {"package.json": json.dumps({"dependencies": {"mongoose": "8"}}), "server.js": js,
                   "requirements.txt": "pymongo==4.6\n", "app.py": py})
    _write(sql, {"package.json": json.dumps({"dependencies": {"pg": "8"}}), "server.js": js, "app.py": py})
    assert _rules(mongo) == [("auth.nosql-injection", "server.js", 1, "potential"),
                             ("auth.nosql-injection", "server.js", 2, "potential")]
    taint = [(f.rule_id, f.line_start) for f in run_pipeline(mongo, PipelineConfig(analyzers=["taint"])).findings]
    assert taint == [("eval:taint.nosql-injection", 7), ("eval:taint.nosql-injection", 9)]
    assert _rules(sql) == [] and run_pipeline(sql, PipelineConfig(analyzers=["taint"])).findings == []
    _write(mongo, {"server.js": "app.use(mongoSanitize());\n" + js})
    assert _rules(mongo) == []


def test_report_shows_profile_and_applicability(tmp_path):
    _write(tmp_path, {"requirements.txt": "flask==3.0.0\nflask-login==0.6.3\n", "app.py": "x = 1\n"})
    model = run_pipeline(tmp_path, PipelineConfig(analyzers=["auth_security"])).to_dict()
    assert model["app_profile"]["auth"] == {"cookie": "dependency flask-login"}
    md = render_markdown(model)
    assert "## Application profile" in md
    assert "| CSRF protection | yes | browsers send credentials automatically" in md
    assert "| NoSQL (MongoDB) operator injection | no | no MongoDB driver or ODM |" in md
