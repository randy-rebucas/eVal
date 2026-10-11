"""Regression cases from the analyzer audit: each one is a missed problem or a false alarm that was fixed. Every case
states the input and whether the rule must fire, so heuristics stay precise in both directions."""

from __future__ import annotations

import pytest

from eval_engine.analyzers.dependencies import OSVAnalyzer, _severity, cvss3_base_score
from eval_engine.dedupe import family_of
from tests.engine.test_engineering_checks import run, write

FLASK = "flask\nflask-login\n"
EXPRESS = '{"dependencies": {"express": "4.19.2", "cors": "2.8.5"}}'
FASTAPI = "fastapi\n"
DJANGO = "django\n"

# (case id, analyzer, files, rule (substring of rule_id), must fire)
CASES = [
    # ------------------------------------------------------------------ secrets
    ("fstring-dsn-placeholders", "secrets",
     {"db.py": 'DSN = f"postgresql://{user}:{password}@{host}/app"\n'}, "secrets.credentials-in-url", False),
    ("real-dsn-password", "secrets",
     {"db.py": 'DSN = "postgresql://app:S3cr3tPassw0rd@db/app"\n'}, "secrets.credentials-in-url", True),
    ("private-key-pem-file", "secrets",
     {"deploy/server.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdef\n"
                           "-----END RSA PRIVATE KEY-----\n"}, "secrets.private-key", True),
    ("private-key-id-rsa", "secrets",
     {"keys/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"
                     "-----END OPENSSH PRIVATE KEY-----\n"}, "secrets.private-key", True),
    # ------------------------------------------------------------------ taint
    ("presence-check-is-not-validation", "taint",
     {"requirements.txt": FLASK, "app.py": (
         "import os\nfrom flask import request\n@app.route('/x', methods=['POST'])\ndef x():\n"
         "    if 'cmd' in request.form:\n        os.system(request.form['cmd'])\n    return ''\n")},
     "taint.command-injection", True),
    ("allow-list-membership-validates", "taint",
     {"requirements.txt": FLASK, "app.py": (
         "import os\nfrom flask import request\nALLOWED = {'ls'}\n@app.route('/x', methods=['POST'])\ndef x():\n"
         "    cmd = request.form['cmd']\n    if cmd in ALLOWED:\n        os.system(cmd)\n    return ''\n")},
     "taint.command-injection", False),
    ("or-default-keeps-taint", "taint",
     {"requirements.txt": FLASK, "app.py": (
         "from flask import request, redirect\n@app.route('/login')\ndef login():\n"
         "    nxt = request.args.get('next') or '/'\n    return redirect(nxt)\n")},
     "taint.open-redirect", True),
    ("loop-variable-over-request-files", "taint",
     {"requirements.txt": FLASK, "app.py": (
         "from flask import request\n@app.route('/up', methods=['POST'])\ndef up():\n"
         "    for f in request.files.getlist('f'):\n        f.save('/data/' + f.filename)\n    return ''\n")},
     "taint.upload-path-traversal", True),
    ("flask-session-get-is-not-ssrf", "taint",
     {"requirements.txt": FLASK, "app.py": (
         "from flask import request, session\n@app.route('/p')\ndef p():\n"
         "    key = request.args['k']\n    return str(session.get(key))\n")},
     "taint.ssrf", False),
    ("requests-session-get-is-ssrf", "taint",
     {"requirements.txt": FLASK, "app.py": (
         "import requests\nfrom flask import request\nsession = requests.Session()\n@app.route('/p')\ndef p():\n"
         "    return session.get(request.args['url'], timeout=5).text\n")},
     "taint.ssrf", True),
    # ------------------------------------------------------------------ auth
    ("commented-out-csrf-middleware", "auth_security",
     {"requirements.txt": DJANGO, "proj/settings.py": (
         "MIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n"
         "    'django.contrib.sessions.middleware.SessionMiddleware',\n"
         "    # 'django.middleware.csrf.CsrfViewMiddleware',\n]\n"
         "INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.sessions']\n")},
     "auth.django-csrf-middleware-missing", True),
    ("enabled-csrf-middleware", "auth_security",
     {"requirements.txt": DJANGO, "proj/settings.py": (
         "MIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n"
         "    'django.contrib.sessions.middleware.SessionMiddleware',\n"
         "    'django.middleware.csrf.CsrfViewMiddleware',\n]\n"
         "INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.sessions']\n")},
     "auth.django-csrf-middleware-missing", False),
    # ------------------------------------------------------------------ API security
    ("logging-user-agent-is-not-a-credential", "api_security",
     {"requirements.txt": FLASK, "app.py": (
         "import logging\nfrom flask import request\nlogger = logging.getLogger(__name__)\n"
         "def f():\n    logger.info('ua=%s', request.headers.get('User-Agent'))\n")},
     "api.sensitive-data-logged", False),
    ("logging-authorization-header", "api_security",
     {"requirements.txt": FLASK, "app.py": (
         "import logging\nfrom flask import request\nlogger = logging.getLogger(__name__)\n"
         "def f():\n    logger.info('auth=%s', request.headers.get('Authorization'))\n")},
     "api.sensitive-data-logged", True),
    ("express-cors-origin-star", "api_security",
     {"package.json": EXPRESS, "server.js": (
         "const express = require('express');\nconst cors = require('cors');\nconst app = express();\n"
         "app.use(cors({ origin: '*' }));\n")}, "api.cors-wildcard", True),
    ("fastapi-cors-middleware-star", "api_security",
     {"requirements.txt": FASTAPI, "main.py": (
         "from fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp = FastAPI()\n"
         "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n")},
     "api.cors-wildcard", True),
    ("fastapi-cors-middleware-allow-list", "api_security",
     {"requirements.txt": FASTAPI, "main.py": (
         "from fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp = FastAPI()\n"
         "app.add_middleware(CORSMiddleware, allow_origins=['https://app.example.com'])\n")},
     "api.cors-wildcard", False),
    ("django-cors-allow-all", "api_security",
     {"requirements.txt": DJANGO, "proj/settings.py": "CORS_ALLOW_ALL_ORIGINS = True\n"}, "api.cors-wildcard", True),
    ("non-auth-require-decorator", "api_security",
     {"requirements.txt": FLASK, "app.py": (
         "from flask_login import login_required\n"
         "@app.route('/a', methods=['POST'])\n@login_required\ndef a():\n    return ''\n"
         "@app.route('/transfer', methods=['POST'])\n@require_json\ndef transfer():\n    return ''\n")},
     "api.route-without-auth", True),
    ("express-global-auth-middleware", "api_security",
     {"package.json": EXPRESS, "server.js": (
         "const express = require('express');\nconst passport = require('passport');\n"
         "const jwt = require('jsonwebtoken');\nconst app = express();\n"
         "app.use(passport.authenticate('jwt', { session: false }));\n"
         "app.post('/orders', (req, res) => res.json({}));\n")}, "api.route-without-auth", False),
    ("express-auth-router-mount-is-not-global-auth", "api_security",
     {"package.json": EXPRESS, "server.js": (
         "const express = require('express');\nconst jwt = require('jsonwebtoken');\nconst app = express();\n"
         "app.use('/auth', authRouter);\napp.post('/orders', (req, res) => res.json({}));\n")},
     "api.route-without-auth", True),
    ("fastapi-router-empty-path", "api_security",
     {"requirements.txt": FASTAPI, "routes.py": (
         "from fastapi import APIRouter\nfrom fastapi.security import OAuth2PasswordBearer\n"
         "router = APIRouter(prefix='/orders')\n@router.post('')\ndef create():\n    return {}\n")},
     "api.route-without-auth", True),
    ("before-request-without-auth-check", "api_security",
     {"requirements.txt": FLASK, "app.py": (
         "from flask_login import login_required\nTOKEN_TTL = 60\n"
         "@app.before_request\ndef open_db():\n    g.db = connect()\n"
         "@app.route('/orders', methods=['POST'])\ndef create():\n    return ''\n")},
     "api.route-without-auth", True),
    ("before-request-with-auth-check", "api_security",
     {"requirements.txt": FLASK, "app.py": (
         "from flask_login import login_required, current_user\n"
         "@app.before_request\ndef guard():\n    if not current_user.is_authenticated:\n        abort(401)\n"
         "@app.route('/orders', methods=['POST'])\ndef create():\n    return ''\n")},
     "api.route-without-auth", False),
    ("tls-verify-off-on-client", "api_security",
     {"requirements.txt": "httpx\n", "client.py": "import httpx\nclient = httpx.Client(verify=False)\n"},
     "api.tls-verify-disabled", True),
    ("error-body-returned-with-400", "api_security",
     {"requirements.txt": FLASK, "app.py": (
         "from flask import jsonify\n@app.get('/a')\ndef a():\n"
         "    resp = jsonify({'error': 'bad'})\n    return resp, 400\n")}, "api.error-status-200", False),
    # ------------------------------------------------------------------ architecture / testing / database
    ("package-reexport-is-not-a-cycle", "architecture",
     {"pkg/__init__.py": "from .a import A\nfrom .b import B\n", "pkg/a.py": "class A:\n    pass\n",
      "pkg/b.py": "from . import a\nclass B(a.A):\n    pass\n"}, "architecture.import-cycle", False),
    ("real-module-cycle", "architecture",
     {"pkg/__init__.py": "", "pkg/a.py": "from pkg import b\n", "pkg/b.py": "from pkg import a\n"},
     "architecture.import-cycle", True),
    ("fixture-named-test-is-not-a-test", "testing",
     {"app/service.py": "def add(a, b):\n    return a + b\n",
      "tests/conftest.py": "import pytest\n@pytest.fixture\ndef test_user():\n    return {'name': 'x'}\n",
      "tests/test_service.py": "from app.service import add\ndef test_add():\n    assert add(1, 2) == 3\n"},
     "testing.tests-without-assertions", False),
    ("multiline-template-literal-sql", "database",
     {"package.json": EXPRESS, "repo.js": (
         "async function find(id) {\n  return db.query(`\n    SELECT * FROM users\n    WHERE id = ${id}\n  `);\n}\n")},
     "database.sql-string-formatting", True),
    # ------------------------------------------------------------------ performance
    ("executor-helper-is-not-blocking", "performance",
     {"svc.py": ("import asyncio, time\nasync def handler():\n    def work():\n        time.sleep(1)\n"
                 "    await asyncio.get_running_loop().run_in_executor(None, work)\n")},
     "performance.blocking-call-in-async", False),
    ("sleep-in-async", "performance",
     {"svc.py": "import time\nasync def handler():\n    time.sleep(1)\n"}, "performance.blocking-call-in-async", True),
    ("timeout-via-kwargs", "performance",
     {"svc.py": "import requests\ndef f(url, **opts):\n    return requests.get(url, **opts)\n"},
     "performance.http-without-timeout", False),
    # ------------------------------------------------------------------ observability
    ("prefixed-health-route", "observability",
     {"requirements.txt": FASTAPI, "main.py": (
         "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/api/health')\ndef health():\n    return {}\n")},
     "devops.no-health-endpoint", False),
    ("django-health-path", "observability",
     {"requirements.txt": DJANGO, "proj/urls.py": (
         "from django.urls import path\nfrom . import views\nurlpatterns = [path('healthz/', views.health)]\n"),
      "proj/views.py": "def health(request):\n    pass\n"}, "devops.no-health-endpoint", False),
    ("status-dict-key-is-not-a-health-route", "observability",
     {"requirements.txt": FASTAPI, "main.py": (
         "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items():\n"
         "    return {'status': 'ok'}\n")}, "devops.no-health-endpoint", True),
    # ------------------------------------------------------------------ devops
    ("multi-stage-alias", "devops",
     {"Dockerfile": ("FROM node:20.11-alpine AS base\nFROM base AS deps\nRUN npm ci\n"
                     "FROM base AS runner\nUSER node\nCMD [\"node\", \"server.js\"]\n"), ".dockerignore": ".git\n"},
     "devops.dockerfile-unpinned-base", False),
    ("platform-flag", "devops",
     {"Dockerfile": "FROM --platform=linux/amd64 python:3.12-slim\nUSER app\nCMD [\"python\"]\n",
      ".dockerignore": ".git\n"}, "devops.dockerfile-unpinned-base", False),
    ("platform-flag-unpinned-image", "devops",
     {"Dockerfile": "FROM --platform=linux/amd64 python\nUSER app\n", ".dockerignore": ".git\n"},
     "devops.dockerfile-unpinned-base", True),
    ("secret-file-path-env", "devops",
     {"Dockerfile": "FROM python:3.12\nENV DB_PASSWORD_FILE=/run/secrets/db\nUSER app\n", ".dockerignore": ".git\n"},
     "devops.dockerfile-secret-in-env", False),
    ("untrusted-context-via-env", "devops",
     {".github/workflows/triage.yml": (
         "name: triage\non: issues\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
         "    steps:\n      - name: echo\n        env:\n          TITLE: ${{ github.event.issue.title }}\n"
         "        run: echo \"$TITLE\"\n")}, "devops.gha-script-injection", False),
    ("untrusted-context-in-run-block", "devops",
     {".github/workflows/triage.yml": (
         "name: triage\non: issues\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
         "    steps:\n      - run: |\n          echo start\n          echo \"${{ github.event.issue.title }}\"\n"
         "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n        with:\n"
         "          script: console.log(\"${{ github.event.issue.body }}\")\n")},
     "devops.gha-script-injection", True),
]


@pytest.mark.parametrize(("case", "analyzer", "files", "rule", "fires"), CASES, ids=[c[0] for c in CASES])
def test_audit_regression(tmp_path, case, analyzer, files, rule, fires):
    write(tmp_path, files)
    hits = [f"{f.file_path}:{f.line_start}" for f in run(analyzer, tmp_path) if rule in f.rule_id]
    assert bool(hits) == fires, hits


def test_run_block_and_github_script_both_flagged(tmp_path):
    write(tmp_path, {".github/workflows/triage.yml": CASES[-1][2][".github/workflows/triage.yml"]})
    lines = sorted(f.line_start for f in run("devops", tmp_path) if f.rule_id.endswith("gha-script-injection"))
    assert lines == [11, 14]


# ---------------------------------------------------------------------------------------------- OSV
def test_cvss3_base_score():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None


def test_osv_severity_from_cvss_when_no_label():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    pysec = {"id": "PYSEC-1", "severity": [{"type": "CVSS_V3", "score": vector}]}
    assert _severity(pysec) == "critical"
    assert _severity({"database_specific": {"severity": "LOW"}, **pysec}) == "low"
    assert _severity({"id": "X"}) == "medium"


def test_osv_queries_large_lockfiles_in_batches(tmp_path):
    from tests.engine.test_analyzers import ctx_for

    class Resp:
        def __init__(self, data):
            self._d, self.status_code = data, 200

        def json(self):
            return self._d

        def raise_for_status(self):
            pass

    class FakeHTTP:
        batches: list[int] = []

        def post(self, url, json, timeout):
            self.batches.append(len(json["queries"]))
            results = [{} for _ in json["queries"]]
            if len(self.batches) == 3:
                results[-1] = {"vulns": [{"id": "GHSA-last"}]}  # the very last package must still be checked
            return Resp({"results": results})

        def get(self, url, timeout):
            return Resp({"id": "GHSA-last", "database_specific": {"severity": "HIGH"}})

    write(tmp_path, {"app.py": ""})
    packages = [("npm", f"pkg{i}", "1.0.0", "package-lock.json") for i in range(2500)]
    http = FakeHTTP()
    findings = OSVAnalyzer().query(ctx_for(tmp_path), packages, session=http)
    assert http.batches == [1000, 1000, 500]
    assert [f.title for f in findings] == ["pkg2499 1.0.0: GHSA-last"] and findings[0].severity == "high"


# ---------------------------------------------------------------------------------------------- dedupe
def test_provider_secrets_from_eval_and_trivy_share_a_family():
    assert family_of("eval:secrets.aws-access-key") == family_of("trivy:secret-aws-access-key-id") \
        == family_of("bandit:B105") == "hardcoded-secret"
    assert family_of("eval:secrets.env-file-committed") is None
