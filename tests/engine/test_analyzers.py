"""Analyzer behaviour against fixture repositories with known, deliberate issues (and a clean control)."""

from __future__ import annotations

import json
import shutil

import pytest

from eval_engine import sandbox
from eval_engine.analyzers import registry
from eval_engine.analyzers.base import AnalyzerContext
from eval_engine.analyzers.dependencies import OSVAnalyzer, collect_pinned
from eval_engine.analyzers.semgrep import SemgrepAnalyzer
from eval_engine.analyzers.trivy import TrivyAnalyzer
from eval_engine.languages import detect
from eval_engine.pipeline import run_analyzer
from eval_engine.workspace import iter_files
from tests.conftest import FIXTURES


def ctx_for(path):
    files = list(iter_files(path))
    return AnalyzerContext(root=path, files=files, languages=detect(path, files), timeout=120)


def rules_from(name, fixture):
    analyzer = registry.get([name])[0]
    outcome = run_analyzer(analyzer, ctx_for(FIXTURES / fixture))
    assert outcome.status in ("ok", "skipped"), outcome.reason
    return outcome, {f.rule_id for f in outcome.findings}, outcome.findings


def test_language_detection():
    ctx = ctx_for(FIXTURES / "vulnapp")
    assert ctx.languages.primary == "python"
    assert "flask" in ctx.languages.frameworks and "sqlalchemy" in ctx.languages.frameworks
    js = ctx_for(FIXTURES / "jsapp").languages
    assert js.has("javascript") and js.has("typescript") and "express" in js.frameworks


def test_secrets_analyzer():
    _, rules, findings = rules_from("secrets", "vulnapp")
    assert "eval:secrets.aws-access-key" in rules
    aws = next(f for f in findings if f.rule_id == "eval:secrets.aws-access-key")
    assert aws.severity == "critical" and aws.line_start == 10
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.evidence  # evidence is redacted
    _, clean, _ = rules_from("secrets", "cleanapp")
    assert clean == set()


def test_secrets_ignores_placeholders(tmp_path):
    (tmp_path / "config.py").write_text('PASSWORD = "changeme"\nAPI_KEY = "your-api-key"\nTOKEN = "${TOKEN}"\n'
                                        'SECRET = os.environ["SECRET"]\n')
    (tmp_path / ".env.example").write_text("API_KEY=\n")
    analyzer = registry.get(["secrets"])[0]
    assert run_analyzer(analyzer, ctx_for(tmp_path)).findings == []


def test_committed_env_file_flagged(tmp_path):
    (tmp_path / ".env").write_text("DEBUG=1\n")
    out = run_analyzer(registry.get(["secrets"])[0], ctx_for(tmp_path))
    assert {f.rule_id for f in out.findings} == {"eval:secrets.env-file-committed"}


def test_api_security_analyzer():
    _, rules, findings = rules_from("api_security", "vulnapp")
    assert {"eval:api.flask-debug-enabled", "eval:api.mass-assignment", "eval:api.hardcoded-session-secret",
            "eval:api.no-authentication"} <= rules
    _, js_rules, _ = rules_from("api_security", "jsapp")
    assert {"eval:api.cors-wildcard", "eval:api.mass-assignment", "eval:api.express-no-helmet"} <= js_rules


def test_route_with_auth_decorator_not_flagged(tmp_path):
    (tmp_path / "views.py").write_text(
        "from flask_login import login_required\n"
        "@bp.route('/items', methods=['POST'])\n@login_required\ndef create():\n    return 1\n"
        "@bp.route('/items/<id>', methods=['DELETE'])\ndef remove(id):\n    return 1\n"
        "@bp.post('/login')\ndef login():\n    return 1\n")
    out = run_analyzer(registry.get(["api_security"])[0], ctx_for(tmp_path))
    flagged = [f for f in out.findings if f.rule_id == "eval:api.route-without-auth"]
    assert len(flagged) == 1 and "DELETE /items/<id>" in flagged[0].title


def test_jwt_verification_disabled(tmp_path):
    (tmp_path / "auth.py").write_text(
        "import jwt\nclaims = jwt.decode(tok, options={'verify_signature': False})\n"
        "c2 = jwt.decode(tok, key, algorithms=['none'])\nc3 = jwt.decode(tok, key, algorithms=['HS256'])\n")
    out = run_analyzer(registry.get(["api_security"])[0], ctx_for(tmp_path))
    rule = "eval:api.jwt-verification-disabled"
    found = sorted((f.line_start, f.severity) for f in out.findings if f.rule_id == rule)
    assert found == [(2, "high"), (3, "critical")]


def _api_findings(tmp_path, files):
    for name, code in files.items():
        (tmp_path / name).write_text(code)
    out = run_analyzer(registry.get(["api_security"])[0], ctx_for(tmp_path))
    return sorted((f.rule_id.removeprefix("eval:api."), f.file_path, f.line_start, f.kind) for f in out.findings
                  if f.rule_id.removeprefix("eval:api.") in ("insecure-cookie", "sensitive-data-logged",
                                                            "upload-unvalidated", "upload-client-filename",
                                                            "no-rate-limiting"))


def test_insecure_cookies(tmp_path):
    got = _api_findings(tmp_path, {
        "settings.py": "SESSION_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = True\n"
                       "class TestingConfig:\n    SESSION_COOKIE_SECURE = False\n",
        "settings_dev.py": "SESSION_COOKIE_SECURE = False\n",
        "views.py": "def v(resp, t):\n"
                    "    resp.set_cookie('session_id', t)\n"
                    "    resp.set_cookie('auth', t, secure=False, httponly=True)\n"
                    "    resp.set_cookie('auth', t, secure=True, httponly=True)\n"
                    "    resp.set_cookie('theme', 'dark')\n"
                    "    resp.set_cookie('csrftoken', t, secure=True)\n",
        "server.js": "app.use(session({ secret: s, cookie: { httpOnly: false } }));\n"
                     "res.cookie('jwt', token);\nres.cookie('jwt', token, { httpOnly: true, secure: true });\n"
                     "\n\n\nconst mail = { host: h, secure: false };  // SMTP option\n",
    })
    assert got == [("insecure-cookie", "server.js", 1, "potential"), ("insecure-cookie", "server.js", 2, "potential"),
                   ("insecure-cookie", "settings.py", 1, "confirmed"), ("insecure-cookie", "views.py", 2, "potential"),
                   ("insecure-cookie", "views.py", 3, "potential")], got


def test_sensitive_data_logged(tmp_path):
    got = _api_findings(tmp_path, {
        "auth.py": "import logging\nlog = logging.getLogger(__name__)\n"
                   "def login(request, password, user):\n"
                   "    log.info('login %s %s', user.email, password)\n"
                   "    log.debug(f'headers: {request.headers}')\n"
                   "    logging.warning('auth', extra={'api_key': user.key})\n"
                   "    log.info('bad password for %s', user.email)\n"
                   "    log.info('token count %d', token_count)\n"
                   "    log.info('len %d', len(password))\n"
                   "    log.info('%s', mask_token(user.token))\n"
                   "    print(password)\n",
        "app.js": "console.log(`user ${req.body.email} pw ${req.body.password}`);\n"
                  "logger.info('invalid password for', user.email);\n"
                  "console.log(req.headers);\n",
    })
    assert got == [("sensitive-data-logged", "app.js", 1, "potential"),
                   ("sensitive-data-logged", "app.js", 3, "potential"),
                   ("sensitive-data-logged", "auth.py", 4, "potential"),
                   ("sensitive-data-logged", "auth.py", 5, "potential"),
                   ("sensitive-data-logged", "auth.py", 6, "potential")], got


def test_unvalidated_uploads(tmp_path):
    got = _api_findings(tmp_path, {
        "up.py": "from flask import request\n"
                 "def upload():\n"
                 "    f = request.files['f']\n"
                 "    f.save('/srv/uploads/x')\n"
                 "def upload_checked():\n"
                 "    f = request.files['f']\n"
                 "    if not allowed_file(f.filename):\n        abort(400)\n"
                 "    f.save('/srv/uploads/y')\n"
                 "async def api(file: UploadFile):\n"
                 "    with open('/srv/z', 'wb') as out:\n        out.write(await file.read())\n",
        "server.js": "const upload = multer({ dest: 'uploads/' });\n"
                     "const s = multer.diskStorage({ filename: (req, file, cb) => cb(null, file.originalname) });\n",
        "ok.js": "const upload = multer({ dest: 'u/', fileFilter, limits: { fileSize: 1e6 } });\n",
    })
    assert got == [("upload-client-filename", "server.js", 2, "potential"),
                   ("upload-unvalidated", "server.js", 1, "potential"),
                   ("upload-unvalidated", "up.py", 4, "potential"),
                   ("upload-unvalidated", "up.py", 11, "potential")], got


def test_python_login_without_rate_limiting(tmp_path):
    route = "@app.post('/auth/login')\ndef login():\n    return 1\n"
    assert _api_findings(tmp_path, {"app.py": route}) == [("no-rate-limiting", "app.py", 2, "potential")]
    (tmp_path / "requirements.txt").write_text("Flask-Limiter==3.5\n")
    assert _api_findings(tmp_path, {"app.py": route}) == []


def test_database_analyzer():
    _, rules, findings = rules_from("database", "vulnapp")
    assert {"eval:database.sql-string-formatting", "eval:database.fk-without-index",
            "eval:database.no-migrations"} <= rules
    sqli = next(f for f in findings if f.rule_id == "eval:database.sql-string-formatting")
    assert sqli.line_start == 16 and "f-string" in sqli.title


def test_parameterized_sql_not_flagged(tmp_path):
    (tmp_path / "repo.py").write_text(
        "def get(conn, uid):\n    return conn.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
        "def get2(s, uid):\n    return s.execute(text('SELECT 1 FROM t WHERE id = :id'), {'id': uid})\n"
        "MSG = f'select a value: {x}'\n")
    out = run_analyzer(registry.get(["database"])[0], ctx_for(tmp_path))
    assert out.findings == []


def test_devops_analyzer():
    _, rules, _ = rules_from("devops", "vulnapp")
    assert {"eval:devops.dockerfile-runs-as-root", "eval:devops.dockerfile-secret-in-env",
            "eval:devops.dockerfile-curl-pipe-shell", "eval:devops.dockerfile-unpinned-base", "eval:devops.no-ci",
            "eval:devops.missing-dockerignore"} <= rules


def test_github_workflow_checks(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n"
        "      - uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c\n")
    out = run_analyzer(registry.get(["devops"])[0], ctx_for(tmp_path))
    rules = {f.rule_id for f in out.findings}
    assert {"eval:devops.gha-pull-request-target-checkout", "eval:devops.gha-script-injection",
            "eval:devops.gha-default-permissions", "eval:devops.gha-unpinned-actions"} <= rules
    assert "eval:devops.no-ci" not in rules
    unpinned = next(f for f in out.findings if f.rule_id == "eval:devops.gha-unpinned-actions")
    assert unpinned.title.startswith("1 ")  # the SHA-pinned action is not counted


def test_testing_analyzer():
    _, rules, _ = rules_from("testing", "vulnapp")
    assert "eval:testing.no-tests" in rules
    _, js_rules, _ = rules_from("testing", "jsapp")
    assert "eval:testing.npm-default-test-script" in js_rules
    _, clean, _ = rules_from("testing", "cleanapp")
    assert "eval:testing.no-tests" not in clean


def test_assertionless_tests_detected(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(
        "def test_a():\n    f()\n\ndef test_b():\n    assert f() == 1\n\n"
        "def test_c():\n    with pytest.raises(ValueError):\n        f()\n")
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    out = run_analyzer(registry.get(["testing"])[0], ctx_for(tmp_path))
    f = next(f for f in out.findings if f.rule_id == "eval:testing.tests-without-assertions")
    assert f.title.startswith("1 ") and "test_a" in f.description


def test_dependencies_analyzer():
    _, rules, findings = rules_from("dependencies", "vulnapp")
    unpinned = next(f for f in findings if f.rule_id == "eval:dependencies.unpinned-python")
    assert "flask" in unpinned.evidence and "requests" not in unpinned.evidence
    _, js_rules, _ = rules_from("dependencies", "jsapp")
    assert {"eval:dependencies.no-js-lockfile", "eval:dependencies.risky-js-specifier"} <= js_rules


def test_osv_disabled_by_default_in_tests():
    outcome, _, _ = rules_from("osv", "vulnapp")
    assert outcome.status == "skipped" and "EVAL_OSV_ENABLED" in outcome.reason


def test_osv_query_parsing_with_fake_http():
    class Resp:
        def __init__(self, data, status=200):
            self._d, self.status_code = data, status

        def json(self):
            return self._d

        def raise_for_status(self):
            pass

    class FakeHTTP:
        def post(self, url, json, timeout):
            assert all(q["package"]["ecosystem"] == "PyPI" for q in json["queries"])
            return Resp({"results": [{"vulns": [{"id": "GHSA-x84v-xcm2-53pg"}]}]})

        def get(self, url, timeout):
            return Resp({"id": "GHSA-x84v-xcm2-53pg", "aliases": ["CVE-2018-18074"], "summary": "Creds leak",
                         "database_specific": {"severity": "HIGH"},
                         "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]})

    ctx = ctx_for(FIXTURES / "vulnapp")
    pinned = collect_pinned(ctx)
    assert pinned == [("PyPI", "requests", "2.19.0", "requirements.txt")]
    findings = OSVAnalyzer().query(ctx, pinned, session=FakeHTTP())
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "vuln:CVE-2018-18074" and f.severity == "high" and "2.20.0" in f.remediation
    assert f.title == "requests 2.19.0: CVE-2018-18074"


def test_maintainability_analyzer(tmp_path):
    branches = "\n".join(f"    if x == {i}:\n        return {i}" for i in range(20))
    (tmp_path / "big.py").write_text(f"def complex_fn(x):\n{branches}\n    return -1\n\n"
                                     "def swallow():\n    try:\n        f()\n    except:\n        pass\n")
    block = "\n".join(f"    total = total + compute_value_{i}(item)" for i in range(14))
    (tmp_path / "a.py").write_text(f"def a(item):\n    total = 0\n{block}\n    return total\n")
    (tmp_path / "b.py").write_text(f"def b(item):\n    total = 0\n{block}\n    return total\n")
    out = run_analyzer(registry.get(["maintainability"])[0], ctx_for(tmp_path))
    rules = {f.rule_id for f in out.findings}
    assert {"eval:maintainability.high-complexity", "eval:maintainability.swallowed-exception",
            "eval:maintainability.duplicated-code", "eval:maintainability.no-readme"} <= rules


def test_architecture_detects_cycles(tmp_path):
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("from app import b\n")
    (pkg / "b.py").write_text("from . import c\n")
    (pkg / "c.py").write_text("import app.a\n")
    (pkg / "d.py").write_text("from app import a\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "x.ts").write_text("import { y } from './y';\n")
    (tmp_path / "web" / "y.ts").write_text("import { x } from './x';\n")
    out = run_analyzer(registry.get(["architecture"])[0], ctx_for(tmp_path))
    cycles = sorted(f.evidence for f in out.findings if f.rule_id == "eval:architecture.import-cycle")
    assert cycles == ["cycle: app/a.py, app/b.py, app/c.py", "cycle: web/x.ts, web/y.ts"]


def test_architecture_no_false_cycle_for_same_named_modules(tmp_path):
    for pkg in ("billing", "shipping"):
        (tmp_path / pkg).mkdir()
        (tmp_path / pkg / "__init__.py").write_text("")
        (tmp_path / pkg / "models.py").write_text(f"from {pkg} import service\n")
        (tmp_path / pkg / "service.py").write_text("import json\n")
    out = run_analyzer(registry.get(["architecture"])[0], ctx_for(tmp_path))
    assert not [f for f in out.findings if f.rule_id == "eval:architecture.import-cycle"]


def test_performance_analyzer():
    _, rules, findings = rules_from("performance", "vulnapp")
    assert {"eval:performance.query-in-loop", "eval:performance.http-without-timeout",
            "eval:performance.unbounded-query"} <= rules
    assert all(f.kind == "estimate" for f in findings if f.rule_id == "eval:performance.query-in-loop")
    _, clean, _ = rules_from("performance", "cleanapp")
    assert clean == set()


def test_blocking_call_in_async(tmp_path):
    (tmp_path / "svc.py").write_text("import time, requests\nasync def handler():\n    time.sleep(1)\n")
    out = run_analyzer(registry.get(["performance"])[0], ctx_for(tmp_path))
    assert [f.rule_id for f in out.findings] == ["eval:performance.blocking-call-in-async"]


# ------------------------------------------------------------------------------- external tool analyzers
needs = lambda tool: pytest.mark.skipif(sandbox.which(tool) is None, reason=f"{tool} not installed")  # noqa: E731


@needs("bandit")
def test_bandit_runs_on_fixture():
    outcome, rules, _ = rules_from("bandit", "vulnapp")
    assert outcome.status == "ok"
    assert {"bandit:B608", "bandit:B201"} <= rules


@needs("ruff")
def test_ruff_runs_and_ignores_repo_config(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nexclude = ['*']\n")  # hostile config is ignored
    (tmp_path / "m.py").write_text("import os\n\ndef f():\n    return undefined_name\n")
    out = run_analyzer(registry.get(["ruff"])[0], ctx_for(tmp_path))
    assert out.status == "ok"
    assert {"ruff:F401", "ruff:F821"} <= {f.rule_id for f in out.findings}


@needs("mypy")
def test_mypy_ignores_repo_plugins(tmp_path):
    marker = tmp_path / "PWNED"
    (tmp_path / "evil_plugin.py").write_text(
        f"open({str(marker)!r}, 'w').write('x')\ndef plugin(v):\n    return None\n")
    (tmp_path / "mypy.ini").write_text("[mypy]\nplugins = evil_plugin\n")
    (tmp_path / "setup.cfg").write_text("[mypy]\nplugins = evil_plugin\n")
    (tmp_path / "m.py").write_text("def f(x: int) -> str:\n    return x\n")
    out = run_analyzer(registry.get(["mypy"])[0], ctx_for(tmp_path))
    assert out.status == "ok", out.reason
    assert not marker.exists(), "repository mypy plugin was executed"
    assert "mypy:return-value" in {f.rule_id for f in out.findings}


def test_missing_tool_is_skipped_not_passed(monkeypatch):
    monkeypatch.setattr(sandbox, "which", lambda tool: None)
    outcome, _, _ = rules_from("bandit", "vulnapp")
    assert outcome.status == "skipped" and "not installed" in outcome.reason


def test_semgrep_and_trivy_output_parsing():
    ctx = ctx_for(FIXTURES / "vulnapp")
    semgrep_json = json.dumps({"results": [{
        "check_id": "python.flask.security.injection.tainted-sql-string", "path": "app.py",
        "start": {"line": 16}, "end": {"line": 16},
        "extra": {"message": "SQL built from user input", "severity": "ERROR",
                  "metadata": {"category": "security", "confidence": "HIGH", "cwe": ["CWE-89"]}}}]})
    sg = SemgrepAnalyzer().parse(ctx, semgrep_json)
    assert sg[0].severity == "high" and sg[0].category == "security" and sg[0].line_start == 16
    trivy_json = json.dumps({"Results": [
        {"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-2018-18074", "PkgName": "requests",
                                                           "InstalledVersion": "2.19.0", "FixedVersion": "2.20.0",
                                                           "Severity": "HIGH", "Title": "creds leak"}]},
        {"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS002", "Title": "root user", "Severity": "HIGH",
                                                        "Status": "FAIL", "Message": "Specify USER",
                                                        "CauseMetadata": {"StartLine": 1}}]}]})
    tv = TrivyAnalyzer().parse(ctx, trivy_json)
    assert {f.rule_id for f in tv} == {"vuln:CVE-2018-18074", "trivy:DS002"}
    assert next(f for f in tv if f.rule_id.startswith("vuln")).title == "requests 2.19.0: CVE-2018-18074"


@needs("eslint")
def test_eslint_never_loads_repo_config(tmp_path):
    marker = tmp_path / "PWNED"
    (tmp_path / "eslint.config.js").write_text(
        f"require('fs').writeFileSync({json.dumps(str(marker))}, 'x'); module.exports = [];\n")
    (tmp_path / "a.js").write_text("eval('1+1');\n")
    out = run_analyzer(registry.get(["eslint"])[0], ctx_for(tmp_path))
    assert out.status == "ok", out.reason
    assert not marker.exists(), "repository eslint config was executed"
    assert "eslint:no-eval" in {f.rule_id for f in out.findings}


@needs("tsc")
def test_tsc_reports_type_errors_only():
    outcome, rules, _ = rules_from("tsc", "jsapp")
    assert outcome.status == "ok" and rules == {"tsc:TS2345"}


def test_registry_has_all_categories_covered():
    covered = {str(c) for a in registry.all_analyzers() for c in a.categories}
    assert covered == {"security", "architecture", "testing", "database", "api", "dependencies", "performance",
                       "devops", "maintainability"}


def test_fixture_tree_is_untouched_by_analysis(tmp_path):
    src = tmp_path / "copy"
    shutil.copytree(FIXTURES / "vulnapp", src)
    before = sorted(p.relative_to(src).as_posix() for p in src.rglob("*"))
    for analyzer in registry.all_analyzers():
        run_analyzer(analyzer, ctx_for(src))
    after = sorted(p.relative_to(src).as_posix() for p in src.rglob("*"))
    assert before == after
