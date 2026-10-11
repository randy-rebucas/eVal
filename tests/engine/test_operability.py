"""Performance (static risk), dependency, DevOps and observability checks. Each rule has a positive and a negative
case so heuristics stay precise."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from eval_engine.analyzers import registry
from eval_engine.analyzers.ai_code import RegistryAnalyzer
from eval_engine.analyzers.base import AnalyzerContext
from eval_engine.analyzers.dependencies import collect_pinned, satisfies
from eval_engine.languages import detect
from eval_engine.pipeline import run_analyzer
from eval_engine.reports import render
from eval_engine.workspace import iter_files


def write(root, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def ctx_for(root):
    files = list(iter_files(root))
    return AnalyzerContext(root=root, files=files, languages=detect(root, files), timeout=120)


def run(name, root):
    outcome = run_analyzer(registry.get([name])[0], ctx_for(root))
    assert outcome.status == "ok", outcome.reason
    return outcome.findings


def hits(name, root, rule):
    return [(f.file_path, f.line_start) for f in run(name, root) if f.rule_id == f"eval:{rule}"]


# ===================================================================================================== performance
def test_python_network_call_in_loop(tmp_path):
    write(tmp_path, {"svc.py": (
        "import asyncio, requests, httpx\n"
        "def enrich(users):\n"
        "    for u in users:\n"
        "        requests.get(f'https://api/x/{u.id}', timeout=5)\n"                      # 4: flagged
        "def retry():\n"
        "    for attempt in range(3):\n"
        "        requests.get('https://api/x', timeout=5)\n"                              # retry loop
        "session = requests.Session()\n"
        "def names(ids):\n"
        "    return [session.get(f'https://api/{i}', timeout=5).json() for i in ids]\n"  # 10: flagged
        "async def fan_out(urls):\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        await asyncio.gather(*[client.get(u) for u in urls])\n"                  # concurrent: not flagged
        "        for u in urls:\n"
        "            await client.get(u)\n"                                               # 15: flagged
        "def poll(url):\n"
        "    while True:\n"
        "        requests.get(url, timeout=5)\n")})                                       # polling: not flagged
    assert hits("performance", tmp_path, "performance.network-call-in-loop") == [
        ("svc.py", 4), ("svc.py", 10), ("svc.py", 15)]


def test_js_network_call_in_loop(tmp_path):
    write(tmp_path, {"sync.js": (
        "async function run(ids) {\n"
        "  for (const id of ids) {\n"
        "    const r = await fetch(`/api/items/${id}`);\n"                                # 3: flagged
        "  }\n"
        "  ids.forEach(id => axios.post('/api/touch', { id }));\n"                        # 5: flagged
        "  await Promise.all(ids.map(id => fetch(`/api/${id}`)));\n"                      # concurrent: not flagged
        "  buttons.forEach(b => { b.addEventListener('click', () => fetch('/api/click')); });\n"  # handler
        "}\n")})
    assert hits("performance", tmp_path, "performance.network-call-in-loop") == [("sync.js", 3), ("sync.js", 5)]


def test_python_nested_loop_lookup_and_list_membership(tmp_path):
    write(tmp_path, {"report.py": (
        "def join(orders, users):\n"
        "    out = []\n"
        "    for o in orders:\n"
        "        user = next(u for u in users if u.id == o.user_id)\n"                    # 4: O(n·m) join
        "        out.append((o, user))\n"
        "    for o in orders:\n"
        "        for line in o.lines:\n"                                                  # child collection
        "            if line.sku == o.sku:\n"
        "                pass\n"
        "    for i in range(len(orders)):\n"
        "        for j in range(len(users)):\n"                                           # index arithmetic
        "            if orders[i].x == users[j].x:\n"
        "                pass\n"
        "    return out\n"
        "def filt(items, banned_users):\n"
        "    banned = [u.id for u in banned_users]\n"
        "    seen = list()\n"
        "    for it in items:\n"
        "        if it.owner in banned:\n"                                                # 19: flagged
        "            continue\n"
        "        if it.key not in seen:\n"                                                # dedupe: not flagged
        "            seen.append(it.key)\n"
        "        if it.tag in [t.lower() for t in it.allowed]:\n"                         # 23: rebuilt each time
        "            pass\n")})
    assert hits("performance", tmp_path, "performance.nested-loop-lookup") == [("report.py", 4)]
    assert hits("performance", tmp_path, "performance.list-membership-in-loop") == [("report.py", 19),
                                                                                    ("report.py", 23)]


def test_js_nested_loop_lookup(tmp_path):
    write(tmp_path, {"view.ts": (
        "export const rows = users.map(u => ({ ...u, orders: orders.filter(o => o.userId === u.id) }));\n"
        "export const tags = users.map(u => u.tags.filter(t => t.active === true));\n"
        "for (const id of ids) {\n"
        "  const item = items.find(i => i.id === id);\n"
        "}\n")})
    assert hits("performance", tmp_path, "performance.nested-loop-lookup") == [("view.ts", 1), ("view.ts", 4)]


def test_serialization_and_memory_python(tmp_path):
    write(tmp_path, {"util.py": (
        "import copy, json\nfrom functools import lru_cache, cache\n"
        "def clone(x):\n    return json.loads(json.dumps(x))\n"                           # 4: round trip
        "def each(items, template):\n"
        "    for it in items:\n        yield copy.deepcopy(template)\n"                   # 7: deepcopy in loop
        "def lines(path):\n    with open(path) as f:\n        return f.readlines()\n"     # 10: readlines
        "@lru_cache(maxsize=None)\ndef price(sku):\n    return sku\n"                     # 11: unbounded
        "@cache\ndef settings():\n    return {}\n"                                        # no args: fine
        "@lru_cache(maxsize=256)\ndef bounded(sku):\n    return sku\n"
        "@app.post('/upload')\ndef upload():\n    data = request.files['f'].read()\n    return 'ok'\n")})
    found = {(f.rule_id, f.line_start) for f in run("performance", tmp_path)}
    assert {("eval:performance.serialization-roundtrip", 4), ("eval:performance.deepcopy-in-loop", 7),
            ("eval:performance.readlines", 10), ("eval:performance.unbounded-cache", 11),
            ("eval:performance.whole-upload-in-memory", 22)} <= found
    assert not {r for r, line in found if r == "eval:performance.unbounded-cache" and line != 11}
    assert all(f.kind == "estimate" for f in run("performance", tmp_path))


def test_js_serialization_and_memory(tmp_path):
    write(tmp_path, {"server.js": (
        "const express = require('express');\nconst app = express();\n"
        "app.use(express.json({ limit: '50mb' }));\n"                                     # 3: large limit
        "app.use(express.urlencoded({ limit: '1mb', extended: true }));\n"
        "const copy = JSON.parse(JSON.stringify(defaults));\n"                            # 5: round trip
        "app.post('/raw', (req, res) => {\n"
        "  const chunks = [];\n"
        "  req.on('data', chunk => chunks.push(chunk));\n"                                # 8: unbounded buffer
        "  req.on('end', () => res.end(Buffer.concat(chunks)));\n"
        "});\n")})
    found = {(f.rule_id, f.line_start) for f in run("performance", tmp_path)}
    assert {("eval:performance.large-body-limit", 3), ("eval:performance.serialization-roundtrip", 5),
            ("eval:performance.request-buffered-in-memory", 8)} <= found
    assert ("eval:performance.large-body-limit", 4) not in found


def test_reports_separate_static_risk_from_measured_performance():
    model = {"scores": {"overall": 80, "risk": "Low", "categories": {}}, "findings": []}
    for fmt in ("md", "html"):
        text = render(model, fmt)
        assert "Static Risk" in text and "Measured Performance" in text and "Not assessed" in text
    basis = json.loads(render(model, "json"))["performance_basis"]
    assert basis["measured_performance"].startswith("Not assessed")


# ==================================================================================================== dependencies
def test_satisfies_subset_of_pep440():
    assert satisfies("2.31.0", ">=2.0,<3") is True
    assert satisfies("3.0.1", ">=2.0,<3") is False
    assert satisfies("1.4.2", "~=1.4") is True and satisfies("2.0", "~=1.4") is False
    assert satisfies("1.2.9", "==1.2.*") is True and satisfies("1.3.0", "==1.2.*") is False
    assert satisfies("2.0rc1", ">=1") is None and satisfies("1.0", "^1.0") is None


def test_duplicate_declarations(tmp_path):
    write(tmp_path, {
        "requirements.txt": "flask==3.0.3\nrequests==2.32.3\nFlask==3.0.3\n",
        "web/package.json": json.dumps({"dependencies": {"lodash": "^4.17.21"},
                                        "devDependencies": {"lodash": "^4.17.21", "jest": "^29.0.0"}}),
        "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"": {
            "dependencies": {"lodash": "^4.17.21"}, "devDependencies": {"lodash": "^4.17.21", "jest": "^29.0.0"}}}}),
        "svc/pyproject.toml": '[project]\nname = "svc"\ndependencies = ["httpx>=0.27", "HTTPX>=0.27"]\n',
        "svc/uv.lock": "",
    })
    found = {(f.file_path, f.title) for f in run("dependencies", tmp_path)
             if f.rule_id == "eval:dependencies.duplicate-declaration"}
    assert found == {("requirements.txt", "'flask' is declared more than once in requirements.txt"),
                     ("web/package.json", "'lodash' is declared more than once in both dependencies and "
                                          "devDependencies"),
                     ("svc/pyproject.toml", "'httpx' is declared more than once in pyproject.toml (dependencies)")}


def test_conflicting_python_versions(tmp_path):
    write(tmp_path, {
        "requirements.txt": "django==4.2.11\nrequests==2.32.3\n",
        "requirements-dev.txt": "-r requirements.txt\ndjango==5.0.3\npytest==8.2.0\n",
        "pyproject.toml": '[project]\nname = "x"\ndependencies = ["requests>=2.0,<2.30", "pytest>=8"]\n'})
    found = {f.title for f in run("dependencies", tmp_path) if f.rule_id == "eval:dependencies.conflicting-versions"}
    assert found == {"'django' is pinned to different versions",
                     "'requests' 2.32.3 in requirements.txt violates pyproject.toml (>=2.0,<2.30)"}


def test_lockfile_out_of_sync(tmp_path):
    pkg = {"dependencies": {"express": "^4.19.2", "zod": "^3.23.0"}}
    write(tmp_path, {
        "npm/package.json": json.dumps(pkg),
        "npm/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"express": "^4.18.0"}},
            "node_modules/express": {"version": "4.18.2"}}}),
        "yarn/package.json": json.dumps(pkg),
        "yarn/yarn.lock": ('# yarn lockfile v1\n\n"express@^4.19.2":\n  version "4.19.2"\n\n'
                           'zod@^3.23.0:\n  version "3.23.8"\n'),
        "pnpm/package.json": json.dumps(pkg),
        "pnpm/pnpm-lock.yaml": ("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express:\n"
                                "        specifier: ^4.19.2\n        version: 4.19.2\n      zod:\n"
                                "        specifier: ^3.22.0\n        version: 3.22.4\n"),
    })
    found = {f.file_path: f.evidence for f in run("dependencies", tmp_path)
             if f.rule_id == "eval:dependencies.lockfile-out-of-sync"}
    assert set(found) == {"npm/package-lock.json", "pnpm/pnpm-lock.yaml"}  # yarn.lock is in sync
    assert "express: package.json '^4.19.2', lockfile '^4.18.0'" in found["npm/package-lock.json"]
    assert "zod: package.json '^3.23.0', lockfile 'missing'" in found["npm/package-lock.json"]
    assert "zod: package.json '^3.23.0', lockfile '^3.22.0'" in found["pnpm/pnpm-lock.yaml"]


def test_multiple_lockfiles_and_duplicate_versions(tmp_path):
    write(tmp_path, {
        "package.json": json.dumps({"dependencies": {"a": "^1.0.0"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0"}, "node_modules/semver": {"version": "7.6.0"},
            "node_modules/a/node_modules/semver": {"version": "5.7.2"}}}),
        "yarn.lock": 'a@^1.0.0:\n  version "1.0.0"\n'})
    found = {f.rule_id: f for f in run("dependencies", tmp_path)}
    assert found["eval:dependencies.multiple-lockfiles"].file_path == "package-lock.json"
    assert found["eval:dependencies.duplicate-versions"].evidence == "semver: 5.7.2, 7.6.0"
    assert found["eval:dependencies.duplicate-versions"].severity == "info"


def test_unused_dependencies(tmp_path):
    write(tmp_path, {
        "requirements.txt": "flask==3.0.3\nPyYAML==6.0.1\narrow==1.3.0\ngunicorn==22.0.0\nbeautifulsoup4==4.12.3\n",
        "app/__init__.py": "from flask import Flask\n",
        "app/config.py": "import yaml\n",
        "app/scrape.py": "from bs4 import BeautifulSoup\n",
        "web/package.json": json.dumps({"dependencies": {"react": "18.3.1", "react-dom": "18.3.1", "dayjs": "1.11.0",
                                                         "left-pad": "1.3.0", "@types/node": "20.0.0"},
                                        "scripts": {"build": "vite build"}}),
        "web/src/a.tsx": "import React from 'react';\n",
        "web/src/b.ts": "import dayjs from 'dayjs';\n",
        "web/src/c.ts": "export const x = 1;\n",
    })
    found = {f.file_path: f.description for f in run("dependencies", tmp_path)
             if f.rule_id == "eval:dependencies.unused"}
    assert set(found) == {"requirements.txt", "web/package.json"}
    assert "mentions: arrow." in found["requirements.txt"]
    assert "mentions: left-pad." in found["web/package.json"]


def test_unused_not_reported_for_tiny_projects(tmp_path):
    write(tmp_path, {"requirements.txt": "arrow==1.3.0\n", "main.py": "print(1)\n"})
    assert not hits("dependencies", tmp_path, "dependencies.unused")


def test_collect_pinned_reads_yarn_pnpm_and_pipfile_locks(tmp_path):
    write(tmp_path, {
        "yarn.lock": '"@scope/pkg@npm:^1.0.0":\n  version: 1.2.0\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n',
        "web/pnpm-lock.yaml": ("lockfileVersion: '6.0'\npackages:\n  /express@4.19.2:\n    resolution: {integrity: x}\n"
                               "  /@babel/core@7.24.0(supports-color@8.1.1):\n    dev: true\n"),
        "old/pnpm-lock.yaml": "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.21:\n    dev: false\n",
        "Pipfile.lock": json.dumps({"default": {"django": {"version": "==4.2.11"}}, "develop": {}}),
    })
    pinned = {(eco, name, ver) for eco, name, ver, _ in collect_pinned(ctx_for(tmp_path))}
    assert {("npm", "@scope/pkg", "1.2.0"), ("npm", "left-pad", "1.3.0"), ("npm", "express", "4.19.2"),
            ("npm", "@babel/core", "7.24.0"), ("npm", "lodash", "4.17.21"), ("PyPI", "django", "4.2.11")} <= pinned


class FakeResponse:
    def __init__(self, data):
        self.status_code, self._data = 200, data

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, table):
        self.table = table

    def get(self, url, **kw):
        return self.table[url]


def test_registry_reports_major_versions_behind(tmp_path):
    write(tmp_path, {"requirements.txt": "django==3.2.25\nrequests==2.32.3\n"})
    ctx = ctx_for(tmp_path)
    old = {"releases": {"0.1": [{"upload_time_iso_8601": "2010-01-01T00:00:00Z"}]}}
    session = FakeSession({
        "https://pypi.org/pypi/django/json": FakeResponse({**old, "info": {"version": "5.1.2"}}),
        "https://pypi.org/pypi/requests/json": FakeResponse({**old, "info": {"version": "2.32.3"}}),
        "https://registry.npmjs.org/zod": FakeResponse({"time": {"created": "2020-03-07T00:00:00Z"},
                                                        "dist-tags": {"latest": "3.23.8"}}),
        "https://registry.npmjs.org/pkg0": FakeResponse({"time": {"created": "2020-03-07T00:00:00Z"},
                                                         "dist-tags": {"latest": "0.9.0"}}),
    })
    versions = {("PyPI", "django"): ("3.2.25", "requirements.txt"), ("PyPI", "requests"): ("2.32.3",
                                                                                           "requirements.txt"),
                ("npm", "zod"): ("3.22.0", "package.json"), ("npm", "pkg0"): ("0.4.1", "package.json")}
    packages = [("PyPI", "django"), ("PyPI", "requests"), ("npm", "zod"), ("npm", "pkg0")]
    findings = RegistryAnalyzer().check(ctx, packages, session=session, now=datetime(2026, 10, 10, tzinfo=UTC),
                                        versions=versions)
    outdated = {f.file_path: f.evidence for f in findings if f.rule_id == "eval:dependencies.outdated"}
    assert outdated == {"requirements.txt": "django 3.2.25 → 5.1.2", "package.json": "pkg0 0.4.1 → 0.9.0"}


# ========================================================================================================== devops
def test_ci_without_tests(tmp_path):
    write(tmp_path, {".github/workflows/build.yml": (
        "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: pip install -r requirements.txt\n      - run: ruff check .\n")})
    assert hits("devops", tmp_path, "devops.ci-no-tests") == [(".github/workflows/build.yml", None)]
    write(tmp_path, {".github/workflows/build.yml": (
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python -m pytest -q\n")})
    assert not hits("devops", tmp_path, "devops.ci-no-tests")


def test_compose_resource_limits(tmp_path):
    write(tmp_path, {"docker-compose.yml": (
        "services:\n  web:\n    image: app:1.0\n    deploy:\n      resources:\n        limits:\n"
        "          memory: 512M\n  worker:\n    image: app:1.0\n    mem_limit: 256m\n"
        "  redis:\n    image: redis:7\n")})
    [f] = [f for f in run("devops", tmp_path) if f.rule_id == "eval:devops.compose-no-resource-limits"]
    assert f.evidence == "no limits: redis" and f.line_start == 11


K8S_BAD = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.example.com/api:latest
          securityContext:
            privileged: true
          env:
            - name: DEBUG
              value: "true"
"""
K8S_GOOD = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: api
          image: registry.example.com/api:1.4.2
          resources:
            limits:
              memory: 512Mi
          readinessProbe:
            httpGet: {path: /readyz, port: 8000}
---
apiVersion: v1
kind: Service
metadata:
  name: api
"""


def test_kubernetes_manifests(tmp_path):
    write(tmp_path, {"k8s/bad.yaml": K8S_BAD, "k8s/good.yaml": K8S_GOOD,
                     "chart/templates/deploy.yaml": "kind: Deployment\nspec:\n  containers:\n"
                                                    "    - image: {{ .Values.image }}\n"})
    found = {(f.rule_id, f.file_path, f.line_start) for f in run("devops", tmp_path)
             if f.rule_id.startswith(("eval:devops.k8s", "eval:devops.debug"))}
    assert found == {("eval:devops.k8s-no-resource-limits", "k8s/bad.yaml", 2),
                     ("eval:devops.k8s-no-probes", "k8s/bad.yaml", 2),
                     ("eval:devops.k8s-runs-as-root", "k8s/bad.yaml", 2),
                     ("eval:devops.k8s-privileged", "k8s/bad.yaml", 2),
                     ("eval:devops.k8s-unpinned-image", "k8s/bad.yaml", 10),
                     ("eval:devops.debug-in-deployment-config", "k8s/bad.yaml", 14)}


def test_debug_and_dev_server_in_deployment_files(tmp_path):
    write(tmp_path, {
        "Dockerfile": ("FROM node:20 AS build\nENV NODE_ENV development\nRUN npm ci\n"
                       "FROM python:3.12-slim\nENV FLASK_DEBUG=1\nUSER app\n"
                       "CMD [\"flask\", \"run\", \"--host=0.0.0.0\"]\n"),
        "Dockerfile.dev": "FROM python:3.12\nENV DEBUG=1\nCMD [\"flask\", \"run\"]\n",
        "Procfile": "web: uvicorn app:app --reload\nworker: celery -A app worker\n",
        ".env.production": "DEBUG=true\n",
        "fly.toml": "[env]\n  LOG_LEVEL = \"info\"\n",
    })
    found = {(f.rule_id, f.file_path, f.line_start) for f in run("devops", tmp_path)
             if f.rule_id in ("eval:devops.debug-in-deployment-config", "eval:devops.dev-server-in-production")}
    assert found == {("eval:devops.debug-in-deployment-config", "Dockerfile", 5),  # final stage only
                     ("eval:devops.dev-server-in-production", "Dockerfile", 7),
                     ("eval:devops.dev-server-in-production", "Procfile", 1),
                     ("eval:devops.debug-in-deployment-config", ".env.production", 1)}


DEPLOY_BAD = """on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: docker build -t ghcr.io/acme/api:latest .
  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - run: docker push ghcr.io/acme/api:latest
      - run: ssh deploy@prod.example.com 'docker compose pull && docker compose up -d'
"""
DEPLOY_GOOD = """on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
  build:
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - run: docker build -t ghcr.io/acme/api:${{ github.sha }} .
  deploy:
    needs:
      - build
    environment: production
    runs-on: ubuntu-latest
    steps:
      - run: kubectl set image deploy/api api=ghcr.io/acme/api:${{ github.sha }}
"""


def test_deployment_pipeline_risks(tmp_path):
    write(tmp_path, {".github/workflows/deploy.yml": DEPLOY_BAD})
    found = {(f.rule_id, f.line_start) for f in run("devops", tmp_path)
             if f.rule_id.split(".", 1)[1] in ("deploy-without-test-gate", "deploy-mutable-tag",
                                               "no-environment-separation", "no-rollback-strategy")}
    assert found == {("eval:devops.deploy-without-test-gate", 9), ("eval:devops.deploy-mutable-tag", 13),
                     ("eval:devops.no-environment-separation", 9), ("eval:devops.no-rollback-strategy", 9)}


def test_deployment_pipeline_well_configured(tmp_path):
    write(tmp_path, {".github/workflows/deploy.yml": DEPLOY_GOOD,
                     "docs/RUNBOOK.md": "Roll back with `kubectl rollout undo deploy/api`.\n"})
    rules = {f.rule_id for f in run("devops", tmp_path)}
    assert not rules & {"eval:devops.deploy-without-test-gate", "eval:devops.deploy-mutable-tag",
                        "eval:devops.no-environment-separation", "eval:devops.no-rollback-strategy",
                        "eval:devops.ci-no-tests"}


# =================================================================================================== observability
FLASK_APP = "from flask import Flask\napp = Flask(__name__)\n@app.get('/healthz')\ndef h():\n    return 'ok'\n"


def test_error_tracking_and_tracing_are_reported_separately(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\nopentelemetry-sdk\n", "app.py": FLASK_APP})
    rules = {f.rule_id for f in run("observability", tmp_path)}
    assert "eval:devops.no-tracing" not in rules and "eval:devops.no-error-tracking" not in rules
    write(tmp_path, {"requirements.txt": "flask\nsentry-sdk\n"})
    rules = {f.rule_id for f in run("observability", tmp_path)}
    assert "eval:devops.no-tracing" in rules and "eval:devops.no-error-tracking" not in rules


def test_structured_logging(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\n", "app.py": "import logging\n" + FLASK_APP})
    assert "eval:devops.unstructured-logging" in {f.rule_id for f in run("observability", tmp_path)}
    write(tmp_path, {"requirements.txt": "flask\npython-json-logger\n"})
    assert "eval:devops.unstructured-logging" not in {f.rule_id for f in run("observability", tmp_path)}


def test_audit_log(tmp_path):
    write(tmp_path, {"requirements.txt": "flask\nflask-login\n", "app.py": (
        "from flask_login import login_required\n" + FLASK_APP)})
    assert "eval:devops.no-audit-log" in {f.rule_id for f in run("observability", tmp_path)}
    write(tmp_path, {"audit.py": "def record_audit_event(actor, action):\n    pass\n"})
    assert "eval:devops.no-audit-log" not in {f.rule_id for f in run("observability", tmp_path)}


def test_background_job_monitoring(tmp_path):
    write(tmp_path, {"tasks.py": "from celery import Celery\napp = Celery('t')\n@app.task\ndef send():\n    pass\n"})
    [f] = [f for f in run("observability", tmp_path) if f.rule_id == "eval:devops.no-job-monitoring"]
    assert (f.file_path, f.line_start) == ("tasks.py", 1) and "celery" in f.title
    write(tmp_path, {"signals.py": "from celery.signals import task_failure\n"})
    assert "eval:devops.no-job-monitoring" not in {f.rule_id for f in run("observability", tmp_path)}
    write(tmp_path, {"worker.js": "const { Worker } = require('bullmq');\nnew Worker('q', async () => {});\n"})
    assert "eval:devops.no-job-monitoring" not in {f.rule_id for f in run("observability", tmp_path)}
