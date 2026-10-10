"""Taint analysis: request data reaching SQL, shell, eval, files, outbound URLs, templates, redirects."""

from __future__ import annotations

import textwrap

from eval_engine.pipeline import PipelineConfig, run_pipeline

VULNERABLE = '''
import os
import subprocess
import requests
from flask import Flask, request, redirect, render_template_string, send_file
from fastapi import APIRouter

app = Flask(__name__)
router = APIRouter()


@app.route("/users")
def users(db):
    name = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)


@app.post("/ping")
def ping():
    host = request.form["host"].strip()
    os.system("ping -c1 " + host)
    subprocess.run(f"nslookup {host}", shell=True)


@app.get("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.get("/file")
def download():
    path = os.path.join("/srv/files", request.args["f"])
    return send_file(path)


@app.get("/fetch")
def fetch():
    url = request.json.get("url")
    return requests.get(url, timeout=5).text


@app.get("/hello")
def hello():
    tpl = "<h1>Hello %s</h1>" % request.args.get("who")
    return render_template_string(tpl)


@app.get("/go")
def go():
    return redirect(request.args.get("next"))


@router.get("/items/{item_id}")
async def item(item_id: str, db):
    return db.execute("SELECT * FROM items WHERE id = " + item_id)
'''

SAFE = '''
import subprocess
import shlex
from flask import Flask, request, redirect, url_for

app = Flask(__name__)
ALLOWED = {"a", "b"}


@app.route("/users")
def users(db):
    name = request.args.get("name", "")
    return db.execute("SELECT * FROM users WHERE name = ?", (name,))


@app.get("/n")
def number(db):
    n = int(request.args["n"])
    return db.execute(f"SELECT * FROM t LIMIT {n}")


@app.get("/run")
def run():
    subprocess.run(["ls", request.args["dir"]])
    subprocess.run("ls " + shlex.quote(request.args["dir"]), shell=True)


@app.get("/go")
def go():
    target = request.args.get("next", "")
    if target.startswith("/") and not target.startswith("//"):
        return redirect(target)
    return redirect(url_for("index"))


@app.get("/pick")
def pick():
    choice = request.args.get("c")
    return redirect(choice if choice in ALLOWED else "/")


@router.get("/items/{item_id}")
async def item(item_id: int, db):
    return db.execute(f"SELECT * FROM items WHERE id = {item_id}")


def helper(cursor, sql):
    cursor.execute(sql)  # not request data
'''


def _run(tmp_path, code):
    (tmp_path / "app.py").write_text(textwrap.dedent(code))
    return run_pipeline(tmp_path, PipelineConfig(analyzers=["taint"])).findings


def test_vulnerable_flows_are_reported_with_a_trace(tmp_path):
    findings = _run(tmp_path, VULNERABLE)
    got = sorted((f.rule_id.split(".", 1)[1], f.line_start) for f in findings)
    assert got == [
        ("code-injection", 28), ("command-injection", 22), ("command-injection", 23),
        ("open-redirect", 51), ("path-traversal", 34), ("sql-injection", 16), ("sql-injection", 56),
        ("ssrf", 40), ("template-injection", 46),
    ], got
    sql = next(f for f in findings if f.line_start == 16)
    assert sql.kind == "confirmed" and sql.confidence == "high" and sql.severity == "critical"
    assert "request.args" in sql.description and "name → query" in sql.description and "CWE-89" in sql.description
    fastapi = next(f for f in findings if f.line_start == 56)
    assert "route parameter 'item_id'" in fastapi.description


def test_safe_code_is_quiet(tmp_path):
    assert [(f.rule_id, f.line_start) for f in _run(tmp_path, SAFE)] == []


def test_taint_upgrades_the_pattern_finding_on_the_same_line(tmp_path):
    (tmp_path / "app.py").write_text(textwrap.dedent('''
        from flask import request

        def users(db):
            name = request.args["name"]
            return db.execute(f"SELECT * FROM users WHERE name = '{name}'")
    '''))
    result = run_pipeline(tmp_path, PipelineConfig(analyzers=["taint", "database"]))
    sql = [f for f in result.findings if f.line_start == 6]
    assert len(sql) == 1, [(f.rule_id, f.sources) for f in result.findings]
    f = sql[0]
    assert set(f.sources) == {"taint", "database"} and f.kind == "confirmed" and "Data flow in users()" in f.description
