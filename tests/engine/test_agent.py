"""eVal in AI coding agents: Claude Code hook, MCP server, changed-file audits."""

from __future__ import annotations

import io
import json
import shutil
import subprocess

import pytest

from eval_engine.agent import changed_files, fast_analyzers, hook_main, mcp_main
from eval_engine.cli import main
from tests.conftest import FIXTURES

LEAK = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    shutil.copytree(FIXTURES / "cleanapp", root)
    (root / ".git").mkdir()  # marks the project root for the hook
    return root


def _hook(event):
    err = io.StringIO()
    code = hook_main(stdin=io.StringIO(json.dumps(event)), stderr=err)
    return code, err.getvalue()


def test_fast_analyzers_are_builtin_and_offline():
    names = fast_analyzers()
    assert "secrets" in names and "ai_code" in names
    assert not {"ruff", "bandit", "semgrep", "osv", "registry", "trivy"} & set(names)


def test_hook_reports_findings_in_the_edited_file(project):
    (project / "settings.py").write_text(LEAK)
    code, err = _hook({"tool_name": "Write", "cwd": str(project), "tool_input": {"file_path": "settings.py"}})
    assert code == 2
    assert "settings.py" in err and "aws" in err.lower() and "Fix:" in err
    assert "AKIAIOSFODNN7EXAMPLE" not in err  # evidence is never echoed; only titles and fixes


def test_hook_is_quiet_for_clean_files_other_tools_and_bad_input(project):
    (project / "settings.py").write_text(LEAK)
    (project / "ok.py").write_text("def add(a, b):\n    return a + b\n")
    assert _hook({"tool_name": "Edit", "cwd": str(project), "tool_input": {"file_path": "ok.py"}}) == (0, "")
    assert _hook({"tool_name": "Read", "cwd": str(project), "tool_input": {"file_path": "settings.py"}})[0] == 0
    assert _hook({"tool_name": "Write", "cwd": str(project), "tool_input": {"file_path": "missing.py"}})[0] == 0
    assert hook_main(stdin=io.StringIO("not json"), stderr=io.StringIO()) == 0
    # Threshold: the leak is critical/high, so a "critical"-only hook still reports it; info-level noise never.
    code, _ = _hook({"tool_name": "Write", "cwd": str(project), "tool_input": {"file_path": str(project / "ok.py")}})
    assert code == 0


def _mcp(root, *messages):
    out = io.StringIO()
    mcp_main(root, stdin=io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), stdout=out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_mcp_session(project):
    (project / "settings.py").write_text(LEAK)
    replies = _mcp(project,
                   {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                   {"jsonrpc": "2.0", "method": "notifications/initialized"},
                   {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                   {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "eval_check_files", "arguments": {"paths": ["settings.py"]}}},
                   {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "eval_audit", "arguments": {"min_severity": "high"}}},
                   {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "eval_check_files", "arguments": {"paths": ["../../etc/passwd"]}}},
                   {"jsonrpc": "2.0", "id": 6, "method": "nope"},
                   {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "rm_rf", "arguments": {}}})
    assert [r["id"] for r in replies] == [1, 2, 3, 4, 5, 6, 7]  # the notification gets no reply
    assert replies[0]["result"]["serverInfo"]["name"] == "eval" and "tools" in replies[0]["result"]["capabilities"]
    assert {t["name"] for t in replies[1]["result"]["tools"]} == {"eval_audit", "eval_check_files"}
    checked = json.loads(replies[2]["result"]["content"][0]["text"])
    assert checked["scope"] == "settings.py" and checked["findings"] >= 1
    assert all(r["file"] == "settings.py" for r in checked["results"])
    audited = json.loads(replies[3]["result"]["content"][0]["text"])
    assert audited["scope"] == "all files" and all(r["severity"] in ("high", "critical") for r in audited["results"])
    assert replies[4]["result"]["isError"] is True and "outside the server root" in \
        replies[4]["result"]["content"][0]["text"]
    assert replies[5]["error"]["code"] == -32601 and replies[6]["error"]["code"] == -32602


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_changed_files_and_cli_changed(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / "vulnapp", root)
    _git(root, "init", "-q")
    _git(root, "-c", "user.email=t@example.com", "-c", "user.name=t", "add", ".")
    _git(root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "init")
    assert changed_files(root) == []
    (root / "new.py").write_text(LEAK)
    assert changed_files(root) == ["new.py"]
    out = tmp_path / "r.json"
    code = main([str(root), "--changed", "--analyzers", "secrets", "--format", "json", "-o", str(out),
                 "--fail-on", "high"])
    report = json.loads(out.read_text())
    assert code == 1 and {f["file_path"] for f in report["findings"]} == {"new.py"}
    with pytest.raises(ValueError):
        changed_files(root, "--output=/tmp/x")
