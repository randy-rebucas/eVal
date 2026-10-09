"""Regression tests for the self-audit fixes: dotfile findings, tool-config isolation, redaction, analyzer FPs."""

from __future__ import annotations

from pathlib import Path

import pytest

from eval_engine import sandbox
from eval_engine.analyzers import registry
from eval_engine.analyzers.base import Analyzer
from eval_engine.cli import main as cli_main
from eval_engine.dedupe import normalize_path
from eval_engine.pipeline import PipelineConfig, run_analyzer, run_pipeline
from eval_engine.redaction import contains_secret, redact
from tests.engine.test_analyzers import ctx_for

needs = lambda tool: pytest.mark.skipif(sandbox.which(tool) is None, reason=f"{tool} not installed")  # noqa: E731
AWS = "AKIA" + "QWERTYUIOPASDFGH"


@pytest.mark.parametrize(("raw", "expected"), [
    (".github/workflows/ci.yml", ".github/workflows/ci.yml"),
    ("./.env", ".env"),
    ("././a/b.py", "a/b.py"),
    (".\\x\\y.py", "x/y.py"),
])
def test_normalize_path_keeps_leading_dots(raw, expected):
    assert normalize_path(raw) == expected


def test_findings_on_dotfiles_are_kept(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo \"${{ github.event.pull_request.title }}\"\n")
    (tmp_path / ".env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    (tmp_path / "main.py").write_text("print(1)\n")
    result = run_pipeline(tmp_path, PipelineConfig(analyzers=["secrets", "devops"]))
    kept = {(f.rule_id, f.file_path) for f in result.findings}
    assert result.stats["dropped_invalid"] == 0
    assert ("eval:secrets.env-file-committed", ".env") in kept
    assert ("eval:secrets.aws-access-key", ".env") in kept
    assert ("eval:devops.gha-script-injection", ".github/workflows/ci.yml") in kept


# ------------------------------------------------------------------------------- repository cannot steer tools
def _captured_args(monkeypatch, name, root):
    captured = {}

    def fake_run_tool(self, ctx, args, ok_codes=(0, 1)):
        captured["args"] = list(args)
        captured["files"] = {a: Path(a).read_text() for a in args if Path(a).is_file() and Path(a).is_absolute()}

        class R:
            stdout = "{}"
        return R()

    monkeypatch.setattr(Analyzer, "run_tool", fake_run_tool)
    registry.get([name])[0].run(ctx_for(root))
    return captured


def test_trivy_uses_its_own_config_and_ignore_file(monkeypatch, tmp_path):
    (tmp_path / "trivy.yaml").write_text("output: /tmp/x\nseverity: [LOW]\n")
    (tmp_path / ".trivyignore").write_text("CVE-2018-18074\n")
    got = _captured_args(monkeypatch, "trivy", tmp_path)
    args = got["args"]
    config, ignore = args[args.index("--config") + 1], args[args.index("--ignorefile") + 1]
    assert not config.startswith(str(tmp_path)) and not ignore.startswith(str(tmp_path))
    assert got["files"][config].strip() == "{}" and got["files"][ignore] == ""


def test_semgrep_disables_nosem(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert "--disable-nosem" in _captured_args(monkeypatch, "semgrep", tmp_path)["args"]


@needs("bandit")
def test_bandit_ignores_repo_ini_and_nosec(tmp_path):
    (tmp_path / ".bandit").write_text("[bandit]\nskips: B608,B201\nexclude: ./app.py\n")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "def q(cur, name):\n    cur.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)  # nosec\n"
        "app.run(debug=True)  # nosec B201\n")
    out = run_analyzer(registry.get(["bandit"])[0], ctx_for(tmp_path))
    assert out.status == "ok", out.reason
    assert {"bandit:B608", "bandit:B201"} <= {f.rule_id for f in out.findings}


@needs("ruff")
def test_ruff_ignores_noqa(tmp_path):
    (tmp_path / "m.py").write_text("import os  # noqa\n\ndef f():\n    return undefined_name  # noqa: F821\n")
    out = run_analyzer(registry.get(["ruff"])[0], ctx_for(tmp_path))
    assert {"ruff:F401", "ruff:F821"} <= {f.rule_id for f in out.findings}


# -------------------------------------------------------------------------------------------------- redaction
def test_redacts_private_key_body_lines_without_begin_line():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R"
    excerpt = f"12 | {body}\n13 | {body[::-1]}\n14 | -----END PRIVATE KEY-----"
    out = redact(excerpt)
    assert body not in out and body[::-1] not in out and "12 | [REDACTED]" in out
    assert not contains_secret(body)  # mask-only pattern: never evidence of a secret


# ------------------------------------------------------------------------------------- analyzer false positives
def test_secrets_skips_word_slugs_and_names_escaped_assignments(tmp_path):
    (tmp_path / "rules.py").write_text(
        'FAMILIES = {"eval:api.hardcoded-session-secret": "hardcoded-secret"}\n'
        "ENV = \"FOO=1\\nDB_PASSWORD='q8Zr2Lm9Xc4Tv7Ny'\"\n")
    findings = run_analyzer(registry.get(["secrets"])[0], ctx_for(tmp_path)).findings
    titles = [f.title for f in findings]
    assert titles == ["Hardcoded credential assigned to 'DB_PASSWORD'"], titles


def test_fk_covered_by_table_args_index_not_flagged(tmp_path):
    (tmp_path / "models.py").write_text(
        "import sqlalchemy as sa\nfrom app import db\n\n"
        "class Audit(db.Model):\n"
        "    __table_args__ = (sa.Index('ix_audits_repo_created', 'repository_id', 'created_at'),)\n"
        "    repository_id = db.Column(db.ForeignKey('repositories.id'))\n"
        "    user_id = db.Column(db.ForeignKey('users.id'))\n\n"
        "links = sa.Table('links', db.metadata, sa.Column('audit_id', sa.ForeignKey('audits.id')))\n")
    findings = run_analyzer(registry.get(["database"])[0], ctx_for(tmp_path)).findings
    lines = sorted(f.line_start for f in findings if f.rule_id == "eval:database.fk-without-index")
    assert lines == [7, 9]  # user_id and the Core table column; repository_id leads the composite index


def test_cli_title_names_current_directory(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "shop"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(repo)
    assert cli_main([".", "--analyzers", "secrets", "--format", "md"]) == 0
    assert capsys.readouterr().out.startswith("# eVal audit: shop\n")
