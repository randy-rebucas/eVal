from __future__ import annotations

import logging
import sys

import pytest

from eval_engine import sandbox
from eval_engine.redaction import RedactingFilter, contains_secret, redact


def test_disallowed_tool_rejected(tmp_path):
    with pytest.raises(sandbox.SandboxError, match="allow-listed"):
        sandbox.run("bash", ["-c", "id"], cwd=tmp_path)
    assert sandbox.which("python") is None  # not on the allow-list


@pytest.fixture
def python_tool(monkeypatch):
    """Temporarily allow-list the test interpreter so sandbox behaviour can be observed."""
    monkeypatch.setattr(sandbox, "ALLOWED_TOOLS", sandbox.ALLOWED_TOOLS | {"python"})
    real_which = sandbox.which
    monkeypatch.setattr(sandbox, "which", lambda t: sys.executable if t == "python" else real_which(t))


def test_environment_is_scrubbed(tmp_path, monkeypatch, python_tool):
    monkeypatch.setenv("EVAL_SECRET_KEY", "super-secret-value")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h/db")
    r = sandbox.run("python", ["-c", "import os,json;print(json.dumps(dict(os.environ)))"], cwd=tmp_path)
    assert r.returncode == 0
    assert "super-secret-value" not in r.stdout and "DATABASE_URL" not in r.stdout


def test_timeout_kills_process(tmp_path, python_tool):
    r = sandbox.run("python", ["-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout=1)
    assert r.timed_out and r.duration < 20


def test_output_is_capped(tmp_path, python_tool):
    r = sandbox.run("python", ["-c", "print('x' * 100000)"], cwd=tmp_path, max_output=1000)
    assert r.truncated and len(r.stdout) == 1000


def test_args_are_not_shell_interpreted(tmp_path, python_tool):
    r = sandbox.run("python", ["-c", "import sys; print(sys.argv[1])", "$(whoami); echo pwned"], cwd=tmp_path)
    assert r.stdout.strip() == "$(whoami); echo pwned"


@pytest.mark.parametrize("secret", [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a1B2" * 9,
    "sk-ant-api03-" + "x" * 30,
    "xoxb-123456789012-abcdefghij",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
])
def test_redact_provider_tokens(secret):
    out = redact(f"value = {secret} end")
    assert secret not in out and "[REDACTED]" in out
    assert contains_secret(secret)


def test_redact_assignments_and_urls_but_not_env_lookups():
    assert "hunter2pass" not in redact('password = "hunter2pass"')
    assert "s3cr" not in redact("postgres://admin:s3cret@db:5432/app")
    assert redact('password = os.environ["DB_PASSWORD"]') == 'password = os.environ["DB_PASSWORD"]'
    assert redact("token = None") == "token = None"


def test_logging_filter_redacts(caplog):
    logger = logging.getLogger("eval.test.redaction")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="eval.test.redaction"):
        logger.info("token is %s", "ghp_" + "Z" * 36)
    assert "ghp_" not in caplog.text and "[REDACTED]" in caplog.text
