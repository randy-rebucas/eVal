"""On-device AI: loopback enforcement, CLI wiring, and an end-to-end run against a local OpenAI-compatible server."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from eval_engine import cli
from eval_engine.ai import AIError, StaticProvider
from eval_engine.ai.local import build_local_provider, is_loopback_url
from tests.conftest import FIXTURES
from tests.engine.test_ai import good_responder


@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:11434/v1", True),
    ("http://localhost:1234/v1", True),
    ("http://[::1]:8080/v1", True),
    ("https://127.0.0.2/v1", True),
    ("http://10.0.0.5:11434/v1", False),
    ("https://api.openai.com/v1", False),
    ("http://localhost.evil.example/v1", False),
    ("file:///etc/passwd", False),
    ("not a url", False),
])
def test_is_loopback_url(url, ok):
    assert is_loopback_url(url) is ok


def test_build_local_provider_rejects_remote_endpoints():
    with pytest.raises(AIError, match="loopback"):
        build_local_provider(model="m", base_url="https://api.openai.com/v1")
    p = build_local_provider(model="llama3.1:8b", base_url="http://localhost:11434/v1")
    assert (p.info.name, p.info.model) == ("local", "llama3.1:8b")


def test_cli_refuses_non_loopback_ai_url(capsys):
    code = cli.main([str(FIXTURES / "vulnapp"), "--analyzers", "secrets", "--ai", "local",
                     "--ai-url", "https://api.openai.com/v1"])
    assert code == 2 and "loopback" in capsys.readouterr().err


def test_cli_local_ai_explains_findings_without_changing_scores(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "build_local_provider",
                        lambda **k: StaticProvider(good_responder, name="local", model=k["model"]))
    args = [str(FIXTURES / "vulnapp"), "--analyzers", "secrets,database", "--format", "json"]
    cli.main(args + ["-o", str(tmp_path / "plain.json")])
    cli.main(args + ["-o", str(tmp_path / "ai.json"), "--ai", "local", "--ai-model", "tiny:1b",
                     "--ai-max-findings", "2"])
    plain, ai = (json.loads((tmp_path / n).read_text()) for n in ("plain.json", "ai.json"))
    assert ai["scores"] == plain["scores"]
    assert ai["ai_summary"]["explained"] == 2 and ai["ai_summary"]["model"] == "tiny:1b"
    assert sum(1 for f in ai["findings"] if f["ai_explanation"]) == 2

    md = tmp_path / "ai.md"
    cli.main([str(FIXTURES / "vulnapp"), "--analyzers", "secrets", "--ai", "local", "--ai-model", "tiny:1b",
              "-o", str(md)])
    text = md.read_text(encoding="utf-8")
    assert "**Model:** tiny:1b (local, prompt v1)" in text and "**AI explanation** (tiny:1b" in text
    assert "Suggested patch (AI-generated" in text


def test_cli_completes_audit_when_local_model_is_down(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_local_provider", lambda **k: StaticProvider(
        lambda **_: AIError("Could not reach the AI provider."), name="local", model="m"))
    out = tmp_path / "r.html"
    code = cli.main([str(FIXTURES / "vulnapp"), "--analyzers", "secrets", "--ai", "local", "--format", "html",
                     "-o", str(out), "--fail-on", "critical"])
    assert code == 1  # the gate still works from deterministic findings
    assert "warning: local AI" in capsys.readouterr().err
    assert "not available: Could not reach the AI provider." in out.read_text(encoding="utf-8")


# ----------------------------------------------------------------- end to end over HTTP on 127.0.0.1
class _FakeLocalModel(BaseHTTPRequestHandler):
    """Minimal OpenAI-compatible /chat/completions endpoint, standing in for Ollama / LM Studio."""

    requests: list[dict] = []
    models = ["qwen2.5-coder:7b", "llama3.1:latest"]

    def do_GET(self):  # noqa: N802 - http.server API
        self._send(json.dumps({"object": "list", "data": [{"id": m, "object": "model"} for m in self.models]}))

    def _send(self, text: str):
        payload = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        system, user = body["messages"][0]["content"], body["messages"][1]["content"]
        schema = json.loads(system.split("matching this JSON Schema:\n", 1)[1])
        content = json.dumps(good_responder(system=system, user=user, schema=schema))
        self._send(json.dumps({
            "id": "c1", "object": "chat.completion", "created": 0, "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": content}}],
        }))

    def log_message(self, *args):
        pass


@pytest.fixture
def local_model_server():
    _FakeLocalModel.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeLocalModel)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()
    server.server_close()


def test_end_to_end_with_local_openai_compatible_server(tmp_path, local_model_server):
    out = tmp_path / "r.json"
    code = cli.main([str(FIXTURES / "vulnapp"), "--analyzers", "secrets,database", "--format", "json",
                     "-o", str(out), "--ai", "local", "--ai-url", local_model_server, "--ai-model", "qwen2.5-coder:7b"])
    report = json.loads(out.read_text())
    assert code == 0 and "error" not in report["ai_summary"]
    assert report["ai_summary"]["provider"] == "local" and report["ai_summary"]["explained"] >= 1
    reqs = _FakeLocalModel.requests
    # findings are explained in batches (default 3 per request), then one summary request
    explain_calls = -(-report["ai_summary"]["explained"] // 3)
    assert len(reqs) == explain_calls + 1 and all(r["path"] == "/v1/chat/completions" for r in reqs)
    assert all(r["body"]["model"] == "qwen2.5-coder:7b" for r in reqs)
    assert all(r["body"]["response_format"] == {"type": "json_object"} for r in reqs)
    assert all("AKIAIOSFODNN7EXAMPLE" not in json.dumps(r["body"]) for r in reqs)  # redacted before sending


def test_local_provider_ignores_proxy_environment(tmp_path, local_model_server, monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://proxy.invalid:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    out = tmp_path / "r.json"
    cli.main([str(FIXTURES / "vulnapp"), "--analyzers", "secrets", "--format", "json", "-o", str(out),
              "--ai", "local", "--ai-url", local_model_server])
    assert "error" not in json.loads(out.read_text())["ai_summary"]


# ------------------------------------------------------------------------------------------ offline mode
def test_offline_audit_with_local_ai_makes_no_outbound_connections(tmp_path, local_model_server, monkeypatch):
    monkeypatch.setenv("EVAL_OSV_ENABLED", "1")
    out = tmp_path / "r.json"
    code = cli.main([str(FIXTURES / "vulnapp"), "--analyzers", "secrets,osv,dependencies", "--format", "json",
                     "-o", str(out), "--offline", "--ai", "local", "--ai-url", local_model_server])
    report = json.loads(out.read_text())
    assert code == 0 and report["offline"] == {"enabled": True, "blocked_connections": []}
    osv = next(t for t in report["tools"] if t["name"] == "osv")
    assert osv["status"] == "skipped" and osv["reason"].startswith("offline mode:")
    assert report["ai_summary"]["explained"] >= 1 and "error" not in report["ai_summary"]
    md = render_md(report)
    assert "Offline mode: checks that need network access were skipped" in md and "blocked: 0" in md


def render_md(report: dict) -> str:
    from eval_engine.reports import render

    return render(report, "md")


def test_netguard_blocks_and_records_outbound_but_allows_loopback(local_model_server):
    import socket
    import urllib.request

    from eval_engine.netguard import OfflineViolation, block_outbound

    original = socket.getaddrinfo
    with block_outbound() as blocked:
        with pytest.raises(OfflineViolation):
            socket.getaddrinfo("api.osv.dev", 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(OfflineViolation):
            s.connect(("93.184.216.34", 443))
        s.close()
        with urllib.request.urlopen(local_model_server + "/models", timeout=5) as resp:  # noqa: S310
            assert resp.status == 200
    assert blocked == ["api.osv.dev", "93.184.216.34:443"]
    assert socket.getaddrinfo is original


def test_network_required_reasons(tmp_path, monkeypatch):
    from eval_engine.analyzers.base import AnalyzerContext
    from eval_engine.analyzers.semgrep import SemgrepAnalyzer
    from eval_engine.analyzers.trivy import TrivyAnalyzer
    from eval_engine.languages import LanguageReport

    ctx = AnalyzerContext(root=tmp_path, files=[], languages=LanguageReport(), offline=True)
    monkeypatch.delenv("EVAL_SEMGREP_CONFIG", raising=False)
    assert "Semgrep registry" in SemgrepAnalyzer().network_required(ctx)
    monkeypatch.setenv("EVAL_SEMGREP_CONFIG", str(tmp_path))
    assert SemgrepAnalyzer().network_required(ctx) is None
    monkeypatch.setenv("EVAL_TRIVY_CACHE_DIR", str(tmp_path))
    assert "pre-seed" in TrivyAnalyzer().network_required(ctx)
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "trivy.db").write_bytes(b"")
    assert TrivyAnalyzer().network_required(ctx) is None


# ------------------------------------------------------------------------- small-model batching / retry
def _ai_run(responder, **enricher_kwargs):
    from eval_engine.ai.enrich import Enricher
    from eval_engine.pipeline import PipelineConfig, run_pipeline

    provider = StaticProvider(responder)
    result = run_pipeline(FIXTURES / "vulnapp", PipelineConfig(
        analyzers=["secrets", "database", "api_security", "testing"], ai=Enricher(provider, **enricher_kwargs)))
    return provider, result


def test_findings_are_explained_in_batches():
    provider, result = _ai_run(good_responder, max_findings=6, batch_size=3)
    explain = [c for c in provider.calls if "explanations" in c["schema"]["properties"]]
    assert [len(re.findall(r'"id": "F\d+"', c["user"])) for c in explain] == [3, 3]
    assert result.ai_summary["explained"] == 6 and len(provider.calls) == 3


def test_invalid_output_is_retried_once():
    from eval_engine.ai import AIOutputError

    seen = {"n": 0}

    def flaky(system, user, schema):
        seen["n"] += 1
        return AIOutputError("The model returned invalid JSON.") if seen["n"] == 1 else \
            good_responder(system=system, user=user, schema=schema)

    _, result = _ai_run(flaky, max_findings=3, batch_size=3)
    assert result.ai_summary["explained"] == 3 and result.ai_summary["retries"] == 1
    assert "error" not in result.ai_summary


def test_connection_errors_are_not_retried():
    provider, result = _ai_run(lambda **k: AIError("Could not reach the AI provider."), max_findings=3,
                               batch_size=3)
    assert len(provider.calls) == 2  # one explain batch + summary, no retries
    assert result.ai_summary["error"] == "Could not reach the AI provider."


def test_report_orders_likely_real_findings_first_within_a_severity():
    from eval_engine.reports import _sorted_findings

    def f(title, sev, fp=None):
        return {"title": title, "severity": sev, "category": "security", "file_path": "a.py",
                "ai_explanation": {"false_positive_likelihood": fp} if fp else {}}

    order = _sorted_findings({"findings": [f("hi-fp", "high", "high"), f("crit", "critical"),
                                           f("hi-unrated", "high"), f("hi-real", "high", "low")]})
    assert [x["title"] for x in order] == ["crit", "hi-real", "hi-unrated", "hi-fp"]


# ------------------------------------------------------------------------------------------------ doctor
def test_doctor_ready_when_model_is_available(local_model_server, capsys):
    assert cli.main(["doctor", "--ai-url", local_model_server, "--ai-model", "qwen2.5-coder:7b"]) == 0
    out = capsys.readouterr().out
    assert "Ready: eval-audit PATH --ai local" in out and "secrets" in out
    assert "internet osv" in " ".join(out.split()) and "local analyzers" in " ".join(out.split())
    assert cli.main(["doctor", "--ai-url", local_model_server, "--ai-model", "llama3.1"]) == 0  # ":latest"


def test_doctor_reports_missing_model_and_unreachable_server(local_model_server, capsys):
    assert cli.main(["doctor", "--ai-url", local_model_server, "--ai-model", "phi4:14b"]) == 1
    assert "ollama pull phi4:14b" in capsys.readouterr().out
    assert cli.main(["doctor", "--ai-url", "http://127.0.0.1:9/v1"]) == 1
    assert "unreachable" in capsys.readouterr().out
