from __future__ import annotations

import re

import pytest

from eval_app.models import AISettings, Audit, IntegrationCredential
from eval_engine.ai import AIError, StaticProvider
from tests.app.helpers import make_project, upload_new, zip_bytes
from tests.conftest import FIXTURES, register


def add_anthropic_key(client, org):
    client.post(f"/o/{org}/settings/integrations",
                data={"provider": "anthropic", "label": "Claude", "secret": "sk-ant-api03-" + "k" * 40})


def test_ai_disabled_by_default_and_requires_key(alice, db):
    c, org = alice["client"], alice["org"]
    page = c.get(f"/o/{org}/settings/integrations").data.decode()
    assert "AI-assisted analysis" in page and "disabled" in page
    c.post(f"/o/{org}/settings/ai", data={"enabled": "on", "provider": "anthropic", "model": ""})
    assert db.session.execute(db.select(AISettings)).scalar_one_or_none() is None


def test_ai_settings_admin_only(app, alice):
    m = app.test_client()
    register(m, "member@example.com", "Member Org")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "member@example.com", "role": "member"})
    assert m.post(f"/o/{alice['org']}/settings/ai", data={"provider": "anthropic"}).status_code == 403


def test_compatible_base_url_must_be_allow_listed(alice, db, app):
    c, org = alice["client"], alice["org"]
    c.post(f"/o/{org}/settings/ai", data={"enabled": "on", "provider": "openai_compatible", "model": "llama3",
                                         "base_url": "http://169.254.169.254/latest"})
    assert db.session.execute(db.select(AISettings)).scalar_one_or_none() is None
    app.config["AI_ALLOWED_BASE_URLS"] = "http://ollama:11434/v1"
    c.post(f"/o/{org}/settings/ai", data={"enabled": "on", "provider": "openai_compatible", "model": "llama3",
                                         "base_url": "http://ollama:11434/v1"})
    s = db.session.execute(db.select(AISettings)).scalar_one()
    assert s.enabled and s.base_url == "http://ollama:11434/v1"


def test_model_picker_lists_provider_models_and_accepts_other(alice, db, app):
    c, org = alice["client"], alice["org"]
    page = c.get(f"/o/{org}/settings/integrations").data.decode()
    assert '<option value="claude-sonnet-5-5"' in page and "data-ai-models" in page and "gpt-5-mini" in page
    app.config["AI_ALLOWED_BASE_URLS"] = "http://ollama:11434/v1"
    c.post(f"/o/{org}/settings/ai", data={"provider": "openai_compatible", "model": "", "model_custom": "phi4",
                                         "base_url": "http://ollama:11434/v1"})
    assert db.session.execute(db.select(AISettings)).scalar_one().model == "phi4"
    page = c.get(f"/o/{org}/settings/integrations").data.decode()
    assert 'value="phi4"' in page and '<option value="qwen2.5-coder:7b"' in page


def test_models_endpoint_lists_models_for_the_selected_key(alice, db, monkeypatch):
    c, org = alice["client"], alice["org"]
    add_anthropic_key(c, org)
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    seen = {}

    def fake_list(name, *, api_key, base_url):
        seen.update(name=name, api_key=api_key, base_url=base_url)
        return ["claude-opus-5-5", "claude-haiku-5-5"]

    monkeypatch.setattr("eval_app.ai_config.list_models", fake_list)
    r = c.post(f"/o/{org}/settings/ai/models", data={"provider": "anthropic", "credential_id": str(cred.id)})
    assert r.status_code == 200 and r.json == {"models": ["claude-opus-5-5", "claude-haiku-5-5"]}
    assert seen == {"name": "anthropic", "api_key": "sk-ant-api03-" + "k" * 40, "base_url": ""}
    # A key stored for another provider, or no key at all, is refused before any outbound call.
    seen.clear()
    r = c.post(f"/o/{org}/settings/ai/models", data={"provider": "openai", "credential_id": str(cred.id)})
    assert r.status_code == 400 and "credential" in r.json["error"]
    assert c.post(f"/o/{org}/settings/ai/models", data={"provider": "openai"}).status_code == 400
    assert seen == {}


def test_models_endpoint_guards_compatible_urls_and_reports_errors(alice, app, monkeypatch):
    c, org = alice["client"], alice["org"]
    calls = []

    def fake_list(name, *, api_key, base_url):
        calls.append(base_url)
        raise AIError("Could not reach the AI provider.")

    monkeypatch.setattr("eval_app.ai_config.list_models", fake_list)
    r = c.post(f"/o/{org}/settings/ai/models",
               data={"provider": "openai_compatible", "base_url": "http://169.254.169.254/latest"})
    assert r.status_code == 400 and calls == []
    app.config["AI_ALLOWED_BASE_URLS"] = "http://ollama:11434/v1"
    r = c.post(f"/o/{org}/settings/ai/models",
               data={"provider": "openai_compatible", "base_url": "http://ollama:11434/v1"})
    assert r.status_code == 400 and r.json["error"] == "Could not reach the AI provider."
    assert calls == ["http://ollama:11434/v1"]


def test_models_endpoint_admin_only(app, alice):
    m = app.test_client()
    register(m, "member@example.com", "Member Org")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "member@example.com", "role": "member"})
    assert m.post(f"/o/{alice['org']}/settings/ai/models", data={"provider": "anthropic"}).status_code == 403


def test_credential_of_other_org_cannot_be_selected(alice, bob, db):
    add_anthropic_key(bob["client"], bob["org"])
    bob_cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    alice["client"].post(f"/o/{alice['org']}/settings/ai",
                         data={"enabled": "on", "provider": "anthropic", "credential_id": str(bob_cred.id)})
    assert db.session.execute(db.select(AISettings)).scalar_one_or_none() is None


@pytest.fixture
def ai_enabled(alice, db, monkeypatch):
    c, org = alice["client"], alice["org"]
    add_anthropic_key(c, org)
    cred = db.session.execute(db.select(IntegrationCredential)).scalar_one()
    c.post(f"/o/{org}/settings/ai", data={"enabled": "on", "provider": "anthropic", "credential_id": str(cred.id),
                                         "max_findings": "3"})
    assert db.session.execute(db.select(AISettings)).scalar_one().enabled
    seen = {}

    def responder(system, user, schema):
        ids = re.findall(r'"id": "(F\d+)"', user)
        if "explanations" in schema["properties"]:
            return {"explanations": [{"id": i, "explanation": f"<b>why</b> {i}", "remediation_steps": ["step"],
                                      "suggested_patch": "patch()", "false_positive_likelihood": "low"}
                                     for i in ids]}
        return {"summary": "Overall: fix secrets first.", "top_risks": ["Secrets"], "observations": []}

    def fake_build(name, *, api_key, model, base_url, timeout):
        seen.update(name=name, api_key=api_key)
        return StaticProvider(responder, name="anthropic", model="claude-opus-5-5")

    monkeypatch.setattr("eval_app.ai_config.build_provider", fake_build)
    return {**alice, "seen": seen}


def test_audit_with_ai_stores_labelled_explanations(ai_enabled, db):
    c, org = ai_enabled["client"], ai_enabled["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "vulnapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded"
    assert ai_enabled["seen"] == {"name": "anthropic", "api_key": "sk-ant-api03-" + "k" * 40}  # decrypted in worker
    assert audit.ai_summary["summary"] == "Overall: fix secrets first." and audit.ai_summary["explained"] == 3
    explained = [f for f in audit.findings if f.ai_explanation]
    assert len(explained) == 3
    page = c.get(f"/o/{org}/audits/{audit.id}").data.decode()
    assert "AI-assisted architectural summary" in page and "does not affect scores" in page
    detail = c.get(f"/o/{org}/findings/{explained[0].id}").data.decode()
    assert "AI-generated" in detail and "never modifies your code" in detail
    assert "&lt;b&gt;why&lt;/b&gt;" in detail  # model output is escaped


def test_ai_misconfiguration_is_reported_not_fatal(ai_enabled, db, monkeypatch):
    def broken(*a, **k):
        raise AIError("Anthropic model 'x' was not found.")

    monkeypatch.setattr("eval_app.ai_config.build_provider", broken)
    c, org = ai_enabled["client"], ai_enabled["org"]
    pid = make_project(c, org)
    upload_new(c, org, pid, zip_bytes(FIXTURES / "cleanapp"))
    audit = db.session.execute(db.select(Audit)).scalar_one()
    assert audit.status == "succeeded" and "not found" in audit.ai_summary["error"]
    assert "did not complete" in c.get(f"/o/{org}/audits/{audit.id}").data.decode()
