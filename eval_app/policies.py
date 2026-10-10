"""Audit policies in the app: organization default ← repository override ← repository ``.eval.toml``.

The repository file is the least trusted layer: it is ignored when the organization disables it, and on pull-request
audits it is ignored when the pull request changes it, so a PR cannot relax the gate that judges it.
"""

from __future__ import annotations

from pathlib import Path

from eval_engine.policy import MAX_POLICY_BYTES, POLICY_FILE, GateResult, Policy, PolicyError, evaluate_gate, layered
from eval_engine.workspace import read_text

from .extensions import db
from .models import Audit, Finding, Organization

TEMPLATE = """# eVal audit policy (TOML). Empty = defaults: gate fails on high or critical findings.
# [gate]
# fail_on = "high"                 # critical | high | medium | low | info | never
# require_analyzers = ["semgrep"]
# max_change_risk = "medium"       # pull requests: fail when the change risk is above this (low | medium)
#
# [[gate.paths]]
# pattern = "src/payments/**"
# fail_on = "medium"
#
# [rules]
# disable = ["eval:maintainability.*"]
# [rules.severity]
# "bandit:B101" = "low"
#
# [paths]
# exclude = ["vendor/**"]
"""


def validate_text(text: str) -> str:
    """Normalize and validate policy text from a form; raises PolicyError."""
    text = (text or "").replace("\r\n", "\n").strip()
    if text:
        layered([("this", text)])
    return text + "\n" if text else ""


def effective_policy(audit: Audit, root: Path | None) -> tuple[Policy, list[str]]:
    """The policy for ``audit`` (source checked out at ``root``) and notes about layers that were ignored."""
    repo = audit.repository
    org = db.session.get(Organization, audit.organization_id)
    layers = [("organization", org.policy_toml or ""), ("repository", repo.policy_toml or "")]
    notes = []
    if root is not None and (root / POLICY_FILE).is_file():
        if not org.allow_repo_policy_file:
            notes.append(f"{POLICY_FILE} ignored: repository policy files are disabled for this organization.")
        elif audit.pr_number and POLICY_FILE in (audit.changed_files or []):
            notes.append(f"{POLICY_FILE} ignored: this pull request changes it.")
        elif (root / POLICY_FILE).is_symlink():
            notes.append(f"{POLICY_FILE} ignored: it is a symbolic link.")
        else:
            text = read_text(root, POLICY_FILE, max_bytes=MAX_POLICY_BYTES) or ""
            try:
                layered([("file", text)])
                layers.append(("file", text))
            except PolicyError as exc:
                notes.append(f"{POLICY_FILE} ignored: {exc}")
    return layered(layers), notes


def audit_policy(audit: Audit) -> Policy:
    return Policy.from_dict(audit.policy) if audit.policy else Policy()


def gate_candidates(audit: Audit) -> list[Finding]:
    """PR audits gate on findings the PR introduced; other audits on every open scored finding."""
    if audit.pr_number:
        from .findings.services import pr_introduced

        return pr_introduced(audit)
    return [f for f in audit.findings if f.kind != "ai_observation" and f.triage_status == "open"]


def evaluate(audit: Audit) -> GateResult:
    return evaluate_gate(audit_policy(audit), gate_candidates(audit), audit.tool_status or [],
                         change_risk=(audit.stats or {}).get("change_risk"))
