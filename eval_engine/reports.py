"""Report renderers: JSON, Markdown, standalone HTML, and SARIF 2.1.0.

All renderers take the *report model* — the dict produced by ``AuditResult.to_dict()`` plus a ``meta`` block —
so the CLI and the web app render identically. Repository-derived text is untrusted and always escaped.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime

from . import ENGINE_VERSION
from .findings import CATEGORY_LABELS, SEVERITY_ORDER, Category

DISCLAIMER = (
    "Scores are risk indicators derived from automated static analysis, not guarantees of security or production "
    "readiness. Absence of findings does not mean absence of vulnerabilities. Static estimates are not "
    "measurements; potential risks require human verification."
)
KIND_LABELS = {
    "confirmed": "Confirmed",
    "potential": "Potential risk",
    "estimate": "Static estimate",
    "ai_observation": "AI observation (unscored)",
}
FORMATS = ("json", "md", "html", "sarif")


def _meta(model: dict) -> dict:
    meta = dict(model.get("meta") or {})
    meta.setdefault("generated_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))
    meta.setdefault("engine_version", model.get("engine_version", ENGINE_VERSION))
    meta.setdefault("title", "eVal audit report")
    return meta


def _location(f: dict) -> str:
    if not f.get("file_path"):
        return "(repository)"
    return f"{f['file_path']}:{f['line_start']}" if f.get("line_start") else f["file_path"]


def _triage_text(f: dict) -> str:
    """One-line triage decision for reports ("" when the finding is open)."""
    t = f.get("triage") or {}
    status = t.get("status") or f.get("triage_status") or "open"
    if status == "open":
        return ""
    parts = [status.replace("_", " ")]
    if t.get("expires_on"):
        parts[0] += f" until {t['expires_on']}"
    if t.get("owner"):
        parts.append(f"owner: {t['owner']}")
    if t.get("reason"):
        parts.append(t["reason"])
    return " · ".join(parts)


def _ai_status(model: dict) -> str:
    """Which model produced the AI content, or why there is none ("" when AI was not requested)."""
    ai = model.get("ai_summary") or {}
    if not ai:
        return ""
    who = f"{ai['model']} ({ai['provider']}, prompt {ai.get('prompt_version', '?')})" if ai.get("model") else "AI"
    text = f"{who}: {ai.get('explained', 0)} finding(s) explained"
    if ai.get("error"):
        text += f"; not available: {ai['error']}"
    return text


def _offline_text(model: dict) -> str:
    off = model.get("offline") or {}
    if not off.get("enabled"):
        return ""
    blocked = off.get("blocked_connections") or []
    return ("Offline mode: checks that need network access were skipped (see coverage); outbound connections "
            f"blocked: {len(blocked)}" + (f" ({', '.join(blocked[:5])})" if blocked else ""))


# Within a severity, findings the AI rated unlikely to be false positives come first (unrated in the middle).
# Ordering only: severities and scores stay deterministic.
_FP_ORDER = {"low": 0, "medium": 1, "high": 2}


def _compliance(f: dict) -> dict:
    """The finding's framework mapping (computed when the model does not carry one)."""
    from .compliance import map_finding

    if not f.get("compliance"):
        f["compliance"] = map_finding(f["rule_id"], f.get("category", ""), f.get("description", ""),
                                      f.get("references"))
    return f["compliance"]


def _compliance_line(f: dict) -> str:
    c = _compliance(f)
    parts = [*c["cwe"], *c["owasp"], *(f"ASVS {x}" for x in c["asvs"]), *(f"SOC 2 {x}" for x in c["soc2"]),
             *(f"ISO 27001 {x}" for x in c["iso27001"])]
    return " · ".join(parts)


def _compliance_summary(model: dict) -> dict:
    from .compliance import summarize

    findings = [f for f in model.get("findings", []) if f.get("kind") != "ai_observation"]
    for f in findings:
        _compliance(f)
    return summarize(findings)


COMPLIANCE_NOTE = ("Mappings are indicative: a finding is evidence relevant to a control, not a determination that "
                   "the control is or is not met.")


def _sorted_findings(model: dict) -> list[dict]:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    def fp_rank(f: dict) -> int:
        return _FP_ORDER.get((f.get("ai_explanation") or {}).get("false_positive_likelihood", ""), 1)

    return sorted(model.get("findings", []), key=lambda f: (rank.get(f["severity"], 9), fp_rank(f),
                                                            f.get("category", ""), f.get("file_path", ""),
                                                            f.get("line_start") or 0))


# ------------------------------------------------------------------------------------------------ json
def render_json(model: dict) -> str:
    out = dict(model)
    out["meta"] = _meta(model)
    out["disclaimer"] = DISCLAIMER
    out["compliance"] = {"note": COMPLIANCE_NOTE, "controls": _compliance_summary(model)}
    return json.dumps(out, indent=2, sort_keys=False, default=str)


# -------------------------------------------------------------------------------------------- markdown
def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def render_markdown(model: dict) -> str:
    meta, scores = _meta(model), model.get("scores", {})
    lines = [f"# {_md(meta['title'])}", ""]
    for key, label in (("repository", "Repository"), ("ref", "Ref"), ("commit", "Commit"),
                       ("generated_at", "Generated"), ("engine_version", "Engine")):
        if meta.get(key):
            lines.append(f"- **{label}:** {_md(meta[key])}")
    overall = scores.get("overall")
    lines += ["", f"## Overall: {overall if overall is not None else 'not assessed'} / 100 — "
                  f"{scores.get('risk', 'n/a')} risk", "", f"> {DISCLAIMER}", "",
              "| Category | Score | Risk | Findings |", "|---|---:|---|---:|"]
    for name, cs in (scores.get("categories") or {}).items():
        label = CATEGORY_LABELS.get(Category(name), name)
        score_txt = "—" if cs.get("score") is None else f"{cs['score']:.0f}"
        lines.append(f"| {label} | {score_txt} | {cs.get('risk')} | {cs.get('findings', 0)} |")
    counts = scores.get("severity_counts") or {}
    if _offline_text(model):
        lines += ["", f"**{_md(_offline_text(model))}**"]
    lines += ["", "**Severity distribution:** " + ", ".join(f"{s}: {counts.get(s, 0)}" for s in SEVERITY_ORDER)]
    lc = model.get("lifecycle") or {}
    if lc:
        lines.append(f"**Since previous audit:** {lc.get('new', 0)} new, {lc.get('recurring', 0)} recurring, "
                     f"{lc.get('existing', 0)} existing, {len(lc.get('resolved', []))} resolved")
    tools = model.get("tools") or []
    if tools:
        lines += ["", "## Analyzer coverage", "", "| Analyzer | Status | Findings | Note |", "|---|---|---:|---|"]
        for t in tools:
            lines.append(f"| {_md(t['title'])} | {t['status']} | {t['findings']} | {_md(t.get('reason', ''))} |")
    profile = model.get("app_profile") or {}
    if profile:
        auth = ", ".join(profile.get("auth") or {}) or "none detected"
        stores = ", ".join(profile.get("datastores") or {}) or "none detected"
        if profile.get("sql_dialects"):
            stores += f" (SQL: {', '.join(profile['sql_dialects'])})"
        lines += ["", "## Application profile", "",
                  f"- **Web framework:** {_md(', '.join(profile.get('web_frameworks') or []) or 'none detected')}",
                  f"- **Authentication:** {_md(auth)}", f"- **Data stores:** {_md(stores)}", "",
                  "| Security check | Applies | Why |", "|---|---|---|"]
        for row in profile.get("applicability") or []:
            lines.append(f"| {_md(row['check'])} | {'yes' if row['applies'] else 'no'} | {_md(row['reason'])} |")
    if _ai_status(model):
        lines += ["", "## AI-assisted analysis", "", f"**Model:** {_md(_ai_status(model))}", "",
                  "_Generated by an AI model from the findings below; verify before acting. AI never changes "
                  "scores._"]
        if model["ai_summary"].get("summary"):
            lines += ["", _md(model["ai_summary"]["summary"])]
    from .compliance import FRAMEWORK_TITLES

    summary = _compliance_summary(model)
    if any(summary.values()):
        lines += ["", "## Compliance mapping", "", f"_{COMPLIANCE_NOTE}_", ""]
        for fw, controls in summary.items():
            if controls:
                top = ", ".join(f"{c['control']}{' ' + c['title'] if c['title'] else ''} ({c['findings']})"
                                for c in controls[:8])
                lines.append(f"- **{FRAMEWORK_TITLES[fw]}:** {_md(top)}")
    lines += ["", "## Findings", ""]
    findings = _sorted_findings(model)
    if not findings:
        lines.append("No findings were reported by the analyzers that ran. See coverage above.")
    for i, f in enumerate(findings, start=1):
        lines += [f"### {i}. [{f['severity'].upper()}] {_md(f['title'])}", "",
                  f"- **Location:** `{_location(f)}`", f"- **Category:** {f['category']} · **Type:** "
                  f"{KIND_LABELS.get(f['kind'], f['kind'])} · **Confidence:** {f['confidence']}",
                  f"- **Rule:** `{f['rule_id']}` · **Sources:** {', '.join(f.get('sources', []))}"]
        if f.get("lifecycle"):
            lines.append(f"- **Status vs. previous audit:** {f['lifecycle']}")
        if _compliance_line(f):
            lines.append(f"- **Maps to:** {_md(_compliance_line(f))}")
        if _triage_text(f):
            lines.append(f"- **Triage:** {_md(_triage_text(f))}")
        lines += ["", _md(f.get("description", "")), ""]
        if f.get("evidence"):
            lines += ["```", f["evidence"].replace("```", "ʼʼʼ"), "```", ""]
        lines += [f"**Remediation:** {_md(f.get('remediation', ''))}", ""]
        ai = f.get("ai_explanation") or {}
        if ai.get("explanation"):
            fp = ai.get("false_positive_likelihood")
            lines += [f"**AI explanation** ({_md(ai.get('model', 'AI'))}"
                      f"{f'; false-positive likelihood: {fp}' if fp else ''}): {_md(ai['explanation'])}", ""]
            lines += [f"{n}. {_md(s)}" for n, s in enumerate(ai.get("remediation_steps") or [], start=1)]
            if ai.get("suggested_patch"):
                lines += ["", "Suggested patch (AI-generated, review before use):", "",
                          "```", ai["suggested_patch"].replace("```", "ʼʼʼ"), "```"]
            lines.append("")
        if f.get("references"):
            lines += ["References: " + ", ".join(_md(r) for r in f["references"][:5]), ""]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------------------------ html
_CSS = """
body{font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2328;max-width:1100px;margin:2rem auto;
padding:0 1rem}h1{margin-bottom:.25rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid
#d0d7de;padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:#f6f8fa}.sev{display:inline-block;
padding:0 .4rem;border-radius:3px;color:#fff;font-size:12px;font-weight:600}.critical{background:#8b0000}.high{
background:#d9480f}.medium{background:#e8a100;color:#111}.low{background:#1c7ed6}.info{background:#6c757d}pre{
background:#f6f8fa;border:1px solid #d0d7de;padding:.6rem;overflow:auto;white-space:pre-wrap}.note{background:#fff8c5;
border:1px solid #d4a72c;padding:.6rem}.finding{border:1px solid #d0d7de;border-radius:6px;padding:.75rem;margin:
.75rem 0}.muted{color:#656d76}code{font-size:12px}
"""


def render_html(model: dict) -> str:
    e = html.escape
    meta, scores = _meta(model), model.get("scores", {})
    parts = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
             "content='width=device-width,initial-scale=1'>", f"<title>{e(meta['title'])}</title>",
             f"<style>{_CSS}</style></head><body>", f"<h1>{e(meta['title'])}</h1><p class='muted'>"]
    parts.append(" · ".join(e(str(meta[k])) for k in ("repository", "ref", "commit", "generated_at") if meta.get(k)))
    overall = scores.get("overall")
    parts.append(f"</p><h2>Overall {e(str(overall if overall is not None else 'n/a'))} / 100 — "
                 f"{e(str(scores.get('risk', 'n/a')))} risk</h2><p class='note'>{e(DISCLAIMER)}</p>")
    parts.append("<table><tr><th>Category</th><th>Score</th><th>Risk</th><th>Findings</th><th>Note</th></tr>")
    for name, cs in (scores.get("categories") or {}).items():
        label = CATEGORY_LABELS.get(Category(name), name)
        score_txt = "—" if cs.get("score") is None else f"{cs['score']:.0f}"
        parts.append(f"<tr><td>{e(label)}</td><td>{score_txt}</td><td>{e(str(cs.get('risk')))}</td>"
                     f"<td>{cs.get('findings', 0)}</td><td>{e(cs.get('ceiling_reason', ''))}</td></tr>")
    parts.append("</table>")
    if _offline_text(model):
        parts.append(f"<p class='note'>{e(_offline_text(model))}</p>")
    tools = model.get("tools") or []
    if tools:
        parts.append("<h2>Analyzer coverage</h2><table><tr><th>Analyzer</th><th>Status</th><th>Findings</th>"
                     "<th>Note</th></tr>")
        parts += [f"<tr><td>{e(t['title'])}</td><td>{e(t['status'])}</td><td>{t['findings']}</td>"
                  f"<td>{e(t.get('reason', ''))}</td></tr>" for t in tools]
        parts.append("</table>")
    if _ai_status(model):
        parts.append(f"<h2>AI-assisted analysis</h2><p class='muted'>{e(_ai_status(model))}. Generated by an AI "
                     "model; verify before acting. AI never changes scores.</p>")
        if model["ai_summary"].get("summary"):
            parts.append(f"<p>{e(model['ai_summary']['summary'])}</p>")
    from .compliance import FRAMEWORK_TITLES

    summary = _compliance_summary(model)
    if any(summary.values()):
        parts.append(f"<h2>Compliance mapping</h2><p class='muted'>{e(COMPLIANCE_NOTE)}</p><table><tr>"
                     "<th>Framework</th><th>Control</th><th>Findings</th></tr>")
        for fw, controls in summary.items():
            for c in controls[:10]:
                parts.append(f"<tr><td>{e(FRAMEWORK_TITLES[fw])}</td><td>{e(c['control'])} {e(c['title'])}</td>"
                             f"<td>{c['findings']}</td></tr>")
        parts.append("</table>")
    findings = _sorted_findings(model)
    parts.append(f"<h2>Findings ({len(findings)})</h2>")
    for f in findings:
        sev = f["severity"] if f["severity"] in SEVERITY_ORDER else "info"
        parts.append(
            f"<div class='finding'><span class='sev {sev}'>{e(sev.upper())}</span> <strong>{e(f['title'])}</strong>"
            f"<div class='muted'><code>{e(_location(f))}</code> · {e(f['category'])} · "
            f"{e(KIND_LABELS.get(f['kind'], f['kind']))} · confidence {e(f['confidence'])} · "
            f"<code>{e(f['rule_id'])}</code></div><p>{e(f.get('description', ''))}</p>"
        )
        if _compliance_line(f):
            parts.append(f"<p class='muted'>Maps to: {e(_compliance_line(f))}</p>")
        if _triage_text(f):
            parts.append(f"<p class='note'><strong>Triage:</strong> {e(_triage_text(f))}</p>")
        if f.get("evidence"):
            parts.append(f"<pre>{e(f['evidence'])}</pre>")
        parts.append(f"<p><strong>Remediation:</strong> {e(f.get('remediation', ''))}</p>")
        ai = f.get("ai_explanation") or {}
        if ai.get("explanation"):
            fp = ai.get("false_positive_likelihood")
            parts.append(f"<div class='note'><strong>AI explanation</strong> <span class='muted'>"
                         f"({e(str(ai.get('model', 'AI')))}{e(f'; false-positive likelihood: {fp}') if fp else ''})"
                         f"</span><p>{e(ai['explanation'])}</p>")
            if ai.get("remediation_steps"):
                parts.append("<ol>" + "".join(f"<li>{e(s)}</li>" for s in ai["remediation_steps"]) + "</ol>")
            if ai.get("suggested_patch"):
                parts.append("<p class='muted'>Suggested patch (AI-generated, review before use):</p>"
                             f"<pre>{e(ai['suggested_patch'])}</pre>")
            parts.append("</div>")
        parts.append("</div>")
    parts.append(f"<p class='muted'>eVal engine {e(str(meta['engine_version']))}</p></body></html>")
    return "".join(parts)


# ----------------------------------------------------------------------------------------------- sarif
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def render_sarif(model: dict) -> str:
    meta = _meta(model)
    rules: dict[str, dict] = {}
    results = []
    for f in _sorted_findings(model):
        if f["kind"] == "ai_observation":
            continue
        c = _compliance(f)
        tags = [f["category"], "eval"] + (["security"] if f["category"] in ("security", "api") or c["cwe"] else [])
        tags += [f"external/cwe/{x.lower()}" for x in c["cwe"]]
        tags += [f"owasp-top10-2021/{x.split(':')[0].lower()}" for x in c["owasp"]]
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"],
            "shortDescription": {"text": f["title"][:200]},
            "helpUri": (f.get("references") or [None])[0],
            "properties": {"category": f["category"], "tags": tags,
                           "security-severity": _SECURITY_SEVERITY[f["severity"]]},
        })
        result = {
            "ruleId": f["rule_id"],
            "level": _SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}. {f.get('description', '')} Remediation: {f.get('remediation', '')}"},
            "partialFingerprints": {"evalFingerprint/v1": f.get("fingerprint", "")},
            "properties": {"severity": f["severity"], "confidence": f["confidence"], "kind": f["kind"],
                           "lifecycle": f.get("lifecycle", "")},
        }
        if f.get("file_path"):
            region = {"startLine": f["line_start"]} if f.get("line_start") else {}
            if f.get("line_end") and f.get("line_start"):
                region["endLine"] = f["line_end"]
            loc = {"artifactLocation": {"uri": f["file_path"], "uriBaseId": "%SRCROOT%"}}
            if region:
                loc["region"] = region
            result["locations"] = [{"physicalLocation": loc}]
        triage = f.get("triage") or {}
        if triage.get("status") in ("accepted_risk", "false_positive"):
            # Reported as suppressed (not absent), so code-scanning tools record a dismissal rather than a fix.
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": _triage_text(f)[:1000]}]
        results.append(result)
    for r in rules.values():
        if not r["helpUri"]:
            del r["helpUri"]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "eVal", "version": str(meta["engine_version"]),
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"overallScore": model.get("scores", {}).get("overall"),
                           "risk": model.get("scores", {}).get("risk"), "disclaimer": DISCLAIMER},
        }],
    }
    return json.dumps(sarif, indent=2)


RENDERERS = {"json": render_json, "md": render_markdown, "html": render_html, "sarif": render_sarif}
CONTENT_TYPES = {"json": "application/json", "md": "text/markdown; charset=utf-8", "html": "text/html; charset=utf-8",
                 "sarif": "application/sarif+json"}


def render(model: dict, fmt: str) -> str:
    if fmt not in RENDERERS:
        raise ValueError(f"unknown report format {fmt!r}; choose from {', '.join(FORMATS)}")
    return RENDERERS[fmt](model)
