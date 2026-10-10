"""Map findings to compliance frameworks: CWE, OWASP Top 10 (2021), OWASP ASVS 4.0, SOC 2 (TSC 2017) and
ISO/IEC 27001:2022 Annex A.

Mappings come from, in order: an explicit table for eVal's own rules and common tool rules, CWE ids that tools
report (Bandit, Semgrep: "CWE-89" in the description or a cwe.mitre.org reference), and a per-category fallback.
They are *indicative*: a finding is evidence relevant to a control, not a statement that the control fails or
passes. Reports say so.
"""

from __future__ import annotations

import re

FRAMEWORKS = ("cwe", "owasp", "asvs", "soc2", "iso27001")
FRAMEWORK_TITLES = {
    "cwe": "CWE", "owasp": "OWASP Top 10 (2021)", "asvs": "OWASP ASVS 4.0", "soc2": "SOC 2 (TSC 2017)",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
}
CONTROL_TITLES = {
    "A01:2021": "Broken Access Control", "A02:2021": "Cryptographic Failures", "A03:2021": "Injection",
    "A04:2021": "Insecure Design", "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components", "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures", "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
    "CC6.1": "Logical access security", "CC6.6": "Boundary protection", "CC6.8": "Malicious software prevention",
    "CC7.1": "Vulnerability detection and monitoring", "CC7.2": "Security event monitoring",
    "CC8.1": "Change management", "A1.2": "Availability: capacity and recovery",
    "A.5.17": "Authentication information", "A.5.21": "ICT supply chain security",
    "A.8.6": "Capacity management", "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management", "A.8.15": "Logging", "A.8.16": "Monitoring activities",
    "A.8.20": "Network security", "A.8.24": "Use of cryptography", "A.8.25": "Secure development life cycle",
    "A.8.26": "Application security requirements", "A.8.27": "Secure system architecture",
    "A.8.28": "Secure coding", "A.8.29": "Security testing in development and acceptance",
    "A.8.32": "Change management",
}

# CWE -> OWASP Top 10 2021 category for the CWEs eVal's analyzers commonly report.
CWE_TO_OWASP = {
    22: "A01:2021", 23: "A01:2021", 200: "A01:2021", 284: "A01:2021", 285: "A01:2021", 352: "A01:2021",
    639: "A01:2021", 862: "A01:2021", 863: "A01:2021", 915: "A08:2021",
    259: "A07:2021", 287: "A07:2021", 295: "A07:2021", 306: "A07:2021", 307: "A07:2021", 798: "A07:2021",
    321: "A02:2021", 326: "A02:2021", 327: "A02:2021", 328: "A02:2021", 330: "A02:2021", 338: "A02:2021",
    319: "A02:2021", 20: "A03:2021", 74: "A03:2021", 77: "A03:2021", 78: "A03:2021", 79: "A03:2021",
    89: "A03:2021", 94: "A03:2021", 95: "A03:2021", 917: "A03:2021", 1336: "A03:2021",
    16: "A05:2021", 611: "A05:2021", 614: "A05:2021", 942: "A05:2021", 1004: "A05:2021", 489: "A05:2021",
    605: "A05:2021", 250: "A05:2021", 1104: "A06:2021", 937: "A06:2021", 1035: "A06:2021",
    502: "A08:2021", 494: "A08:2021", 829: "A08:2021", 1357: "A08:2021", 345: "A08:2021",
    778: "A09:2021", 117: "A09:2021", 532: "A09:2021", 755: "A04:2021", 434: "A04:2021",
    918: "A10:2021", 400: "A04:2021", 770: "A04:2021", 703: "A04:2021",
    209: "A04:2021", 377: "A01:2021", 732: "A01:2021",
}

_M = dict  # readability in the table below


# Rule id patterns (exact, or prefix ending in "*") -> mapping. First match wins.
RULES: list[tuple[str, dict]] = [
    ("eval:secrets.*", _M(cwe=[798], asvs=["V2.10.4", "V6.4.1"], soc2=["CC6.1"], iso27001=["A.5.17", "A.8.24"])),
    ("trivy:secret-*", _M(cwe=[798], asvs=["V2.10.4", "V6.4.1"], soc2=["CC6.1"], iso27001=["A.5.17", "A.8.24"])),
    ("eval:database.sql-string-formatting", _M(cwe=[89], asvs=["V5.3.4"], soc2=["CC6.1"], iso27001=["A.8.28"])),
    ("eval:architecture.sql-in-handlers", _M(cwe=[1061], soc2=["CC8.1"], iso27001=["A.8.27"])),
    ("eval:api.no-authentication", _M(cwe=[306], asvs=["V4.1.1"], soc2=["CC6.1"], iso27001=["A.8.26"])),
    ("eval:api.route-without-auth", _M(cwe=[862], asvs=["V4.1.1", "V4.1.3"], soc2=["CC6.1"], iso27001=["A.8.26"])),
    ("eval:api.mass-assignment", _M(cwe=[915], asvs=["V5.1.2"], soc2=["CC6.1"], iso27001=["A.8.28"])),
    ("eval:api.idor-unscoped-lookup", _M(cwe=[639], asvs=["V4.2.1"], soc2=["CC6.1"], iso27001=["A.8.26"])),
    ("eval:api.error-details-exposed", _M(cwe=[209], asvs=["V7.4.1"], soc2=["CC6.1"], iso27001=["A.8.28"])),
    ("eval:api.no-error-handler", _M(cwe=[755], asvs=["V7.4.1"], soc2=["CC7.2"], iso27001=["A.8.28"])),
    ("eval:api.jwt-verification-disabled", _M(cwe=[347, 345], owasp=["A02:2021"], asvs=["V3.5.3"], soc2=["CC6.1"],
                                              iso27001=["A.8.24"])),
    ("eval:api.tls-verify-disabled", _M(cwe=[295], asvs=["V9.2.1"], soc2=["CC6.1", "CC6.6"], iso27001=["A.8.20"])),
    ("eval:api.cors-wildcard", _M(cwe=[942], asvs=["V14.5.3"], soc2=["CC6.6"], iso27001=["A.8.9"])),
    ("eval:api.flask-no-csrf", _M(cwe=[352], asvs=["V4.2.2"], soc2=["CC6.1"], iso27001=["A.8.26"])),
    ("eval:api.no-rate-limiting", _M(cwe=[307, 770], asvs=["V2.2.1", "V11.1.4"], soc2=["CC6.1", "A1.2"],
                                     iso27001=["A.8.6"])),
    ("eval:api.hardcoded-session-secret", _M(cwe=[798, 321], owasp=["A02:2021"], asvs=["V6.4.1"], soc2=["CC6.1"],
                                             iso27001=["A.8.24"])),
    ("eval:api.insecure-cookie", _M(cwe=[614, 1004], asvs=["V3.4.1", "V3.4.2"], soc2=["CC6.1"],
                                    iso27001=["A.8.26"])),
    ("eval:api.sensitive-data-logged", _M(cwe=[532], asvs=["V7.1.1"], soc2=["CC6.1", "CC7.2"],
                                          iso27001=["A.8.15", "A.5.17"])),
    ("eval:api.upload-unvalidated", _M(cwe=[434], asvs=["V12.1.1", "V12.2.1"], soc2=["CC6.1"], iso27001=["A.8.28"])),
    ("eval:api.upload-client-filename", _M(cwe=[22, 434], asvs=["V12.3.1"], soc2=["CC6.1"], iso27001=["A.8.28"])),
    ("eval:api.*debug*", _M(cwe=[489], asvs=["V14.3.2"], soc2=["CC8.1"], iso27001=["A.8.9"])),
    ("eval:api.django-allowed-hosts-wildcard", _M(cwe=[16], asvs=["V14.1.1"], soc2=["CC6.6"], iso27001=["A.8.9"])),
    ("eval:api.express-no-helmet", _M(cwe=[1021, 693], owasp=["A05:2021"], asvs=["V14.4.1"], soc2=["CC6.6"],
                                      iso27001=["A.8.9"])),
    ("vuln:*", _M(cwe=[1104], asvs=["V14.2.1"], soc2=["CC7.1"], iso27001=["A.8.8"])),
    ("eval:ai-code.lookalike-package", _M(cwe=[1357], asvs=["V14.2.4"], soc2=["CC7.1", "CC8.1"],
                                          iso27001=["A.5.21"])),
    ("eval:ai-code.package-*", _M(cwe=[1357], asvs=["V14.2.4"], soc2=["CC7.1", "CC8.1"], iso27001=["A.5.21"])),
    ("eval:ai-code.undeclared-import", _M(cwe=[1357], asvs=["V14.2.4"], soc2=["CC8.1"], iso27001=["A.5.21"])),
    ("eval:ai-code.placeholder-value", _M(cwe=[1188], owasp=["A05:2021"], soc2=["CC8.1"], iso27001=["A.8.9"])),
    ("eval:ai-code.*", _M(soc2=["CC8.1"], iso27001=["A.8.25", "A.8.28"])),
    ("eval:dependencies.*", _M(cwe=[1104, 829], owasp=["A06:2021", "A08:2021"], asvs=["V14.2.1"], soc2=["CC8.1"],
                               iso27001=["A.5.21", "A.8.8"])),
    ("eval:devops.gha-script-injection", _M(cwe=[78], asvs=["V14.1.5"], soc2=["CC8.1"], iso27001=["A.8.32"])),
    ("eval:devops.gha-*", _M(cwe=[829], owasp=["A08:2021"], asvs=["V14.1.5"], soc2=["CC8.1"],
                             iso27001=["A.8.32", "A.5.21"])),
    ("eval:devops.dockerfile-runs-as-root", _M(cwe=[250], asvs=["V14.1.1"], soc2=["CC6.1"], iso27001=["A.8.9"])),
    ("eval:devops.dockerfile-secret-in-env", _M(cwe=[798], asvs=["V6.4.1"], soc2=["CC6.1"], iso27001=["A.5.17"])),
    ("eval:devops.dockerfile-curl-pipe-shell", _M(cwe=[494], asvs=["V14.2.4"], soc2=["CC8.1"], iso27001=["A.5.21"])),
    ("eval:devops.no-logging", _M(cwe=[778], asvs=["V7.1.1"], soc2=["CC7.2"], iso27001=["A.8.15", "A.8.16"])),
    ("eval:devops.no-health-endpoint", _M(soc2=["CC7.2", "A1.2"], iso27001=["A.8.16"])),
    ("eval:devops.no-metrics", _M(cwe=[778], asvs=["V7.1.1"], soc2=["CC7.2", "A1.2"], iso27001=["A.8.16",
                                                                                               "A.8.6"])),
    ("eval:devops.no-tracing", _M(cwe=[778], asvs=["V7.1.1"], soc2=["CC7.2"], iso27001=["A.8.15", "A.8.16"])),
    ("eval:devops.no-request-id", _M(asvs=["V7.1.1"], soc2=["CC7.2"], iso27001=["A.8.15"])),
    ("eval:devops.print-logging", _M(cwe=[778], asvs=["V7.1.1"], soc2=["CC7.2"], iso27001=["A.8.15"])),
    ("eval:devops.compose-*", _M(cwe=[250, 16], owasp=["A05:2021"], soc2=["CC6.6"], iso27001=["A.8.9",
                                                                                           "A.8.20"])),
    ("eval:devops.*", _M(soc2=["CC8.1"], iso27001=["A.8.9", "A.8.32"])),
    ("eval:testing.*", _M(asvs=["V1.1.1"], soc2=["CC8.1"], iso27001=["A.8.29"])),
    ("eval:database.money-as-float", _M(cwe=[1339], soc2=["CC8.1"], iso27001=["A.8.28"])),
    ("eval:config.hardcoded-endpoint", _M(cwe=[547], asvs=["V14.1.3"], soc2=["CC8.1"], iso27001=["A.8.9"])),
    ("eval:config.*", _M(asvs=["V14.1.3"], soc2=["CC8.1"], iso27001=["A.8.9", "A.8.25"])),
    ("eval:maintainability.swallowed-exception", _M(cwe=[390, 703], soc2=["CC7.2"], iso27001=["A.8.28"])),
    ("eval:performance.http-without-timeout", _M(cwe=[400], soc2=["A1.2"], iso27001=["A.8.6"])),
    ("eval:performance.*", _M(cwe=[400], soc2=["A1.2"], iso27001=["A.8.6"])),
    ("bandit:B105", _M(cwe=[259])), ("bandit:B106", _M(cwe=[259])), ("bandit:B107", _M(cwe=[259])),
    ("bandit:B602", _M(cwe=[78])), ("bandit:B605", _M(cwe=[78])), ("bandit:B608", _M(cwe=[89])),
    ("bandit:B301", _M(cwe=[502])), ("bandit:B501", _M(cwe=[295])), ("bandit:B324", _M(cwe=[327])),
    ("bandit:B201", _M(cwe=[94])), ("bandit:B104", _M(cwe=[605])),
]

CATEGORY_FALLBACK = {
    "security": _M(soc2=["CC6.1", "CC7.1"], iso27001=["A.8.28"]),
    "api": _M(soc2=["CC6.1", "CC6.6"], iso27001=["A.8.26"]),
    "database": _M(soc2=["CC6.1"], iso27001=["A.8.28"]),
    "dependencies": _M(owasp=["A06:2021"], soc2=["CC7.1"], iso27001=["A.8.8", "A.5.21"]),
    "devops": _M(soc2=["CC8.1"], iso27001=["A.8.9", "A.8.32"]),
    "testing": _M(soc2=["CC8.1"], iso27001=["A.8.29"]),
    "architecture": _M(soc2=["CC8.1"], iso27001=["A.8.27"]),
    "maintainability": _M(soc2=["CC8.1"], iso27001=["A.8.25"]),
    "performance": _M(soc2=["A1.2"], iso27001=["A.8.6"]),
}
CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b|cwe\.mitre\.org/data/definitions/(\d{1,5})", re.I)


def _match(pattern: str, rule_id: str) -> bool:
    if "*" not in pattern:
        return pattern == rule_id
    head, _, tail = pattern.partition("*")
    if tail.endswith("*"):  # "eval:api.*debug*"
        return rule_id.startswith(head) and tail[:-1] in rule_id[len(head):]
    return rule_id.startswith(head) and rule_id.endswith(tail)


def map_finding(rule_id: str, category: str, description: str = "", references: list[str] | None = None) -> dict:
    """``{"cwe": ["CWE-89"], "owasp": ["A03:2021"], "asvs": [...], "soc2": [...], "iso27001": [...]}``."""
    out: dict[str, list] = {k: [] for k in FRAMEWORKS}
    rule = next((m for p, m in RULES if _match(p, rule_id)), None)
    cwes = list((rule or {}).get("cwe", []))
    for m in CWE_RE.finditer(" ".join([description or "", *(references or [])])):
        n = int(m.group(1) or m.group(2))
        if n not in cwes:
            cwes.append(n)
    out["cwe"] = [f"CWE-{n}" for n in cwes]
    owasp = list((rule or {}).get("owasp", []))
    for n in cwes:
        if n in CWE_TO_OWASP and CWE_TO_OWASP[n] not in owasp:
            owasp.append(CWE_TO_OWASP[n])
    fallback = CATEGORY_FALLBACK.get(category, {})
    out["owasp"] = owasp or list(fallback.get("owasp", []))
    for k in ("asvs", "soc2", "iso27001"):
        out[k] = list((rule or {}).get(k) or fallback.get(k, []))
    return out


def summarize(findings: list[dict]) -> dict:
    """Per framework and control: how many open findings relate to it, by severity. ``findings`` are report dicts
    (``rule_id``, ``category``, ``severity``, ``description``, ``references``, optional ``compliance``)."""
    summary: dict[str, dict[str, dict]] = {k: {} for k in FRAMEWORKS}
    for f in findings:
        mapping = f.get("compliance") or map_finding(f["rule_id"], f.get("category", ""), f.get("description", ""),
                                                     f.get("references"))
        for fw, controls in mapping.items():
            for control in controls:
                entry = summary[fw].setdefault(control, {"control": control, "title": CONTROL_TITLES.get(control, ""),
                                                         "findings": 0, "by_severity": {}})
                entry["findings"] += 1
                entry["by_severity"][f["severity"]] = entry["by_severity"].get(f["severity"], 0) + 1
    return {fw: sorted(v.values(), key=lambda e: (-e["findings"], e["control"])) for fw, v in summary.items()}
