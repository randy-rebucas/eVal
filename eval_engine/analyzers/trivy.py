"""Trivy filesystem scan: known-vulnerable dependencies, IaC misconfigurations, and secrets.

Trivy downloads its vulnerability database on first use; set ``EVAL_TRIVY_CACHE_DIR`` to a persistent,
writable directory so the worker does not re-download it per audit (or pre-seed it for offline use).
"""

from __future__ import annotations

import json
import os

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError
from .registry import register

SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
       "UNKNOWN": Severity.LOW}


def vuln_title(pkg: str, version: str, vuln_id: str) -> str:
    """Shared with the OSV analyzer so the same vulnerability from both tools deduplicates."""
    return f"{pkg} {version}: {vuln_id}"


@register
class TrivyAnalyzer(Analyzer):
    name = "trivy"
    title = "Trivy (dependencies, IaC, secrets)"
    categories = (Category.DEPENDENCIES, Category.DEVOPS)
    tool = "trivy"
    address_space_limit = None  # Trivy mmaps its vulnerability DB; RLIMIT_AS makes that fail

    def run(self, ctx: AnalyzerContext):
        args = ["fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", "--exit-code", "0",
                "--skip-dirs", "node_modules", "--skip-dirs", ".venv", "--timeout", f"{max(ctx.timeout - 10, 30)}s"]
        cache = os.environ.get("EVAL_TRIVY_CACHE_DIR")
        if cache:
            args += ["--cache-dir", cache]
        result = self.run_tool(ctx, [*args, "."], ok_codes=(0,))
        return self.parse(ctx, result.stdout)

    def parse(self, ctx: AnalyzerContext, stdout: str):
        try:
            data = json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AnalyzerError("could not parse trivy output") from exc
        findings = []
        for res in data.get("Results") or []:
            target = self.relpath(ctx, res.get("Target", ""))
            for v in res.get("Vulnerabilities") or []:
                vid = v.get("VulnerabilityID", "UNKNOWN")
                fixed = v.get("FixedVersion")
                findings.append(
                    self.finding(
                        ctx,
                        rule=f"vuln:{vid}",
                        title=vuln_title(v.get("PkgName", "?"), v.get("InstalledVersion", "?"), vid),
                        category=Category.DEPENDENCIES,
                        severity=SEV.get(v.get("Severity", "UNKNOWN"), Severity.LOW),
                        confidence=Confidence.HIGH,
                        kind=FindingKind.CONFIRMED,
                        description=(f"{v.get('Title') or vid}. The declared version is affected; whether the "
                                     "vulnerable code path is reachable was not analyzed."),
                        remediation=(f"Upgrade {v.get('PkgName')} to {fixed} or later." if fixed
                                     else "No fixed version published; assess exposure or replace the package."),
                        file_path=target,
                        evidence=f"{v.get('PkgName')}=={v.get('InstalledVersion')} declared in {target}",
                        references=[v["PrimaryURL"]] if v.get("PrimaryURL") else [],
                    )
                )
            for m in res.get("Misconfigurations") or []:
                if m.get("Status") == "PASS":
                    continue
                cause = m.get("CauseMetadata") or {}
                findings.append(
                    self.finding(
                        ctx,
                        rule=f"trivy:{m.get('ID', 'misconfig')}",
                        title=f"{m.get('ID')}: {m.get('Title', '')}"[:300],
                        category=Category.DEVOPS,
                        severity=SEV.get(m.get("Severity", "UNKNOWN"), Severity.LOW),
                        confidence=Confidence.HIGH,
                        kind=FindingKind.CONFIRMED,
                        description=m.get("Message") or m.get("Description", ""),
                        remediation=m.get("Resolution") or "See the reference.",
                        file_path=target,
                        line=cause.get("StartLine") or None,
                        line_end=cause.get("EndLine") or None,
                        references=[m["PrimaryURL"]] if m.get("PrimaryURL") else [],
                    )
                )
            for s in res.get("Secrets") or []:
                findings.append(
                    self.finding(
                        ctx,
                        rule=f"trivy:secret-{s.get('RuleID', 'generic')}",
                        title=f"Secret detected: {s.get('Title', s.get('RuleID', ''))}"[:300],
                        category=Category.SECURITY,
                        severity=SEV.get(s.get("Severity", "HIGH"), Severity.HIGH),
                        confidence=Confidence.HIGH,
                        kind=FindingKind.CONFIRMED,
                        description="A credential-like value is committed to the repository.",
                        remediation="Revoke and rotate the secret, remove it from history, load it at runtime.",
                        file_path=target,
                        line=s.get("StartLine") or None,
                        evidence=str(s.get("Match", ""))[:200],  # Trivy masks the secret value in Match
                    )
                )
        return findings
