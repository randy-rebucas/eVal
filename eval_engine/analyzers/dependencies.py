"""Dependency hygiene (pinning, lockfiles, risky specifiers) and known-vulnerability lookup via OSV.dev."""

from __future__ import annotations

import json
import os
import re
import tomllib

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError
from .registry import register
from .trivy import vuln_title

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")
JS_LOCKS = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock")
PY_LOCKS = ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock")
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
MAX_OSV_PACKAGES = 1000
MAX_OSV_DETAILS = 200


def _dir(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


@register
class DependencyHygieneAnalyzer(Analyzer):
    name = "dependencies"
    title = "Dependency hygiene"
    categories = (Category.DEPENDENCIES,)

    def applicable(self, ctx: AnalyzerContext):
        return None if ctx.languages.manifests else "no dependency manifests found"

    def run(self, ctx: AnalyzerContext):
        findings = []
        for rel in ctx.languages.manifests:
            name = rel.rsplit("/", 1)[-1]
            if name.startswith("requirements") and name.endswith(".txt"):
                findings.extend(self._requirements(ctx, rel))
            elif name == "package.json":
                findings.extend(self._package_json(ctx, rel))
            elif name == "pyproject.toml":
                findings.extend(self._pyproject(ctx, rel))
        return findings

    def _f(self, ctx, rule, title, sev, conf, kind, desc, fix, rel, line=None, evidence=None):
        return self.finding(ctx, rule=rule, title=title, category=Category.DEPENDENCIES, severity=sev,
                            confidence=conf, kind=kind, description=desc, remediation=fix, file_path=rel, line=line,
                            evidence=evidence)

    def _requirements(self, ctx, rel):
        out, unpinned = [], []
        for i, line in enumerate(ctx.lines(rel), start=1):
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("-"):
                if stripped.startswith(("-e git+", "-e http")):
                    out.append(self._f(ctx, "dependencies.vcs-dependency", "Dependency installed from a VCS URL",
                                       Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                       "VCS/URL requirements bypass the package index and are hard to audit.",
                                       "Publish to a (private) index and pin a version.", rel, i))
                continue
            if re.search(r"(git\+|https?://)", stripped):
                out.append(self._f(ctx, "dependencies.vcs-dependency", "Dependency installed from a VCS URL",
                                   Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                   "VCS/URL requirements bypass the package index and are hard to audit.",
                                   "Pin to a released version from a trusted index.", rel, i))
                continue
            m = REQ_LINE.match(stripped)
            if m and "==" not in m.group(3) and "===" not in m.group(3):
                unpinned.append((i, m.group(1)))
        has_lock = any(ctx.exists(f"{_dir(rel)}/{lock}".lstrip("/")) for lock in PY_LOCKS)
        if unpinned and not has_lock:
            names = ", ".join(n for _, n in unpinned[:15])
            out.append(self._f(ctx, "dependencies.unpinned-python", f"{len(unpinned)} unpinned Python "
                               "requirement(s)", Severity.MEDIUM if len(unpinned) > 3 else Severity.LOW,
                               Confidence.HIGH, FindingKind.CONFIRMED,
                               "Requirements without exact versions resolve differently over time, so builds are "
                               "not reproducible and can silently pull compromised or breaking releases. Also, "
                               "vulnerability scanners cannot check versions that are not pinned.",
                               "Pin exact versions (pip-tools `pip-compile`, uv, or Poetry lockfiles) and update "
                               "them deliberately.", rel, unpinned[0][0], evidence=f"unpinned: {names}"))
        return out

    def _pyproject(self, ctx, rel):
        try:
            data = tomllib.loads(ctx.read(rel) or "")
        except tomllib.TOMLDecodeError:
            return [self._f(ctx, "dependencies.invalid-manifest", "pyproject.toml is not valid TOML", Severity.LOW,
                            Confidence.HIGH, FindingKind.CONFIRMED, "The manifest could not be parsed.",
                            "Fix the TOML syntax.", rel)]
        deps = data.get("project", {}).get("dependencies") or []
        has_lock = any(ctx.exists(f"{_dir(rel)}/{lock}".lstrip("/")) for lock in PY_LOCKS)
        bare = [d for d in deps if isinstance(d, str) and not re.search(r"[<>=~!]", d.split(";")[0])]
        if bare and not has_lock and not any(ctx.exists(f"{_dir(rel)}/{n}".lstrip("/")) for n in ("requirements.txt",)):
            return [self._f(ctx, "dependencies.unconstrained-python", f"{len(bare)} dependency(ies) without version "
                            "constraints and no lockfile", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                            "Applications should lock their full dependency tree for reproducible deploys.",
                            "Add version bounds and commit a lockfile (uv.lock / poetry.lock).", rel,
                            evidence=", ".join(bare[:15]))]
        return []

    def _package_json(self, ctx, rel):
        out = []
        try:
            data = json.loads(ctx.read(rel) or "{}")
        except json.JSONDecodeError:
            return [self._f(ctx, "dependencies.invalid-manifest", "package.json is not valid JSON", Severity.LOW,
                            Confidence.HIGH, FindingKind.CONFIRMED, "The manifest could not be parsed.",
                            "Fix the JSON syntax.", rel)]
        if not isinstance(data, dict):
            return out
        deps = {}
        for key in ("dependencies", "devDependencies"):
            if isinstance(data.get(key), dict):
                deps.update(data[key])
        if deps and not any(ctx.exists(f"{_dir(rel)}/{lock}".lstrip("/")) for lock in JS_LOCKS) and \
                not data.get("workspaces") and not any(ctx.exists(lock) for lock in JS_LOCKS):
            out.append(self._f(ctx, "dependencies.no-js-lockfile", "No JavaScript lockfile committed",
                               Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                               "Without package-lock.json / yarn.lock / pnpm-lock.yaml every install may resolve "
                               "different transitive versions, including compromised ones.",
                               "Commit the lockfile and install with `npm ci` (or equivalent) in CI and Docker.", rel))
        risky = [(n, v) for n, v in deps.items() if isinstance(v, str) and (
            v.strip() in ("*", "latest", "") or v.startswith(("git", "http", "github:", "file:")))]
        if risky:
            text = ctx.lines(rel)
            line = next((i for i, ln in enumerate(text, 1) if f'"{risky[0][0]}"' in ln), None)
            out.append(self._f(ctx, "dependencies.risky-js-specifier", f"{len(risky)} dependency(ies) with wildcard "
                               "or non-registry version", Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                               "'*', 'latest', git and URL specifiers accept arbitrary future code.",
                               "Use semver ranges from the registry and rely on the lockfile.", rel, line,
                               evidence=", ".join(f"{n}@{v}" for n, v in risky[:10])))
        return out


@register
class OSVAnalyzer(Analyzer):
    """Queries OSV.dev for exact pinned versions. Sends only ecosystem/package/version — never source code.
    Disable with EVAL_OSV_ENABLED=0 (e.g. air-gapped installs; use Trivy with a local DB instead)."""

    name = "osv"
    title = "Known vulnerabilities (OSV.dev)"
    categories = (Category.DEPENDENCIES,)
    network_use = "api.osv.dev: ecosystem, package name and version of pinned dependencies (no source code)"

    def applicable(self, ctx: AnalyzerContext):
        if os.environ.get("EVAL_OSV_ENABLED", "1").lower() in ("0", "false", "no", "off"):
            return "disabled by configuration (EVAL_OSV_ENABLED=0)"
        if not ctx.languages.manifests:
            return "no dependency manifests found"
        return None

    def network_required(self, ctx: AnalyzerContext):
        return "queries OSV.dev (use Trivy with a pre-seeded EVAL_TRIVY_CACHE_DIR for offline vulnerability checks)"

    def run(self, ctx: AnalyzerContext):
        packages = collect_pinned(ctx)
        if not packages:
            return []
        return self.query(ctx, packages)

    def query(self, ctx, packages, session=None):
        import requests

        http = session or requests
        packages = packages[:MAX_OSV_PACKAGES]
        payload = {"queries": [{"package": {"ecosystem": eco, "name": name}, "version": ver}
                               for eco, name, ver, _src in packages]}
        try:
            resp = http.post(OSV_URL, json=payload, timeout=(5, 30))
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except (requests.RequestException, ValueError) as exc:
            raise AnalyzerError("OSV.dev could not be reached (dependency vulnerabilities not checked)") from exc
        findings = []
        details: dict[str, dict] = {}
        for (eco, name, ver, src), res in zip(packages, results, strict=False):
            for v in (res or {}).get("vulns", [])[:50]:
                vid = v.get("id", "")
                if vid not in details:
                    details[vid] = self._details(http, vid) if len(details) < MAX_OSV_DETAILS else {}
                d = details[vid]
                display_id = next((a for a in d.get("aliases", []) if a.startswith("CVE-")), vid)
                findings.append(self.finding(
                    ctx, rule=f"vuln:{display_id}", title=vuln_title(name, ver, display_id),
                    category=Category.DEPENDENCIES, severity=_severity(d), confidence=Confidence.HIGH,
                    kind=FindingKind.CONFIRMED,
                    description=f"{d.get('summary') or vid} ({eco}). The pinned version is listed as affected; "
                    "reachability of the vulnerable code was not analyzed.",
                    remediation=_fix_text(d, name),
                    file_path=src, evidence=f"{name}=={ver} pinned in {src}",
                    references=[f"https://osv.dev/vulnerability/{vid}"]))
        return findings

    @staticmethod
    def _details(http, vid: str) -> dict:
        import requests

        try:
            r = http.get(OSV_VULN_URL + vid, timeout=(5, 15))
            return r.json() if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            return {}


def _severity(d: dict) -> Severity:
    label = str((d.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    return mapping.get(label, Severity.MEDIUM)


def _fix_text(d: dict, name: str) -> str:
    fixed = set()
    for aff in d.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fixed.add(ev["fixed"])
    if fixed:
        return f"Upgrade {name} to a fixed version ({', '.join(sorted(fixed)[:5])})."
    return "No fixed version is listed; evaluate exposure, apply mitigations, or replace the package."


def collect_pinned(ctx: AnalyzerContext) -> list[tuple[str, str, str, str]]:
    """(ecosystem, name, version, source_file) for exactly pinned dependencies."""
    out: list[tuple[str, str, str, str]] = []
    seen = set()

    def add(eco, name, ver, src):
        key = (eco, name.lower(), ver)
        if key not in seen and ver and re.fullmatch(r"[\w.+!-]+", ver):
            seen.add(key)
            out.append((eco, name, ver, src))

    for rel in ctx.languages.manifests:
        name = rel.rsplit("/", 1)[-1]
        if name.startswith("requirements") and name.endswith(".txt"):
            for line in ctx.lines(rel):
                m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([\w.+!-]+)", line)
                if m:
                    add("PyPI", m.group(1), m.group(2), rel)
        elif name == "poetry.lock" or name == "uv.lock":
            try:
                data = tomllib.loads(ctx.read(rel) or "")
            except tomllib.TOMLDecodeError:
                continue
            for pkg in data.get("package", []) or []:
                if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                    add("PyPI", pkg["name"], str(pkg["version"]), rel)
        elif name == "package-lock.json":
            try:
                data = json.loads(ctx.read(rel) or "{}")
            except json.JSONDecodeError:
                continue
            for path, meta in (data.get("packages") or {}).items():
                if path and isinstance(meta, dict) and meta.get("version") and "node_modules/" in path:
                    add("npm", path.rsplit("node_modules/", 1)[-1], meta["version"], rel)
    return out
