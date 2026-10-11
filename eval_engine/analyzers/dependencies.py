"""Dependency analysis: manifests and lockfiles (requirements.txt, pyproject.toml, package.json, package-lock.json,
yarn.lock, pnpm-lock.yaml, Pipfile.lock, poetry.lock, uv.lock).

* Hygiene: pinning, lockfiles, risky specifiers.
* Duplicates: a package declared twice, or resolved to several versions in a lockfile.
* Conflicts: pins that disagree between manifests, lockfiles out of sync with their manifest, several lockfiles for
  one project.
* Unused: runtime dependencies nothing in the repository imports or mentions.
* Known vulnerabilities via OSV.dev (scanner evidence only). Outdated versions are checked by the registry analyzer,
  which already queries PyPI / npm.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections import defaultdict

from ..findings import Category, Confidence, FindingKind, Severity
from .base import Analyzer, AnalyzerContext, AnalyzerError, is_test_path
from .registry import register
from .trivy import vuln_title

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")
PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*\(?([^;)]*)\)?")
JS_LOCKS = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock")
PY_LOCKS = ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock")
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_BATCH = 1000  # /v1/querybatch accepts at most 1,000 queries per request
MAX_OSV_PACKAGES = 20000
MAX_OSV_DETAILS = 500
OSV_DETAIL_WORKERS = 8
MIN_SOURCE_FILES_FOR_UNUSED = 3
MAX_CORPUS_FILES = 4000
CORPUS_SUFFIXES = (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".json",
                   ".toml", ".cfg", ".ini", ".yml", ".yaml", ".sh", ".txt", ".md", ".html", ".conf", ".env", ".example")
CORPUS_NAMES = ("Dockerfile", "Procfile", "Makefile", "justfile", ".babelrc", ".eslintrc", ".prettierrc")
# Runtime packages loaded by name from configuration, URLs or other packages rather than imported.
IMPLICIT_PY = {"gunicorn", "uvicorn", "hypercorn", "daphne", "waitress", "gevent", "eventlet", "psycopg", "psycopg2",
               "psycopg2-binary", "psycopg-binary", "psycopg-pool", "mysqlclient", "pymysql", "asyncpg", "aiosqlite",
               "cx-oracle", "oracledb", "pyodbc", "hiredis", "redis", "python-dotenv", "email-validator", "certifi",
               "cryptography", "setuptools", "wheel", "pip", "uvloop", "httptools", "watchfiles", "brotli",
               "whitenoise", "python-multipart", "tzdata", "pytz", "orjson", "ujson", "bcrypt", "argon2-cffi",
               "greenlet", "celery", "kombu", "flower", "supervisor", "boto3-stubs", "jinja2", "markupsafe"}
IMPLICIT_JS = {"react-dom", "next", "nuxt", "vue-template-compiler", "typescript", "tslib", "core-js",
               "regenerator-runtime", "@babel/runtime", "sharp", "pg", "pg-hstore", "mysql", "mysql2", "sqlite3",
               "better-sqlite3", "tedious", "oracledb", "bufferutil", "utf-8-validate", "encoding", "dotenv",
               "reflect-metadata", "rxjs", "zone.js", "@angular/platform-browser-dynamic", "@angular/animations",
               "postcss", "autoprefixer", "tailwindcss", "prisma", "@prisma/client", "ts-node", "tsx", "nodemon",
               "pm2", "cross-env", "npm-run-all", "concurrently", "vite", "webpack", "esbuild", "react-scripts"}
# Distribution -> modules it provides, where the import name differs (beyond ai_code.IMPORT_TO_DIST).
EXTRA_DIST_MODULES = {"djangorestframework": {"rest_framework"}, "django-cors-headers": {"corsheaders"},
                      "opencv-python-headless": {"cv2"}, "scikit-image": {"skimage"}, "pyjwt": {"jwt"},
                      "protobuf": {"google.protobuf"}, "msgpack-python": {"msgpack"}, "pymongo": {"pymongo", "bson"},
                      "python-socketio": {"socketio"}, "pycryptodomex": {"Cryptodome"}, "ruamel.yaml": {"ruamel"}}


def _dir(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def version_tuple(version: str) -> tuple[int, ...] | None:
    """Release segment of a plain numeric version ("1.2.3", "v2.0"); None for anything else (pre-releases…)."""
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", version.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _pad(a: tuple[int, ...], b: tuple[int, ...]):
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def satisfies(version: str, spec: str) -> bool | None:
    """Whether ``version`` meets a PEP 440 specifier set (==, !=, >=, <=, >, <, ~=, ==X.*). None when either side
    uses syntax this subset does not evaluate, so callers only report certain conflicts."""
    v = version_tuple(version)
    if v is None:
        return None
    for clause in (c.strip() for c in spec.split(",")):
        if not clause:
            continue
        m = re.fullmatch(r"(===|==|!=|>=|<=|~=|>|<)\s*([0-9][\w.]*(?:\.\*)?)", clause)
        if not m:
            return None
        op, target = m.groups()
        if target.endswith(".*") and op in ("==", "!="):
            prefix = version_tuple(target[:-2])
            if prefix is None:
                return None
            match = v[:len(prefix)] == prefix
            if match != (op == "=="):
                return False
            continue
        t = version_tuple(target)
        if t is None:
            return None
        a, b = _pad(v, t)
        ok = {"==": a == b, "===": a == b, "!=": a != b, ">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b,
              "~=": a >= b and len(t) >= 2 and v[:len(t) - 1] == t[:-1]}[op]
        if not ok:
            return False
    return True


def requirement_entries(ctx: AnalyzerContext, rel: str) -> list[tuple[int, str, str]]:
    """(line, raw name, specifier) for each requirement line of a requirements file."""
    out = []
    for i, line in enumerate(ctx.lines(rel), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-") or re.search(r"(git\+|https?://)", stripped):
            continue
        if m := REQ_LINE.match(stripped):
            out.append((i, m.group(1), m.group(3).split(";", 1)[0].strip()))
    return out


def pyproject_entries(data: dict) -> list[tuple[str, str, str]]:
    """(group, raw name, specifier) for PEP 621, PEP 735 and Poetry dependency declarations."""
    out = []
    project = data.get("project", {}) or {}
    groups = {"dependencies": project.get("dependencies") or []}
    for name, deps in (project.get("optional-dependencies") or {}).items():
        groups[f"optional:{name}"] = deps
    for name, deps in (data.get("dependency-groups") or {}).items():
        groups[f"group:{name}"] = deps
    for group, deps in groups.items():
        for spec in deps if isinstance(deps, list) else []:
            if isinstance(spec, str) and (m := PEP508.match(spec)):
                out.append((group, m.group(1), m.group(2).strip()))
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    poetry_groups = {"poetry": poetry.get("dependencies") or {}, "poetry:dev": poetry.get("dev-dependencies") or {}}
    for name, group in (poetry.get("group") or {}).items():
        poetry_groups[f"poetry:{name}"] = (group or {}).get("dependencies") or {}
    for group, deps in poetry_groups.items():
        for name, spec in deps.items() if isinstance(deps, dict) else []:
            if name.lower() == "python":
                continue
            version = spec.get("version", "") if isinstance(spec, dict) else spec if isinstance(spec, str) else ""
            out.append((group, name, version.strip()))
    return out


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
        findings.extend(self._lockfiles(ctx))
        findings.extend(self._python_conflicts(ctx))
        findings.extend(self._unused(ctx))
        return findings

    def _duplicate(self, ctx, rel, name, lines, where):
        return self._f(ctx, "dependencies.duplicate-declaration", f"'{name}' is declared more than once in {where}",
                       Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                       f"'{name}' appears {len(lines)} times (lines {', '.join(map(str, lines))}). Which declaration "
                       "wins depends on the tool, so the installed version can differ from the one a reader expects.",
                       "Keep a single declaration of each package.", rel, lines[0] if lines[0] else None)

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
        seen: dict[str, list[int]] = defaultdict(list)
        for i, name, _ in requirement_entries(ctx, rel):
            seen[norm_py(name)].append(i)
        out += [self._duplicate(ctx, rel, name, lines, rel.rsplit("/", 1)[-1])
                for name, lines in seen.items() if len(lines) > 1]
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
        out = []
        entries = pyproject_entries(data)
        has_lock = any(ctx.exists(f"{_dir(rel)}/{lock}".lstrip("/")) for lock in PY_LOCKS)
        bare = [name for group, name, spec in entries if group in ("dependencies", "poetry")
                and (not re.search(r"[<>=~!^\d]", spec) or spec.strip() == "*")]
        if bare and not has_lock and not any(ctx.exists(f"{_dir(rel)}/{n}".lstrip("/")) for n in ("requirements.txt",)):
            out.append(self._f(ctx, "dependencies.unconstrained-python", f"{len(bare)} dependency(ies) without "
                               "version constraints and no lockfile", Severity.LOW, Confidence.HIGH,
                               FindingKind.CONFIRMED,
                               "Applications should lock their full dependency tree for reproducible deploys.",
                               "Add version bounds and commit a lockfile (uv.lock / poetry.lock).", rel,
                               evidence=", ".join(bare[:15])))
        by_group: dict[tuple[str, str], int] = defaultdict(int)
        for group, name, _ in entries:
            by_group[(group, norm_py(name))] += 1
        lines = ctx.lines(rel)
        for (group, name), count in sorted(by_group.items()):
            if count > 1:
                pattern = re.escape(name).replace("-", "[-_.]")
                hits = [i for i, ln in enumerate(lines, 1) if re.search(rf"""(?i)^\s*["']?{pattern}\b""", ln)] or [0]
                out.append(self._duplicate(ctx, rel, name, hits, f"pyproject.toml ({group})"))
        return out

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
        runtime, dev = data.get("dependencies"), data.get("devDependencies")
        if isinstance(runtime, dict) and isinstance(dev, dict):
            text = ctx.lines(rel)
            for name in sorted(set(runtime) & set(dev)):
                hits = [i for i, ln in enumerate(text, 1) if f'"{name}"' in ln] or [0]
                out.append(self._duplicate(ctx, rel, name, hits, "both dependencies and devDependencies"))
        out.extend(self._js_lock_drift(ctx, rel, data))
        return out

    def _js_lock_drift(self, ctx, rel, data):
        """package.json and its lockfile disagree: `npm ci` / `yarn --frozen-lockfile` / `pnpm install
        --frozen-lockfile` fail, or plain installs silently resolve something the lockfile never recorded."""
        declared = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(data.get(key), dict):
                declared.update({k: v for k, v in data[key].items() if isinstance(v, str)})
        if not declared:
            return []
        directory = _dir(rel)
        drift: list[str] = []
        lock = None
        if ctx.exists(lock_rel := _join(directory, "package-lock.json")):
            lock = lock_rel
            try:
                root = (json.loads(ctx.read(lock_rel) or "{}").get("packages") or {}).get("")
            except (json.JSONDecodeError, AttributeError):
                root = None
            if isinstance(root, dict):
                recorded = {}
                for key in ("dependencies", "devDependencies", "optionalDependencies"):
                    recorded.update(root.get(key) or {})
                drift = [f"{n}: package.json {v!r}, lockfile {recorded.get(n, 'missing')!r}"
                         for n, v in sorted(declared.items()) if recorded.get(n) != v]
        elif ctx.exists(lock_rel := _join(directory, "yarn.lock")):
            lock = lock_rel
            specs = {spec for _, _, entry_specs in parse_yarn_lock(ctx.read(lock_rel) or "") for spec in entry_specs}
            drift = [f"{n}@{v}: not in yarn.lock" for n, v in sorted(declared.items())
                     if not v.startswith(("workspace:", "file:", "link:", "portal:"))
                     and f"{n}@{v}" not in specs and f"{n}@npm:{v}" not in specs]
        elif ctx.exists(lock_rel := _join(directory, "pnpm-lock.yaml")):
            lock = lock_rel
            recorded = pnpm_importer_specifiers(ctx.read(lock_rel) or "")
            if recorded is not None:
                drift = [f"{n}: package.json {v!r}, lockfile {recorded.get(n, 'missing')!r}"
                         for n, v in sorted(declared.items()) if recorded.get(n) != v]
        if not drift:
            return []
        return [self._f(ctx, "dependencies.lockfile-out-of-sync", f"{lock.rsplit('/', 1)[-1]} is out of sync with "
                        f"package.json ({len(drift)} package(s))", Severity.MEDIUM, Confidence.HIGH,
                        FindingKind.CONFIRMED,
                        "Dependencies declared in package.json do not match what the lockfile records. Clean installs "
                        "in CI (`npm ci`, frozen lockfile) fail, and other installs resolve versions nobody reviewed.",
                        "Run the package manager's install locally and commit the updated lockfile together with "
                        "package.json.", lock, evidence="; ".join(drift[:10]))]

    def _lockfiles(self, ctx):
        """Several lockfiles for one project, and packages resolved to several versions."""
        out = []
        by_dir: dict[str, list[str]] = defaultdict(list)
        for rel in ctx.files:
            if rel.rsplit("/", 1)[-1] in JS_LOCKS + PY_LOCKS and "node_modules/" not in rel:
                by_dir[_dir(rel)].append(rel.rsplit("/", 1)[-1])
        for directory, names in sorted(by_dir.items()):
            for family in (JS_LOCKS, PY_LOCKS):
                found = sorted(n for n in set(names) if n in family)
                if "bun.lock" in found and "bun.lockb" in found:
                    found.remove("bun.lockb")  # Bun writes both during its lockfile format migration
                if len(found) > 1:
                    out.append(self._f(ctx, "dependencies.multiple-lockfiles", f"{len(found)} lockfiles for one "
                                       "project", Severity.LOW, Confidence.HIGH, FindingKind.CONFIRMED,
                                       f"{', '.join(found)} live in the same directory. Each package manager "
                                       "resolves from its own file, so developers, CI and Docker can install "
                                       "different dependency trees.",
                                       "Choose one package manager, delete the other lockfiles, and enforce it (e.g. "
                                       "the packageManager field or `only-allow`).", _join(directory, found[0])))
        for rel in ctx.languages.manifests:
            versions = lock_versions(ctx, rel)
            dupes = {n: v for n, v in versions.items() if len(v) > 1}
            if dupes:
                top = sorted(dupes.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:10]
                out.append(self._f(ctx, "dependencies.duplicate-versions", f"{len(dupes)} package(s) installed in "
                                   f"several versions ({rel.rsplit('/', 1)[-1]})", Severity.INFO, Confidence.HIGH,
                                   FindingKind.CONFIRMED,
                                   "The lockfile resolves the same package to more than one version, usually because "
                                   "dependencies require incompatible ranges. Each copy adds install size and bundle "
                                   "weight, and fixes or patches must be applied to every copy.",
                                   "Update the dependencies that pin old ranges, then deduplicate (`npm dedupe`, "
                                   "`yarn dedupe`, `pnpm dedupe`); use overrides/resolutions only as a last resort.",
                                   rel, evidence="; ".join(f"{n}: {', '.join(sorted(v))}" for n, v in top)))
        return out

    def _python_conflicts(self, ctx):
        """Python pins that disagree: between requirements files of one project, or with pyproject constraints."""
        out = []
        dirs: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
        for rel in ctx.languages.manifests:
            name = rel.rsplit("/", 1)[-1]
            if name.startswith("requirements") and name.endswith(".txt"):
                for line, raw, spec in requirement_entries(ctx, rel):
                    if m := re.fullmatch(r"===?\s*([\w.+!-]+)", spec):
                        dirs[_dir(rel)][norm_py(raw)].append((m.group(1), rel, line))
            elif name in ("poetry.lock", "uv.lock"):
                try:
                    data = tomllib.loads(ctx.read(rel) or "")
                except tomllib.TOMLDecodeError:
                    continue
                for pkg in data.get("package", []) or []:
                    if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                        dirs[_dir(rel)][norm_py(pkg["name"])].append((str(pkg["version"]), rel, None))
        for directory, pins in sorted(dirs.items()):
            for name, entries in sorted(pins.items()):
                req_pins = {(v, r) for v, r, ln in entries if ln is not None}
                if len({v for v, _ in req_pins}) > 1:
                    first = next(e for e in entries if e[2] is not None)
                    out.append(self._f(ctx, "dependencies.conflicting-versions", f"'{name}' is pinned to different "
                                       "versions", Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                       f"'{name}' is pinned to {', '.join(sorted({v for v, _ in req_pins}))} in "
                                       f"{', '.join(sorted({r for _, r in req_pins}))}. Installing the files together "
                                       "fails, and environments installed from different files run different code.",
                                       "Pin each package once (e.g. in a constraints file) and include it with -r/-c.",
                                       first[1], first[2]))
            pyproject = _join(directory, "pyproject.toml")
            if not ctx.exists(pyproject):
                continue
            try:
                data = tomllib.loads(ctx.read(pyproject) or "")
            except tomllib.TOMLDecodeError:
                continue
            for group, raw, spec in pyproject_entries(data):
                if not spec or group.startswith("poetry"):
                    continue
                for version, src, _ in pins.get(norm_py(raw), []):
                    if satisfies(version, spec) is False:
                        out.append(self._f(ctx, "dependencies.conflicting-versions", f"'{raw}' {version} in "
                                           f"{src.rsplit('/', 1)[-1]} violates pyproject.toml ({spec})",
                                           Severity.MEDIUM, Confidence.HIGH, FindingKind.CONFIRMED,
                                           f"pyproject.toml requires {raw} {spec}, but {src} pins {version}. The "
                                           "lock or requirements file is stale, or the constraint is wrong; the "
                                           "deployed version is not the one the project declares it supports.",
                                           "Re-lock (uv lock / poetry lock / pip-compile) after changing constraints, "
                                           "and check in CI that the lockfile is current.", src))
                        break
        return out

    # ------------------------------------------------------------------------------------------------- unused
    def _corpus(self, ctx, exclude: set[str]) -> str:
        parts = []
        for rel in ctx.files:
            name = rel.rsplit("/", 1)[-1]
            if rel in exclude or "node_modules/" in rel or name in JS_LOCKS + PY_LOCKS:
                continue
            if rel.lower().endswith(CORPUS_SUFFIXES) or name in CORPUS_NAMES or name.startswith(("Dockerfile", ".env")):
                parts.append(ctx.read(rel) or "")
                if len(parts) >= MAX_CORPUS_FILES:
                    break
        return "\n".join(parts)

    def _unused(self, ctx):
        """Runtime dependencies that no file in the repository imports, requires or mentions."""
        from .ai_code import DIST_PROVIDES, IMPORT_TO_DIST

        _norm = norm_py
        out = []
        py_manifests = [m for m in ctx.languages.manifests if m.rsplit("/", 1)[-1] in ("requirements.txt",
                                                                                        "pyproject.toml")]
        js_manifests = [m for m in ctx.languages.manifests if m.endswith("package.json")]
        if not py_manifests and not js_manifests:
            return out
        corpus = self._corpus(ctx, set(ctx.languages.manifests))
        modules_of: dict[str, set[str]] = defaultdict(set)
        for module, dist in IMPORT_TO_DIST.items():
            modules_of[_norm(dist)].add(module)
        for dist, modules in EXTRA_DIST_MODULES.items():
            modules_of[_norm(dist)] |= modules
        providers = {_norm(d) for d in DIST_PROVIDES}

        def mentioned(*names: str) -> bool:
            return any(re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", corpus) for n in names if n)

        for rel in py_manifests:
            directory = _dir(rel)
            sources = [f for f in ctx.python_files() if f.startswith(directory) and not is_test_path(f)]
            if len(sources) < MIN_SOURCE_FILES_FOR_UNUSED:
                continue
            if rel.endswith(".txt"):
                declared = [(raw, line) for line, raw, _ in requirement_entries(ctx, rel)]
            else:
                try:
                    data = tomllib.loads(ctx.read(rel) or "")
                except tomllib.TOMLDecodeError:
                    continue
                declared = [(raw, None) for group, raw, _ in pyproject_entries(data) if group in ("dependencies",
                                                                                                  "poetry")]
            unused = []
            for raw, line in declared:
                dist = _norm(raw)
                if dist in IMPLICIT_PY or norm_py(raw) in IMPLICIT_PY or dist in providers or raw.startswith(
                        ("types-", "pytest")):
                    continue
                candidates = {raw, raw.lower(), dist, dist.replace("-", "_"), *modules_of.get(dist, ())}
                for prefix in ("python-", "py-", "django-", "flask-"):
                    if dist.startswith(prefix):
                        rest = dist[len(prefix):]
                        candidates |= {rest, rest.replace("-", "_"), rest.replace("-", "")}
                if not mentioned(*candidates):
                    unused.append((raw, line))
            if unused:
                out.append(self._unused_finding(ctx, rel, unused))
        for rel in js_manifests:
            directory = _dir(rel)
            sources = [f for f in ctx.files_with_suffix(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue",
                                                        ".svelte") if f.startswith(directory)
                       and "node_modules/" not in f and not is_test_path(f)]
            if len(sources) < MIN_SOURCE_FILES_FOR_UNUSED:
                continue
            try:
                data = json.loads(ctx.read(rel) or "{}")
            except json.JSONDecodeError:
                continue
            runtime = data.get("dependencies") if isinstance(data, dict) else None
            if not isinstance(runtime, dict):
                continue
            scripts = json.dumps(data.get("scripts") or {}) + json.dumps({k: v for k, v in data.items()
                                                                          if k not in ("dependencies",
                                                                                       "devDependencies")})
            lines = ctx.lines(rel)
            unused = []
            for name in runtime:
                if name in IMPLICIT_JS or name.startswith(("@types/", "@fontsource", "@babel/", "eslint")):
                    continue
                short = name.rsplit("/", 1)[-1]
                if not mentioned(name) and name not in scripts and not (name.startswith("@") and short in scripts):
                    unused.append((name, next((i for i, ln in enumerate(lines, 1) if f'"{name}"' in ln), None)))
            if unused:
                out.append(self._unused_finding(ctx, rel, unused))
        return out

    def _unused_finding(self, ctx, rel, unused):
        names = ", ".join(n for n, _ in unused[:20])
        return self._f(ctx, "dependencies.unused", f"{len(unused)} declared dependency(ies) appear unused",
                       Severity.LOW, Confidence.MEDIUM, FindingKind.POTENTIAL,
                       f"No file in the repository imports, requires or mentions: {names}. Unused dependencies "
                       "enlarge installs and images and widen the supply-chain attack surface for no benefit. "
                       "(Plugins loaded by name from configuration elsewhere may be false positives.)",
                       "Remove packages that are no longer needed (and re-lock), or move build-only tools to dev "
                       "dependencies.", rel, next((ln for _, ln in unused if ln), None))


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
        unchecked = packages[MAX_OSV_PACKAGES:]
        packages = packages[:MAX_OSV_PACKAGES]
        results: list = []
        for start in range(0, len(packages), OSV_BATCH):  # large lockfiles need several batches
            chunk = packages[start:start + OSV_BATCH]
            payload = {"queries": [{"package": {"ecosystem": eco, "name": name}, "version": ver}
                                   for eco, name, ver, _src in chunk]}
            try:
                resp = http.post(OSV_URL, json=payload, timeout=(5, 30))
                resp.raise_for_status()
                batch = resp.json().get("results", [])
            except (requests.RequestException, ValueError) as exc:
                raise AnalyzerError("OSV.dev could not be reached (dependency vulnerabilities not checked)") from exc
            results += list(batch[:len(chunk)]) + [{}] * (len(chunk) - len(batch))  # keep results aligned
        vids = list(dict.fromkeys(v.get("id", "") for res in results for v in (res or {}).get("vulns", [])[:50]))
        details = self._all_details(http, vids[:MAX_OSV_DETAILS], deadline=max(ctx.timeout - 15, 15))
        findings = []
        for (eco, name, ver, src), res in zip(packages, results, strict=False):
            for v in (res or {}).get("vulns", [])[:50]:
                vid = v.get("id", "")
                d = details.get(vid, {})
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
        if unchecked:
            findings.append(self.finding(
                ctx, rule="dependencies.osv-incomplete", title=f"{len(unchecked)} pinned packages were not checked "
                "against OSV.dev", category=Category.DEPENDENCIES, severity=Severity.INFO, confidence=Confidence.HIGH,
                kind=FindingKind.CONFIRMED,
                description=f"The lockfiles pin {len(packages) + len(unchecked)} packages; only the first "
                f"{len(packages)} were queried, so known vulnerabilities in the rest are not reported.",
                remediation="Run a full scan with Trivy (pre-seeded EVAL_TRIVY_CACHE_DIR) or `osv-scanner` for "
                "complete coverage.", file_path=unchecked[0][3]))
        return findings

    def _all_details(self, http, vids: list[str], deadline: float) -> dict[str, dict]:
        """Vulnerability records fetched concurrently; whatever is not back within ``deadline`` seconds is left
        out (those findings fall back to the id and a medium severity)."""
        from concurrent.futures import ThreadPoolExecutor, wait

        if not vids:
            return {}
        pool = ThreadPoolExecutor(max_workers=OSV_DETAIL_WORKERS, thread_name_prefix="osv")
        futures = {pool.submit(self._details, http, vid): vid for vid in vids}
        done, _ = wait(futures, timeout=deadline)
        pool.shutdown(wait=False, cancel_futures=True)
        return {futures[f]: f.result() for f in done}

    @staticmethod
    def _details(http, vid: str) -> dict:
        import requests

        try:
            r = http.get(OSV_VULN_URL + vid, timeout=(5, 15))
            return r.json() if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            return {}


def _severity(d: dict) -> Severity:
    """GitHub advisories carry a severity label; other OSV sources (PYSEC, RUSTSEC, …) only a CVSS vector."""
    label = str((d.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    if label in mapping:
        return mapping[label]
    scores = [s for entry in d.get("severity") or [] if isinstance(entry, dict)
              and (s := cvss3_base_score(str(entry.get("score", "")))) is not None]
    if not scores:
        return Severity.MEDIUM
    score = max(scores)
    return (Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else Severity.MEDIUM if score >= 4
            else Severity.LOW)


_CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
          "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/3.1 base score from a vector string (``CVSS:3.1/AV:N/AC:L/…``); None for other formats."""
    import math

    if not vector.startswith("CVSS:3."):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        exploitability = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
        iss = 1 - math.prod(1 - _CVSS3["CIA"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    total = min((1.08 if changed else 1.0) * (impact + exploitability), 10.0)
    return math.ceil(round(total * 100000) / 10000) / 10  # the specification's "round up" to one decimal


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
        elif name == "Pipfile.lock":
            try:
                data = json.loads(ctx.read(rel) or "{}")
            except json.JSONDecodeError:
                continue
            for section in ("default", "develop"):
                for pkg, meta in (data.get(section) or {}).items():
                    if isinstance(meta, dict) and str(meta.get("version", "")).startswith("=="):
                        add("PyPI", pkg, meta["version"].lstrip("="), rel)
        elif name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            for pkg, versions in lock_versions(ctx, rel).items():
                for ver in sorted(versions):
                    add("npm", pkg, ver, rel)
    return out


def simple_yaml(text: str) -> dict:
    """Parse the block-mapping subset of YAML used by pnpm-lock.yaml into nested dicts (scalars stay strings;
    sequences are ignored). Avoids a YAML dependency for one well-structured file format."""
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "- ")):
            continue
        m = re.match(r"""^('(?:[^']|'')*'|"[^"]*"|[^:'"][^:]*?):(?:\s+(.*))?$""", stripped)
        if not m:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        key, value = m.group(1).strip("'\""), m.group(2)
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if value is None or not value.strip():
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = value.strip().strip("'\"")
    return root


def pnpm_importer_specifiers(text: str) -> dict[str, str] | None:
    """Root project's declared specifiers as recorded in pnpm-lock.yaml (lockfile v5, v6 and v9)."""
    data = simple_yaml(text)
    project = (data.get("importers") or {}).get(".") if isinstance(data.get("importers"), dict) else data
    if not isinstance(project, dict):
        return None
    specs = dict(project.get("specifiers") or {}) if isinstance(project.get("specifiers"), dict) else {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        section = project.get(key)
        for name, entry in (section.items() if isinstance(section, dict) else []):
            if isinstance(entry, dict) and "specifier" in entry:
                specs[name] = entry["specifier"]
    return specs


def parse_yarn_lock(text: str) -> list[tuple[str, str, list[str]]]:
    """(name, resolved version, requested specs) for each entry of a yarn.lock (classic v1 and Berry)."""
    out = []
    current: list | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        if not raw[0].isspace():
            specs = [s.strip() for s in raw.rstrip().rstrip(":").replace('"', "").split(",") if s.strip()]
            names = {s.rsplit("@", 1)[0] for s in specs if "@" in s[1:]}
            name = next(iter(names)) if len(names) == 1 else ""
            current = [name, "", specs] if name and ":" not in name else None
            if current:
                out.append(current)
        elif current is not None and (m := re.match(r"""^\s+version:?\s+"?([^"\s]+)"?""", raw)):
            current[1] = m.group(1)
    return [(n, v, s) for n, v, s in out if v]


def lock_versions(ctx: AnalyzerContext, rel: str) -> dict[str, set[str]]:
    """Package name -> resolved versions recorded in a JavaScript lockfile ({} for other files)."""
    name = rel.rsplit("/", 1)[-1]
    text = ctx.read(rel) or ""
    versions: dict[str, set[str]] = defaultdict(set)
    if name == "package-lock.json":
        try:
            data = json.loads(text or "{}")
        except json.JSONDecodeError:
            return {}
        for path, meta in (data.get("packages") or {}).items() if isinstance(data, dict) else []:
            if path and isinstance(meta, dict) and meta.get("version") and "node_modules/" in path \
                    and not meta.get("link"):
                versions[path.rsplit("node_modules/", 1)[-1]].add(str(meta["version"]))
    elif name == "yarn.lock":
        for pkg, ver, _ in parse_yarn_lock(text):
            versions[pkg].add(ver)
    elif name == "pnpm-lock.yaml":
        packages = simple_yaml(text).get("packages")
        for key in packages if isinstance(packages, dict) else []:
            key = re.sub(r"\(.*$", "", key.lstrip("/"))
            if "@" in key[1:]:  # v6+: name@version
                pkg, ver = key.rsplit("@", 1)
            else:  # v5: name/version_peer
                pkg, _, ver = key.rpartition("/")
                ver = ver.split("_", 1)[0]
            if pkg and version_tuple(ver.split("-", 1)[0]) is not None:
                versions[pkg].add(ver)
    return dict(versions)
