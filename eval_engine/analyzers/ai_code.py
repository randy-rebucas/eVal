"""Failure patterns typical of AI-generated code, found statically (nothing is executed or installed).

* **Undeclared imports**: a module is imported but no declared dependency provides it. Often a hallucinated package,
  or one the generator assumed was installed.
* **Lookalike dependencies**: a declared package is one or two edits away from a popular package
  ("slopsquatting" / typosquatting).
* **Stubs and placeholders**: functions whose body is only ``pass`` / ``...`` / ``raise NotImplementedError``;
  "in a real application you would…" comments; ``YOUR_API_KEY``-style values left in code.
* **Tests that test nothing**: tautological assertions (``assert True``, ``assert x == x``, ``expect(true).toBe(true)``)
  and JavaScript test files without any ``expect``/``assert``.

The registry existence check (does the declared package exist at all?) needs the network and lives in
``RegistryAnalyzer`` below, with its network use declared.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from ..findings import Category, Confidence, FindingKind, Severity
from ..languages import js_dependencies, python_dependencies
from .base import Analyzer, AnalyzerContext, AnalyzerError, is_test_path
from .registry import register

# Import name -> distribution name, for packages whose import name differs from what is declared.
IMPORT_TO_DIST = {
    "yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt", "jose": "python-jose",
    "magic": "python-magic", "multipart": "python-multipart", "Crypto": "pycryptodome", "OpenSSL": "pyopenssl",
    "git": "gitpython", "google": "google-api-python-client", "googleapiclient": "google-api-python-client",
    "psycopg2": "psycopg2-binary", "MySQLdb": "mysqlclient", "serial": "pyserial", "usb": "pyusb",
    "attr": "attrs", "docx": "python-docx", "pptx": "python-pptx", "fitz": "pymupdf", "zmq": "pyzmq",
    "slugify": "python-slugify", "telegram": "python-telegram-bot", "discord": "discord.py", "socks": "pysocks",
    "markdown": "markdown", "Levenshtein": "python-levenshtein", "flask_sqlalchemy": "flask-sqlalchemy",
    "flask_login": "flask-login", "flask_wtf": "flask-wtf", "flask_migrate": "flask-migrate",
    "flask_cors": "flask-cors", "pkg_resources": "setuptools", "setuptools": "setuptools", "_pytest": "pytest",
    "email_validator": "email-validator", "jinja2": "jinja2", "werkzeug": "werkzeug", "sentry_sdk": "sentry-sdk",
}
# Imports that come with other packages or the toolchain and are rarely declared on their own.
IMPLICIT_IMPORTS = {"pkg_resources", "setuptools", "_pytest", "pip", "wheel", "distutils", "typing_extensions",
                    "__future__", "conftest"}
# Distributions that provide differently named modules (when declared, these imports are satisfied).
DIST_PROVIDES = {"psycopg": {"psycopg"}, "psycopg2-binary": {"psycopg2"}, "celery": {"kombu", "billiard"},
                 "flask": {"werkzeug", "jinja2", "itsdangerous", "click", "markupsafe"},
                 "requests": {"urllib3", "idna", "certifi", "charset_normalizer"},
                 "fastapi": {"starlette", "pydantic"}, "uvicorn": {"h11", "click"},
                 "boto3": {"botocore", "s3transfer"}, "sqlalchemy": {"sqlalchemy"},
                 "gitpython": {"git", "gitdb"}, "pytest": {"_pytest", "pluggy"}, "anthropic": {"httpx"},
                 "openai": {"httpx"}, "django": {"asgiref"}, "flask-wtf": {"wtforms"}, "flask-migrate": {"alembic"}}

NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib", "test",
}

POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "boto3", "botocore",
    "pytest", "urllib3", "setuptools", "certifi", "idna", "charset-normalizer", "six", "python-dateutil",
    "pyyaml", "typing-extensions", "packaging", "cryptography", "jinja2", "markupsafe", "werkzeug", "click",
    "attrs", "pillow", "scipy", "matplotlib", "scikit-learn", "tensorflow", "torch", "keras", "celery", "redis",
    "psycopg2", "psycopg2-binary", "psycopg", "pymongo", "aiohttp", "httpx", "uvicorn", "gunicorn", "starlette",
    "beautifulsoup4", "lxml", "selenium", "openai", "anthropic", "langchain", "transformers", "tqdm", "rich",
    "colorama", "pyjwt", "bcrypt", "passlib", "paramiko", "docker", "kubernetes", "google-api-python-client",
    "protobuf", "grpcio", "pytz", "tzdata", "simplejson", "ujson", "orjson", "marshmallow", "alembic",
    "flask-sqlalchemy", "flask-login", "flask-wtf", "flask-cors", "wtforms", "python-dotenv", "loguru",
    "structlog", "sentry-sdk", "stripe", "twilio", "pyodbc", "mysqlclient", "pymysql", "elasticsearch",
    "opencv-python", "nltk", "spacy", "seaborn", "plotly", "dash", "streamlit", "gradio", "pyarrow", "polars",
    "dask", "numba", "sympy", "networkx", "mypy", "ruff", "black", "flake8", "pylint", "isort", "coverage",
    "tox", "nox", "poetry", "pip", "wheel", "virtualenv", "gitpython", "jsonschema", "toml", "tomli",
    "markdown", "pygments", "sphinx", "docutils", "itsdangerous", "pyopenssl", "pycryptodome", "rsa", "ecdsa",
    "httplib2", "oauthlib", "requests-oauthlib", "websockets", "websocket-client", "pyzmq", "kafka-python",
    "pika", "boto", "s3transfer", "awscli", "azure-core", "google-cloud-storage", "firebase-admin", "pytest-cov",
    "pytest-mock", "faker", "factory-boy", "hypothesis", "responses", "freezegun", "arrow", "pendulum",
    "email-validator", "phonenumbers", "babel", "regex", "chardet", "xmltodict", "openpyxl", "xlrd", "reportlab",
}
POPULAR_NPM = {
    "react", "react-dom", "next", "vue", "nuxt", "svelte", "angular", "@angular/core", "express", "koa", "fastify",
    "hapi", "nestjs", "@nestjs/core", "lodash", "underscore", "axios", "node-fetch", "request", "moment", "dayjs",
    "date-fns", "uuid", "chalk", "commander", "yargs", "debug", "dotenv", "cors", "body-parser", "cookie-parser",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "mongoose", "mongodb", "pg", "mysql", "mysql2", "sequelize",
    "prisma", "@prisma/client", "typeorm", "knex", "redis", "ioredis", "socket.io", "ws", "graphql",
    "apollo-server", "@apollo/client", "webpack", "vite", "rollup", "esbuild", "babel-loader", "@babel/core",
    "typescript", "ts-node", "eslint", "prettier", "jest", "mocha", "chai", "vitest", "cypress", "playwright",
    "@playwright/test", "supertest", "sinon", "nodemon", "pm2", "tailwindcss", "postcss", "autoprefixer", "sass",
    "styled-components", "@emotion/react", "redux", "@reduxjs/toolkit", "react-redux", "zustand", "mobx",
    "rxjs", "zod", "yup", "joi", "ajv", "validator", "helmet", "morgan", "winston", "pino", "multer", "sharp",
    "aws-sdk", "@aws-sdk/client-s3", "firebase", "stripe", "openai", "@anthropic-ai/sdk", "langchain",
    "react-router", "react-router-dom", "@tanstack/react-query", "swr", "formik", "react-hook-form", "classnames",
    "clsx", "immer", "ramda", "async", "bluebird", "glob", "rimraf", "mkdirp", "fs-extra", "semver", "minimist",
    "inquirer", "ora", "cheerio", "puppeteer", "jsdom", "nodemailer", "handlebars", "ejs", "pug", "marked",
    "highlight.js", "three", "d3", "chart.js", "lodash.merge", "qs", "cross-env", "concurrently", "husky",
}

PLACEHOLDER_COMMENT = re.compile(
    r"(?:#|//|/\*|\*)\s*.*?\b("
    r"in a real(?:-world)? (?:application|app|implementation|system|project|scenario)"
    r"|in (?:a )?production,? you (?:would|should|'d)"
    r"|(?:replace|swap) (?:this|it) with (?:a |an |the |your )?(?:real|actual|proper)"
    r"|(?:mock|dummy|fake|placeholder|simplified|simulated) (?:implementation|logic|data|response|version)"
    r"|todo:?\s*(?:implement|add (?:real|proper|actual)|replace)"
    r"|for now,? (?:just |we )?(?:return|simulate|mock|hard-?code|pretend)"
    r")", re.I)
PLACEHOLDER_VALUE = re.compile(  # used as a value (assigned, passed, or a mapping value), not quoted in prose
    r"""(?:[=:(,]\s*|^\s*)["'](?:your[-_ ]?(?:api[-_ ]?key|secret(?:[-_ ]?key)?|token|password|key)(?:[-_ ]?here)?"""
    r"""|<\s*your[^>]{1,40}>|changeme|change[-_]me|replace[-_]me|xxx+|todo|insert[-_ ][a-z_ -]{1,30}here)["']""",
    re.I)
JS_NOT_IMPLEMENTED = re.compile(r"throw\s+new\s+Error\(\s*['\"`](?:not\s+implemented|todo|implement\s+me)", re.I)
JS_IMPORT = re.compile(r"""(?:^|[\s;(])(?:import\s+(?:[^'";]+?\s+from\s+)?|require\(\s*|import\(\s*)['"]([^'"]+)['"]""",
                       re.M)
JS_TEST_CALL = re.compile(r"^\s*(?:it|test)(?:\.(?:only|skip|each\([^)]*\)))?\s*\(", re.M)
JS_ASSERT = re.compile(r"\b(?:expect|assert|should)\b|\.toBe|\.toEqual|t\.(?:is|true|deepEqual)")
JS_TAUTOLOGY = re.compile(r"expect\(\s*(true|1|false|null)\s*\)\s*\.\s*(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)")
JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
SKIP_DIRS = ("docs/", "doc/", "examples/", "example/", "samples/", "fixtures/")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()).strip("-")


def edit_distance(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance, short-circuiting above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def lookalike_of(name: str, popular: set[str]) -> str | None:
    """The popular package ``name`` imitates, if it is not itself popular and is 1 edit (2 for long names) away."""
    n = _norm(name)
    normalized = {_norm(p): p for p in popular}
    if n in normalized or len(n) < 5:  # short names have too many legitimate one-edit neighbours
        return None
    limit = 2 if len(n) >= 10 else 1
    for pn, original in normalized.items():
        if pn[0] != n[0] and pn[-1] != n[-1]:
            continue  # cheap filter: real typosquats keep the first or last character
        if edit_distance(n, pn, limit) <= limit:
            return original
    return None


def _is_optional_import(node: ast.AST, parents: dict) -> bool:
    """Inside ``try: ... except ImportError`` or ``if TYPE_CHECKING:``."""
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, ast.Try):
            for h in cur.handlers:
                names = [h.type] if not isinstance(h.type, ast.Tuple) else list(h.type.elts)
                if h.type is None or any(isinstance(t, ast.Name) and t.id in (
                        "ImportError", "ModuleNotFoundError", "Exception") for t in names):
                    return True
        if isinstance(cur, ast.If) and "TYPE_CHECKING" in ast.unparse(cur.test):
            return True
        cur = parents.get(cur)
    return False


def _is_stub(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    body = list(func.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]  # docstring
    if not body or len(body) > 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
        return True
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
        return isinstance(exc, ast.Name) and exc.id == "NotImplementedError"
    return False


_EXEMPT_DECORATORS = ("abstractmethod", "overload", "abstractproperty", "override", "hookspec", "hookimpl")
_EXEMPT_BASES = ("Protocol", "ABC", "ABCMeta", "Interface", "Exception", "TypedDict", "NamedTuple")


_HOOK_PREFIXES = ("on_", "handle_", "before_", "after_", "setup", "teardown", "set_up", "tear_down", "visit_")


def _exempt_function(func, cls: ast.ClassDef | None) -> bool:
    for d in func.decorator_list:
        text = ast.unparse(d)
        if any(text.endswith(x) for x in _EXEMPT_DECORATORS):
            return True
    if func.name.startswith("__") and func.name.endswith("__"):
        return True  # dunder no-ops (__init__ with pass, __enter__) are usually intentional
    if cls is None:
        return False
    # Methods: `raise NotImplementedError` is the classic abstract-method idiom, no-op hooks are meant to be
    # overridden, and base classes / interfaces declare methods for subclasses.
    last = func.body[-1]
    if isinstance(last, ast.Raise):
        return True
    if func.name.lower().startswith(_HOOK_PREFIXES):
        return True
    name = cls.name.lower()
    if name.startswith(("base", "abstract", "mixin")) or name.endswith(("base", "mixin", "interface")):
        return True
    return any(any(ast.unparse(b).endswith(x) for x in _EXEMPT_BASES) for b in cls.bases)


def _tautology(test: ast.AST) -> bool:
    if isinstance(test, ast.Constant):
        return bool(test.value) and test.value is not Ellipsis
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Constant):
        return not test.operand.value
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq | ast.Is):
        left, right = ast.dump(test.left), ast.dump(test.comparators[0])
        if left == right and not isinstance(test.left, ast.Call):
            return True
        if isinstance(test.left, ast.Constant) and isinstance(test.comparators[0], ast.Constant):
            return test.left.value == test.comparators[0].value
    return False


@register
class AICodeAnalyzer(Analyzer):
    name = "ai_code"
    title = "AI-generated code patterns"
    categories = (Category.DEPENDENCIES, Category.MAINTAINABILITY, Category.TESTING)

    def applicable(self, ctx: AnalyzerContext):
        if not (ctx.python_files() or ctx.files_with_suffix(*JS_EXTS)):
            return "no Python or JavaScript/TypeScript files detected"
        return None

    def run(self, ctx: AnalyzerContext):
        findings = []
        findings += self._python_imports(ctx)
        findings += self._js_imports(ctx)
        findings += self._lookalikes(ctx)
        findings += self._stubs_and_placeholders(ctx)
        findings += self._tautologies(ctx)
        return findings

    # ------------------------------------------------------------------ dependencies
    def _python_imports(self, ctx: AnalyzerContext):
        manifests = [m for m in ctx.languages.manifests
                     if m.rsplit("/", 1)[-1] in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile")
                     or (m.rsplit("/", 1)[-1].startswith("requirements") and m.endswith(".txt"))]
        if not manifests or any(m.endswith(("setup.py", "setup.cfg", "Pipfile")) for m in manifests):
            return []  # nothing declared (another analyzer reports that), or a format not parsed here
        declared = {_norm(d) for d in python_dependencies(ctx.root, manifests)}
        provided = {m for d in declared for m in DIST_PROVIDES.get(d, ())}
        local = set()
        for f in ctx.python_files():
            parts = f[:-3].split("/")
            local.update(parts)  # any directory or module name in the tree may be importable (src/ layouts…)
        stdlib = set(sys.stdlib_module_names)
        seen: dict[str, list[tuple[str, int]]] = {}
        for rel in ctx.python_files():
            if is_test_path(rel) or rel.startswith(SKIP_DIRS):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    roots = [node.module.split(".")[0]]
                else:
                    continue
                for root in roots:
                    if root in stdlib or root in local or root in IMPLICIT_IMPORTS or root in provided:
                        continue
                    dist = _norm(IMPORT_TO_DIST.get(root, root))
                    if dist in declared or _norm(root) in declared or _is_optional_import(node, parents):
                        continue
                    seen.setdefault(root, []).append((rel, node.lineno))
        return [self._undeclared(ctx, mod, locs, "Python", manifests[0]) for mod, locs in sorted(seen.items())]

    def _js_imports(self, ctx: AnalyzerContext):
        pkg_files = [m for m in ctx.languages.manifests if m.endswith("package.json")]
        if not pkg_files:
            return []
        declared = js_dependencies(ctx.root, pkg_files)
        aliases = any("paths" in (ctx.read(f) or "") for f in ctx.files_named("tsconfig.json", "jsconfig.json"))
        seen: dict[str, list[tuple[str, int]]] = {}
        for rel in ctx.files_with_suffix(*JS_EXTS):
            if is_test_path(rel) or rel.startswith(SKIP_DIRS) or "node_modules/" in rel or rel.endswith(".d.ts"):
                continue
            text = ctx.read(rel) or ""
            for m in JS_IMPORT.finditer(text):
                spec = m.group(1)
                if spec.startswith((".", "/", "node:", "~", "#", "virtual:", "data:", "http:", "https:")) \
                        or "${" in spec:
                    continue
                if spec.startswith("@") and aliases and spec.startswith("@/"):
                    continue
                parts = spec.split("/")
                name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
                if name in NODE_BUILTINS or name.lower() in declared or (aliases and not spec.startswith("@")
                                                                       and "/" in spec and name in ("src", "app")):
                    continue
                line = text.count("\n", 0, m.start(1)) + 1
                seen.setdefault(name, []).append((rel, line))
        return [self._undeclared(ctx, mod, locs, "JavaScript", pkg_files[0]) for mod, locs in sorted(seen.items())]

    def _undeclared(self, ctx, module: str, locs, lang: str, manifest: str):
        rel, line = locs[0]
        where = ", ".join(sorted({p for p, _ in locs})[:5])
        return self.finding(
            ctx, rule="ai-code.undeclared-import", title=f"Import of undeclared package '{module}'",
            category=Category.DEPENDENCIES, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            kind=FindingKind.POTENTIAL,
            description=f"'{module}' is imported ({len(locs)}× in {where}) but no dependency in {manifest} provides "
            f"it. {lang} code generated by AI often imports packages that were never added to the project, or that do "
            "not exist at all; an attacker can register a hallucinated name and wait for someone to install it.",
            remediation=f"Confirm the package that provides '{module}' is real and maintained, then declare and pin "
            "it, or remove the import.", file_path=rel, line=line)

    def _lookalikes(self, ctx: AnalyzerContext):
        out = []
        manifests = ctx.languages.manifests
        py = python_dependencies(ctx.root, manifests)
        js = js_dependencies(ctx.root, [m for m in manifests if m.endswith("package.json")])
        for names, popular, eco in ((py, POPULAR_PYPI, "PyPI"), (js, POPULAR_NPM, "npm")):
            for name in sorted(names):
                target = lookalike_of(name, popular)
                if target is None:
                    continue
                src = next((m for m in manifests if name in (ctx.read(m) or "").lower()), manifests[0])
                line = next((i for i, ln in enumerate(ctx.lines(src), 1) if name in ln.lower()), None)
                out.append(self.finding(
                    ctx, rule="ai-code.lookalike-package", title=f"'{name}' looks like a misspelling of '{target}'",
                    category=Category.DEPENDENCIES, severity=Severity.HIGH, confidence=Confidence.LOW,
                    kind=FindingKind.POTENTIAL,
                    description=f"The declared {eco} package '{name}' differs from the popular package '{target}' by "
                    "one or two characters. Typosquatted and AI-hallucinated names are a known supply-chain attack "
                    "vector: installing them can run attacker code.",
                    remediation=f"Check that '{name}' is the package you intend (publisher, downloads, repository). "
                    f"If you meant '{target}', fix the name.", file_path=src, line=line))
        return out

    # ------------------------------------------------------------------ stubs and placeholders
    def _stubs_and_placeholders(self, ctx: AnalyzerContext):
        out = []
        for rel in ctx.python_files():
            if is_test_path(rel) or rel.startswith(SKIP_DIRS) or rel.endswith(".pyi"):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            stubs = []
            for node in ast.walk(tree):
                classes = [node] if isinstance(node, ast.ClassDef) else []
                for cls in classes:
                    for item in cls.body:
                        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and _is_stub(item) \
                                and not _exempt_function(item, cls):
                            stubs.append(item)
            stubs += [n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
                      and _is_stub(n) and not _exempt_function(n, None)]
            if stubs:
                stubs.sort(key=lambda n: n.lineno)
                out.append(self.finding(
                    ctx, rule="ai-code.stub-function", title=f"{len(stubs)} unimplemented function(s)",
                    category=Category.MAINTAINABILITY, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description="These functions have no implementation (only pass, ..., or raise "
                    "NotImplementedError) outside an abstract base class or protocol: "
                    + ", ".join(n.name for n in stubs[:10]) + ". Generated code often leaves such stubs behind, and "
                    "callers then silently get None.",
                    remediation="Implement them, or mark the class abstract (abc.ABC + @abstractmethod) so the gap "
                    "fails loudly.", file_path=rel, line=stubs[0].lineno))
        for rel in [*ctx.python_files(), *ctx.files_with_suffix(*JS_EXTS)]:
            if is_test_path(rel) or rel.startswith(SKIP_DIRS) or "node_modules/" in rel:
                continue
            lines = ctx.lines(rel)
            comments = [(i, m.group(1)) for i, ln in enumerate(lines, 1) if (m := PLACEHOLDER_COMMENT.search(ln))]
            values = [i for i, ln in enumerate(lines, 1) if PLACEHOLDER_VALUE.search(ln)]
            not_impl = [i for i, ln in enumerate(lines, 1) if JS_NOT_IMPLEMENTED.search(ln)] \
                if rel.endswith(JS_EXTS) else []
            if comments:
                out.append(self.finding(
                    ctx, rule="ai-code.placeholder-logic", title=f"{len(comments)} placeholder comment(s)",
                    category=Category.MAINTAINABILITY, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description=f"Comments such as “{comments[0][1]}” mark simplified or simulated logic that was "
                    "never replaced — a frequent leftover in AI-generated code (lines "
                    + ", ".join(str(i) for i, _ in comments[:10]) + ").",
                    remediation="Replace the placeholder with the real implementation, or turn it into a tracked "
                    "issue and fail explicitly until then.", file_path=rel, line=comments[0][0]))
            if values or not_impl:
                first = min([*values, *not_impl])
                out.append(self.finding(
                    ctx, rule="ai-code.placeholder-value", title="Placeholder value or not-implemented error",
                    category=Category.MAINTAINABILITY, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description="Template values like 'YOUR_API_KEY' / 'changeme', or a 'not implemented' error, "
                    "are still in the code (lines " + ", ".join(str(i) for i in sorted([*values, *not_impl])[:10])
                    + ").", remediation="Load real values from configuration, and implement or remove the code path.",
                    file_path=rel, line=first))
        return out

    # ------------------------------------------------------------------ tests
    def _tautologies(self, ctx: AnalyzerContext):
        out = []
        for rel in ctx.python_files():
            if not is_test_path(rel):
                continue
            tree = ctx.python_ast(rel)
            if tree is None:
                continue
            hits = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert) and _tautology(n.test)]
            hits += [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and n.func.attr in ("assertTrue", "assertIsNotNone") and n.args
                     and isinstance(n.args[0], ast.Constant) and n.args[0].value not in (None, False, 0, "")]
            if hits:
                out.append(self._tautology_finding(ctx, rel, sorted(hits)))
        for rel in ctx.files_with_suffix(*JS_EXTS):
            if not is_test_path(rel) or "node_modules/" in rel:
                continue
            text = ctx.read(rel) or ""
            hits = [text.count("\n", 0, m.start()) + 1 for m in JS_TAUTOLOGY.finditer(text)]
            if hits:
                out.append(self._tautology_finding(ctx, rel, hits))
            tests = JS_TEST_CALL.findall(text)
            if tests and not JS_ASSERT.search(text):
                first = text.count("\n", 0, JS_TEST_CALL.search(text).start()) + 1
                out.append(self.finding(
                    ctx, rule="ai-code.tests-without-expect", title=f"{len(tests)} test(s) without any assertion",
                    category=Category.TESTING, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description="This test file defines tests but never calls expect/assert, so the tests only "
                    "check that the code does not throw.",
                    remediation="Assert on return values, rendered output, and error cases.", file_path=rel,
                    line=first))
        return out

    def _tautology_finding(self, ctx, rel: str, lines: list[int]):
        return self.finding(
            ctx, rule="ai-code.tautological-assertion", title=f"{len(lines)} assertion(s) that can never fail",
            category=Category.TESTING, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            kind=FindingKind.CONFIRMED,
            description="Assertions like `assert True`, `assert x == x` or `expect(true).toBe(true)` always pass, "
            "so these tests report success without checking anything (lines "
            + ", ".join(str(i) for i in lines[:10]) + ").",
            remediation="Assert on the behaviour under test: the return value, state change, or raised error.",
            file_path=rel, line=lines[0])


# ------------------------------------------------------------------------------------------- registry check
PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}"
MAX_REGISTRY_PACKAGES = 300
NEW_PACKAGE_DAYS = 30


@register
class RegistryAnalyzer(Analyzer):
    """Checks that declared dependencies exist on PyPI / npm and are not brand new. Sends only package names.
    Disable with EVAL_REGISTRY_CHECK_ENABLED=0; skipped for projects that configure a private package index."""

    name = "registry"
    title = "Dependency existence (PyPI / npm)"
    categories = (Category.DEPENDENCIES,)
    network_use = "pypi.org / registry.npmjs.org: names of declared dependencies (no source code, no versions)"

    def applicable(self, ctx: AnalyzerContext):
        if os.environ.get("EVAL_REGISTRY_CHECK_ENABLED", "1").lower() in ("0", "false", "no", "off"):
            return "disabled by configuration (EVAL_REGISTRY_CHECK_ENABLED=0)"
        if not ctx.languages.manifests:
            return "no dependency manifests found"
        if self._private_index(ctx):
            return "a private package index is configured; public registries would not know its packages"
        return None

    def network_required(self, ctx: AnalyzerContext):
        return "queries pypi.org and registry.npmjs.org"

    @staticmethod
    def _private_index(ctx: AnalyzerContext) -> bool:
        for rel in ctx.files_named(".npmrc", "pip.conf", ".pypirc"):
            if re.search(r"registry\s*=|index-url", ctx.read(rel) or ""):
                return True
        for rel in ctx.languages.manifests:
            text = ctx.read(rel) or ""
            if re.search(r"^\s*--(?:extra-)?index-url", text, re.M) or "[[tool.poetry.source]]" in text \
                    or "[[tool.uv.index]]" in text:
                return True
        return False

    def run(self, ctx: AnalyzerContext):
        manifests = ctx.languages.manifests
        packages = [("PyPI", n) for n in sorted(python_dependencies(ctx.root, manifests))]
        packages += [("npm", n) for n in sorted(js_dependencies(ctx.root, [m for m in manifests
                                                                           if m.endswith("package.json")]))]
        return self.check(ctx, packages[:MAX_REGISTRY_PACKAGES])

    def check(self, ctx, packages, session=None, now: datetime | None = None):
        import requests

        http = session or requests
        now = now or datetime.now(UTC)

        def lookup(item):
            eco, name = item
            url = (PYPI_URL if eco == "PyPI" else NPM_URL).format(name=requests.utils.quote(name, safe="@"))
            try:
                r = http.get(url, timeout=(5, 15), headers={"Accept": "application/json"})
            except requests.RequestException:
                return item, "error", None
            if r.status_code == 404:
                return item, "missing", None
            if r.status_code != 200:
                return item, "error", None
            try:
                return item, "ok", _first_release(eco, r.json())
            except (ValueError, KeyError, TypeError):
                return item, "ok", None

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lookup, packages))
        if results and all(status == "error" for _, status, _ in results):
            raise AnalyzerError("package registries could not be reached (dependency existence not checked)")
        out = []
        for (eco, name), status, created in results:
            src = next((m for m in ctx.languages.manifests if name in (ctx.read(m) or "").lower()),
                       ctx.languages.manifests[0])
            line = next((i for i, ln in enumerate(ctx.lines(src), 1) if name in ln.lower()), None)
            if status == "missing":
                out.append(self.finding(
                    ctx, rule="ai-code.package-not-found", title=f"Dependency '{name}' does not exist on {eco}",
                    category=Category.DEPENDENCIES, severity=Severity.HIGH, confidence=Confidence.HIGH,
                    kind=FindingKind.CONFIRMED,
                    description=f"{eco} has no package named '{name}'. AI assistants regularly invent package names; "
                    "anyone can later register the name with malicious code, and the next install will run it.",
                    remediation="Remove the dependency or replace it with the real package that provides the "
                    "functionality. If it comes from a private index, configure that index in the project.",
                    file_path=src, line=line))
            elif created is not None and (now - created).days < NEW_PACKAGE_DAYS:
                out.append(self.finding(
                    ctx, rule="ai-code.package-very-new",
                    title=f"Dependency '{name}' was first published {max((now - created).days, 0)} day(s) ago",
                    category=Category.DEPENDENCIES, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    kind=FindingKind.POTENTIAL,
                    description=f"'{name}' first appeared on {eco} on {created:%Y-%m-%d}. Very new packages have no "
                    "track record, and squatted hallucinated names are, by definition, new.",
                    remediation="Verify the publisher and source repository before depending on it, and pin an "
                    "exact version.", file_path=src, line=line))
        return out


def _first_release(eco: str, data: dict) -> datetime | None:
    if eco == "npm":
        created = (data.get("time") or {}).get("created")
        return datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None
    times = [f["upload_time_iso_8601"] for files in (data.get("releases") or {}).values() for f in files
             if f.get("upload_time_iso_8601")]
    return datetime.fromisoformat(min(times).replace("Z", "+00:00")) if times else None
