"""What kind of application is being audited: its web framework, how clients authenticate, where it stores data,
and how it keeps passwords (read from the ORM models, Prisma schema or SQL DDL).

Security checks use the profile to decide whether they apply. CSRF only matters when browsers send credentials
automatically (cookies), JWT checks only when the app issues or verifies JWTs, NoSQL injection only with a document
store, password-storage checks only when the app keeps its own passwords. The profile is reported with the audit
so readers can see the assumptions a "not applicable" rests on. Everything is read statically; nothing is run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .analyzers.base import is_test_path
from .languages import js_dependencies, python_dependencies

WEB_FRAMEWORKS = {"flask", "django", "fastapi", "starlette", "express", "nestjs", "fastify", "koa", "nextjs"}
CODE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
SCHEMA_SUFFIXES = (".prisma", ".sql")
MAX_FILES = 3000

# Authentication schemes. "cookie" means the browser attaches the credential automatically (session cookie or a
# token kept in a cookie); header-borne schemes (bearer, API key, basic) are not sent cross-site by browsers.
AUTH_DEPS = {
    "cookie": {"flask-login", "flask-session", "express-session", "cookie-session", "passport-local", "iron-session",
               "next-auth", "@auth/core", "django-allauth", "koa-session", "@fastify/session",
               "@fastify/secure-session", "lucia"},
    "jwt": {"pyjwt", "python-jose", "flask-jwt-extended", "djangorestframework-simplejwt", "fastapi-jwt-auth",
            "jsonwebtoken", "jose", "passport-jwt", "express-jwt", "@nestjs/jwt", "@fastify/jwt"},
    "oauth": {"authlib", "social-auth-app-django", "flask-dance", "oauthlib", "passport-google-oauth20",
              "passport-github2", "passport-oauth2"},
}
AUTH_CODE = {
    "cookie": re.compile(r"\blogin_user\(|\bsession\[\s*['\"]user|\breq\.session\.\w+\s*=|SessionMiddleware|"
                         r"django\.contrib\.sessions|SessionAuthentication|set_access_cookies|"
                         r"JWT_TOKEN_LOCATION[^\n]*cookies|res\.cookie\(\s*['\"`][\w-]*(?:token|sess|auth|jwt)", re.I),
    "jwt": re.compile(r"\bjwt\.(?:encode|decode|sign|verify)\(|JWTAuthentication|create_access_token\(|jwtVerify\(|"
                      r"new SignJWT\("),
    "bearer-token": re.compile(r"['\"`]Bearer\s|HTTPBearer|OAuth2PasswordBearer|TokenAuthentication|"
                               r"passport-http-bearer|ExtractJwt\.fromAuthHeader", re.I),
    "api-key": re.compile(r"x-api-key|APIKeyHeader|api_key_header|HasAPIKey", re.I),
    "basic": re.compile(r"\bHTTPBasic\b|BasicAuthentication|express-basic-auth|['\"`]Basic\s"),
}
HEADER_SCHEMES = ("jwt", "bearer-token", "api-key", "basic")

PASSWORD_HASHING = re.compile(r"generate_password_hash|check_password_hash|\bbcrypt|\bargon2|passlib|\bscrypt\b|"
                              r"pbkdf2|make_password|set_password\(|check_password\(|hashpw|CryptContext|pwdlib|"
                              r"AbstractUser|AbstractBaseUser|django\.contrib\.auth|@node-rs/argon2|"
                              r"crypto\.scrypt|PasswordHasher")
HASHING_DEPS = {"bcrypt", "bcryptjs", "argon2-cffi", "argon2", "passlib", "pwdlib", "@node-rs/argon2",
                "@node-rs/bcrypt", "scrypt", "django"}
PASSWORD_LOGIN = re.compile(r"check_password|verify_password|\bauthenticate\(|passport-local|LocalStrategy|"
                            r"password_hash|passwordHash|hashed_password")
# A stored password column, by schema dialect. Only the exact names: ``password_hash`` is a hash by its name.
PASSWORD_COLUMN = [
    # SQLAlchemy / Django models / mongoengine. Form fields (WTForms PasswordField/StringField, forms.CharField)
    # describe input, not storage, so bare or forms.-prefixed field classes do not count.
    re.compile(r"^\s*(?:password|passwd|pwd)\s*(?::[^=\n]+)?=\s*(?:(?:(?:db|sa|sqlalchemy|orm)\.)?"
               r"(?:Column|mapped_column)|(?:models\.|me\.|mongoengine\.|fields\.)?(?:CharField|TextField|BinaryField)|"
               r"(?:me|mongoengine|fields)\.StringField)\(", re.M),
    re.compile(r"^\s*(?:password|passwd)\s+String\b", re.M),                           # Prisma
    re.compile(r"^\s*(?:password|passwd)\s*:\s*(?:\{\s*type\s*:\s*)?(?:String|DataTypes\.STRING|Sequelize\.STRING)",
               re.M),                                                                  # Mongoose / Sequelize
    re.compile(r"@Column\([^)]*\)\s*(?:password|passwd)\s*[!?]?\s*:\s*string", re.M),  # TypeORM
    re.compile(r"(?i)^\s*\"?(?:password|passwd)\"?\s+(?:varchar|nvarchar|text|char|character varying)\b", re.M),
]

SQL_DEPS = {"sqlalchemy", "django", "psycopg2", "psycopg2-binary", "psycopg", "pymysql", "mysqlclient", "asyncpg",
            "peewee", "tortoise-orm", "sqlmodel", "aiosqlite", "pg", "mysql", "mysql2", "sqlite3", "better-sqlite3",
            "sequelize", "typeorm", "knex", "drizzle-orm", "kysely", "flask-sqlalchemy"}
MONGO_DEPS = {"pymongo", "motor", "mongoengine", "beanie", "mongoose", "mongodb", "flask-pymongo", "djongo"}
REDIS_DEPS = {"redis", "ioredis", "aioredis"}
UPLOADS = re.compile(r"\brequest\.(?:files|FILES)\b|\bUploadFile\b|\bmulter\b|express-fileupload|formidable|busboy|"
                     r"FileField\(")
PY_RAW_STRING = re.compile(r"""\b[rR][bB]?("|')(?:\\.|(?!\1)[^\n])*\1""")
SERVER_RENDERED = re.compile(r"\brender_template(?:_string)?\(|TemplateResponse\(|\bres\.render\(|"
                             r"django\.shortcuts import render|\brender\(request,")


@dataclass
class AppProfile:
    web_frameworks: list[str] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)        # scheme -> evidence
    datastores: dict[str, str] = field(default_factory=dict)  # sql | mongodb | redis -> evidence
    password_hashing: str = ""                                # evidence of a password hashing function, if any
    password_login: str = ""                                  # evidence the app checks passwords itself
    password_columns: list[tuple[str, int]] = field(default_factory=list)  # (file, line) of stored password fields
    uploads: str = ""
    server_rendered: str = ""

    @property
    def cookie_auth(self) -> bool:
        return "cookie" in self.auth

    @property
    def keeps_passwords(self) -> bool:
        return bool(self.password_columns or self.password_login)

    def applicability(self) -> list[dict]:
        """Which schema-dependent security checks apply to this application, and why."""
        header = [s for s in HEADER_SCHEMES if s in self.auth]
        rows = []

        def add(check: str, applies: bool, reason: str) -> None:
            rows.append({"check": check, "applies": applies, "reason": reason})

        if self.cookie_auth:
            add("CSRF protection", True,
                f"browsers send credentials automatically (cookie auth: {self.auth['cookie']})")
        elif header:
            add("CSRF protection", False, f"credentials are sent in request headers ({', '.join(header)}), which "
                "browsers do not attach to cross-site requests")
        else:
            add("CSRF protection", False, "no cookie-based authentication detected")
        add("JWT weaknesses", "jwt" in self.auth,
            f"JWTs are issued or verified ({self.auth['jwt']})" if "jwt" in self.auth else "no JWT library or usage")
        if self.keeps_passwords:
            where = (f"password field in {self.password_columns[0][0]}:{self.password_columns[0][1]}"
                     if self.password_columns else self.password_login)
            add("Password storage and comparison", True, f"the app stores or checks passwords itself ({where})")
        else:
            add("Password storage and comparison", False, "no stored password field or password check found "
                "(authentication may be delegated to an identity provider)")
        add("SQL injection", "sql" in self.datastores,
            f"SQL data layer ({self.datastores['sql']})" if "sql" in self.datastores else "no SQL driver or ORM")
        add("NoSQL (MongoDB) operator injection", "mongodb" in self.datastores,
            f"MongoDB data layer ({self.datastores['mongodb']})" if "mongodb" in self.datastores
            else "no MongoDB driver or ODM")
        add("File upload validation", bool(self.uploads),
            f"uploads are handled ({self.uploads})" if self.uploads else "no upload handling found")
        return rows

    def to_dict(self) -> dict:
        return {
            "web_frameworks": self.web_frameworks,
            "auth": self.auth,
            "datastores": self.datastores,
            "password_hashing": self.password_hashing,
            "password_columns": [f"{f}:{line}" for f, line in self.password_columns],
            "uploads": self.uploads,
            "server_rendered": self.server_rendered,
            "applicability": self.applicability(),
        }


def build_profile(ctx) -> AppProfile:
    profile = AppProfile(web_frameworks=sorted(set(ctx.languages.frameworks) & WEB_FRAMEWORKS))
    manifests = ctx.languages.manifests
    deps = {d.replace("_", "-") for d in python_dependencies(ctx.root, manifests)} | js_dependencies(ctx.root,
                                                                                                    manifests)
    for scheme, names in AUTH_DEPS.items():
        if hit := sorted(deps & names):
            profile.auth[scheme] = f"dependency {hit[0]}"
    if hit := sorted(deps & HASHING_DEPS):
        profile.password_hashing = f"dependency {hit[0]}"
    for store, names in (("sql", SQL_DEPS), ("mongodb", MONGO_DEPS), ("redis", REDIS_DEPS)):
        if hit := sorted(deps & names):
            profile.datastores[store] = f"dependency {hit[0]}"
    if "@prisma/client" in deps or "prisma" in deps:
        schema = next((f for f in ctx.files if f.endswith("schema.prisma")), None)
        provider = re.search(r'provider\s*=\s*"(\w+)"', re.sub(r"generator\s+\w+\s*\{[^}]*\}", "",
                                                               ctx.read(schema) or "")) if schema else None
        store = "mongodb" if provider and provider.group(1) == "mongodb" else "sql"
        profile.datastores.setdefault(store, f"Prisma ({provider.group(1) if provider else 'schema not found'})")

    sources = [f for f in ctx.files if f.endswith(CODE_SUFFIXES + SCHEMA_SUFFIXES) and not is_test_path(f)]
    for rel in sources[:MAX_FILES]:
        raw = ctx.read(rel) or ""
        if not raw:
            continue
        # Raw-string literals in Python are almost always regexes (e.g. a linter's own detection patterns naming
        # auth classes); they are not usage, so they do not count as evidence.
        text = PY_RAW_STRING.sub('""', raw) if rel.endswith(".py") else raw
        for scheme, pattern in AUTH_CODE.items():
            if scheme not in profile.auth and pattern.search(text):
                profile.auth[scheme] = rel
        if not profile.password_hashing and PASSWORD_HASHING.search(text):
            profile.password_hashing = rel
        if not profile.password_login and PASSWORD_LOGIN.search(text):
            profile.password_login = rel
        for pattern in PASSWORD_COLUMN:
            for m in pattern.finditer(raw):
                if len(profile.password_columns) < 20:
                    start = m.start() + len(m.group(0)) - len(m.group(0).lstrip())  # `^\s*` may span blank lines
                    profile.password_columns.append((rel, raw.count("\n", 0, start) + 1))
        if "sql" not in profile.datastores and (rel.endswith(".sql") or re.search(r"^\s*import sqlite3", text, re.M)):
            profile.datastores["sql"] = rel
        if not profile.uploads and UPLOADS.search(text):
            profile.uploads = rel
        if not profile.server_rendered and SERVER_RENDERED.search(text):
            profile.server_rendered = rel
    if "django" in profile.web_frameworks:
        profile.datastores.setdefault("sql", "Django ORM")
    return profile
