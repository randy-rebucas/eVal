"""eVal SaaS application factory."""

from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, render_template, request

from .extensions import csrf, db, login_manager, migrate

__version__ = "0.1.0"


def create_app(config_name: str | None = None, overrides: dict | None = None) -> Flask:
    # Imported here, not at module level: config classes read os.environ when first imported, and entry points
    # (wsgi.py, celery_worker.py) load a local .env before calling create_app().
    from . import config as config_module

    app = Flask(__name__)
    name = config_name or os.environ.get("EVAL_ENV", "production")
    app.config.from_object(config_module.CONFIGS[name])
    if overrides:
        app.config.update(overrides)
    config_module.validate(app.config)
    if app.config.get("PROXY_FIX_HOPS"):
        from werkzeug.middleware.proxy_fix import ProxyFix

        hops = int(app.config["PROXY_FIX_HOPS"])
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops)

    app.config["DATA_DIR"].mkdir(parents=True, exist_ok=True)
    _configure_logging(app)

    db.init_app(app)
    migrate.init_app(app, db, directory=_migrations_dir())
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    from . import models  # noqa: F401  (register models with SQLAlchemy metadata)

    @login_manager.user_loader
    def load_user(user_id: str):
        import uuid

        try:
            return db.session.get(models.User, uuid.UUID(user_id))
        except ValueError:
            return None

    from .audits.routes import bp as audits_bp
    from .auth.routes import bp as auth_bp
    from .findings.routes import bp as findings_bp
    from .integrations.routes import bp as integrations_bp
    from .orgs.routes import bp as orgs_bp
    from .projects.repo_routes import bp as repos_bp
    from .projects.routes import bp as projects_bp

    for bp in (auth_bp, orgs_bp, projects_bp, repos_bp, audits_bp, findings_bp, integrations_bp):
        app.register_blueprint(bp)

    from .api.routes import bp as api_bp

    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)  # bearer-token API: no ambient cookie credentials, so CSRF does not apply

    from .celery_app import init_celery

    init_celery(app)
    _register_security_headers(app)
    _register_error_handlers(app)
    _register_template_helpers(app)
    _register_cli(app)
    return app


def _migrations_dir() -> str:
    """Source checkout: <repo>/migrations. Installed package (Docker): ./migrations in the working directory.
    EVAL_MIGRATIONS_DIR overrides both."""
    explicit = os.environ.get("EVAL_MIGRATIONS_DIR")
    if explicit:
        return explicit
    beside_package = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "migrations"))
    if os.path.isdir(beside_package):
        return beside_package
    return os.path.abspath("migrations")


def _configure_logging(app: Flask) -> None:
    from eval_engine.redaction import RedactingFilter

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    app.logger.handlers[:] = [handler]
    app.logger.setLevel(logging.DEBUG if app.debug else logging.INFO)


def _register_security_headers(app: Flask) -> None:
    # CDN sources are pinned to the exact package versions base.html loads (with SRI), not the whole CDN, which
    # serves any npm package and would let an injected <script> pull in arbitrary code.
    bootstrap = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/"
    icons = "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/"
    csp = (
        "default-src 'self'; "
        f"style-src 'self' {bootstrap} {icons}; "
        f"script-src 'self' {bootstrap}; "
        f"img-src 'self' data:; font-src 'self' {icons}; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )

    @app.after_request
    def headers(response):
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


def _wants_json() -> bool:
    return request.path.startswith("/api/")


def _register_error_handlers(app: Flask) -> None:
    for code, message in (
        (400, "Bad request"),
        (403, "Forbidden"),
        (404, "Not found"),
        (413, "Upload too large"),
        (429, "Too many requests"),
    ):

        def handler(_err, code=code, message=message):
            if _wants_json():
                return jsonify(error=message), code
            return render_template("error.html", code=code, message=message), code

        app.register_error_handler(code, handler)

    @app.errorhandler(500)
    def server_error(_err):
        if _wants_json():
            return jsonify(error="Internal server error"), 500
        return render_template("error.html", code=500, message="Internal server error"), 500


def _register_template_helpers(app: Flask) -> None:
    from eval_engine.findings import SEVERITY_ORDER

    @app.context_processor
    def inject():
        return {"app_version": __version__, "severity_order": SEVERITY_ORDER}

    @app.template_filter("dt")
    def fmt_dt(value):
        return value.strftime("%Y-%m-%d %H:%M UTC") if value else "—"

    @app.template_filter("score")
    def fmt_score(value):
        return "—" if value is None else f"{value:.0f}"


def _register_cli(app: Flask) -> None:
    import click

    @app.cli.command("create-user")
    @click.argument("email")
    @click.option("--name", default="")
    @click.option("--org", "org_name", default=None, help="Create an organization owned by this user")
    @click.password_option()
    def create_user(email, name, org_name, password):
        """Create a user (and optionally an organization they own)."""
        from .auth.services import AuthError, register_user

        try:
            user, org = register_user(email=email, password=password, name=name, org_name=org_name)
        except AuthError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"created user {user.email}" + (f" with org {org.slug}" if org else ""))
