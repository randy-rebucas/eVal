"""CORS for the JSON API, so browser-hosted clients (the VS Code extension on vscode.dev / github.dev) can call it.

The API authenticates with bearer tokens only and never reads cookies, so a cross-origin page learns nothing without
a token it already holds. ``Access-Control-Allow-Credentials`` is never sent. Origins come from ``API_CORS_ORIGINS``.
"""

from __future__ import annotations

import re

from flask import current_app, request

_HOST_LABELS = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*$")


def origin_allowed(origin: str, patterns: list[str]) -> bool:
    origin = origin.lower()
    for pattern in patterns:
        pattern = pattern.lower()
        if pattern == "*" or pattern == origin:
            return True
        if "://*." in pattern:
            prefix, suffix = pattern.split("://*.", 1)
            head = f"{prefix}://"
            if origin.startswith(head) and origin.endswith(f".{suffix}"):
                sub = origin[len(head):-len(suffix) - 1]
                if _HOST_LABELS.match(sub):
                    return True
    return False


def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if not origin or not origin_allowed(origin, current_app.config.get("API_CORS_ORIGINS") or []):
        return response
    response.headers["Access-Control-Allow-Origin"] = origin
    response.vary.add("Origin")
    if request.method == "OPTIONS":
        response.headers["Access-Control-Allow-Methods"] = "GET, POST"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Max-Age"] = "600"
    return response
