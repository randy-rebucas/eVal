"""Fixtures shared by app tests."""

from __future__ import annotations

import pytest

from eval_app.integrations.github import GitHubClient, GitHubError

FAST = ["secrets", "devops", "api_security", "database", "testing"]


@pytest.fixture(autouse=True)
def fast_analyzers(monkeypatch):
    """App tests exercise the web/worker flow; restrict to built-in analyzers to keep them fast."""
    from eval_engine.analyzers import registry

    real_get = registry.get
    monkeypatch.setattr(registry, "get", lambda names: real_get(names if names is not None else FAST))



@pytest.fixture
def fake_github(monkeypatch):
    calls = []
    issues = []
    repos = {
        "octo/shop": {"full_name": "octo/shop", "default_branch": "main", "private": False, "size": 120,
                      "html_url": "https://github.com/octo/shop", "clone_url": "https://github.com/octo/shop.git"},
        "octo/huge": {"full_name": "octo/huge", "default_branch": "main", "private": True, "size": 10_000_000},
    }

    def fake_request(self, method, path, **kwargs):
        calls.append((method, path, self._headers.get("Authorization")))
        if path == "/user":
            if self._headers.get("Authorization") != "Bearer ghp_validtoken1234567890":
                raise GitHubError("GitHub rejected the credential (401).", 401)
            return {"login": "octocat"}
        if path.startswith("/repos/") and path.count("/") == 3:
            name = path[len("/repos/"):]
            if name not in repos:
                raise GitHubError("Not found on GitHub, or the credential lacks access.", 404)
            return repos[name]
        if path.endswith("/branches"):
            return [{"name": "main"}, {"name": "develop"}]
        if path.endswith("/commits"):
            return [{"sha": "a" * 40, "commit": {"message": "Fix bug\n\nbody", "author": {"name": "Ann"}}}]
        if path.endswith("/issues") and method == "POST":
            issues.append(kwargs.get("json"))
            n = len(issues)
            return {"number": n, "html_url": f"https://github.com/octo/shop/issues/{n}"}
        if path == "/repos/octo/shop/pulls/5":
            return {"number": 5, "state": pull_state["state"], "title": "Add export",
                    "head": {"sha": "d" * 40, "ref": "feature/export"}, "base": {"ref": "main"}}
        if path == "/repos/octo/shop/pulls/5/files":
            page = kwargs.get("params", {}).get("page", 1)
            return [{"filename": "export.py", "status": "added"}, {"filename": "gone.py", "status": "removed"}] \
                if page == 1 else []
        if path == "/repos/octo/shop/issues/5/comments" and method == "POST":
            comments.append(kwargs["json"]["body"])
            return {"html_url": "https://github.com/octo/shop/pull/5#issuecomment-1"}
        raise AssertionError(path)

    comments: list[str] = []
    pull_state = {"state": "open"}
    monkeypatch.setattr(GitHubClient, "_request", fake_request)
    return {"calls": calls, "issues": issues, "comments": comments, "pull_state": pull_state}
