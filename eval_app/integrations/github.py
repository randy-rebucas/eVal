"""Minimal GitHub REST client. Tokens are held only in memory for the life of the client and never logged."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import requests

FULL_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
DEFAULT_TIMEOUT = (5, 20)


class GitHubError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class RepoInfo:
    full_name: str
    default_branch: str
    private: bool
    size_kb: int
    html_url: str
    clone_url: str


def validate_full_name(full_name: str) -> str:
    full_name = full_name.strip().removeprefix("https://github.com/").removesuffix(".git").strip("/")
    if not FULL_NAME_RE.match(full_name) or full_name.endswith((".", "..")):
        raise GitHubError("Repository must be in the form owner/name.")
    return full_name


def _error_message(resp) -> str:
    """GitHub's own reason (and, for fine-grained tokens, the permission it wanted) — never echoes the token."""
    msg = f"GitHub API error ({resp.status_code})"
    try:
        detail = str((resp.json() or {}).get("message") or "").strip()
    except ValueError:
        detail = ""
    if detail:
        msg += f": {detail[:200]}"
    needed = resp.headers.get("X-Accepted-GitHub-Permissions")
    if resp.status_code == 403 and needed:
        msg += f" (token needs: {needed[:100]})"
    return msg + "."


OAUTH_SCOPE = "repo"  # private repository contents and issues; OAuth apps have no finer read-only scope


def oauth_authorize_url(web_url: str, client_id: str, redirect_uri: str, state: str) -> str:
    query = urlencode({"client_id": client_id, "redirect_uri": redirect_uri, "scope": OAUTH_SCOPE,
                       "state": state, "allow_signup": "false"})
    return f"{web_url.rstrip('/')}/login/oauth/authorize?{query}"


def exchange_oauth_code(web_url: str, client_id: str, client_secret: str, code: str, redirect_uri: str) -> str:
    """Trade the callback's one-time ``code`` for an access token. Errors never include the secret or token."""
    try:
        resp = requests.post(
            f"{web_url.rstrip('/')}/login/oauth/access_token",
            data={"client_id": client_id, "client_secret": client_secret, "code": code,
                  "redirect_uri": redirect_uri},
            headers={"Accept": "application/json", "User-Agent": "eVal-auditor"},
            timeout=DEFAULT_TIMEOUT,
        )
        data = resp.json() if resp.content else {}
    except (requests.RequestException, ValueError) as exc:
        raise GitHubError("Could not reach GitHub.") from exc
    token = data.get("access_token") if resp.status_code == 200 else None
    if not token:
        reason = str(data.get("error_description") or data.get("error") or resp.status_code)[:200]
        raise GitHubError(f"GitHub sign-in failed: {reason}.")
    return token


class GitHubClient:
    def __init__(self, token: str | None, api_url: str = "https://api.github.com", session=None):
        self.api_url = api_url.rstrip("/")
        self._session = session or requests.Session()
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "eVal-auditor",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.api_url}{path}"
        try:
            resp = self._session.request(method, url, headers=self._headers, timeout=DEFAULT_TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise GitHubError("Could not reach GitHub.") from exc
        if resp.status_code == 401:
            raise GitHubError("GitHub rejected the credential (401).", 401)
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            raise GitHubError("GitHub API rate limit exceeded.", 403)
        if resp.status_code == 404:
            raise GitHubError("Not found on GitHub, or the credential lacks access.", 404)
        if resp.status_code >= 400:
            raise GitHubError(_error_message(resp), resp.status_code)
        return resp.json() if resp.content else {}

    def get_user(self) -> dict:
        data = self._request("GET", "/user")
        return {"login": data.get("login", "")}

    def get_repo(self, full_name: str) -> RepoInfo:
        full_name = validate_full_name(full_name)
        d = self._request("GET", f"/repos/{full_name}")
        return RepoInfo(
            full_name=d["full_name"],
            default_branch=d.get("default_branch") or "main",
            private=bool(d.get("private")),
            size_kb=int(d.get("size") or 0),
            html_url=d.get("html_url", ""),
            clone_url=d.get("clone_url") or f"https://github.com/{d['full_name']}.git",
        )

    def list_repos(self, owner: str | None = None, limit: int = 1000) -> list[dict]:
        """Repositories the token can see (every page, most recently updated first), or, with ``owner``, that
        user's or organization's repositories visible to the client (public ones when unauthenticated)."""
        if owner:
            if not OWNER_RE.match(owner):
                raise GitHubError("Owner must be a GitHub user or organization name.")
            path, params = f"/users/{owner}/repos", {"type": "owner"}
        else:
            path, params = "/user/repos", {"affiliation": "owner,collaborator,organization_member"}
        params.update(sort="updated", per_page=100)
        out: list[dict] = []
        page = 1
        while len(out) < limit:
            data = self._request("GET", path, params={**params, "page": page})
            if not data:
                break
            out.extend(
                {
                    "full_name": r["full_name"],
                    "private": bool(r.get("private")),
                    "archived": bool(r.get("archived")),
                    "fork": bool(r.get("fork")),
                    "description": (r.get("description") or "")[:200],
                    "updated_at": r.get("pushed_at") or r.get("updated_at") or "",
                }
                for r in data
            )
            if len(data) < 100:
                break
            page += 1
        return out[:limit]

    def list_branches(self, full_name: str, limit: int = 100) -> list[str]:
        full_name = validate_full_name(full_name)
        data = self._request("GET", f"/repos/{full_name}/branches", params={"per_page": min(limit, 100)})
        return [b["name"] for b in data][:limit]

    def list_commits(self, full_name: str, branch: str, limit: int = 20) -> list[dict]:
        full_name = validate_full_name(full_name)
        data = self._request(
            "GET", f"/repos/{full_name}/commits", params={"sha": branch, "per_page": min(limit, 100)}
        )
        out = []
        for c in data[:limit]:
            commit = c.get("commit", {})
            out.append(
                {
                    "sha": c.get("sha", ""),
                    "message": (commit.get("message") or "").splitlines()[0][:120] if commit.get("message") else "",
                    "author": (commit.get("author") or {}).get("name", ""),
                    "date": (commit.get("author") or {}).get("date", ""),
                }
            )
        return out

    def get_pull(self, full_name: str, number: int) -> dict:
        full_name = validate_full_name(full_name)
        d = self._request("GET", f"/repos/{full_name}/pulls/{int(number)}")
        return {
            "number": d["number"],
            "head_sha": d["head"]["sha"],
            "head_ref": d["head"].get("ref", ""),
            "base_ref": d["base"].get("ref", ""),
            "state": d.get("state", ""),
            "title": d.get("title", ""),
        }

    def list_pull_files(self, full_name: str, number: int, limit: int = 3000) -> list[str]:
        """Changed file paths (GitHub caps this listing at 3000 files)."""
        return [f["path"] for f in self.list_pull_file_stats(full_name, number, limit) if f["status"] != "removed"]

    def list_pull_file_stats(self, full_name: str, number: int, limit: int = 3000) -> list[dict]:
        """[{path, status, additions, deletions}] for every file the pull request touches (removed ones too)."""
        full_name = validate_full_name(full_name)
        files: list[dict] = []
        page = 1
        while len(files) < limit:
            data = self._request("GET", f"/repos/{full_name}/pulls/{int(number)}/files",
                                 params={"per_page": 100, "page": page})
            if not data:
                break
            files.extend({"path": f["filename"], "status": f.get("status", ""),
                          "additions": int(f.get("additions") or 0), "deletions": int(f.get("deletions") or 0)}
                         for f in data)
            if len(data) < 100:
                break
            page += 1
        return files[:limit]

    def create_issue_comment(self, full_name: str, number: int, body: str) -> dict:
        full_name = validate_full_name(full_name)
        d = self._request("POST", f"/repos/{full_name}/issues/{int(number)}/comments", json={"body": body[:65000]})
        return {"html_url": d.get("html_url", "")}

    def get_file(self, full_name: str, path: str, ref: str, max_bytes: int = 1_000_000) -> tuple[str, str]:
        """(UTF-8 text, blob sha) of a file at ``ref``."""
        full_name = validate_full_name(full_name)
        d = self._request("GET", f"/repos/{full_name}/contents/{quote(path)}", params={"ref": ref})
        if not isinstance(d, dict) or d.get("type") != "file":
            raise GitHubError(f"{path} is not a file.")
        if int(d.get("size") or 0) > max_bytes or d.get("encoding") != "base64":
            raise GitHubError(f"{path} is too large to fix automatically.")
        try:
            text = base64.b64decode(d.get("content") or "").decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise GitHubError(f"{path} is not a UTF-8 text file.") from exc
        return text, d["sha"]

    def create_branch(self, full_name: str, branch: str, sha: str) -> None:
        full_name = validate_full_name(full_name)
        self._request("POST", f"/repos/{full_name}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})

    def update_file(self, full_name: str, path: str, *, branch: str, content: str, blob_sha: str,
                    message: str) -> None:
        """Commit new content for an existing file (fails if the file changed since ``blob_sha``)."""
        full_name = validate_full_name(full_name)
        self._request("PUT", f"/repos/{full_name}/contents/{quote(path)}", json={
            "message": message[:500], "branch": branch, "sha": blob_sha,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        })

    def create_pull(self, full_name: str, *, title: str, body: str, head: str, base: str) -> dict:
        full_name = validate_full_name(full_name)
        d = self._request("POST", f"/repos/{full_name}/pulls", json={
            "title": title[:256], "body": body[:65000], "head": head, "base": base, "maintainer_can_modify": True,
        })
        return {"number": d["number"], "html_url": d["html_url"]}

    def create_issue(self, full_name: str, title: str, body: str, labels: list[str] | None = None) -> dict:
        full_name = validate_full_name(full_name)
        payload = {"title": title[:256], "body": body[:65000]}
        if labels:
            payload["labels"] = labels
        d = self._request("POST", f"/repos/{full_name}/issues", json=payload)
        return {"number": d["number"], "html_url": d["html_url"]}

    # ------------------------------------------------------------------ GitHub App (see github_app.py)
    def create_installation_token(self, installation_id: int) -> dict:
        """App-JWT client only: a one-hour token for ``installation_id``."""
        d = self._request("POST", f"/app/installations/{int(installation_id)}/access_tokens")
        return {"token": d["token"], "expires_at": d.get("expires_at", "")}

    def get_installation(self, installation_id: int) -> dict:
        """App-JWT client only."""
        d = self._request("GET", f"/app/installations/{int(installation_id)}")
        account = d.get("account") or {}
        return {"id": d["id"], "account_login": account.get("login", ""), "account_type": account.get("type", ""),
                "suspended": bool(d.get("suspended_at"))}

    def user_installation_ids(self, limit: int = 500) -> set[int]:
        """User-token client: installations of this App the signed-in user can access."""
        ids: set[int] = set()
        page = 1
        while len(ids) < limit:
            d = self._request("GET", "/user/installations", params={"per_page": 100, "page": page})
            items = d.get("installations") or []
            ids.update(int(i["id"]) for i in items)
            if len(items) < 100:
                break
            page += 1
        return ids

    def create_check_run(self, full_name: str, *, name: str, head_sha: str, details_url: str = "",
                         external_id: str = "", status: str = "in_progress", output: dict | None = None) -> dict:
        full_name = validate_full_name(full_name)
        payload = {"name": name, "head_sha": head_sha, "status": status}
        if details_url:
            payload["details_url"] = details_url
        if external_id:
            payload["external_id"] = external_id
        if output:
            payload["output"] = output
        d = self._request("POST", f"/repos/{full_name}/check-runs", json=payload)
        return {"id": d["id"], "html_url": d.get("html_url", "")}

    def update_check_run(self, full_name: str, check_run_id: int, **fields) -> None:
        full_name = validate_full_name(full_name)
        self._request("PATCH", f"/repos/{full_name}/check-runs/{int(check_run_id)}", json=fields)
