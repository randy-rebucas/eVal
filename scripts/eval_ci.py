#!/usr/bin/env python3
"""eVal CI gate: trigger an audit through the eVal API, wait for it, and fail the build on findings.

Standard library only, so it runs in any CI image with Python 3.9+.

    EVAL_URL=https://eval.example.com EVAL_TOKEN=evl_... \
      python eval_ci.py --repository <repo-id> --pr 42 --fail-on high --sarif eval.sarif

For pull requests only findings *introduced in changed files* (relative to the base branch's latest audit)
are gated. Exit codes: 0 pass, 1 gate failed, 2 usage/API error, 3 audit failed or timed out.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def check_url(base: str) -> str:
    parts = urllib.parse.urlsplit(base)
    local = parts.hostname in ("localhost", "127.0.0.1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise SystemExit("EVAL_URL must be an https:// URL (http:// is allowed only for localhost).")
    return base.rstrip("/")


def multipart_zip(path: str) -> tuple[bytes, str]:
    boundary = "----eval" + uuid.uuid4().hex
    with open(path, "rb") as fh:
        payload = fh.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"source.zip\"\r\n"
            "Content-Type: application/zip\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def call(base: str, token: str, method: str, path: str, body: dict | None = None, raw: bool = False,
         archive: str | None = None):
    content_type = None
    if archive:
        data, content_type = multipart_zip(archive)
    else:
        data = json.dumps(body).encode() if body is not None else None
        content_type = "application/json" if data is not None else None
    url = check_url(base) + "/api/v1" + path  # scheme restricted to https (or http on localhost)
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310  # nosec B310
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310  # nosec B310
            payload = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise SystemExit(f"eVal API {method} {path} failed: HTTP {exc.code} {detail}") from None
    return payload.decode("utf-8") if raw else json.loads(payload)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--url", default=os.environ.get("EVAL_URL"))
    p.add_argument("--repository", required=True, help="eVal repository id")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--pr", type=int, help="pull request number")
    g.add_argument("--ref", help="branch, tag or commit SHA (default: repository default branch)")
    g.add_argument("--archive", help="upload this .zip of the checkout (for upload-type repositories)")
    p.add_argument("--fail-on", choices=SEVERITIES[:4] + ["never", "policy"], default="high",
                   help="severity threshold, or 'policy' to use the gate of the policy configured in eVal")
    p.add_argument("--timeout", type=int, default=1800, help="seconds to wait for the audit")
    p.add_argument("--sarif", help="write a SARIF report to this path (for code-scanning upload)")
    p.add_argument("--comment", action="store_true", help="post a summary comment on the PR")
    args = p.parse_args(argv)
    token = os.environ.get("EVAL_TOKEN")
    if not args.url or not token:
        print("EVAL_URL (or --url) and EVAL_TOKEN must be set", file=sys.stderr)
        return 2
    try:
        check_url(args.url)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.archive and not os.path.isfile(args.archive):
        print(f"archive not found: {args.archive}", file=sys.stderr)
        return 2

    if args.pr:
        started = call(args.url, token, "POST", f"/repositories/{args.repository}/pulls/{args.pr}/audits")
    elif args.archive:
        started = call(args.url, token, "POST", f"/repositories/{args.repository}/audits", archive=args.archive)
    else:
        started = call(args.url, token, "POST", f"/repositories/{args.repository}/audits",
                       {"ref": args.ref} if args.ref else {})
    audit_id = started["audit"]["id"]
    print(f"eVal audit {audit_id} started: {started['audit']['url']}")

    deadline = time.monotonic() + args.timeout
    while True:
        audit = call(args.url, token, "GET", f"/audits/{audit_id}")["audit"]
        if audit["status"] in ("succeeded", "failed", "cancelled"):
            break
        if time.monotonic() > deadline:
            print("timed out waiting for the audit", file=sys.stderr)
            return 3
        time.sleep(5)
    if audit["status"] != "succeeded":
        print(f"audit {audit['status']}: {audit.get('error', '')}", file=sys.stderr)
        return 3

    print(f"overall score {audit['overall_score']} | risk {audit['risk_level']}")
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(call(args.url, token, "GET", f"/audits/{audit_id}/report.sarif", raw=True))
    if args.comment and args.pr:
        print("PR comment:", call(args.url, token, "POST", f"/audits/{audit_id}/pr-comment")["comment_url"])

    if args.pr:
        findings = call(args.url, token, "GET", f"/audits/{audit_id}/findings?introduced=1")["findings"]
        scope = "introduced in this pull request"
    else:
        findings, page = [], 1
        while True:
            data = call(args.url, token, "GET", f"/audits/{audit_id}/findings?page={page}")
            findings += data["findings"]
            if page >= data["pages"]:
                break
            page += 1
        scope = "open"
    findings = [f for f in findings if f["kind"] != "ai_observation"]
    for f in findings[:25]:
        loc = f"{f['file_path']}:{f['line_start']}" if f.get("line_start") else (f["file_path"] or "(repository)")
        print(f"  [{f['severity'].upper():8}] {f['title']}  {loc}")
    if args.fail_on == "never":
        return 0
    if args.fail_on == "policy":
        gate = audit.get("gate") or {}
        for reason in gate.get("reasons", []):
            print(f"gate: {reason}", file=sys.stderr)
        print("PASS: policy gate passed." if gate.get("passed") else "FAIL: policy gate failed.",
              file=sys.stdout if gate.get("passed") else sys.stderr)
        return 0 if gate.get("passed") else 1
    threshold = SEVERITIES.index(args.fail_on)
    blocking = [f for f in findings if SEVERITIES.index(f["severity"]) <= threshold]
    if blocking:
        print(f"FAIL: {len(blocking)} {scope} finding(s) at or above '{args.fail_on}'.", file=sys.stderr)
        return 1
    print(f"PASS: no {scope} findings at or above '{args.fail_on}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
