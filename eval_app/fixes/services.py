"""AI auto-fix: generate a reviewed diff for selected findings, then open it as a GitHub pull request."""

from __future__ import annotations

import difflib
import re
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from flask import current_app, url_for

from eval_engine.ai import AIError
from eval_engine.ai.fix import MAX_FILES, MAX_FINDINGS, FixTarget, generate_fixes
from eval_engine.workspace import DEFAULT_LIMITS, WorkspaceError, validate_relative_path

from .. import ai_config
from ..extensions import db
from ..integrations.github import GitHubError
from ..integrations.services import CredentialError, has_write_access, repo_client
from ..models import Audit, Finding, FixProposal, Organization, utcnow
from ..projects.repositories import upload_path
from ..security import events, ratelimit

MAX_SOURCE_BYTES = 512 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


class FixError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ request
def create_proposal(org: Organization, audit: Audit, finding_ids: list, user_id) -> FixProposal:
    if audit.status != "succeeded":
        raise FixError("Fixes can only be generated for a completed audit.")
    if not ai_config.ai_enabled(org.id):
        raise FixError("Auto-fix uses your AI provider. Enable AI under Settings → Integrations first.")
    findings = db.session.execute(
        db.select(Finding).where(Finding.id.in_(finding_ids), Finding.audit_id == audit.id,
                                 Finding.organization_id == org.id)
    ).scalars().all()
    order = {str(i): n for n, i in enumerate(finding_ids)}
    findings = sorted((f for f in findings if f.file_path), key=lambda f: order.get(str(f.id), len(order)))
    if not findings:
        raise FixError("Select at least one finding that points at a file.")
    if len(findings) > MAX_FINDINGS:
        raise FixError(f"Fix at most {MAX_FINDINGS} findings at a time.")
    if len({f.file_path for f in findings}) > MAX_FILES:
        raise FixError(f"Selected findings span more than {MAX_FILES} files; select fewer.")
    if not ratelimit.hit("autofix", str(org.id), 30, 3600):
        raise FixError("Too many fix requests this hour; try again later.")
    proposal = FixProposal(organization_id=org.id, audit_id=audit.id, created_by_id=user_id, status="queued",
                           finding_ids=[str(f.id) for f in findings])
    db.session.add(proposal)
    db.session.flush()
    events.record("fix.requested", organization_id=org.id, target=proposal, findings=len(findings))
    db.session.commit()
    _enqueue(proposal)
    return proposal


def _enqueue(proposal: FixProposal) -> None:
    from .tasks import generate_fix

    try:
        generate_fix.apply_async(args=[str(proposal.id)], queue="audits")
    except Exception as exc:  # broker unavailable
        current_app.logger.error("failed to enqueue fix %s: %s", proposal.id, type(exc).__name__)
        _fail(proposal, "The work queue is unavailable. Try again shortly.")
        db.session.commit()
        return
    db.session.refresh(proposal)  # eager mode: the task already ran and committed


def _fail(proposal: FixProposal, message: str) -> None:
    proposal.status = "failed"
    proposal.error = message[:2000]
    proposal.finished_at = utcnow()


# ---------------------------------------------------------------------------------------------- generate
def proposal_findings(proposal: FixProposal) -> list[Finding]:
    """The proposal's findings, in the order they were selected."""
    ids = [uuid.UUID(i) for i in proposal.finding_ids]
    rows = {f.id: f for f in db.session.execute(
        db.select(Finding).where(Finding.id.in_(ids), Finding.organization_id == proposal.organization_id)
    ).scalars()}
    return [rows[i] for i in ids if i in rows]


def _read_upload_file(audit: Audit, path: str) -> str:
    """A file from the audit's uploaded archive (GitHub-style wrapper directory tolerated)."""
    with zipfile.ZipFile(upload_path(audit.upload)) as zf:
        names = {i.filename.replace("\\", "/"): i for i in zf.infolist() if not i.is_dir()}
        info = names.get(path) or next((i for n, i in names.items() if n.split("/", 1)[-1] == path
                                        and n.count("/") == path.count("/") + 1), None)
        if info is None:
            raise FixError(f"{path} is not in the uploaded archive.")
        if info.file_size > MAX_SOURCE_BYTES:
            raise FixError(f"{path} is too large to fix automatically.")
        try:
            return zf.read(info).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FixError(f"{path} is not a UTF-8 text file.") from exc


def read_sources(audit: Audit, paths: set[str]) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """({path: text}, {path: blob sha}, {path: reason unreadable}) at the audited commit."""
    repo = audit.repository
    sources, blobs, problems = {}, {}, {}
    client = None
    for path in sorted(paths):
        try:
            validate_relative_path(path, DEFAULT_LIMITS)
        except WorkspaceError:
            problems[path] = "not a repository-relative path"
            continue
        try:
            if repo.source == "github":
                client = client or repo_client(repo)
                text, blob = client.get_file(repo.full_name, str(PurePosixPath(path)), audit.commit_sha,
                                             max_bytes=MAX_SOURCE_BYTES)
                blobs[path] = blob
            else:
                if audit.upload is None:
                    raise FixError("The uploaded archive is no longer available.")
                text = _read_upload_file(audit, path)
        except (GitHubError, CredentialError, FixError, OSError, zipfile.BadZipFile) as exc:
            problems[path] = str(exc)
            continue
        sources[path] = text
    return sources, blobs, problems


def unified_diff(path: str, before: str, after: str) -> str:
    lines = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                 fromfile=f"a/{path}", tofile=f"b/{path}")
    out = []
    for line in lines:
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return f"diff --git a/{path} b/{path}\n" + "".join(out)


def run_generation(proposal: FixProposal, provider=None) -> None:
    """Fill in ``proposal`` (called from the worker). ``provider`` overrides the org's AI settings in tests."""
    audit = proposal.audit
    findings = proposal_findings(proposal)
    sources, blobs, problems = read_sources(audit, {f.file_path for f in findings})
    targets = [FixTarget(id=str(f.id), rule_id=f.rule_id, title=f.title, severity=f.severity,
                         description=f.description, remediation=f.remediation, file_path=f.file_path,
                         line_start=f.line_start, line_end=f.line_end) for f in findings]
    unreadable = [{"id": t.id, "reason": f"Could not read {t.file_path}: {problems[t.file_path]}"}
                  for t in targets if t.file_path in problems]
    try:
        provider = provider or ai_config.build_ai_provider(proposal.organization_id)
        if provider is None:
            raise AIError("AI is disabled for this organization.")
        result = generate_fixes(provider, targets, sources)
    except AIError as exc:
        _fail(proposal, str(exc))
        proposal.results = {"fixed": [], "failed": unreadable}
        return
    proposal.ai_model = f"{result.provider} {result.model}"[:160]
    proposal.results = {"fixed": result.fixed, "failed": unreadable + result.failed}
    proposal.files = [{"path": p, "blob_sha": blobs.get(p, ""), "after": c} for p, c in sorted(result.files.items())]
    proposal.diff = "".join(unified_diff(p, sources[p], c) for p, c in sorted(result.files.items()))
    if result.files:
        proposal.status = "ready"
        if current_app.config.get("FIX_VERIFY", True):
            proposal.verification = run_verification(proposal, findings)
    else:
        _fail(proposal, "No safe change could be generated for the selected findings.")
    proposal.finished_at = utcnow()


# ------------------------------------------------------------------------------------------------ verify
# Dependency-vulnerability lookups: a code patch cannot change their result unless it touches a manifest.
VERIFY_SKIP = {"osv", "trivy"}


def run_verification(proposal: FixProposal, targets: list[Finding]) -> dict:
    """Re-audit the audited tree with the proposal's files applied; never raises."""
    from eval_engine.verify import BaselineFinding, select_analyzers, verify_patch
    from eval_engine.workspace import remove_tree

    from ..audits.workspaces import fetch_source, limits_from_config
    from ..policies import audit_policy

    audit = proposal.audit
    cfg = current_app.config
    files = {f["path"]: f["after"] for f in proposal.files}
    fixed = {i["id"] for i in proposal.results.get("fixed", [])}
    baseline = [BaselineFinding(fingerprint=f.fingerprint, rule_id=f.rule_id, file_path=f.file_path, title=f.title,
                                severity=f.severity, line_start=f.line_start, id=str(f.id), sources=list(f.sources))
                for f in db.session.execute(db.select(Finding).where(Finding.audit_id == audit.id,
                                                                    Finding.organization_id == audit.organization_id,
                                                                    Finding.kind != "ai_observation")).scalars()]
    by_id = {b.id: b for b in baseline}
    wanted = [by_id[str(t.id)] for t in targets if str(t.id) in fixed and str(t.id) in by_id]
    manifests_changed = any(p.rsplit("/", 1)[-1].lower().startswith(("requirements", "package", "pyproject", "poetry",
                                                                     "uv.lock")) for p in files)
    analyzers = select_analyzers(audit.tool_status or [], baseline, set(files),
                                 skip=set() if manifests_changed else VERIFY_SKIP)
    workdir = Path(cfg.get("WORK_DIR") or cfg["DATA_DIR"] / "work") / f"fix-{proposal.id.hex}"
    try:
        remove_tree(workdir)
        src = workdir / "src"
        src.mkdir(parents=True)
        limits = limits_from_config()
        sha, _ = fetch_source(audit, src, limits, ref=audit.commit_sha if audit.repository.source == "github" else None)
        if audit.commit_sha and sha[:12] != audit.commit_sha[:12]:
            return {"verdict": "error", "error": "The audited commit could not be fetched again."}
        result = verify_patch(src, files, wanted, baseline, analyzers, limits=limits,
                              tool_timeout=cfg["ANALYZER_TIMEOUT_SECONDS"], policy=audit_policy(audit))
        return result.to_dict()
    except Exception as exc:  # noqa: BLE001 - verification is evidence, not a precondition for generating
        current_app.logger.warning("fix %s verification failed: %s", proposal.id, type(exc).__name__)
        message = str(exc) if isinstance(exc, (WorkspaceError, ValueError)) else "internal error"
        return {"verdict": "error", "error": f"Verification could not run: {message}"[:500]}
    finally:
        remove_tree(workdir)


# -------------------------------------------------------------------------------------------- pull request
def _base_branch(audit: Audit) -> str:
    branch = audit.branch or ""
    if not branch or SHA_RE.match(branch):
        return audit.repository.default_branch or "main"
    return branch


def pr_body(proposal: FixProposal, findings: dict[str, Finding], link: str) -> str:
    lines = ["Automated fixes proposed by eVal for findings from a static audit.", ""]
    for item in proposal.results.get("fixed", []):
        f = findings.get(item["id"])
        if f is not None:
            lines.append(f"- **[{f.severity}] {f.title}** (`{f.location}`, rule `{f.rule_id}`): {item['summary']}")
    skipped = proposal.results.get("failed", [])
    if skipped:
        lines += ["", f"{len(skipped)} selected finding(s) were not changed; see eVal for the reasons."]
    lines += ["", *verification_summary(proposal.verification or {}, findings)]
    sha = proposal.audit.commit_sha[:12]
    lines += ["", f"<sub>Generated by AI ({proposal.ai_model}) from audited commit `{sha}` · [view in eVal]({link}). "
              "Review carefully and run your tests before merging.</sub>"]
    return "\n".join(lines)


VERDICT_TEXT = {
    "passed": "✅ **Verified by re-audit:** every fixed finding is gone and no new finding was introduced.",
    "partial": "🟡 **Partially verified:** nothing new was introduced, but some targeted findings are still reported.",
    "regressed": "❌ **Re-audit found new problems** introduced by this change.",
    "incomplete": "⚪ **Verification incomplete:** some analyzers could not re-run.",
    "error": "⚪ **Not verified:** the re-audit could not run.",
}


def verification_summary(v: dict, findings: dict[str, Finding]) -> list[str]:
    """Markdown lines describing a verification result (PR body)."""
    if not v:
        return ["⚪ **Not verified:** this fix was not re-audited."]
    lines = [VERDICT_TEXT.get(v.get("verdict"), VERDICT_TEXT["error"])]
    for fid in v.get("still_present", []):
        if fid in findings:
            lines.append(f"- still reported: {findings[fid].title} (`{findings[fid].location}`)")
    for item in v.get("introduced", [])[:20]:
        loc = f"{item['file_path']}:{item['line_start']}" if item.get("line_start") else item["file_path"]
        lines.append(f"- new: [{item['severity']}] {item['title']} (`{loc}`, rule `{item['rule_id']}`)")
    for item in v.get("incomplete", [])[:10]:
        lines.append(f"- not re-run: {item['name']} ({item['reason']})")
    if v.get("analyzers"):
        lines.append(f"<sub>Re-audited with: {', '.join(v['analyzers'])}.</sub>")
    return lines


def open_pull_request(org: Organization, proposal: FixProposal, user_id, *, accept_regression: bool = False) -> str:
    audit = proposal.audit
    repo = audit.repository
    if proposal.status != "ready":
        raise FixError("Only a generated, unpublished fix can be opened as a pull request.")
    if (proposal.verification or {}).get("verdict") == "regressed" and not accept_regression:
        raise FixError("The re-audit found new problems in this change. Review them and confirm that you want to "
                       "open the pull request anyway.")
    if repo.source != "github":
        raise FixError("Pull requests need a GitHub repository; download the patch instead.")
    if not has_write_access(repo):
        raise FixError("Attach a GitHub credential with Contents and Pull requests write access to this "
                       "repository first.")
    findings = {str(f.id): f for f in proposal_findings(proposal)}
    branch = f"eval/fix-{proposal.id.hex[:10]}"
    base = _base_branch(audit)
    link = url_for("fixes.detail", org_slug=org.slug, fix_id=proposal.id, _external=True)
    titles = [findings[i["id"]].title for i in proposal.results.get("fixed", []) if i["id"] in findings]
    title = f"[eVal] Fix: {titles[0]}" if len(titles) == 1 else f"[eVal] Fix {len(titles)} audit findings"
    try:
        client = repo_client(repo)
        client.create_branch(repo.full_name, branch, audit.commit_sha)
        for f in proposal.files:
            client.update_file(repo.full_name, f["path"], branch=branch, content=f["after"], blob_sha=f["blob_sha"],
                               message=f"eVal: fix audit findings in {f['path']}")
        pr = client.create_pull(repo.full_name, title=title, body=pr_body(proposal, findings, link), head=branch,
                                base=base)
    except (GitHubError, CredentialError) as exc:
        raise FixError(f"GitHub: {exc}") from exc
    proposal.status = "pr_opened"
    proposal.branch = branch
    proposal.pr_number = pr["number"]
    proposal.pr_url = pr["html_url"]
    events.record("fix.pr_opened", organization_id=org.id, target=proposal, actor_id=user_id, pr=pr["number"],
                  verdict=(proposal.verification or {}).get("verdict", "none"), accepted_regression=accept_regression)
    db.session.commit()
    return pr["html_url"]


def proposals_for(audit: Audit) -> list[FixProposal]:
    return list(db.session.execute(
        db.select(FixProposal).where(FixProposal.audit_id == audit.id,
                                     FixProposal.organization_id == audit.organization_id)
        .order_by(FixProposal.created_at.desc()).limit(10)
    ).scalars())
