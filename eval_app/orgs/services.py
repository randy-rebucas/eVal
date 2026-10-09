from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy.orm import selectinload

from eval_engine.findings import CATEGORY_LABELS, Category
from eval_engine.scoring import CRITICAL_CATEGORIES, RISK_ORDER, SCORING_VERSION, risk_for

from ..extensions import db
from ..models import ROLES, Audit, Finding, Membership, Organization, Repository, User, utcnow
from ..security import events
from ..security.tenancy import role_at_least

# A repository whose newest successful audit is older than this is flagged as stale on the dashboard.
STALE_AFTER_DAYS = 30
# Accepted risks whose review date falls within this window are called out as due.
ACCEPTED_DUE_DAYS = 14
HISTORY_LENGTH = 10
NOT_ASSESSED = "Not assessed"
# Dashboard order: unknown risk sorts above Low, because "never checked" is not "checked and fine".
PORTFOLIO_RANK = {"Critical": 0, "High": 1, "Moderate": 2, NOT_ASSESSED: 3, "Low": 4}
# Two-letter codes that label the dashboard's coverage cells, in Category order.
CATEGORY_CODES = {
    Category.SECURITY: "SE", Category.ARCHITECTURE: "AR", Category.TESTING: "TE", Category.DATABASE: "DB",
    Category.API: "AP", Category.DEPENDENCIES: "DE", Category.PERFORMANCE: "PE", Category.DEVOPS: "OP",
    Category.MAINTAINABILITY: "MA",
}
# Dashboard state filters: the attention notes link to these.
STATES = ("failed", "running", "stale", "partial", "due")
REVISION_LIMIT = 12
SCORING = SCORING_VERSION


class OrgError(Exception):
    pass


def user_orgs(user: User) -> list[tuple[Organization, str]]:
    rows = db.session.execute(
        db.select(Organization, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.name)
    ).all()
    return [(org, role) for org, role in rows]


@dataclass
class Reason:
    """Why a repository has its risk level: the category that sets it and, when a single finding capped that
    category, the finding's title."""

    category: str
    label: str
    finding: str = ""
    detail: str = ""  # e.g. "confirmed critical finding" or "scored 38"


@dataclass
class PortfolioRow:
    repo: Repository
    latest: Audit | None  # newest successful branch audit (pull-request audits never describe the repository)
    attempt: Audit | None  # a newer audit that has not succeeded: queued, running, failed or cancelled
    history: list[Audit]
    open: dict[str, int]
    accepted: dict[str, int]
    accepted_owners: list[str] = field(default_factory=list)  # every owner, soonest review first
    accepted_review: date | None = None  # the soonest review date among accepted risks
    reason: Reason | None = None
    coverage: list[dict] = field(default_factory=list)
    age_days: int | None = None
    # Critical/high finding titles in the latest audit -> "open" or "accepted_risk"; used to find patterns that
    # repeat across repositories.
    flagged: dict[str, str] = field(default_factory=dict)

    @property
    def missing(self) -> list[str]:
        return [c["label"] for c in self.coverage if not c["assessed"]]

    def in_state(self, state: str, due_by: date) -> bool:
        if state == "failed":
            return bool(self.attempt and self.attempt.status == "failed")
        if state == "running":
            return bool(self.attempt and self.attempt.status in ("queued", "running"))
        if state == "stale":
            return self.stale
        if state == "partial":
            return bool(self.latest) and 0 < self.assessed < len(self.coverage)
        if state == "due":
            return bool(self.accepted_review and self.accepted_review <= due_by)
        return True

    def settled(self, due_by: date) -> bool:
        """Needs no attention: Low risk with every category assessed, and nothing failed, unfinished, stale or due
        for review. The dashboard folds these rows beneath the register."""
        return (self.risk == "Low" and bool(self.coverage) and self.assessed == len(self.coverage)
                and self.attempt is None and not self.stale and not self.in_state("due", due_by))

    @property
    def flat(self) -> bool:
        """Every category assessed and none above Low: the coverage cells would say nothing the count doesn't."""
        return bool(self.coverage) and all(c["assessed"] and c["risk"] == "Low" for c in self.coverage)

    @property
    def risk(self) -> str:
        return (self.latest.risk_level or NOT_ASSESSED) if self.latest else NOT_ASSESSED

    @property
    def assessed(self) -> int:
        return sum(1 for c in self.coverage if c["assessed"])

    @property
    def stale(self) -> bool:
        return self.age_days is not None and self.age_days > STALE_AFTER_DAYS

    @property
    def average_risk(self) -> str:
        """The risk the weighted average alone would give; differs from ``risk`` when a ceiling escalated it."""
        if not self.latest or self.latest.overall_score is None:
            return ""
        return risk_for(self.latest.overall_score)

    @property
    def previous_risk(self) -> str:
        """Risk level of the successful audit before the latest, when it differs: the change since last check."""
        if len(self.history) < 2:
            return ""
        before = self.history[-2].risk_level or NOT_ASSESSED
        return before if before != self.risk else ""

    @property
    def escalated(self) -> bool:
        return bool(self.average_risk) and self.average_risk != self.risk


def _reason(scores: dict, risk: str, worst: dict[str, tuple[str, str]] | None = None) -> Reason | None:
    """Name the category that sets the overall risk (mirrors ``eval_engine.scoring.escalate_overall_risk``) and the
    finding behind it: the one that capped the category, else its worst open finding (``worst``: category ->
    (title, detail))."""
    if risk not in RISK_ORDER or RISK_ORDER.index(risk) == 0:
        return None
    best = None
    for name, cs in (scores or {}).get("categories", {}).items():
        if not cs.get("assessed") or cs.get("risk") not in RISK_ORDER:
            continue
        try:
            cat = Category(name)
        except ValueError:
            continue
        level = RISK_ORDER.index(cs["risk"])
        floor = level if cat in CRITICAL_CATEGORIES else level - 1
        key = (floor, cat in CRITICAL_CATEGORIES, -(cs.get("score") or 0))
        if best is None or key > best[0]:
            best = (key, cat, cs)
    if best is None:
        return None
    _, cat, cs = best
    ceiling = cs.get("ceiling_reason") or ""
    if ": " in ceiling:
        # "capped at 35 by confirmed critical finding: Hardcoded AWS key"
        head, title = ceiling.split(": ", 1)
        detail = head.split(" by ", 1)[-1]
        return Reason(cat.value, CATEGORY_LABELS[cat], title, detail)
    if worst and cat.value in worst:
        title, detail = worst[cat.value]
        return Reason(cat.value, CATEGORY_LABELS[cat], title, detail)
    score = cs.get("score")
    return Reason(cat.value, CATEGORY_LABELS[cat], "", f"scored {score:.0f}" if score is not None else "")


def _coverage(scores: dict) -> list[dict]:
    cats = (scores or {}).get("categories", {})
    cells = []
    for cat in Category:
        cs = cats.get(cat.value) or {}
        cells.append({"key": cat.value, "label": CATEGORY_LABELS[cat], "code": CATEGORY_CODES[cat],
                      "assessed": bool(cs.get("assessed")),
                      "risk": cs.get("risk") if cs.get("assessed") else NOT_ASSESSED, "score": cs.get("score")})
    return cells


def _ranked_audits(org: Organization, *, succeeded: bool, limit: int) -> list[Audit]:
    """The newest ``limit`` branch audits per repository, newest first, in one query."""
    rn = db.func.row_number().over(partition_by=Audit.repository_id, order_by=Audit.created_at.desc()).label("rn")
    q = db.select(Audit.id, rn).where(Audit.organization_id == org.id, Audit.pr_number.is_(None))
    if succeeded:
        q = q.where(Audit.status == "succeeded")
    sub = q.subquery()
    return list(db.session.execute(
        db.select(Audit).join(sub, sub.c.id == Audit.id).where(sub.c.rn <= limit).order_by(Audit.created_at.desc())
    ).scalars())


def portfolio(org: Organization) -> list[PortfolioRow]:
    """Every repository with its newest successful audit, any newer unfinished or failed attempt, open and accepted
    finding counts, the reason for its risk level, category coverage and score history. Worst first; a fixed
    number of queries regardless of how many repositories the organization has."""
    repos = db.session.execute(
        db.select(Repository).where(Repository.organization_id == org.id)
        .options(selectinload(Repository.project)).order_by(Repository.name)
    ).scalars().all()
    history: dict = defaultdict(list)
    for a in _ranked_audits(org, succeeded=True, limit=HISTORY_LENGTH):
        history[a.repository_id].append(a)
    newest = {a.repository_id: a for a in _ranked_audits(org, succeeded=False, limit=1)}
    latest = {repo_id: audits[0] for repo_id, audits in history.items()}
    latest_ids = [a.id for a in latest.values()]

    counts: dict = defaultdict(lambda: {"open": defaultdict(int), "accepted_risk": defaultdict(int)})
    accepted_next: dict = {}
    owners: dict = defaultdict(list)
    worst_by_audit: dict = {}
    flagged: dict = defaultdict(dict)
    if latest_ids:
        for audit_id, severity, status, n in db.session.execute(
            db.select(Finding.audit_id, Finding.severity, Finding.triage_status, db.func.count(Finding.id))
            .where(Finding.organization_id == org.id, Finding.audit_id.in_(latest_ids),
                   Finding.kind != "ai_observation", Finding.triage_status.in_(("open", "accepted_risk")))
            .group_by(Finding.audit_id, Finding.severity, Finding.triage_status)
        ):
            counts[audit_id][status][severity] = n
        for audit_id, owner, review in db.session.execute(
            db.select(Finding.audit_id, Finding.triage_owner, Finding.triage_expires_on)
            .where(Finding.organization_id == org.id, Finding.audit_id.in_(latest_ids),
                   Finding.triage_status == "accepted_risk")
            .order_by(Finding.triage_expires_on.is_(None), Finding.triage_expires_on)
        ):
            accepted_next.setdefault(audit_id, review)
            if owner and owner not in owners[audit_id]:
                owners[audit_id].append(owner)
        for audit_id, title, status in db.session.execute(
            db.select(Finding.audit_id, Finding.title, Finding.triage_status).distinct()
            .where(Finding.organization_id == org.id, Finding.audit_id.in_(latest_ids),
                   Finding.kind != "ai_observation", Finding.severity.in_(("critical", "high")),
                   Finding.triage_status.in_(("open", "accepted_risk")))
        ):
            if flagged[audit_id].get(title) != "open":
                flagged[audit_id][title] = status
        # The worst finding per category, named when no single finding capped the category. Accepted risks still
        # count (triage never changes scores), so an accepted finding can be the reason; it is labelled as such.
        rank = {"critical": 0, "high": 1, "medium": 2}
        best: dict = {}
        for audit_id, category, severity, kind, confidence, status, title, total in db.session.execute(
            db.select(Finding.audit_id, Finding.category, Finding.severity, Finding.kind, Finding.confidence,
                      Finding.triage_status, db.func.min(Finding.title), db.func.count(Finding.id))
            .where(Finding.organization_id == org.id, Finding.audit_id.in_(latest_ids),
                   Finding.kind != "ai_observation", Finding.triage_status.in_(("open", "accepted_risk")),
                   Finding.severity.in_(tuple(rank)))
            .group_by(Finding.audit_id, Finding.category, Finding.severity, Finding.kind, Finding.confidence,
                      Finding.triage_status)
        ):
            key = (rank[severity], status != "open", kind != "confirmed", confidence != "high")
            if (audit_id, category) not in best or key < best[(audit_id, category)][0]:
                label = "confirmed" if kind == "confirmed" else kind.replace("_", " ")
                more = f", {total - 1} more like it" if total > 1 else ""
                accepted = ", accepted risk" if status == "accepted_risk" else ""
                best[(audit_id, category)] = (key, title, f"{label} {severity} finding{more}{accepted}")
        for (audit_id, category), (_, title, detail) in best.items():
            worst_by_audit.setdefault(audit_id, {})[category] = (title, detail)

    now = utcnow()
    rows = []
    for repo in repos:
        last = latest.get(repo.id)
        attempt = newest.get(repo.id)
        if attempt is not None and (attempt.status == "succeeded" or (last and attempt.created_at <= last.created_at)):
            attempt = None
        c = counts[last.id] if last else {"open": {}, "accepted_risk": {}}
        review = accepted_next.get(last.id) if last else None
        finished = (last.finished_at or last.created_at) if last else None
        if finished is not None and finished.tzinfo is None:  # SQLite returns naive UTC datetimes
            finished = finished.replace(tzinfo=now.tzinfo)
        rows.append(PortfolioRow(
            repo=repo, latest=last, attempt=attempt, history=list(reversed(history.get(repo.id, []))),
            open=dict(c["open"]), accepted=dict(c["accepted_risk"]),
            accepted_owners=list(owners.get(last.id, [])) if last else [], accepted_review=review,
            reason=_reason(last.scores, last.risk_level, worst_by_audit.get(last.id)) if last else None,
            coverage=_coverage(last.scores) if last else [],
            age_days=(now - finished).days if finished else None,
            flagged=dict(flagged.get(last.id, {})) if last else {},
        ))
    rows.sort(key=lambda r: (PORTFOLIO_RANK.get(r.risk, 3), -r.open.get("critical", 0), -r.open.get("high", 0),
                             r.latest.overall_score if r.latest and r.latest.overall_score is not None else 101,
                             r.repo.name.lower()))
    return rows


def due_date() -> date:
    return utcnow().date() + timedelta(days=ACCEPTED_DUE_DAYS)


def _rev_label(n: int) -> str:
    """Drawing revision letters: A..Z, then AA, AB, ..."""
    label = ""
    n += 1
    while n:
        n, rem = divmod(n - 1, 26)
        label = chr(65 + rem) + label
    return label


def revisions(rows: list[PortfolioRow], limit: int = REVISION_LIMIT) -> list[dict]:
    """Risk-level changes between consecutive successful audits, newest first, lettered like a drawing's
    revision block (oldest shown revision is A)."""
    changes = []
    for r in rows:
        for before, after in zip(r.history, r.history[1:], strict=False):
            was, now = before.risk_level or NOT_ASSESSED, after.risk_level or NOT_ASSESSED
            if was != now:
                changes.append({"repo": r.repo, "audit": after, "was": was, "now": now,
                                "worse": PORTFOLIO_RANK.get(now, 3) < PORTFOLIO_RANK.get(was, 3),
                                "when": after.finished_at or after.created_at})
    changes.sort(key=lambda c: c["when"], reverse=True)
    changes = changes[:limit]
    for i, c in enumerate(reversed(changes)):
        c["rev"] = _rev_label(i)
    return changes


def portfolio_summary(rows: list[PortfolioRow]) -> dict:
    """Totals for the dashboard's directive band, title block, notes and risk rail, computed over ``rows`` (the
    repositories in the current project scope, before any drill-down filter)."""
    due_by = due_date()
    by_risk = dict.fromkeys(PORTFOLIO_RANK, 0)
    for r in rows:
        by_risk[r.risk if r.risk in by_risk else NOT_ASSESSED] += 1
    checked = [r.latest.finished_at or r.latest.created_at for r in rows if r.latest]
    # The same critical/high finding in several repositories is one problem, reported once.
    patterns: dict[str, list[PortfolioRow]] = defaultdict(list)
    for r in rows:
        for title in r.flagged:
            patterns[title].append(r)
    pattern_counts = {title: len(rs) for title, rs in patterns.items() if len(rs) > 1}
    first = rows[0] if rows and rows[0].risk in ("Critical", "High") else None
    first_pattern = None
    if first and first.reason and first.reason.finding in pattern_counts:
        title = first.reason.finding
        first_pattern = {"title": title, "rows": patterns[title],
                         "open": [r for r in patterns[title] if r.flagged[title] == "open"]}
    assessed_rows = [r for r in rows if r.coverage]
    gaps = []
    for cat in Category:
        missing = sum(1 for r in assessed_rows if cat.value in {c["key"] for c in r.coverage if not c["assessed"]})
        if missing >= 2 and missing * 2 >= len(assessed_rows):
            gaps.append({"label": CATEGORY_LABELS[cat], "missing": missing, "of": len(assessed_rows)})
    in_state = {state: [r for r in rows if r.in_state(state, due_by)] for state in STATES}
    revs = revisions(rows)
    return {
        "total": len(rows),
        "latest_check": max(checked) if checked else None,
        "by_risk": by_risk,
        "state_rows": in_state,
        "accepted": sum(sum(r.accepted.values()) for r in rows),
        "first": first,
        "first_pattern": first_pattern,
        "pattern_counts": pattern_counts,
        "gaps": gaps,
        "revisions": revs,
        "scoring_version": SCORING,
    }


def members(org: Organization) -> list[Membership]:
    return list(
        db.session.execute(
            db.select(Membership).join(User).where(Membership.organization_id == org.id).order_by(User.email)
        ).scalars()
    )


def _owner_count(org: Organization) -> int:
    return db.session.scalar(
        db.select(db.func.count(Membership.id)).where(
            Membership.organization_id == org.id, Membership.role == "owner"
        )
    )


def add_member(org: Organization, actor: Membership, email: str, role: str) -> Membership:
    """Add an *existing* user. (Email invitations require an SMTP integration — see ROADMAP.)"""
    if role not in ROLES:
        raise OrgError("Unknown role.")
    if role == "owner" and actor.role != "owner":
        raise OrgError("Only owners can grant the owner role.")
    user = db.session.execute(db.select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
    if user is None:
        raise OrgError("No user with that email. Ask them to register first.")
    existing = db.session.execute(
        db.select(Membership).where(Membership.organization_id == org.id, Membership.user_id == user.id)
    ).scalar_one_or_none()
    if existing:
        raise OrgError("That user is already a member.")
    membership = Membership(organization_id=org.id, user_id=user.id, role=role)
    db.session.add(membership)
    events.record("member.added", organization_id=org.id, target=membership, role=role)
    db.session.commit()
    return membership


def change_role(org: Organization, actor: Membership, membership: Membership, role: str) -> None:
    if role not in ROLES:
        raise OrgError("Unknown role.")
    if (role == "owner" or membership.role == "owner") and actor.role != "owner":
        raise OrgError("Only owners can grant or revoke the owner role.")
    if not role_at_least(actor.role, membership.role):
        raise OrgError("You cannot change the role of a member above your own role.")
    if membership.role == "owner" and role != "owner" and _owner_count(org) <= 1:
        raise OrgError("An organization must keep at least one owner.")
    old = membership.role
    membership.role = role
    events.record("member.role_changed", organization_id=org.id, target=membership, old=old, new=role)
    db.session.commit()


def remove_member(org: Organization, actor: Membership, membership: Membership) -> None:
    if membership.role == "owner" and actor.role != "owner":
        raise OrgError("Only owners can remove an owner.")
    if not role_at_least(actor.role, membership.role):
        raise OrgError("You cannot remove a member above your own role.")
    if membership.role == "owner" and _owner_count(org) <= 1:
        raise OrgError("An organization must keep at least one owner.")
    events.record("member.removed", organization_id=org.id, target=membership)
    db.session.delete(membership)
    db.session.commit()
