"""Tenant isolation and RBAC. Foreign resources must 404 (no existence oracle); low roles must 403."""

from __future__ import annotations

from eval_app.models import Membership, Project, User
from tests.conftest import login, register


def _create_project(client, org, name="Web"):
    resp = client.post(f"/o/{org}/projects", data={"name": name, "description": ""})
    assert resp.status_code == 302, resp.data
    return resp.headers["Location"].rsplit("/", 1)[-1]


def test_member_can_create_and_view_project(alice):
    pid = _create_project(alice["client"], alice["org"])
    resp = alice["client"].get(f"/o/{alice['org']}/projects/{pid}")
    assert resp.status_code == 200 and b"Web" in resp.data


def test_other_tenant_cannot_see_org_or_project(alice, bob):
    pid = _create_project(alice["client"], alice["org"])
    c = bob["client"]
    assert c.get(f"/o/{alice['org']}").status_code == 404
    assert c.get(f"/o/{alice['org']}/projects/{pid}").status_code == 404
    # Bob's own org with Alice's project id: still 404 (scoped by organization_id).
    assert c.get(f"/o/{bob['org']}/projects/{pid}").status_code == 404
    assert c.post(f"/o/{bob['org']}/projects/{pid}/delete").status_code == 404


def test_malformed_ids_404(alice):
    assert alice["client"].get(f"/o/{alice['org']}/projects/not-a-uuid").status_code == 404


def test_viewer_cannot_create_project(app, alice, db):
    viewer = app.test_client()
    register(viewer, "v@example.com", "Other")
    resp = alice["client"].post(f"/o/{alice['org']}/members", data={"email": "v@example.com", "role": "viewer"})
    assert resp.status_code == 302
    assert viewer.get(f"/o/{alice['org']}/projects").status_code == 200
    assert viewer.post(f"/o/{alice['org']}/projects", data={"name": "X"}).status_code == 403
    assert db.session.scalar(db.select(db.func.count(Project.id))) == 0


def test_member_cannot_delete_project_or_manage_members(app, alice, db):
    m = app.test_client()
    register(m, "m@example.com", "Other")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "m@example.com", "role": "member"})
    pid = _create_project(alice["client"], alice["org"])
    assert m.post(f"/o/{alice['org']}/projects/{pid}/delete").status_code == 403
    owner_membership = db.session.execute(
        db.select(Membership).join(User).where(User.email == "alice@example.com")
    ).scalar_one()
    assert m.post(f"/o/{alice['org']}/members/{owner_membership.id}/remove").status_code == 403


def test_last_owner_cannot_be_demoted(alice, db):
    own = db.session.execute(db.select(Membership)).scalar_one()
    # Alice is the only owner; demoting herself must fail. (UI hides it, API path enforces it.)
    alice["client"].post(f"/o/{alice['org']}/members/{own.id}/role", data={"role": "member"})
    db.session.refresh(own)
    assert own.role == "owner"


def test_admin_cannot_grant_owner(app, alice, db):
    admin = app.test_client()
    register(admin, "ad@example.com", "Other")
    register(app.test_client(), "x@example.com", "Third")
    alice["client"].post(f"/o/{alice['org']}/members", data={"email": "ad@example.com", "role": "admin"})
    admin.post(f"/o/{alice['org']}/members", data={"email": "x@example.com", "role": "owner"})
    x = db.session.execute(db.select(User).where(User.email == "x@example.com")).scalar_one()
    org_memberships = [m for m in x.memberships if m.role == "owner"]
    assert len(org_memberships) == 1  # only the org x created themselves


def test_membership_id_from_other_org_is_404(alice, bob, db):
    bob_membership = db.session.execute(
        db.select(Membership).join(User).where(User.email == "bob@example.com")
    ).scalar_one()
    resp = alice["client"].post(f"/o/{alice['org']}/members/{bob_membership.id}/remove")
    assert resp.status_code == 404


def test_login_lands_on_single_org(client):
    register(client, "solo@example.com", "Solo")
    client.post("/logout")
    login(client, "solo@example.com")
    assert client.get("/orgs").headers["Location"].endswith("/o/solo")
