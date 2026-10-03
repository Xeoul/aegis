"""SCIM 2.0 provisioning: an IdP drives joiner/mover/leaver through the same lifecycle code."""

import pytest
from conftest import ALICE, BOB, GRACE

from app.routers.scim import ENTERPRISE, PATCH_OP, USER_SCHEMA

TOKEN = "scim-test-token"
SCIM = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/scim+json"}


@pytest.fixture()
def scim(client, monkeypatch):
    monkeypatch.setenv("AEGIS_SCIM_TOKEN", TOKEN)
    return client


def _lookup(scim, email):
    body = scim.get("/scim/v2/Users", params={"filter": f'userName eq "{email}"'}, headers=SCIM).json()
    assert body["totalResults"] == 1
    return body["Resources"][0]


def _grant(client, headers):
    resp = client.post("/request-access", json={"request_text": "read prod-db for 4 hours to debug"}, headers=headers)
    assert resp.json()["status"] == "ACTIVE", resp.text
    return resp.json()["request_id"]


def _request(client, auth, request_id):
    return client.get(f"/requests/{request_id}", headers=auth(GRACE)).json()


def _patch(*operations):
    return {"schemas": [PATCH_OP], "Operations": list(operations)}


def test_disabled_without_a_token(client):
    resp = client.get("/scim/v2/Users", headers=SCIM)
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/scim+json")
    assert client.get("/meta").json()["scim"] is False


def test_rejects_missing_or_wrong_token(scim, auth):
    for headers in ({}, {"Authorization": "Bearer nope"}, auth(ALICE)):
        resp = scim.get("/scim/v2/Users", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
        assert resp.headers["www-authenticate"].startswith("Bearer")


def test_discovery_endpoints(scim):
    config = scim.get("/scim/v2/ServiceProviderConfig", headers=SCIM)
    assert config.status_code == 200 and config.json()["patch"]["supported"] is True
    assert config.headers["content-type"].startswith("application/scim+json")
    types = scim.get("/scim/v2/ResourceTypes", headers=SCIM).json()
    assert types["Resources"][0]["schemaExtensions"][0]["schema"] == ENTERPRISE
    schemas = scim.get("/scim/v2/Schemas", headers=SCIM).json()
    assert {s["id"] for s in schemas["Resources"]} == {USER_SCHEMA, ENTERPRISE}
    assert scim.get("/meta").json()["scim"] is True


def test_lookup_and_representation(scim):
    bob = _lookup(scim, BOB.upper())
    assert bob["userName"] == BOB and bob["title"] == "sre" and bob["active"] is True
    assert bob[ENTERPRISE]["department"] == "Engineering"
    assert bob[ENTERPRISE]["manager"]["displayName"] == "Maya Torres"
    assert scim.get(f"/scim/v2/Users/{bob['id']}", headers=SCIM).json() == bob
    assert scim.get("/scim/v2/Users/9999", headers=SCIM).status_code == 404
    assert scim.get("/scim/v2/Users/abc", headers=SCIM).status_code == 404


def test_pagination_and_filters(scim):
    everyone = scim.get("/scim/v2/Users", headers=SCIM).json()
    assert everyone["totalResults"] == len(everyone["Resources"]) >= 10
    page = scim.get("/scim/v2/Users", params={"startIndex": 3, "count": 2}, headers=SCIM).json()
    assert page["startIndex"] == 3 and page["itemsPerPage"] == 2
    assert [u["id"] for u in page["Resources"]] == [u["id"] for u in everyone["Resources"][2:4]]
    none = scim.get("/scim/v2/Users", params={"filter": 'userName eq "nobody@aegis.example"'}, headers=SCIM).json()
    assert none["totalResults"] == 0 and none["Resources"] == []
    bad = scim.get("/scim/v2/Users", params={"filter": 'name.familyName co "a"'}, headers=SCIM)
    assert bad.status_code == 400 and bad.json()["scimType"] == "invalidFilter"


def test_joiner_is_provisioned_and_can_request_access(scim, auth):
    body = {
        "schemas": [USER_SCHEMA, ENTERPRISE],
        "userName": "Nina.Shah@aegis.example",
        "externalId": "00u1okta",
        "name": {"givenName": "Nina", "familyName": "Shah"},
        "title": "engineer",
        "active": True,
        "is_admin": True,  # not a SCIM attribute; must be ignored
        ENTERPRISE: {"department": "Engineering", "manager": {"value": _lookup(scim, BOB)["id"]}},
    }
    resp = scim.post("/scim/v2/Users", json=body, headers=SCIM)
    assert resp.status_code == 201, resp.text
    nina = resp.json()
    assert resp.headers["location"] == f"/scim/v2/Users/{nina['id']}"
    assert nina["userName"] == "nina.shah@aegis.example" and nina["displayName"] == "Nina Shah"
    assert nina["externalId"] == "00u1okta"
    users = {u["email"]: u for u in scim.get("/users", headers=auth(GRACE)).json()}
    assert users["nina.shah@aegis.example"]["is_admin"] is False
    _grant(scim, auth("nina.shah@aegis.example"))

    by_external = scim.get("/scim/v2/Users", params={"filter": 'externalId eq "00u1okta"'}, headers=SCIM).json()
    assert by_external["Resources"][0]["id"] == nina["id"]
    logs = scim.get("/audit-logs", params={"event": "USER_CREATED"}, headers=auth(GRACE)).json()
    assert any("via SCIM" in e["detail"] and e["actor_id"] is None for e in logs)


def test_joiner_defaults_fail_closed(scim):
    nina = scim.post("/scim/v2/Users", json={"userName": "nina@aegis.example"}, headers=SCIM).json()
    assert nina["title"] == "employee" and nina[ENTERPRISE]["department"] == "Unassigned"


def test_duplicates_and_bad_values_are_rejected(scim):
    taken = scim.post("/scim/v2/Users", json={"userName": BOB}, headers=SCIM)
    assert taken.status_code == 409 and taken.json()["scimType"] == "uniqueness"
    for body in (
        {"userName": "not-an-email"},
        {"userName": "x@aegis.example", "active": "maybe"},
        {"userName": "x@aegis.example", ENTERPRISE: {"manager": {"value": "9999"}}},
        {"userName": "x@aegis.example", "title": "x" * 81},
    ):
        resp = scim.post("/scim/v2/Users", json=body, headers=SCIM)
        assert resp.status_code == 400 and resp.json()["scimType"] == "invalidValue", body


def test_okta_style_deactivation_revokes_access(scim, auth):
    alice = auth(ALICE)
    request_id = _grant(scim, alice)
    user_id = _lookup(scim, ALICE)["id"]
    resp = scim.patch(
        f"/scim/v2/Users/{user_id}", json=_patch({"op": "replace", "value": {"active": False}}), headers=SCIM
    )
    assert resp.status_code == 200 and resp.json()["active"] is False
    detail = _request(scim, auth, request_id)
    assert detail["status"] == "REVOKED" and detail["revoke_reason"].startswith("Leaver")
    assert scim.get("/me", headers=alice).status_code == 403
    assert scim.post("/auth/dev-token", json={"email": ALICE}).status_code == 401


def test_entra_style_deactivation(scim, auth):
    request_id = _grant(scim, auth(ALICE))
    user_id = _lookup(scim, ALICE)["id"]
    op = {"op": "Replace", "path": "active", "value": "False"}
    assert scim.patch(f"/scim/v2/Users/{user_id}", json=_patch(op), headers=SCIM).json()["active"] is False
    assert _request(scim, auth, request_id)["status"] == "REVOKED"


def test_mover_via_patch_revokes_open_access(scim, auth):
    request_id = _grant(scim, auth(ALICE))
    user_id = _lookup(scim, ALICE)["id"]
    ops = _patch(
        {"op": "replace", "path": f"{ENTERPRISE}:department", "value": "Finance"},
        {"op": "replace", "path": 'emails[type eq "work"].value', "value": "ignored@aegis.example"},
    )
    moved = scim.patch(f"/scim/v2/Users/{user_id}", json=ops, headers=SCIM).json()
    assert moved[ENTERPRISE]["department"] == "Finance" and moved["userName"] == ALICE
    detail = _request(scim, auth, request_id)
    assert detail["status"] == "REVOKED" and detail["revoke_reason"].startswith("Mover")


def test_renaming_is_not_a_mover_event(scim, auth):
    request_id = _grant(scim, auth(ALICE))
    user_id = _lookup(scim, ALICE)["id"]
    ops = _patch({"op": "replace", "path": "name.formatted", "value": "Alice Chen-Park"})
    assert scim.patch(f"/scim/v2/Users/{user_id}", json=ops, headers=SCIM).json()["displayName"] == "Alice Chen-Park"
    assert _request(scim, auth, request_id)["status"] == "ACTIVE"


def test_patch_rejects_malformed_operations(scim):
    user_id = _lookup(scim, ALICE)["id"]
    for body in (
        {"Operations": []},
        _patch({"op": "move", "path": "active", "value": False}),
        _patch({"op": "remove"}),
        _patch({"op": "replace", "value": "x"}),
    ):
        assert scim.patch(f"/scim/v2/Users/{user_id}", json=body, headers=SCIM).status_code == 400, body


def test_manager_cannot_be_self(scim):
    user_id = _lookup(scim, ALICE)["id"]
    ops = _patch({"op": "replace", "path": "manager", "value": user_id})
    assert scim.patch(f"/scim/v2/Users/{user_id}", json=ops, headers=SCIM).status_code == 400


def test_put_replaces_and_unchanged_put_is_a_no_op(scim, auth):
    request_id = _grant(scim, auth(ALICE))
    alice = _lookup(scim, ALICE)
    same = {k: v for k, v in alice.items() if k not in {"id", "meta"}}
    assert scim.put(f"/scim/v2/Users/{alice['id']}", json=same, headers=SCIM).json() == alice
    assert _request(scim, auth, request_id)["status"] == "ACTIVE"

    promoted = {**same, "title": "senior engineer"}
    assert scim.put(f"/scim/v2/Users/{alice['id']}", json=promoted, headers=SCIM).json()["title"] == "senior engineer"
    assert _request(scim, auth, request_id)["status"] == "REVOKED"
    taken = {**same, "userName": BOB}
    assert scim.put(f"/scim/v2/Users/{alice['id']}", json=taken, headers=SCIM).status_code == 409


def test_delete_deactivates_and_keeps_history(scim, auth):
    request_id = _grant(scim, auth(ALICE))
    user_id = _lookup(scim, ALICE)["id"]
    assert scim.delete(f"/scim/v2/Users/{user_id}", headers=SCIM).status_code == 204
    assert scim.get(f"/scim/v2/Users/{user_id}", headers=SCIM).json()["active"] is False
    assert _request(scim, auth, request_id)["status"] == "REVOKED"
    assert scim.delete(f"/scim/v2/Users/{user_id}", headers=SCIM).status_code == 204  # idempotent
    assert scim.get("/audit-logs/verify", headers=auth(GRACE)).json()["valid"] is True
