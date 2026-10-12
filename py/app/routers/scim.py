"""SCIM 2.0 user provisioning (RFC 7643 / RFC 7644), for Okta, Entra ID and other IdPs.

The identity provider stays the source of truth for who works here: it creates users when
they join (joiner), updates their title, department or manager when they move (mover), and
sets ``active: false`` when they leave (leaver). Every change goes through the same
lifecycle code as the admin API (:mod:`app.identity`), so deprovisioning someone in the IdP
revokes their grants and live AWS sessions at once.

Authentication is a separate bearer token (``AEGIS_SCIM_TOKEN``), not a user's token: the
IdP is a system integration, not a person. When the variable is unset, SCIM is switched off
and every route returns 404. SCIM can't make anyone an Aegis administrator; that stays a
deliberate action by an existing admin.
"""

import hmac
import os
import re
from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, identity
from app.database import get_db
from app.models import AuditEvent, User

router = APIRouter(prefix="/scim/v2", tags=["scim"])

MEDIA_TYPE = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

# Used when the IdP doesn't send a title or department. An unknown role gets the lowest
# clearance in policies/attributes.json, so a missing title fails closed.
DEFAULT_ROLE = "employee"
DEFAULT_DEPARTMENT = "Unassigned"
MAX_PAGE = 200
VIA = "via SCIM"

# Only the equality filters IdPs use to look a user up before creating them.
_FILTER_RE = re.compile(r'^\s{0,10}(userName|externalId|id)\s{1,10}eq\s{1,10}"([^"]{0,254})"\s{0,10}$', re.IGNORECASE)
_EMAIL = TypeAdapter(EmailStr)
_LIMITS = {"name": 120, "department": 80, "role": 80, "external_id": 255}


class ScimError(Exception):
    """An error returned in the SCIM error format (RFC 7644 section 3.12)."""

    def __init__(self, status_code: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


def error_response(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, ScimError):  # registered only for ScimError
        raise exc
    body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(exc.status_code), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    headers = {"WWW-Authenticate": 'Bearer realm="scim"'} if exc.status_code == 401 else None
    return JSONResponse(body, status_code=exc.status_code, media_type=MEDIA_TYPE, headers=headers)


def _scim(body: Any, status_code: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status_code, media_type=MEDIA_TYPE, headers=headers)


def require_scim_client(request: Request) -> None:
    expected = os.getenv("AEGIS_SCIM_TOKEN", "")
    if not expected:
        raise ScimError(404, "SCIM provisioning is not enabled")
    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(presented.encode(), expected.encode()):
        raise ScimError(401, "A valid SCIM bearer token is required")


# --- Representation ----------------------------------------------------------------


def _location(user: User) -> str:
    return f"/scim/v2/Users/{user.id}"


def to_scim(user: User) -> dict[str, Any]:
    enterprise: dict[str, Any] = {"department": user.department}
    if user.manager is not None:
        enterprise["manager"] = {"value": str(user.manager.id), "displayName": user.manager.name}
    body: dict[str, Any] = {
        "schemas": [USER_SCHEMA, ENTERPRISE],
        "id": str(user.id),
        "userName": user.email,
        "name": {"formatted": user.name},
        "displayName": user.name,
        "emails": [{"value": user.email, "type": "work", "primary": True}],
        "title": user.role,
        "active": user.is_active,
        ENTERPRISE: enterprise,
        "meta": {"resourceType": "User", "location": _location(user)},
    }
    if user.external_id:
        body["externalId"] = user.external_id
    return body


# --- Parsing -----------------------------------------------------------------------


def _string(value: Any, attribute: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScimError(400, f"'{attribute}' must be a non-empty string", "invalidValue")
    return value.strip()


def _bool(value: Any) -> bool:
    # Entra ID sends booleans as the strings "True" / "False" in PATCH operations.
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise ScimError(400, "'active' must be a boolean", "invalidValue")


def _email(value: Any) -> str:
    try:
        return _EMAIL.validate_python(_string(value, "userName")).lower()
    except ValidationError as exc:
        raise ScimError(400, "'userName' must be the user's email address", "invalidValue") from exc


def _manager(value: Any) -> int | None:
    if isinstance(value, dict):
        value = value.get("value")
    if value in (None, ""):
        return None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ScimError(400, "'manager.value' must be the manager's SCIM id", "invalidValue")


def _name(body: dict[str, Any]) -> str | None:
    name = body.get("name")
    if not isinstance(name, dict):
        name = {}
    if name.get("formatted"):
        return _string(name["formatted"], "name.formatted")
    parts = [p for p in (name.get("givenName"), name.get("familyName")) if isinstance(p, str) and p.strip()]
    if parts:
        return " ".join(p.strip() for p in parts)
    if body.get("displayName"):
        return _string(body["displayName"], "displayName")
    return None


def _from_resource(body: dict[str, Any]) -> dict[str, Any]:
    """Aegis fields from a full SCIM User (POST and PUT). Absent optional attributes are cleared."""
    if not isinstance(body, dict):
        raise ScimError(400, "The request body must be a SCIM User", "invalidSyntax")
    email = _email(body.get("userName"))
    enterprise = body.get(ENTERPRISE)
    if not isinstance(enterprise, dict):
        enterprise = {}
    external_id = body.get("externalId")
    return {
        "email": email,
        "name": _name(body) or email,
        "role": _string(body["title"], "title") if body.get("title") else DEFAULT_ROLE,
        "department": _string(enterprise["department"], "department")
        if enterprise.get("department")
        else DEFAULT_DEPARTMENT,
        "manager_id": _manager(enterprise.get("manager")),
        "is_active": _bool(body.get("active", True)),
        "external_id": _string(external_id, "externalId") if external_id else None,
    }


def _patch_attribute(path: str, value: Any, remove: bool) -> dict[str, Any]:
    """Aegis fields for one PATCH path. Attributes Aegis doesn't store are accepted and ignored."""
    key = path.lower()
    if key.startswith(ENTERPRISE.lower() + ":"):
        key = key[len(ENTERPRISE) + 1 :]
    if key == "active":
        return {"is_active": False if remove else _bool(value)}
    if key == "title":
        return {"role": DEFAULT_ROLE if remove else _string(value, "title")}
    if key == "department":
        return {"department": DEFAULT_DEPARTMENT if remove else _string(value, "department")}
    if key in {"manager", "manager.value"}:
        return {"manager_id": None if remove else _manager(value)}
    if key in {"name.formatted", "displayname"} and not remove:
        return {"name": _string(value, path)}
    if key == "username" and not remove:
        return {"email": _email(value)}
    if key == "externalid":
        return {"external_id": None if remove else _string(value, "externalId")}
    return {}


def _from_patch(body: dict[str, Any]) -> dict[str, Any]:
    operations = body.get("Operations") if isinstance(body, dict) else None
    if not isinstance(operations, list) or not operations:
        raise ScimError(400, "A PatchOp body needs a non-empty 'Operations' list", "invalidSyntax")
    changes: dict[str, Any] = {}
    for operation in operations:
        if not isinstance(operation, dict):
            raise ScimError(400, "Each operation must be an object", "invalidSyntax")
        op = str(operation.get("op", "")).lower()
        if op not in {"add", "replace", "remove"}:
            raise ScimError(400, f"Unsupported PATCH op {operation.get('op')!r}", "invalidSyntax")
        path, value = operation.get("path"), operation.get("value")
        if path:
            changes.update(_patch_attribute(str(path), value, op == "remove"))
        elif op == "remove":
            raise ScimError(400, "'remove' needs a path", "noTarget")
        elif isinstance(value, dict):
            # Okta style: {"op": "replace", "value": {"active": false}}
            for attribute, inner in value.items():
                if attribute == ENTERPRISE and isinstance(inner, dict):
                    for ext_attribute, ext_value in inner.items():
                        changes.update(_patch_attribute(ext_attribute, ext_value, False))
                elif attribute == "name" and isinstance(inner, dict):
                    if name := _name({"name": inner}):
                        changes["name"] = name
                else:
                    changes.update(_patch_attribute(attribute, inner, False))
        else:
            raise ScimError(400, "An operation without a path needs an object value", "invalidValue")
    return changes


# --- Validation and persistence -----------------------------------------------------


def _check(db: Session, fields: dict[str, Any], user: User | None = None) -> None:
    for field, limit in _LIMITS.items():
        if isinstance(fields.get(field), str) and len(fields[field]) > limit:
            raise ScimError(400, f"'{field}' is longer than {limit} characters", "invalidValue")
    user_id = user.id if user else None
    if "manager_id" in fields and (error := identity.manager_error(db, fields["manager_id"], user_id)):
        raise ScimError(400, error, "invalidValue")
    for field, column in (("email", User.email), ("external_id", User.external_id)):
        value = fields.get(field)
        if value is None:
            continue
        clash = db.scalar(
            select(User).where(column == value, User.id != user_id) if user_id else select(User).where(column == value)
        )
        if clash is not None:
            raise ScimError(
                409, f"Another user already has this {'userName' if field == 'email' else 'externalId'}", "uniqueness"
            )


def _get_user(db: Session, user_id: str) -> User:
    user = db.get(User, int(user_id)) if user_id.isdigit() else None
    if user is None:
        raise ScimError(404, f"User {user_id} not found")
    return user


def _update(db: Session, user: User, fields: dict[str, Any]) -> JSONResponse:
    _check(db, fields, user)
    if identity.apply_changes(db, user, fields, None, via=VIA):
        audit.commit(db)
    return _scim(to_scim(user))


# --- Routes ------------------------------------------------------------------------


@router.get("/Users", dependencies=[Depends(require_scim_client)])
def list_users(
    scim_filter: str | None = Query(None, alias="filter"),
    start_index: int = Query(1, alias="startIndex"),
    count: int = Query(100),
    db: Session = Depends(get_db),
) -> JSONResponse:
    query = select(User)
    if scim_filter:
        match = _FILTER_RE.match(scim_filter)
        if not match:
            raise ScimError(400, 'Only filters of the form userName eq "..." are supported', "invalidFilter")
        attribute, value = match.group(1).lower(), match.group(2)
        if attribute == "username":
            query = query.where(User.email == value.lower())
        elif attribute == "externalid":
            query = query.where(User.external_id == value)
        else:
            query = query.where(User.id == (int(value) if value.isdigit() else -1))
    start_index, count = max(start_index, 1), min(max(count, 0), MAX_PAGE)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    page = db.scalars(query.order_by(User.id).offset(start_index - 1).limit(count)).all()
    return _scim(
        {
            "schemas": [LIST_RESPONSE],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": len(page),
            "Resources": [to_scim(u) for u in page],
        }
    )


@router.get("/Users/{user_id}", dependencies=[Depends(require_scim_client)])
def get_user(user_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    return _scim(to_scim(_get_user(db, user_id)))


@router.post("/Users", dependencies=[Depends(require_scim_client)])
def create_user(body: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> JSONResponse:
    """Joiner. SCIM never sets ``is_admin``."""
    fields = _from_resource(body)
    _check(db, fields)
    user = User(**fields)
    db.add(user)
    db.flush()
    audit.record(
        db,
        AuditEvent.USER_CREATED,
        user_id=user.id,
        detail=f"Provisioned {user.email} ({user.department}/{user.role}) {VIA}.",
    )
    audit.commit(db)
    return _scim(to_scim(user), status.HTTP_201_CREATED, {"Location": _location(user)})


@router.put("/Users/{user_id}", dependencies=[Depends(require_scim_client)])
def replace_user(user_id: str, body: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> JSONResponse:
    user = _get_user(db, user_id)
    return _update(db, user, _from_resource(body))


@router.patch("/Users/{user_id}", dependencies=[Depends(require_scim_client)])
def patch_user(user_id: str, body: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> JSONResponse:
    """Mover and leaver. Handles both Okta's and Entra ID's PATCH styles."""
    user = _get_user(db, user_id)
    return _update(db, user, _from_patch(body))


@router.delete("/Users/{user_id}", dependencies=[Depends(require_scim_client)])
def delete_user(user_id: str, db: Session = Depends(get_db)) -> Response:
    """Leaver. The account is deactivated, not erased, so its audit history stays intact."""
    user = _get_user(db, user_id)
    if identity.apply_changes(db, user, {"is_active": False}, None, via=VIA):
        audit.commit(db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Discovery (RFC 7644 section 4) -------------------------------------------------


@router.get("/ServiceProviderConfig", dependencies=[Depends(require_scim_client)])
def service_provider_config() -> JSONResponse:
    unsupported = {"supported": False}
    return _scim(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://github.com/Xeoul/aegis/blob/main/docs/DESIGN.md#scim-provisioning",
            "patch": {"supported": True},
            "bulk": {**unsupported, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_PAGE},
            "changePassword": unsupported,
            "sort": unsupported,
            "etag": unsupported,
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "Bearer token",
                    "description": "The token configured in AEGIS_SCIM_TOKEN",
                    "primary": True,
                }
            ],
            "meta": {"resourceType": "ServiceProviderConfig", "location": "/scim/v2/ServiceProviderConfig"},
        }
    )


@router.get("/ResourceTypes", dependencies=[Depends(require_scim_client)])
def resource_types() -> JSONResponse:
    user_type = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "schema": USER_SCHEMA,
        "schemaExtensions": [{"schema": ENTERPRISE, "required": False}],
        "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User"},
    }
    return _scim({"schemas": [LIST_RESPONSE], "totalResults": 1, "Resources": [user_type]})


def _attribute(name: str, *, required: bool = False, type_: str = "string", **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "type": type_,
        "multiValued": False,
        "required": required,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": "server" if name == "userName" else "none",
        **extra,
    }


@router.get("/Schemas", dependencies=[Depends(require_scim_client)])
def schemas() -> JSONResponse:
    core = {
        "id": USER_SCHEMA,
        "name": "User",
        "description": "Aegis user. userName is the work email that Aegis matches tokens on.",
        "attributes": [
            _attribute("userName", required=True),
            _attribute(
                "name",
                type_="complex",
                subAttributes=[_attribute("formatted"), _attribute("givenName"), _attribute("familyName")],
            ),
            _attribute("displayName"),
            _attribute("title", description="Aegis role; drives clearance in policies/attributes.json"),
            _attribute("active", type_="boolean", description="false deprovisions the user and revokes all access"),
            _attribute("externalId"),
        ],
    }
    enterprise = {
        "id": ENTERPRISE,
        "name": "EnterpriseUser",
        "description": "Department and manager, used for ABAC decisions and approval routing.",
        "attributes": [
            _attribute("department"),
            _attribute("manager", type_="complex", subAttributes=[_attribute("value"), _attribute("displayName")]),
        ],
    }
    resources = [
        {
            **s,
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{s['id']}"},
        }
        for s in (core, enterprise)
    ]
    return _scim({"schemas": [LIST_RESPONSE], "totalResults": len(resources), "Resources": resources})
