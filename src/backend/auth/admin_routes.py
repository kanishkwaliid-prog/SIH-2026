"""
/admin routes (Phase 4): manage the members of the caller's own
organisation. Every endpoint needs Permission.MANAGE_USERS (admin only) and
every query is scoped by the caller's org_id, which comes from the
database-backed user, never from the request. Someone else's user_id gets
the same 404 as one that doesn't exist.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

import activity_log
from . import config, store
from .config import Permission, Role
from .deps import require_permission
from .routes import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, _clean_email
from .store import User

router = APIRouter(prefix="/admin", tags=["admin"])

USER_NOT_FOUND = "No such member in your organization."


class AddMemberRequest(BaseModel):
    email: str
    name: str
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    role: Role = config.DEFAULT_MEMBER_ROLE

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        return _clean_email(v)

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = v.strip()
        if not 1 <= len(v) <= 100:
            raise ValueError("Must be between 1 and 100 characters.")
        return v

    @field_validator("password")
    @classmethod
    def _password(cls, v):
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return v


class ChangeRoleRequest(BaseModel):
    role: Role


@router.get("/users")
def list_members(admin: User = Depends(require_permission(Permission.MANAGE_USERS))):
    return {"users": [u.public() for u in store.list_org_users(admin.org_id)]}


@router.post("/users", status_code=status.HTTP_201_CREATED)
def add_member(body: AddMemberRequest,
               admin: User = Depends(require_permission(Permission.MANAGE_USERS))):
    """Adds a member to the ADMIN'S org (never a client-chosen one) with the
    password the admin sets. Defaults to viewer."""
    try:
        user = store.create_user_in_org(
            org_id=admin.org_id, email=body.email, name=body.name,
            password=body.password, role=body.role,
        )
    except store.EmailAlreadyRegistered:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists.")
    activity_log.log_event(admin, "member_add", target=user.user_id,
                            detail={"email": user.email, "role": user.role})
    return user.public()


@router.patch("/users/{user_id}/role")
def change_role(user_id: str, body: ChangeRoleRequest,
                admin: User = Depends(require_permission(Permission.MANAGE_USERS))):
    try:
        user = store.set_user_role(admin.org_id, user_id, body.role)
    except store.UserNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, USER_NOT_FOUND)
    except store.LastAdminError:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An organization needs at least one admin. Make someone else an admin first.",
        )
    activity_log.log_event(admin, "role_change", target=user.user_id, detail={"new_role": user.role})
    return user.public()


@router.post("/users/{user_id}/reset-2fa")
def reset_member_2fa(user_id: str,
                     admin: User = Depends(require_permission(Permission.MANAGE_USERS))):
    """For a member who lost their phone and used every backup code. Turns
    their 2FA off; they sign in with just a password and can enrol again."""
    if user_id == admin.user_id:
        # A stolen admin token must not be able to switch off the admin's own
        # second factor without the password + code that /auth/2fa/disable asks for.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Turn off your own two-factor authentication from Security settings.",
        )
    try:
        user = store.reset_user_totp(admin.org_id, user_id)
    except store.UserNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, USER_NOT_FOUND)
    activity_log.log_event(admin, "2fa_reset", target=user.user_id)
    return user.public()
