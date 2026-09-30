"""
FastAPI dependencies. Add `user: User = Depends(get_current_user)` to an
endpoint and it rejects any request without a valid, unexpired access
token. Endpoints that do something
sensitive use require_permission(Permission.X) instead, which calls this and
then checks the caller's role.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import config, security, store
from .config import Permission
from .store import User

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    if credentials is None:
        raise _unauthorized("Not signed in.")

    try:
        claims = security.decode_token(credentials.credentials, config.TOKEN_TYPE_ACCESS)
    except security.TokenError:
        raise _unauthorized("Your session has expired or is invalid. Please sign in again.")

    # Fresh read: role and org come from the database, not the token, so a
    # role change or deleted account takes effect on the very next request.
    user = store.get_user_by_id(claims["sub"])
    if user is None:
        raise _unauthorized("This account no longer exists.")
    return user


def require_permission(permission: Permission):
    """Dependency factory: `user: User = Depends(require_permission(Permission.UPLOAD))`.

    Runs get_current_user first (so anonymous callers still get 401), then
    checks the permission against the role freshly read from the database.
    A signed-in user whose role lacks it gets 403 -- checked BEFORE the
    endpoint looks anything up, so a forbidden caller learns nothing about
    which session ids exist.
    """
    def _dependency(user: User = Depends(get_current_user)) -> User:
        if not config.has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role doesn't have permission to do that.",
            )
        return user

    # Lets auth/test_rbac.py verify every route declares a permission.
    _dependency.required_permission = permission
    return _dependency
