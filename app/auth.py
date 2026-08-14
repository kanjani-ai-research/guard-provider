"""SpiceDB authorization middleware for guard-provider."""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import Request
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

SPICEDB_ENDPOINT = os.environ.get("SPICEDB_ENDPOINT", "")
SPICEDB_TOKEN = os.environ.get("SPICEDB_TOKEN", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
JWT_ALGORITHMS = ["HS256", "RS256"]

# Paths that skip authorization
SKIP_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}


def _is_dev_mode() -> bool:
    """Dev mode when SPICEDB_ENDPOINT is not configured."""
    return not SPICEDB_ENDPOINT


async def check_permission(
    user_id: str, permission: str, resource_type: str, resource_id: str
) -> bool:
    """Check permission against SpiceDB.

    Returns True if the user has the specified permission on the resource.
    In dev mode (no SPICEDB_ENDPOINT), always returns True.
    """
    if _is_dev_mode():
        return True

    try:
        from authzed.api.v1 import (
            CheckPermissionRequest,
            CheckPermissionResponse,
            ObjectReference,
            SubjectReference,
        )
        from grpcutil import bearer_token_credentials

        from authzed.api.v1 import Client as AuthzedClient

        client = AuthzedClient(
            SPICEDB_ENDPOINT,
            bearer_token_credentials(SPICEDB_TOKEN),
        )

        subject = SubjectReference(object=ObjectReference(
            object_type="user",
            object_id=user_id,
        ))
        resource = ObjectReference(
            object_type=resource_type,
            object_id=resource_id,
        )

        response = client.CheckPermission(
            CheckPermissionRequest(
                resource=resource,
                permission=permission,
                subject=subject,
            )
        )
        return (
            response.permissionship
            == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
        )
    except Exception as e:
        logger.error(f"SpiceDB check failed: {e}")
        return False


def _extract_user_from_request(request: Request) -> str | None:
    """Extract user ID from JWT in Authorization header."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    try:
        payload: dict[str, Any] = jwt.decode(
            token, JWT_SECRET, algorithms=JWT_ALGORITHMS, options={"verify_exp": False}
        )
        return payload.get("sub")
    except JWTError:
        return None


def _permission_for_method(method: str) -> str:
    """Map HTTP method to permission."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return "view"
    return "manage"


def _resource_from_path(path: str) -> tuple[str, str]:
    """Extract resource type and ID from path."""
    parts = path.strip("/").split("/")
    # /api/v1/{resource_type}/{id} or /api/v1/{resource_type}
    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "v1":
        resource_type = parts[2]
        resource_id = parts[3] if len(parts) > 3 else "*"
        return resource_type, resource_id
    return "guard-provider", "*"


class AuthorizationMiddleware(BaseHTTPMiddleware):
    """Middleware that checks SpiceDB permissions for incoming requests."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip auth for health, docs, and dev mode
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        if _is_dev_mode():
            return await call_next(request)

        # Extract user from JWT
        user_id = _extract_user_from_request(request)
        if not user_id:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: missing or invalid token"},
            )

        # Determine permission and resource
        permission = _permission_for_method(request.method)
        resource_type, resource_id = _resource_from_path(request.url.path)

        # Check permission
        allowed = await check_permission(user_id, permission, resource_type, resource_id)
        if not allowed:
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: insufficient permissions"},
            )

        return await call_next(request)
