"""Authorization middleware — handles humans (JWT) and agents/helpers (MAC/cert).

Two auth paths, one middleware:
    Authorization: Bearer {jwt}              → human (substrate-auth-api /auth/check)
    Authorization: Agent {agent_id}:{mac}    → agent/helper (Agency Broker /agency/verify-identity)
    X-Service-Token: {internal_token}        → trusted internal service (cluster-only)

KISSS: detect caller type from header format, route to correct verifier.
"""

import logging
import os

import httpx
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

# Service endpoints (in-cluster ClusterIP)
AUTH_API_URL = os.environ.get("AUTH_API_URL", "http://substrate-auth-api.substrate:8080")
AGENCY_BROKER_URL = os.environ.get("AGENCY_BROKER_URL", "http://guard-provider.substrate:8090")
INTERNAL_SERVICE_TOKEN = os.environ.get("INTERNAL_SERVICE_TOKEN", "")

# Paths that skip authorization
SKIP_PATHS = {"/health", "/docs", "/openapi.json", "/redoc", "/ui/manifest"}


def _is_dev_mode() -> bool:
    return not AUTH_API_URL or AUTH_API_URL == "http://substrate-auth-api.substrate:8080" and not os.environ.get("ENFORCE_AUTH")


def _permission_for_method(method: str) -> str:
    if method in ("GET", "HEAD", "OPTIONS"):
        return "view"
    return "manage"


def _resource_from_path(path: str) -> tuple[str, str]:
    parts = path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "v1":
        resource_type = parts[2]
        resource_id = parts[3] if len(parts) > 3 else "*"
        return resource_type, resource_id
    return "guard-provider", "*"


class AuthorizationMiddleware(BaseHTTPMiddleware):
    """Middleware that handles humans (JWT), agents (MAC/cert), and internal services."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        if _is_dev_mode():
            request.state.user_id = "dev"
            request.state.org_id = "dev"
            request.state.roles = ["admin"]
            request.state.caller_type = "dev"
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        service_token = request.headers.get("x-service-token", "")

        # ── Path 1: Internal service (trusted, cluster-only) ────────
        if service_token and INTERNAL_SERVICE_TOKEN and service_token == INTERNAL_SERVICE_TOKEN:
            request.state.user_id = "internal"
            request.state.org_id = "system"
            request.state.roles = ["service"]
            request.state.caller_type = "service"
            return await call_next(request)

        # ── Path 2: Agent/Helper (MAC or cert) ─────────────────────
        if auth_header.startswith("Agent "):
            return await self._handle_agent_auth(request, auth_header, call_next)

        # ── Path 3: Human (JWT) ───────────────────────────────────
        if auth_header.startswith("Bearer "):
            return await self._handle_human_auth(request, auth_header, call_next)

        return JSONResponse(status_code=401, content={"detail": "Missing or invalid Authorization header"})

    async def _handle_human_auth(self, request: Request, auth_header: str, call_next) -> Response:
        """Human path: delegate to substrate-auth-api /auth/check."""
        permission = _permission_for_method(request.method)
        resource_type, resource_id = _resource_from_path(request.url.path)

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{AUTH_API_URL}/auth/check",
                    headers={"Authorization": auth_header},
                    json={"resource_type": resource_type, "resource_id": resource_id, "permission": permission},
                )
        except httpx.HTTPError as e:
            logger.error("substrate-auth-api unreachable: %s", e)
            return JSONResponse(status_code=503, content={"detail": "Auth service unavailable"})

        if resp.status_code != 200:
            return JSONResponse(status_code=resp.status_code, content={"detail": "Auth failed"})

        data = resp.json()
        if not data.get("allowed"):
            return JSONResponse(status_code=403, content={"detail": data.get("reason", "Forbidden")})

        request.state.user_id = data.get("user_id", "")
        request.state.org_id = data.get("org_id", "")
        request.state.roles = data.get("roles", [])
        request.state.caller_type = "human"
        return await call_next(request)

    async def _handle_agent_auth(self, request: Request, auth_header: str, call_next) -> Response:
        """Agent/Helper path: verify identity via Agency Broker.

        Header format: Agent {agent_id}:{mac_credential}
        The broker just confirms identity (no agency grant needed for reads).
        """
        try:
            # Parse: "Agent YXFQTW0VCL:abc123def..."
            payload = auth_header[6:]  # strip "Agent "
            if ":" not in payload:
                return JSONResponse(status_code=401, content={"detail": "Invalid Agent header format"})

            agent_id, mac_credential = payload.split(":", 1)

            # Ask the Agency Broker to verify identity only (lightweight check)
            gov_url = os.environ.get("GOV_APP_URL", "https://www.cyber-ai-gov.com")
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{gov_url}/api/v1/agency/request",
                    json={
                        "agent_id": agent_id,
                        "mac_credential": mac_credential,
                        "intent": f"Service call: {request.method} {request.url.path}",
                        "use_case": "service_access",
                        "resources": [],  # No AWS resources needed — just identity verification
                        "context": {"target_service": "guard-provider", "method": request.method, "path": request.url.path},
                        "duration_seconds": 900,
                    },
                )

            if resp.status_code != 200:
                return JSONResponse(status_code=401, content={"detail": "Agent authentication failed"})

            data = resp.json()
            if not data.get("granted"):
                return JSONResponse(status_code=403, content={"detail": data.get("reason", "Agent access denied")})

            request.state.user_id = agent_id
            request.state.org_id = "agent"
            request.state.roles = ["agent"]
            request.state.caller_type = "agent"
            request.state.decision_id = data.get("decision_id", "")
            return await call_next(request)

        except Exception as e:
            logger.error("Agent auth error: %s", e)
            return JSONResponse(status_code=401, content={"detail": "Agent authentication error"})
