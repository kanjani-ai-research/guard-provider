"""Unit tests for app.auth.AuthorizationMiddleware: the three caller types (internal service
token, agent MAC via the Agency Broker, human JWT via substrate-auth-api) and dev mode.
The auth services are httpx.MockTransport stubs."""

from types import SimpleNamespace

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app import auth
from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.fixture
def enforced(monkeypatch):
    monkeypatch.setattr(auth, "_is_dev_mode", lambda: False)


@pytest.fixture
def upstream(monkeypatch):
    """Stub substrate-auth-api and the agency broker; tests set `reply`."""
    state = {"calls": [], "reply": httpx.Response(200, json={})}

    def handler(request):
        state["calls"].append(request)
        if isinstance(state["reply"], Exception):
            raise state["reply"]
        return state["reply"]

    class StubClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(auth, "httpx", SimpleNamespace(AsyncClient=StubClient, HTTPError=httpx.HTTPError))
    return state


@pytest.fixture(autouse=True)
def empty_store(monkeypatch):
    async def list_entries(kind, status=None):
        return []

    async def put_entry(kind, entry_id, data):
        return None

    monkeypatch.setattr("app.main.list_entries", list_entries)
    monkeypatch.setattr("app.main.put_entry", put_entry)


@pytest.mark.parametrize("method,perm", [("GET", "view"), ("HEAD", "view"), ("OPTIONS", "view"),
                                         ("POST", "manage"), ("DELETE", "manage")])
def test_permission_for_method(method, perm):
    assert auth._permission_for_method(method) == perm


@pytest.mark.parametrize("path,resource", [
    ("/api/v1/csp", ("csp", "*")),
    ("/api/v1/csp/abc", ("csp", "abc")),
    ("/api/v1/cluster/c-1/extra", ("cluster", "c-1")),
    ("/ui/other", ("guard-provider", "*")),
])
def test_resource_from_path(path, resource):
    assert auth._resource_from_path(path) == resource


async def test_health_skips_auth(client, enforced, upstream):
    assert (await client.get("/health")).status_code == 200
    assert upstream["calls"] == []


async def test_internal_service_token(client, enforced, upstream, monkeypatch):
    monkeypatch.setattr(auth, "INTERNAL_SERVICE_TOKEN", "s3cret")
    assert (await client.get("/api/v1/csp", headers={"X-Service-Token": "s3cret"})).status_code == 200
    assert (await client.get("/api/v1/csp", headers={"X-Service-Token": "wrong"})).status_code == 401
    assert upstream["calls"] == []


async def test_service_token_is_ignored_when_unconfigured(client, enforced, upstream, monkeypatch):
    monkeypatch.setattr(auth, "INTERNAL_SERVICE_TOKEN", "")
    assert (await client.get("/api/v1/csp", headers={"X-Service-Token": ""})).status_code == 401


async def test_human_allowed_calls_auth_check_with_resource_and_permission(client, enforced, upstream):
    upstream["reply"] = httpx.Response(200, json={"allowed": True, "user_id": "u1", "org_id": "o1", "roles": ["r"]})
    resp = await client.post("/api/v1/helper", headers={"Authorization": "Bearer jwt-1"},
                             json={"name": "h", "endpoint": "https://h"})
    assert resp.status_code == 201
    (call,) = upstream["calls"]
    assert str(call.url) == f"{auth.AUTH_API_URL}/auth/check"
    assert call.headers["authorization"] == "Bearer jwt-1"
    import json
    assert json.loads(call.content) == {"resource_type": "helper", "resource_id": "*", "permission": "manage"}


async def test_human_denied_is_403_with_reason(client, enforced, upstream):
    upstream["reply"] = httpx.Response(200, json={"allowed": False, "reason": "no view on csp"})
    resp = await client.get("/api/v1/csp", headers={"Authorization": "Bearer jwt-1"})
    assert resp.status_code == 403 and resp.json() == {"detail": "no view on csp"}


async def test_human_auth_api_unreachable_is_503(client, enforced, upstream):
    upstream["reply"] = httpx.ConnectError("refused")
    resp = await client.get("/api/v1/csp", headers={"Authorization": "Bearer jwt-1"})
    assert resp.status_code == 503


async def test_agent_bad_header_format(client, enforced, upstream):
    resp = await client.get("/api/v1/csp", headers={"Authorization": "Agent no-colon"})
    assert resp.status_code == 401 and resp.json() == {"detail": "Invalid Agent header format"}
    assert upstream["calls"] == []


async def test_agent_granted_by_broker(client, enforced, upstream):
    upstream["reply"] = httpx.Response(200, json={"granted": True, "decision_id": "d1"})
    resp = await client.get("/api/v1/csp", headers={"Authorization": "Agent AG1:mac-xyz"})
    assert resp.status_code == 200
    import json
    body = json.loads(upstream["calls"][0].content)
    assert (body["agent_id"], body["mac_credential"]) == ("AG1", "mac-xyz")
    assert body["context"] == {"target_service": "guard-provider", "method": "GET", "path": "/api/v1/csp"}


@pytest.mark.parametrize("reply,status", [
    (httpx.Response(200, json={"granted": False, "reason": "nope"}), 403),
    (httpx.Response(500, json={}), 401),
])
async def test_agent_denied(client, enforced, upstream, reply, status):
    upstream["reply"] = reply
    assert (await client.get("/api/v1/csp", headers={"Authorization": "Agent AG1:mac"})).status_code == status


def test_dev_mode_needs_empty_url_or_default_url_without_enforce(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_API_URL", "http://auth.example:8080")
    assert auth._is_dev_mode() is False
    monkeypatch.setattr(auth, "AUTH_API_URL", "")
    assert auth._is_dev_mode() is True
    monkeypatch.setattr(auth, "AUTH_API_URL", "http://substrate-auth-api.substrate:8080")
    monkeypatch.setenv("ENFORCE_AUTH", "1")
    assert auth._is_dev_mode() is False


@pytest.mark.xfail(strict=True, reason=(
    "BUG: auth fails OPEN by default: AUTH_API_URL defaults to the real in-cluster auth-api URL and "
    "_is_dev_mode() treats that default without ENFORCE_AUTH as dev mode (auth.py:29-30), so a pod "
    "deployed with default config serves every /api/v1 call unauthenticated as role admin"))
async def test_default_config_does_not_bypass_auth(client, monkeypatch):
    monkeypatch.delenv("ENFORCE_AUTH", raising=False)
    monkeypatch.setattr(auth, "AUTH_API_URL", "http://substrate-auth-api.substrate:8080")
    assert (await client.get("/api/v1/csp")).status_code == 401
