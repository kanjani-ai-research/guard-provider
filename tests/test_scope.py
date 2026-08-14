"""Unit tests for guard-provider service."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# Ensure dev mode (no SpiceDB) for tests
os.environ.pop("SPICEDB_ENDPOINT", None)

from app.main import app


@pytest.fixture
async def client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client):
    """Test health endpoint returns healthy status."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "guard-provider"


@pytest.mark.asyncio
async def test_scope_returns_active_targets(client):
    """Test scope endpoint returns ACTIVE CSPs and Clusters."""
    mock_scope = [
        {"kind": "csp", "id": "csp-1", "cloud": "aws", "status": "ACTIVE", "name": "prod-aws"},
        {"kind": "cluster", "id": "cluster-1", "cloud": "aws", "status": "ACTIVE", "cluster_name": "eks-prod"},
    ]
    with patch("app.main.get_scope", new_callable=AsyncMock, return_value=mock_scope):
        response = await client.get("/api/v1/scope")
    assert response.status_code == 200
    data = response.json()
    assert len(data["targets"]) == 2
    assert data["targets"][0]["kind"] == "csp"
    assert data["targets"][1]["kind"] == "cluster"


@pytest.mark.asyncio
async def test_scope_excludes_disabled(client):
    """Test scope endpoint only returns ACTIVE entries (disabled excluded by store)."""
    # get_scope only returns ACTIVE entries by design
    mock_scope = [
        {"kind": "csp", "id": "csp-active", "cloud": "aws", "status": "ACTIVE", "name": "active"},
    ]
    with patch("app.main.get_scope", new_callable=AsyncMock, return_value=mock_scope):
        response = await client.get("/api/v1/scope")
    data = response.json()
    assert len(data["targets"]) == 1
    assert data["targets"][0]["id"] == "csp-active"
    # Ensure no disabled entries
    for target in data["targets"]:
        assert target["data"].get("status") != "DISABLED"


@pytest.mark.asyncio
async def test_csp_create(client):
    """Test creating a CSP entry."""
    csp_data = {
        "cloud": "aws",
        "account_id": "123456789012",
        "regions": ["us-east-1", "us-west-2"],
        "name": "production-aws",
        "credential": "arn:aws:iam::123456789012:role/guard",
        "provider_types": ["ec2", "s3"],
        "status": "ACTIVE",
        "schedule": "@hourly",
    }
    with patch("app.main.put_entry", new_callable=AsyncMock) as mock_put:
        response = await client.post("/api/v1/csp", json=csp_data)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["cloud"] == "aws"
    assert data["account_id"] == "123456789012"
    assert data["regions"] == ["us-east-1", "us-west-2"]
    mock_put.assert_called_once()


@pytest.mark.asyncio
async def test_csp_get(client):
    """Test getting a CSP entry by ID."""
    mock_entry = {
        "id": "csp-123",
        "kind": "csp",
        "cloud": "aws",
        "account_id": "123456789012",
        "name": "test-csp",
        "status": "ACTIVE",
    }
    with patch("app.main.get_entry", new_callable=AsyncMock, return_value=mock_entry):
        response = await client.get("/api/v1/csp/csp-123")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "csp-123"
    assert data["cloud"] == "aws"


@pytest.mark.asyncio
async def test_csp_get_not_found(client):
    """Test getting a non-existent CSP entry returns 404."""
    with patch("app.main.get_entry", new_callable=AsyncMock, return_value=None):
        response = await client.get("/api/v1/csp/nonexistent")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_csp_list(client):
    """Test listing CSP entries."""
    mock_entries = [
        {"id": "csp-1", "cloud": "aws", "status": "ACTIVE"},
        {"id": "csp-2", "cloud": "azure", "status": "ACTIVE"},
    ]
    with patch("app.main.list_entries", new_callable=AsyncMock, return_value=mock_entries):
        response = await client.get("/api/v1/csp")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


@pytest.mark.asyncio
async def test_cluster_create(client):
    """Test creating a Cluster entry."""
    cluster_data = {
        "cloud": "aws",
        "cluster_name": "eks-production",
        "account_id": "123456789012",
        "region": "us-east-1",
        "credential": "arn:aws:iam::123456789012:role/eks",
        "argocd": "https://argocd.internal",
        "status": "ACTIVE",
    }
    with patch("app.main.put_entry", new_callable=AsyncMock):
        response = await client.post("/api/v1/cluster", json=cluster_data)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["cluster_name"] == "eks-production"
    assert data["argocd"] == "https://argocd.internal"


@pytest.mark.asyncio
async def test_cluster_get(client):
    """Test getting a Cluster entry by ID."""
    mock_entry = {
        "id": "cluster-abc",
        "kind": "cluster",
        "cloud": "aws",
        "cluster_name": "eks-staging",
        "status": "ACTIVE",
    }
    with patch("app.main.get_entry", new_callable=AsyncMock, return_value=mock_entry):
        response = await client.get("/api/v1/cluster/cluster-abc")
    assert response.status_code == 200
    data = response.json()
    assert data["cluster_name"] == "eks-staging"


@pytest.mark.asyncio
async def test_cluster_list(client):
    """Test listing Cluster entries."""
    mock_entries = [
        {"id": "c-1", "cloud": "aws", "cluster_name": "eks-1", "status": "ACTIVE"},
    ]
    with patch("app.main.list_entries", new_callable=AsyncMock, return_value=mock_entries):
        response = await client.get("/api/v1/cluster")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1


@pytest.mark.asyncio
async def test_auth_rejects_unauthorized(client):
    """Test that auth middleware rejects requests when SpiceDB is configured but no token."""
    with patch.dict(os.environ, {"SPICEDB_ENDPOINT": "localhost:50051", "SPICEDB_TOKEN": "test"}):
        # Reimport to pick up env change - simulate by patching _is_dev_mode
        with patch("app.auth._is_dev_mode", return_value=False):
            response = await client.get("/api/v1/csp")
    assert response.status_code == 401
    assert "Unauthorized" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auth_rejects_invalid_token(client):
    """Test that auth middleware rejects invalid JWT tokens."""
    with patch("app.auth._is_dev_mode", return_value=False):
        response = await client.get(
            "/api/v1/csp",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ui_manifest_structure(client):
    """Test UI manifest returns correct structure."""
    response = await client.get("/ui/manifest")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "guard-provider"
    assert data["version"] == "1.0.0"
    assert "endpoints" in data
    assert "ui" in data
    assert len(data["endpoints"]) >= 4
    assert "navigation" in data["ui"]
    assert data["ui"]["title"] == "Guard Provider"
    # Verify endpoint structure
    for endpoint in data["endpoints"]:
        assert "path" in endpoint
        assert "method" in endpoint
        assert "label" in endpoint


@pytest.mark.asyncio
async def test_helper_create(client):
    """Test creating a Helper entry."""
    helper_data = {
        "name": "vulnerability-scanner",
        "endpoint": "https://scanner.internal/api",
        "health_check": "/health",
        "auth": "iam",
        "capabilities": ["scan", "report"],
        "owner": "security-team",
        "status": "ACTIVE",
    }
    with patch("app.main.put_entry", new_callable=AsyncMock):
        response = await client.post("/api/v1/helper", json=helper_data)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["name"] == "vulnerability-scanner"
    assert data["capabilities"] == ["scan", "report"]


@pytest.mark.asyncio
async def test_helper_get_not_found(client):
    """Test getting a non-existent Helper entry returns 404."""
    with patch("app.main.get_entry", new_callable=AsyncMock, return_value=None):
        response = await client.get("/api/v1/helper/nonexistent")
    assert response.status_code == 404
