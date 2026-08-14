"""Guard-provider FastAPI application."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.auth import AuthorizationMiddleware
from app.models import (
    ClusterEntry,
    CspEntry,
    HelperEntry,
    ScopeResponse,
    ScopeTarget,
)
from app.store import (
    delete_entry,
    get_entry,
    get_scope,
    init_table,
    list_entries,
    put_entry,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize resources on startup."""
    init_table()
    yield


app = FastAPI(
    title="Guard Provider",
    description="Guard-provider service for managing CSPs, Clusters, and Helpers",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authorization middleware
app.add_middleware(AuthorizationMiddleware)


# --- Health ---


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "guard-provider"}


# --- Scope ---


@app.get("/api/v1/scope", response_model=ScopeResponse)
async def get_scope_endpoint() -> ScopeResponse:
    """Return all ACTIVE CSPs and Clusters for Bona scan scope."""
    entries = await get_scope()
    targets = [
        ScopeTarget(
            kind=entry.pop("kind", "unknown"),
            id=entry.get("id", ""),
            data=entry,
        )
        for entry in entries
    ]
    return ScopeResponse(targets=targets)


# --- CSP CRUD ---


@app.get("/api/v1/csp")
async def list_csps(status: str | None = None) -> list[dict[str, Any]]:
    """List all CSP entries, optionally filtered by status."""
    return await list_entries("csp", status=status)


@app.post("/api/v1/csp", status_code=201)
async def create_csp(entry: CspEntry) -> dict[str, Any]:
    """Create a new CSP entry."""
    entry_id = str(uuid.uuid4())
    data = entry.model_dump()
    data["status"] = data["status"].value
    await put_entry("csp", entry_id, data)
    return {"id": entry_id, **data}


@app.get("/api/v1/csp/{entry_id}")
async def get_csp(entry_id: str) -> dict[str, Any]:
    """Get a specific CSP entry."""
    item = await get_entry("csp", entry_id)
    if not item:
        raise HTTPException(status_code=404, detail="CSP entry not found")
    return item


# --- Cluster CRUD ---


@app.get("/api/v1/cluster")
async def list_clusters(status: str | None = None) -> list[dict[str, Any]]:
    """List all Cluster entries, optionally filtered by status."""
    return await list_entries("cluster", status=status)


@app.post("/api/v1/cluster", status_code=201)
async def create_cluster(entry: ClusterEntry) -> dict[str, Any]:
    """Create a new Cluster entry."""
    entry_id = str(uuid.uuid4())
    data = entry.model_dump()
    data["status"] = data["status"].value
    await put_entry("cluster", entry_id, data)
    return {"id": entry_id, **data}


@app.get("/api/v1/cluster/{entry_id}")
async def get_cluster(entry_id: str) -> dict[str, Any]:
    """Get a specific Cluster entry."""
    item = await get_entry("cluster", entry_id)
    if not item:
        raise HTTPException(status_code=404, detail="Cluster entry not found")
    return item


# --- Helper CRUD ---


@app.get("/api/v1/helper")
async def list_helpers(status: str | None = None) -> list[dict[str, Any]]:
    """List all Helper entries, optionally filtered by status."""
    return await list_entries("helper", status=status)


@app.post("/api/v1/helper", status_code=201)
async def create_helper(entry: HelperEntry) -> dict[str, Any]:
    """Create a new Helper entry."""
    entry_id = str(uuid.uuid4())
    data = entry.model_dump()
    data["status"] = data["status"].value
    await put_entry("helper", entry_id, data)
    return {"id": entry_id, **data}


@app.get("/api/v1/helper/{entry_id}")
async def get_helper(entry_id: str) -> dict[str, Any]:
    """Get a specific Helper entry."""
    item = await get_entry("helper", entry_id)
    if not item:
        raise HTTPException(status_code=404, detail="Helper entry not found")
    return item


# --- UI Manifest ---


@app.get("/ui/manifest")
async def ui_manifest() -> dict[str, Any]:
    """Return the UI manifest for the guard-provider service."""
    return {
        "service": "guard-provider",
        "version": "1.0.0",
        "endpoints": [
            {"path": "/api/v1/scope", "method": "GET", "label": "Scan Scope"},
            {"path": "/api/v1/csp", "method": "GET", "label": "CSP Entries"},
            {"path": "/api/v1/cluster", "method": "GET", "label": "Cluster Entries"},
            {"path": "/api/v1/helper", "method": "GET", "label": "Helper Entries"},
        ],
        "ui": {
            "title": "Guard Provider",
            "description": "Manage cloud security posture targets and helpers",
            "navigation": [
                {"label": "Scope", "path": "/scope"},
                {"label": "CSPs", "path": "/csps"},
                {"label": "Clusters", "path": "/clusters"},
                {"label": "Helpers", "path": "/helpers"},
            ],
        },
    }
