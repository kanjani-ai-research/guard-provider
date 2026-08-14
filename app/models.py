"""Pydantic models for guard-provider entities."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntryStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    PENDING = "PENDING"
    ERROR = "ERROR"


class CspEntry(BaseModel):
    cloud: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    account_id: str = Field(..., description="Cloud account identifier")
    regions: list[str] = Field(default_factory=list, description="Target regions")
    name: str = Field(..., description="Human-readable name")
    credential: str = Field(..., description="Credential reference or ARN")
    provider_types: list[str] = Field(default_factory=list, description="Provider types to scan")
    status: EntryStatus = Field(default=EntryStatus.ACTIVE)
    schedule: str = Field(default="@daily", description="Cron schedule expression")


class ClusterEntry(BaseModel):
    cloud: str = Field(..., description="Cloud provider hosting the cluster")
    cluster_name: str = Field(..., description="Cluster name")
    account_id: str = Field(..., description="Cloud account identifier")
    region: str = Field(..., description="Region of the cluster")
    credential: str = Field(..., description="Credential reference or ARN")
    argocd: str | None = Field(default=None, description="ArgoCD endpoint if applicable")
    status: EntryStatus = Field(default=EntryStatus.ACTIVE)


class HelperEntry(BaseModel):
    name: str = Field(..., description="Helper service name")
    endpoint: str = Field(..., description="Helper service endpoint URL")
    health_check: str = Field(default="/health", description="Health check path")
    auth: str | None = Field(default=None, description="Auth mechanism for the helper")
    capabilities: list[str] = Field(default_factory=list, description="Capabilities provided")
    owner: str = Field(default="", description="Owner team or individual")
    status: EntryStatus = Field(default=EntryStatus.ACTIVE)


class ScopeTarget(BaseModel):
    kind: str = Field(..., description="Entry kind: csp or cluster")
    id: str = Field(..., description="Entry identifier")
    data: dict[str, Any] = Field(default_factory=dict, description="Entry configuration")


class ScopeResponse(BaseModel):
    targets: list[ScopeTarget] = Field(default_factory=list)
