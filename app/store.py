"""DynamoDB client for guard-provider-store table."""

from __future__ import annotations

import asyncio
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

TABLE_NAME = "guard-provider-store"
GSI_NAME = "GSI1"

_table = None


def init_table() -> None:
    """Initialize the DynamoDB table resource."""
    global _table
    dynamodb = boto3.resource("dynamodb")
    _table = dynamodb.Table(TABLE_NAME)


def _get_table():
    if _table is None:
        init_table()
    return _table


def _build_pk(kind: str, entry_id: str) -> str:
    return f"ENTRY#{kind}#{entry_id}"


def _build_sk() -> str:
    return "CONFIG"


def _build_gsi1pk() -> str:
    return "CATALOG"


def _build_gsi1sk(kind: str, status: str, entry_id: str) -> str:
    return f"{kind}#{status}#{entry_id}"


def _put_entry_sync(kind: str, entry_id: str, data: dict[str, Any]) -> None:
    table = _get_table()
    status = data.get("status", "ACTIVE")
    item = {
        "PK": _build_pk(kind, entry_id),
        "SK": _build_sk(),
        "GSI1PK": _build_gsi1pk(),
        "GSI1SK": _build_gsi1sk(kind, status, entry_id),
        "kind": kind,
        "id": entry_id,
        **data,
    }
    table.put_item(Item=item)


def _get_entry_sync(kind: str, entry_id: str) -> dict[str, Any] | None:
    table = _get_table()
    response = table.get_item(
        Key={"PK": _build_pk(kind, entry_id), "SK": _build_sk()}
    )
    item = response.get("Item")
    if item:
        item.pop("PK", None)
        item.pop("SK", None)
        item.pop("GSI1PK", None)
        item.pop("GSI1SK", None)
    return item


def _list_entries_sync(kind: str, status: str | None = None) -> list[dict[str, Any]]:
    table = _get_table()
    if status:
        prefix = f"{kind}#{status}#"
    else:
        prefix = f"{kind}#"

    response = table.query(
        IndexName=GSI_NAME,
        KeyConditionExpression=Key("GSI1PK").eq(_build_gsi1pk())
        & Key("GSI1SK").begins_with(prefix),
    )
    items = response.get("Items", [])
    for item in items:
        item.pop("PK", None)
        item.pop("SK", None)
        item.pop("GSI1PK", None)
        item.pop("GSI1SK", None)
    return items


def _update_status_sync(
    kind: str, entry_id: str, status: str, extra: dict[str, Any] | None = None
) -> None:
    table = _get_table()
    update_expr = "SET #st = :status, GSI1SK = :gsi1sk"
    expr_values: dict[str, Any] = {
        ":status": status,
        ":gsi1sk": _build_gsi1sk(kind, status, entry_id),
    }
    expr_names = {"#st": "status"}

    if extra:
        for i, (key, value) in enumerate(extra.items()):
            update_expr += f", #{key} = :val{i}"
            expr_values[f":val{i}"] = value
            expr_names[f"#{key}"] = key

    table.update_item(
        Key={"PK": _build_pk(kind, entry_id), "SK": _build_sk()},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
        ExpressionAttributeNames=expr_names,
    )


def _delete_entry_sync(kind: str, entry_id: str) -> None:
    table = _get_table()
    table.delete_item(Key={"PK": _build_pk(kind, entry_id), "SK": _build_sk()})


def _get_scope_sync() -> list[dict[str, Any]]:
    """Get all ACTIVE csp and cluster entries."""
    csp_entries = _list_entries_sync("csp", status="ACTIVE")
    cluster_entries = _list_entries_sync("cluster", status="ACTIVE")
    results = []
    for entry in csp_entries:
        results.append({"kind": "csp", **entry})
    for entry in cluster_entries:
        results.append({"kind": "cluster", **entry})
    return results


# Async wrappers using asyncio.to_thread


async def put_entry(kind: str, entry_id: str, data: dict[str, Any]) -> None:
    await asyncio.to_thread(_put_entry_sync, kind, entry_id, data)


async def get_entry(kind: str, entry_id: str) -> dict[str, Any] | None:
    return await asyncio.to_thread(_get_entry_sync, kind, entry_id)


async def list_entries(kind: str, status: str | None = None) -> list[dict[str, Any]]:
    return await asyncio.to_thread(_list_entries_sync, kind, status)


async def update_status(
    kind: str, entry_id: str, status: str, extra: dict[str, Any] | None = None
) -> None:
    await asyncio.to_thread(_update_status_sync, kind, entry_id, status, extra or {})


async def delete_entry(kind: str, entry_id: str) -> None:
    await asyncio.to_thread(_delete_entry_sync, kind, entry_id)


async def get_scope() -> list[dict[str, Any]]:
    return await asyncio.to_thread(_get_scope_sync)
