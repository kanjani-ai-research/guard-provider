"""Unit tests for app.store on moto DynamoDB: key layout, status-indexed listing and scope."""

import boto3
import pytest
from moto import mock_aws

from app import store


@pytest.fixture
def table(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        t = boto3.resource("dynamodb").create_table(
            TableName=store.TABLE_NAME,
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("PK", "SK", "GSI1PK", "GSI1SK")],
            GlobalSecondaryIndexes=[{
                "IndexName": store.GSI_NAME,
                "KeySchema": [{"AttributeName": "GSI1PK", "KeyType": "HASH"},
                              {"AttributeName": "GSI1SK", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"}}],
            BillingMode="PAY_PER_REQUEST",
        )
        monkeypatch.setattr(store, "_table", None)
        store.init_table()
        yield t


async def test_put_and_get_strip_key_attributes(table):
    await store.put_entry("csp", "c1", {"name": "prod", "status": "ACTIVE"})
    raw = table.get_item(Key={"PK": "ENTRY#csp#c1", "SK": "CONFIG"})["Item"]
    assert (raw["GSI1PK"], raw["GSI1SK"]) == ("CATALOG", "csp#ACTIVE#c1")
    assert await store.get_entry("csp", "c1") == {"kind": "csp", "id": "c1", "name": "prod", "status": "ACTIVE"}
    assert await store.get_entry("csp", "missing") is None


async def test_list_filters_by_kind_and_status(table):
    await store.put_entry("csp", "a", {"status": "ACTIVE"})
    await store.put_entry("csp", "b", {"status": "DISABLED"})
    await store.put_entry("cluster", "k", {"status": "ACTIVE"})
    assert sorted(e["id"] for e in await store.list_entries("csp")) == ["a", "b"]
    assert [e["id"] for e in await store.list_entries("csp", "DISABLED")] == ["b"]
    assert [e["id"] for e in await store.list_entries("cluster")] == ["k"]


async def test_update_status_moves_entry_between_status_indexes(table):
    await store.put_entry("csp", "a", {"status": "ACTIVE"})
    await store.update_status("csp", "a", "ERROR", {"last_error": "boom"})
    assert await store.list_entries("csp", "ACTIVE") == []
    (entry,) = await store.list_entries("csp", "ERROR")
    assert entry["last_error"] == "boom" and entry["status"] == "ERROR"


async def test_scope_is_active_csps_and_clusters_only(table):
    await store.put_entry("csp", "a", {"status": "ACTIVE"})
    await store.put_entry("csp", "b", {"status": "DISABLED"})
    await store.put_entry("cluster", "k", {"status": "ACTIVE"})
    await store.put_entry("helper", "h", {"status": "ACTIVE"})
    scope = await store.get_scope()
    assert sorted((e["kind"], e["id"]) for e in scope) == [("cluster", "k"), ("csp", "a")]


async def test_delete(table):
    await store.put_entry("helper", "h", {"status": "ACTIVE"})
    await store.delete_entry("helper", "h")
    assert await store.get_entry("helper", "h") is None
