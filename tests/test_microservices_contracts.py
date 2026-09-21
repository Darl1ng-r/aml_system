"""
Test Suite: Microservices Contract & Schema Validation
======================================================
Validates Protobuf IDL definitions and CloudEvents v1.0 JSON schemas.
"""

import json
from pathlib import Path
import pytest


def test_protobuf_contract_files_exist_and_valid():
    """Validates that all microservices protobuf contracts exist and contain valid syntax."""
    proto_dir = Path(__file__).parent.parent / "contracts" / "proto"
    expected_protos = [
        proto_dir / "graph" / "v1" / "graph.proto",
        proto_dir / "screening" / "v1" / "screening.proto",
        proto_dir / "ingestion" / "v1" / "ingestion.proto",
    ]

    for p in expected_protos:
        assert p.exists(), f"Protobuf contract missing: {p}"
        content = p.read_text(encoding="utf-8")
        assert 'syntax = "proto3";' in content, f"Missing syntax specification in {p}"
        assert "service " in content, f"Missing service definition in {p}"
        assert "message " in content, f"Missing message definitions in {p}"


def test_cloudevents_json_schemas_exist_and_parse():
    """Validates that CloudEvents schemas are syntactically valid JSON and contain required spec fields."""
    events_dir = Path(__file__).parent.parent / "contracts" / "events"
    expected_schemas = [
        events_dir / "aml.core.transaction.ingested.v1.json",
        events_dir / "aml.detection.alert.raised.v1.json",
        events_dir / "aml.screening.match.flagged.v1.json",
    ]

    for schema_path in expected_schemas:
        assert schema_path.exists(), f"Schema file missing: {schema_path}"
        with open(schema_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "$schema" in data
        assert "$id" in data
        assert data["type"] == "object"
        assert "specversion" in data["properties"]
        assert data["properties"]["specversion"]["const"] == "1.0"
        assert "data" in data["properties"]
        assert "traceparent" in data["properties"]


def test_cloudevents_transaction_payload_structure():
    """Validates that transaction ingested schema requires financial critical fields."""
    schema_path = (
        Path(__file__).parent.parent
        / "contracts"
        / "events"
        / "aml.core.transaction.ingested.v1.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    data_props = schema["properties"]["data"]["properties"]
    assert "transaction_id" in data_props
    assert "amount" in data_props
    assert "currency" in data_props
    assert "sender_account" in data_props
    assert "receiver_account" in data_props
