"""Unit tests for the Haseen Threat Intel integration."""

import json
from pathlib import Path

import pytest

from HaseenThreatIntel import (
    Client,
    _parse_x_attributes,
    extract_value_from_pattern,
    fetch_indicators_command,
    parse_stix_bundle,
)

TEST_DATA_DIR = Path(__file__).parent / "test_data"


def load_bundle() -> dict:
    return json.loads((TEST_DATA_DIR / "stix_bundle.json").read_text())


@pytest.mark.parametrize(
    "pattern, stix_type, expected",
    [
        ("[ipv4-addr:value = '1.2.3.4']", "ipv4-addr", "1.2.3.4"),
        ("[domain-name:value = 'example.com']", "domain-name", "example.com"),
        ("[url:value = 'https://evil.example/x']", "url", "https://evil.example/x"),
        ("[file:hashes.'SHA-256' = 'abc123']", "file", "abc123"),
        ("[file:hashes.'MD5' = 'fd4390f36e6e60b9533f2f5c6047ce73']", "file", "fd4390f36e6e60b9533f2f5c6047ce73"),
        (
            "[file:hashes.'SHA-1' = '20608406d5bb6d6a9c921118b226f8e084097055']",
            "file",
            "20608406d5bb6d6a9c921118b226f8e084097055",
        ),
    ],
)
def test_extract_value_from_pattern(pattern, stix_type, expected):
    assert extract_value_from_pattern(pattern, stix_type) == expected


def test_parse_stix_bundle_types():
    bundle = load_bundle()
    indicators = parse_stix_bundle(bundle)
    assert len(indicators) == 19
    types = {i["type"] for i in indicators}
    assert types == {"IP", "Domain", "File", "URL"}

    # Spot-check exact values present in the real feed.
    values = {i["value"] for i in indicators}
    assert "89.46.223.88" in values  # ipv4-addr
    assert "globalbusiness-checkers-it.azurewebsites.net" in values  # domain-name
    assert "adclick.g.doubleclick.net/pcs/click" in values  # url
    assert "fd4390f36e6e60b9533f2f5c6047ce73" in values  # MD5
    assert "d85c1e6750b46ab77dde45ec04683e7ad84ad29db6a22392af1f22c395909c30" in values  # SHA-256


def test_parse_stix_bundle_skips_orphan_relationship():
    bundle = {
        "objects": [
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--missing",
            },
            {"type": "ipv4-addr", "value": "9.9.9.9", "modified": "2024-01-01T00:00:00.000Z"},
        ]
    }
    indicators = parse_stix_bundle(bundle)
    assert len(indicators) == 1
    assert indicators[0]["value"] == "9.9.9.9"
    assert "relationships" not in indicators[0]


def test_parse_stix_bundle_resolves_relationship():
    bundle = {
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[domain-name:value = 'evil.com']",
                "name": "evil.com",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "RedQube Stealer",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--1",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
        ]
    }
    indicators = parse_stix_bundle(bundle)

    domain = next(i for i in indicators if i["value"] == "evil.com")
    malware = next(i for i in indicators if i["value"] == "RedQube Stealer")

    # Malware SDO surfaces as a first-class Malware indicator with canonical
    # score — XSOAR treats SDOs as ingestible indicators so the relationship
    # graph can traverse both directions.
    assert malware["type"] == "Malware"
    assert malware["score"] == 3  # ThreatIntel.ObjectsScore.MALWARE

    # Domain gets an `indicates`->`indicated-by` relationship to the malware.
    assert domain["relationships"][0]["name"] == "indicated-by"
    assert domain["relationships"][0]["entityA"] == "evil.com"
    assert domain["relationships"][0]["entityAType"] == "Domain"
    assert domain["relationships"][0]["entityB"] == "RedQube Stealer"
    assert domain["relationships"][0]["entityBType"] == "Malware"


def test_parse_stix_bundle_dedups_duplicate_relationships():
    """Haseen emits each relationship twice; only one edge should survive."""
    rel = {
        "type": "relationship",
        "id": "relationship--1",
        "relationship_type": "indicates",
        "source_ref": "indicator--1",
        "target_ref": "malware--1",
        "created": "2025-01-01T00:00:00.000Z",
        "modified": "2025-01-01T00:00:00.000Z",
    }
    bundle = {
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[domain-name:value = 'evil.com']",
                "name": "evil.com",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "RedQube Stealer",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
            dict(rel),
            dict(rel),  # duplicate
        ]
    }
    indicators = parse_stix_bundle(bundle)
    domain = next(i for i in indicators if i["value"] == "evil.com")
    assert len(domain["relationships"]) == 1


def test_normalize_unknown_relationship_skips():
    bundle = {
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[domain-name:value = 'evil.com']",
                "name": "evil.com",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "X",
                "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z",
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "bogus-relation",
                "source_ref": "indicator--1",
                "target_ref": "malware--1",
            },
        ]
    }
    indicators = parse_stix_bundle(bundle)
    domain = next(i for i in indicators if i["value"] == "evil.com")
    assert "relationships" not in domain


def test_x_attributes_flatten_and_score():
    obj = {
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "name": "1.2.3.4",
        "x_attributes": [
            {"name": "severity", "value": "Critical"},
            {"name": "Threat Type", "value": "Ransomware"},
            {"name": "Threat Type", "value": "Criminal"},
            {"name": "Role", "value": "Command and control location used by malware"},
        ],
    }
    bundle = {"objects": [obj]}
    (indicator,) = parse_stix_bundle(bundle)

    assert indicator["score"] == 3
    fields = indicator["fields"]
    assert fields["severity"] == "Critical"
    assert fields["Threat Type"] == "Ransomware, Criminal"
    assert fields["Role"] == "Command and control location used by malware"


def test_x_attributes_high_severity_scores_3():
    fields, score = _parse_x_attributes({"x_attributes": [{"name": "severity", "value": "High"}]})
    assert score == 3
    assert fields["severity"] == "High"


def test_fetch_indicators_delta(mocker):
    """New indicators are filtered by `modified`; last_run advances."""
    client = mocker.MagicMock()
    client.fetch_bundle.return_value = load_bundle()
    last_run = {"last_modified": "2020-01-01T00:00:00.000Z"}
    indicators, new_last_run = fetch_indicators_command(client, "7 days", 0, last_run)
    assert len(indicators) == 19
    assert new_last_run["last_modified"] >= last_run["last_modified"]


def test_client_uses_token_query_param(mocker):
    """Token must be sent as a `token` query param; optional Basic only when
    credentials are supplied."""
    import base64 as b64

    mock_http = mocker.patch.object(Client, "_http_request", return_value={"objects": []})
    client = Client(url="https://example.com", token="secret", verify=True, proxy=False)
    client.fetch_bundle()
    assert mock_http.call_args.kwargs["params"] == {"token": "secret"}
    assert "Authorization" not in client._headers

    # With username/password, a Basic Authorization header is added.
    client2 = Client(
        url="https://example.com",
        token="secret",
        verify=True,
        proxy=False,
        username="user@example.com",
        password="secret",
    )
    expected = "Basic " + b64.b64encode(b"user@example.com:secret").decode("ascii")
    assert client2._headers.get("Authorization") == expected


def test_fetch_delta_handles_utc_offset(mocker):
    """A '+03:00' modified timestamp must still cut over correctly (regression:
    a raw string compare breaks on non-zero-padded offsets)."""
    bundle = {
        "objects": [
            {
                "type": "ipv4-addr",
                "value": "10.0.0.1",
                # 20:00 UTC+3 == 17:00 UTC — after a 16:00 UTC cutoff.
                "modified": "2025-01-01T20:00:00+03:00",
            }
        ]
    }
    client = mocker.MagicMock()
    client.fetch_bundle.return_value = bundle
    last_run = {"last_modified": "2025-01-01T16:00:00.000Z"}
    indicators, new_last_run = fetch_indicators_command(client, "7 days", 0, last_run)
    assert len(indicators) == 1
    assert indicators[0]["value"] == "10.0.0.1"


def test_fetch_delta_returns_empty_when_nothing_new(mocker):
    """When no indicator crosses the cutoff, nothing is re-emitted."""
    bundle = {"objects": [{"type": "ipv4-addr", "value": "10.0.0.1", "modified": "2025-01-01T00:00:00.000Z"}]}
    client = mocker.MagicMock()
    client.fetch_bundle.return_value = bundle
    last_run = {"last_modified": "2025-06-01T00:00:00.000Z"}  # far future cutoff
    indicators, new_last_run = fetch_indicators_command(client, "7 days", 0, last_run)
    assert indicators == []
