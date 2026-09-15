import json
import re

import pytest
from CommonServerPython import DemistoException
from ZeroNetworksSegmentAssets import (
    OS_TYPES,
    Client,
    asset_quarantine_command,
    asset_search_command,
    asset_to_context,
    enum_label,
    epoch_to_date_string,
    resolve_asset_id,
)
from ZeroNetworksSegmentAssets import test_module as run_test_module

BASE_URL = "https://portal.zeronetworks.com/api/v1"
ASSET_ID = "a:a:JF2xro6g"
FQDN = "server.domain.local"


def load_test_data(file_name: str) -> dict:
    with open(f"test_data/{file_name}") as test_file:
        return json.load(test_file)


@pytest.fixture
def client() -> Client:
    return Client(server_url="https://portal.zeronetworks.com", api_key="api-key", verify=False, proxy=False)


def test_test_module_success(requests_mock, client):
    """
    Given: A reachable Zero Networks server and a valid API key.
    When: Running the test-module command.
    Then: "ok" is returned.
    """
    requests_mock.get(f"{BASE_URL}/assets?_limit=1", json={"items": [], "count": 0})

    assert run_test_module(client) == "ok"


def test_test_module_unauthorized(requests_mock, client):
    """
    Given: An API key the server rejects.
    When: Running the test-module command.
    Then: An authorization-specific message is returned instead of the raw error.
    """
    requests_mock.get(f"{BASE_URL}/assets?_limit=1", status_code=401, json={"message": "unauthorized"})

    assert "Authorization Error" in run_test_module(client)


def test_asset_search_command(requests_mock, client):
    """
    Given: An FQDN that matches an asset.
    When: Running the zero-networks-segment-asset-search command.
    Then: The asset properties are returned in the context, with the numeric enums translated.
    """
    requests_mock.get(f"{BASE_URL}/assets/searchId?fqdn={FQDN}", json={"assetId": ASSET_ID})
    requests_mock.get(f"{BASE_URL}/assets/{ASSET_ID}", json=load_test_data("asset.json"))

    results = asset_search_command(client, {"fqdn": FQDN})

    assert results.outputs_prefix == "ZeroNetworks.Asset"
    assert results.outputs_key_field == "ID"
    assert results.outputs == load_test_data("asset_context.json")
    assert FQDN in results.readable_output


def test_asset_search_command_no_match_returns_message(requests_mock, client):
    """
    Given: An FQDN with no matching asset, answered with 200 and an empty object.
    When: Running the zero-networks-segment-asset-search command.
    Then: A human readable "not found" message is returned and no context is set.
    """
    requests_mock.get(f"{BASE_URL}/assets/searchId?fqdn={FQDN}", json={})

    results = asset_search_command(client, {"fqdn": FQDN})

    assert results.outputs is None
    assert f"No asset was found in Zero Networks for the FQDN '{FQDN}'." == results.readable_output


def test_asset_search_command_no_match_on_404(requests_mock, client):
    """
    Given: An FQDN with no matching asset, answered with 404.
    When: Running the zero-networks-segment-asset-search command.
    Then: The 404 is treated as "not found" rather than raised as an error.
    """
    requests_mock.get(f"{BASE_URL}/assets/searchId?fqdn={FQDN}", status_code=404, json={"message": "not found"})

    results = asset_search_command(client, {"fqdn": FQDN})

    assert results.outputs is None
    assert "No asset was found" in results.readable_output


@pytest.mark.parametrize(
    "quarantine, expected_message",
    [
        (True, f"Asset {ASSET_ID} was successfully quarantined."),
        (False, f"Asset {ASSET_ID} was successfully released from quarantine."),
    ],
)
def test_asset_quarantine_command_by_asset_id(requests_mock, client, quarantine, expected_message):
    """
    Given: An explicit asset ID.
    When: Running the quarantine or unquarantine command.
    Then: The requested state is sent to the API and reflected in the context.
    """
    quarantine_mock = requests_mock.put(f"{BASE_URL}/assets/{ASSET_ID}/actions/quarantine", json={})

    results = asset_quarantine_command(client, {"asset_id": ASSET_ID}, quarantine=quarantine)

    assert quarantine_mock.last_request.json() == {"quarantine": quarantine}
    assert results.outputs == {"ID": ASSET_ID, "IsQuarantined": quarantine}
    assert results.readable_output == expected_message


def test_asset_quarantine_command_by_fqdn(requests_mock, client):
    """
    Given: An FQDN instead of an asset ID.
    When: Running the quarantine command.
    Then: The asset ID is resolved first and both identifiers are returned in the context.
    """
    requests_mock.get(f"{BASE_URL}/assets/searchId?fqdn={FQDN}", json={"assetId": ASSET_ID})
    quarantine_mock = requests_mock.put(f"{BASE_URL}/assets/{ASSET_ID}/actions/quarantine", json={})

    results = asset_quarantine_command(client, {"fqdn": FQDN}, quarantine=True)

    assert quarantine_mock.last_request.json() == {"quarantine": True}
    assert results.outputs == {"ID": ASSET_ID, "FQDN": FQDN, "IsQuarantined": True}
    assert results.readable_output == f"Asset {FQDN} was successfully quarantined."


def test_asset_quarantine_command_unknown_fqdn(requests_mock, client):
    """
    Given: An FQDN that matches no asset.
    When: Running the quarantine command.
    Then: The command fails before any quarantine request is sent.
    """
    requests_mock.get(f"{BASE_URL}/assets/searchId?fqdn={FQDN}", json={})

    with pytest.raises(DemistoException, match=f"No asset was found in Zero Networks for the FQDN '{FQDN}'."):
        asset_quarantine_command(client, {"fqdn": FQDN}, quarantine=True)


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({}, "One of the 'asset_id' or 'fqdn' arguments must be provided."),
        ({"asset_id": ASSET_ID, "fqdn": FQDN}, "Provide either the 'asset_id' or the 'fqdn' argument, not both."),
    ],
)
def test_resolve_asset_id_invalid_arguments(client, args, expected_error):
    """
    Given: Arguments that identify no asset, or that identify one in two conflicting ways.
    When: Resolving the asset to act on.
    Then: A descriptive error is raised.
    """
    with pytest.raises(DemistoException, match=re.escape(expected_error)):
        resolve_asset_id(client, args)


@pytest.mark.parametrize(
    "value, expected",
    [
        (2, "Windows"),
        (None, None),
        (99, "Unknown (99)"),
    ],
)
def test_enum_label(value, expected):
    """
    Given: A numeric enum value that is known, missing, or not in the mapping.
    When: Translating it to a display name.
    Then: The mapped name, None, or an "Unknown" placeholder that keeps the raw value is returned.
    """
    assert enum_label(OS_TYPES, value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (1724932815000, "2024-08-29T12:00:15.000Z"),
        (0, None),
        (None, None),
    ],
)
def test_epoch_to_date_string(value, expected):
    """
    Given: An epoch-milliseconds timestamp, a zero, or None.
    When: Converting it for the context.
    Then: Only a real timestamp is converted, and it is converted as UTC regardless of the host time zone.
    """
    assert epoch_to_date_string(value) == expected


def test_asset_to_context_keeps_false_and_zero():
    """
    Given: An asset that is not quarantined and has a risk score of zero.
    When: Building the context.
    Then: The false and zero values survive, because dropping them would invert their meaning.
    """
    context = asset_to_context({"id": ASSET_ID, "isQuarantined": False, "riskScore": 0})

    assert context["IsQuarantined"] is False
    assert context["RiskScore"] == 0
