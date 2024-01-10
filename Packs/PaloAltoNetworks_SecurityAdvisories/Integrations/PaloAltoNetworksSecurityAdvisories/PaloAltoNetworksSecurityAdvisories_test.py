import json
import os
from unittest.mock import patch
from pathlib import Path
import pytest
from PaloAltoNetworksSecurityAdvisories import Client, fetch_indicators, get_advisories, advisory_to_indicator


def util_load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


BASE_URL = "https://security.paloaltonetworks.com/api/v1"

# Set envvar if you want to run integration tests.
RUN_INTEGRATION_TESTS = os.getenv("INTEGRATION_TESTS")
ClIENT = Client(base_url=BASE_URL)


def test_client_get_products():
    """Integration test; /api/v1/products"""
    if not RUN_INTEGRATION_TESTS:
        pytest.skip("Integration tests disabled.")

    result = ClIENT.get_products()
    assert result.get("success") is True
    assert isinstance(result.get("data"), list)


def test_client_get_pan_os_advisories():
    """Integration test; /api/v1/products"""
    if not RUN_INTEGRATION_TESTS:
        pytest.skip("Integration tests disabled.")

    result = ClIENT.get_advisories("PAN-OS", {})
    assert result.get("success") is True
    assert isinstance(result.get("data"), list)

    result = ClIENT.get_advisories("PAN-OS", {"sort": "-cvss"})
    assert result.get("data")[0].get("impact").get("cvss").get("baseScore") == 10

    result = ClIENT.get_advisories("PAN-OS", {"q": "\"CVE-2021-3056\""})
    assert len(result.get("data")) == 1


@patch("PaloAltoNetworksSecurityAdvisories.Client.get_advisories")
def test_get_advisories_command(patched_get_advisories):
    patched_get_advisories.return_value = util_load_json("test_data/advisories.json")

    result = get_advisories(ClIENT, "PANOS")
    assert result
    assert len(result.raw_response) == 3


@patch("PaloAltoNetworksSecurityAdvisories.Client.get_advisories")
def test_fetch_indicators_command(patched_get_advisories):
    patched_get_advisories.return_value = util_load_json("test_data/advisories.json")
    result = fetch_indicators(ClIENT, "PANOS")
    assert result[0].get("value")
    assert result[0].get("type")
    assert result[0].get("rawJSON")
    for _field, field_value in result[0].get("fields").items():
        assert field_value


def test_advisory_to_indicator() -> None:
    """
    Test the function advisory_to_indicator.

    Given:
        A mock data loaded from "test_data/advisories4.json"
    When:
        The function advisory_to_indicator is called with the response from the mock data
    Then:
        The function should return a dictionary with:
            - "value" key equal to "CVE-2023-38802"
            - "type" key equal to "CVE"
            - "fields" key equal to the "fields" key in the "excepted_response" of the mock data
    """
    mock_data = util_load_json("test_data/advisories4.json")

    result = advisory_to_indicator(mock_data["response"])
    assert result["value"] == "CVE-2023-38802"
    assert result["type"] == "CVE"
    assert result["fields"] == mock_data["excepted_response"]["fields"]
