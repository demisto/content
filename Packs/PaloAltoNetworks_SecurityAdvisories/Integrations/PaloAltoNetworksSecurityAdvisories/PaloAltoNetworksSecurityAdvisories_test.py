"""
Unit and Integrationt tests for Securities API
"""
import json
import os
from unittest.mock import patch
import pytest

BASE_URL = "https://security.paloaltonetworks.com/api/v1"

# Set envvar if you want to run integration tests.
RUN_INTEGRATION_TESTS = os.getenv("INTEGRATION_TESTS")


def test_client_get_products():
    """Integration test; /api/v1/products"""
    if not RUN_INTEGRATION_TESTS:
        pytest.skip("Integration tests disabled.")

    from PaloAltoNetworksSecurityAdvisories import Client
    test_client = Client(base_url=BASE_URL)
    result = test_client.get_products()
    assert result.get("success") is True
    assert isinstance(result.get("data"), list)


def test_client_get_pan_os_advisories():
    """Integration test; /api/v1/products"""
    if not RUN_INTEGRATION_TESTS:
        pytest.skip("Integration tests disabled.")

    from PaloAltoNetworksSecurityAdvisories import Client
    test_client = Client(base_url=BASE_URL)
    result = test_client.get_advisories("PAN-OS", {})
    assert result.get("success") is True
    assert isinstance(result.get("data"), list)

    result = test_client.get_advisories("PAN-OS", {"sort": "-cvss"})
    assert result.get("data")[0].get("impact").get("cvss").get("baseScore") == 10

    result = test_client.get_advisories("PAN-OS", {"q": "\"CVE-2021-3056\""})
    assert len(result.get("data")) == 1


@patch("PaloAltoNetworksSecurityAdvisories.Client.get_advisories")
def test_get_advisories_command(patched_get_advisories):
    patched_get_advisories.return_value = json.load(open("test_data" + os.sep + "advisories.json"))
    from PaloAltoNetworksSecurityAdvisories import Client, get_advisories
    test_client = Client(base_url=BASE_URL)
    result = get_advisories(test_client, "PANOS")
    assert result
    assert len(result.raw_response) == 3


@patch("PaloAltoNetworksSecurityAdvisories.Client.get_advisories")
def test_fetch_indicators_command(patched_get_advisories):
    patched_get_advisories.return_value = json.load(open("test_data" + os.sep + "advisories.json"))
    from PaloAltoNetworksSecurityAdvisories import Client, fetch_indicators
    test_client = Client(base_url=BASE_URL)
    result = fetch_indicators(test_client, "PANOS")
    assert result[0].get("value")
    assert result[0].get("type")
    assert result[0].get("rawJSON")
    for field, field_value in result[0].get("fields").items():
        assert field_value
