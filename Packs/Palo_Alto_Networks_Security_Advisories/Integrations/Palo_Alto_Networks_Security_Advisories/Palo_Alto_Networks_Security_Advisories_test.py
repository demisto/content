"""
Unit and Integrationt tests for Securities API
"""
import json
import os
from unittest.mock import patch, MagicMock
import pytest

BASE_URL = "https://security.paloaltonetworks.com/api/v1"

# Set envvar if you want to run integration tests.
RUN_INTEGRATION_TESTS = os.getenv("INTEGRATION_TESTS")


def test_client_get_products():
    """Integration test; /api/v1/products"""
    if not RUN_INTEGRATION_TESTS:
        pytest.skip("Integration tests disabled.")

    from Palo_Alto_Networks_Security_Advisories import Client
    test_client = Client(base_url=BASE_URL)
    result = test_client.get_products()
    assert result.get("success") == True
    assert isinstance(result.get("data"), list)


def test_client_get_pan_os_advisories():
    """Integration test; /api/v1/products"""
    if not RUN_INTEGRATION_TESTS:
        pytest.skip("Integration tests disabled.")

    from Palo_Alto_Networks_Security_Advisories import Client
    test_client = Client(base_url=BASE_URL)
    result = test_client.get_advisories("PAN-OS", {})
    assert result.get("success") == True
    assert isinstance(result.get("data"), list)

    result = test_client.get_advisories("PAN-OS", {"sort": "-cvss"})
    assert result.get("data")[0].get("impact").get("cvss").get("baseScore") == 10

    result = test_client.get_advisories("PAN-OS", {"q": "\"CVE-2021-3056\""})
    assert len(result.get("data")) == 1


def test_locals_to_dict():
    """Unit test: Tests locals_to_dict"""
    from Palo_Alto_Networks_Security_Advisories import locals_to_dict
    test_local_dict = {
        "arg1": "value1",
        "arg2": None
    }
    assert_dict = {
        "arg1": "value1"
    }
    assert locals_to_dict(test_local_dict) == assert_dict


@patch("Palo_Alto_Networks_Security_Advisories.Client.get_advisories")
def test_get_advisories_command(patched_get_advisories):
    patched_get_advisories.return_value = json.load(open("test_data" + os.sep + "advisories.json"))
    from Palo_Alto_Networks_Security_Advisories import Client, get_advisories
    test_client = Client(base_url=BASE_URL)
    result = get_advisories(test_client, "PANOS")
    assert result
    assert len(result.raw_response) == 3
