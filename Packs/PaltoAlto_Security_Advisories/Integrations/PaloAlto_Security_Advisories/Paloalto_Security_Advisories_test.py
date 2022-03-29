"""
Unit and Integrationt tests for Securities API
"""
import json

BASE_URL = "https://security.paloaltonetworks.com/api/v1"


def test_client_get_products():
    """Integration test; /api/v1/products"""
    from PaloAlto_Security_Advisories import Client
    test_client = Client(base_url=BASE_URL)
    result = test_client.get_products()
    assert result.get("success") == True
    assert isinstance(result.get("data"), list)


def test_client_get_pan_os_advisories():
    """Integration test; /api/v1/products"""
    from PaloAlto_Security_Advisories import Client
    test_client = Client(base_url=BASE_URL)
    result = test_client.get_advisories("PAN-OS", {})
    assert result.get("success") == True
    assert isinstance(result.get("data"), list)