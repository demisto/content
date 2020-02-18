import demistomock as demisto

from .MACVendors import Client, get_mac_vendor

MOCK_URL = "http://fake-api.com"
MOCK_MAC_ADDRESS = "00:0a:95:9d:68:16"
MOCK_VENDOR_DETAILS = {
    "result": {
        "company": "Apple, Inc.",
        "mac_prefix": "B8:09:8A",
        "address": "1 Infinite Loop,Cupertino  CA  95014,US",
        "start_hex": "B8098A000000",
        "end_hex": "B8098AFFFFFF",
        "country": "US",
        "type": "MA-L"
    }
}


def test_get_mac_vendor(requests_mock, mocker):
    requests_mock.get(MOCK_URL + "/api/" + MOCK_MAC_ADDRESS, json=MOCK_VENDOR_DETAILS)
    mocker.patch.object(demisto, 'args', return_value={'address': MOCK_MAC_ADDRESS})
    client = Client(url=MOCK_URL, proxies=False)
    _, outputs, _ = get_mac_vendor(client)
    assert outputs['MACVendors'][0]['Vendor'].startswith('Apple') is True

