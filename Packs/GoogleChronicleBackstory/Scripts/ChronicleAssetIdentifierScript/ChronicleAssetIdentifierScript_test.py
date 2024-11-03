import pytest

FIRST_ACCESSED_TIME = "2018-10-03T02:59:56Z"
LAST_ACCESSED_TIME = "2020-07-02T20:42:30Z"
ACCESSED_DOMAIN = "dummy-accessed-domain.com"


@pytest.mark.parametrize('input_key, output', [('key1', True), ('key4', False)])
def test_has_key(input_key, output):
    from ChronicleAssetIdentifierScript import has_key
    dummy_dict = {
        'key1': 'value1',
        'key2': 'value2'
    }

    expected_output = has_key(dummy_dict, key=input_key)

    assert output == expected_output


def test_get_entry_context_for_hostname():
    from ChronicleAssetIdentifierScript import get_entry_context

    dummy_identifiers = {
        "AccessedDomain": ACCESSED_DOMAIN,
        "FirstAccessedTime": FIRST_ACCESSED_TIME,
        "HostName": "dummy-host-name",
        "IpAddress": "dummy-ip-addres",
        "MacAddress": "dummy-mac-id",
        "LastAccessedTime": LAST_ACCESSED_TIME
    }

    expected_ec = get_entry_context(dummy_identifiers)

    assert expected_ec == {'AssetIdentifiers': ['dummy-host-name']}


def test_get_entry_context_for_ip_address():
    from ChronicleAssetIdentifierScript import get_entry_context

    dummy_identifiers = {
        "AccessedDomain": ACCESSED_DOMAIN,
        "FirstAccessedTime": FIRST_ACCESSED_TIME,
        "IpAddress": "dummy-ip-addres",
        "MacAddress": "dummy-mac-id",
        "LastAccessedTime": LAST_ACCESSED_TIME
    }

    expected_ec = get_entry_context(dummy_identifiers)

    assert expected_ec == {'AssetIdentifiers': ['dummy-ip-addres']}


def test_get_entry_context_for_mac_address():
    from ChronicleAssetIdentifierScript import get_entry_context

    dummy_identifiers = {
        "AccessedDomain": ACCESSED_DOMAIN,
        "FirstAccessedTime": FIRST_ACCESSED_TIME,
        "MacAddress": "dummy-mac-id",
        "LastAccessedTime": LAST_ACCESSED_TIME
    }

    expected_ec = get_entry_context(dummy_identifiers)

    assert expected_ec == {'AssetIdentifiers': ['dummy-mac-id']}
