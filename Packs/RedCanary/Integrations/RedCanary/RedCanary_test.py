import demistomock as demisto
import pytest
import json
import RedCanary


with open("./TestData/incidents.json") as f:
    data = json.load(f)


class TestFetchIncidents:
    test_collection = [
        # lastRun is time
        ({"time": "2019-12-13T17:23:22Z"}, 3, "2019-12-30T22:00:51Z"),
        # No last run
        (None, 3, "2019-12-30T22:00:51Z"),
    ]

    @pytest.mark.parametrize("lastRun, incidents_len, new_last_run", test_collection)
    def test_fetch_when_last_run_is_time(
        self, mocker, lastRun, incidents_len, new_last_run
    ):
        mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value=lastRun)
        mocker.patch.object(
            RedCanary, "get_unacknowledged_detections", return_value=data["data"]
        )
        mocker.patch.object(RedCanary, "get_full_timeline", return_value=None)
        RedCanary.fetch_incidents()
        assert len(demisto.incidents.call_args[0][0]) == incidents_len
        assert demisto.setLastRun.call_args[0][0]["time"] == new_last_run


def test_get_endpoint_context():
    """
    Given:
     - Endpoint data with missing MAC address details (None)

    When:
     - Listing endpoints and generating endpoint standard context

    Then:
     - Ensure get_endpoint_context runs successfully
     - Verify expected endpoint standard context is returned
    """
    endpoint = [
        {
            'id': '1234',
            'attributes': {
                'hostname': 'hostname1',
                'platform': 'OS X',
                'operating_system': 'Mac OSX 10.14.6',
                'is_isolated': False,
                'is_decommissioned': False,
                'endpoint_network_addresses': [
                    {
                        'attributes': {
                            'ip_address': {
                                'attributes': {
                                    'ip_address_matches_rfc_1918?': True,
                                    'ip_address_reverse_dns': None,
                                    'ip_address_defanged': '192.169.1[.]16',
                                    'ip_address_is_link_local?': False,
                                    'ip_address_matches_rfc_4193?': False,
                                    'ip_address': '192.169.1.16'
                                },
                                'type': 'primitives.IpAddress'
                            },
                            'mac_address': {
                                'attributes': {
                                    'address': 'g9:gg:c2:0f:3d:5f'
                                },
                                'type': 'primitives.MacAddress'
                            }
                        }
                    },
                    {
                        'attributes': {
                            'ip_address': {
                                'attributes': {
                                    'ip_address_matches_rfc_1918?': False,
                                    'ip_address_reverse_dns': None,
                                    'ip_address_defanged': '100.144.153[.]501',
                                    'ip_address_is_link_local?': False,
                                    'ip_address_matches_rfc_4193?': False,
                                    'ip_address': '100.144.153.501'
                                },
                                'type': 'primitives.IpAddress'
                            },
                            'mac_address': None
                        }
                    }
                ]
            }
        }
    ]

    endpoint_context = RedCanary.get_endpoint_context(endpoint)
    assert endpoint_context == [{
        'Hostname': 'hostname1',
        'ID': '1234',
        'IPAddress': ['192.169.1.16', '100.144.153.501'],
        'IsDecommissioned': False,
        'IsIsolated': False,
        'MACAddress': ['g9:gg:c2:0f:3d:5f'],
        'OS': 'OS X',
        'OSVersion': 'Mac OSX 10.14.6'}]
