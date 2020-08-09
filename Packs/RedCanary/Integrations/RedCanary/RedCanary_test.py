import demistomock as demisto
import json
import RedCanary

last_run_dict = {"time": "2019-12-13T17:23:22Z", "last_event_ids": []}
latest_time_of_occurrence_of_incidents1 = "2019-12-30T22:00:50Z"
latest_time_of_occurrence_of_incidents2 = "2020-12-25T02:07:37Z"
number_of_incidents = 3


with open("./TestData/incidents.json") as f:
    data = json.load(f)

with open("TestData/incidents2.json") as f2:
    data2 = json.load(f2)


def test_fetch_when_last_run_is_time(mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - fetching incidents
    Then
    - check the number of incidents that are being created
    check that the time in last_run is the on of the latest incident
    """
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun")
    mocker.patch.object(
        RedCanary, "get_unacknowledged_detections", return_value=data["data"]
    )
    mocker.patch.object(RedCanary, "get_full_timeline", return_value=None)
    last_run, incidents = RedCanary.fetch_incidents(last_run_dict)

    assert len(incidents) == number_of_incidents
    assert last_run["time"] == latest_time_of_occurrence_of_incidents1


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


def test_fetch_multiple_times_when_already_fetched_incident_keep(mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - fetching incidents couple of times
    Then
    - fetch for 3 times
    in the first time makes sure 3 incidents were created
    in the others there the same incidents are being fetched as data but no new incidents are being created
    """
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "setLastRun")

    mocker.patch.object(demisto, "getLastRun")
    mocker.patch.object(RedCanary, "get_unacknowledged_detections", return_value=data["data"])
    mocker.patch.object(RedCanary, "get_full_timeline", return_value=None)

    # fetching for the first time
    last_run, incidents = RedCanary.fetch_incidents(last_run_dict)
    assert len(incidents) == 3
    assert last_run["time"] == "2019-12-30T22:00:50Z"

    # fetching for the second time
    last_run, incidents = RedCanary.fetch_incidents(last_run)
    assert len(incidents) == 0
    assert last_run["time"] == "2019-12-30T22:00:50Z"

    # fetching for the third time
    last_run, incidents = RedCanary.fetch_incidents(last_run)
    assert len(incidents) == 0
    assert last_run["time"] == "2019-12-30T22:00:50Z"


def test_fetch_multiple_times_with_new_incidents(mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - fetching incidents couple of times
    fetch incidents for the first time - as in previous tests
    fetch again with new incidents
    Then
    one of the incidents in the new fetch was shown before
    makes sure it is not created again
    the last_run in getting updated
    """
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "setLastRun")

    mocker.patch.object(demisto, "getLastRun")
    mocker.patch.object(RedCanary, "get_unacknowledged_detections", return_value=data["data"])
    mocker.patch.object(RedCanary, "get_full_timeline", return_value=None)

    # fetching for the first time
    last_run, incidents = RedCanary.fetch_incidents(last_run_dict)
    assert len(incidents) == 3
    assert last_run["time"] == "2019-12-30T22:00:50Z"

    # fetching for the second time
    mocker.patch.object(RedCanary, "get_unacknowledged_detections", return_value=data2["data"])
    last_run, incidents = RedCanary.fetch_incidents(last_run)
    # only one incidents is being created out of the 2 that were fetched
    assert len(incidents) == 1
    assert last_run["time"] == latest_time_of_occurrence_of_incidents2
