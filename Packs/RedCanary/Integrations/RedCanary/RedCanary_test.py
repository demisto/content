import demistomock as demisto
import json
import RedCanary

last_run_dict = {"time": "2019-12-13T17:23:22Z", "last_event_ids": []}
latest_time_of_occurrence_of_incidents1 = "2019-12-30T22:00:50Z"
latest_time_of_occurrence_of_incidents2 = "2020-12-25T02:07:37Z"
number_of_incidents = 3


class Mocker:
    # this mocker will return a different response in every following call
    def __init__(self):
        self.counter = 0
        self.res1 = res1
        self.res2 = res2

    def execute(self):
        self.counter = self.counter + 1
        if self.counter % 2 == 0:
            return self.res1
        return self.res2


with open("./TestData/incidents.json") as f:
    data = json.load(f)

with open("TestData/incidents2.json") as f2:
    data2 = json.load(f2)

with open("./TestData/get_full_timeline_raw1.json") as f3:
    res1 = json.load(f3)

with open("./TestData/get_full_timeline_raw2.json") as f4:
    res2 = json.load(f4)


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
    mocker.patch.object(RedCanary, "get_unacknowledged_detections", return_value=data["data"])
    mocker.patch.object(RedCanary, "get_full_timeline", return_value=None)
    last_run, incidents = RedCanary.fetch_incidents(last_run_dict, 2)

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
            "id": "1234",
            "attributes": {
                "hostname": "hostname1",
                "platform": "OS X",
                "operating_system": "Mac OSX 10.14.6",
                "is_isolated": False,
                "is_decommissioned": False,
                "endpoint_network_addresses": [
                    {
                        "attributes": {
                            "ip_address": {
                                "attributes": {
                                    "ip_address_matches_rfc_1918?": True,
                                    "ip_address_reverse_dns": None,
                                    "ip_address_defanged": "192.169.1[.]16",
                                    "ip_address_is_link_local?": False,
                                    "ip_address_matches_rfc_4193?": False,
                                    "ip_address": "192.169.1.16",
                                },
                                "type": "primitives.IpAddress",
                            },
                            "mac_address": {"attributes": {"address": "g9:gg:c2:0f:3d:5f"}, "type": "primitives.MacAddress"},
                        }
                    },
                    {
                        "attributes": {
                            "ip_address": {
                                "attributes": {
                                    "ip_address_matches_rfc_1918?": False,
                                    "ip_address_reverse_dns": None,
                                    "ip_address_defanged": "100.144.153[.]501",
                                    "ip_address_is_link_local?": False,
                                    "ip_address_matches_rfc_4193?": False,
                                    "ip_address": "100.144.153.501",
                                },
                                "type": "primitives.IpAddress",
                            },
                            "mac_address": None,
                        }
                    },
                ],
            },
        }
    ]

    endpoint_context = RedCanary.get_endpoint_context(endpoint)
    assert endpoint_context == [
        {
            "Hostname": "hostname1",
            "ID": "1234",
            "IPAddress": ["192.169.1.16", "100.144.153.501"],
            "IsDecommissioned": False,
            "IsIsolated": False,
            "MACAddress": ["g9:gg:c2:0f:3d:5f"],
            "OS": "OS X",
            "OSVersion": "Mac OSX 10.14.6",
        }
    ]


def test_detections_to_entry_without_endpoint(mocker):
    """
    Given:
     - detection data with missing 'affected_endpoint' details

    Then:
     - Ensure detections_to_entry runs successfully
     - Verify expected result is returned
    """
    detection_data = [
        {
            "type": "Detection",
            "id": 1,
            "attributes": {
                "headline": "Suspicious Activity",
                "confirmed_at": "2023-09-18T21:32:52.039Z",
                "summary": "A user made a series of API calls to expose instance passwords.",
                "severity": "high",
                "last_activity_seen_at": "2023-09-18T20:47:23.609Z",
                "classification": {"superclassification": "Suspicious Activity", "subclassification": ["Reconnaissance"]},
                "time_of_occurrence": "2023-09-18T20:47:23.609Z",
                "last_acknowledged_at": None,
                "last_acknowledged_by": None,
                "associated_releasable_intelligence_profiles": [],
            },
            "hostname": None,
            "username": "username",
            "relationships": {
                "related_endpoint_user": {
                    "links": {"related": "https://example.com/openapi/v3/endpoint_users/11111111"},
                    "data": {"type": "endpoint_user", "id": 11111111},
                }
            },
            "links": {
                "self": {"href": "https://example.com/openapi/v3/detections/1"},
                "activity_timeline": {"href": "https://example.com/openapi/v3/detections/1/timeline"},
                "detectors": {"href": "https://example.com/openapi/v3/detections/1/detectors"},
            },
        }
    ]

    expected_result = {
        "Type": "RedCanaryDetection",
        "ID": 1,
        "Headline": "Suspicious Activity",
        "Severity": "high",
        "Summary": "A user made a series of API calls to expose instance passwords.",
        "Classification": "Suspicious Activity",
        "Subclassification": ["Reconnaissance"],
        "Time": "2023-09-18T20:47:23Z",
        "Acknowledged": True,
        "RemediationStatus": "",
        "Reason": "",
        "EndpointID": "",
        "EndpointUserID": 11111111,
    }
    # Call the function with the sample data
    endpoint_users = [{"Username": "username"}]
    mocker.patch.object(RedCanary, "get_endpoint_user_context", return_value=endpoint_users)
    result = RedCanary.detections_to_entry(detection_data)
    # Assert that the result is as expected
    assert result["Contents"][0] == expected_result


def test_detections_to_entry_without_relationships(mocker):
    """
    Given:
     - detection data with missing 'relationship' details

    Then:
     - Ensure detections_to_entry runs successfully
    """
    detection_data = [
        {
            "type": "Detection",
            "id": 1,
            "attributes": {
                "headline": "Suspicious Activity",
                "confirmed_at": "2023-09-18T21:32:52.039Z",
                "summary": "A user made a series of API calls to expose instance passwords.",
                "severity": "high",
                "last_activity_seen_at": "2023-09-18T20:47:23.609Z",
                "classification": {"superclassification": "Suspicious Activity", "subclassification": ["Reconnaissance"]},
                "time_of_occurrence": "2023-09-18T20:47:23.609Z",
                "last_acknowledged_at": None,
                "last_acknowledged_by": None,
                "associated_releasable_intelligence_profiles": [],
            },
        }
    ]

    expected_result = {
        "Type": "RedCanaryDetection",
        "ID": 1,
        "Headline": "Suspicious Activity",
        "Severity": "high",
        "Summary": "A user made a series of API calls to expose instance passwords.",
        "Classification": "Suspicious Activity",
        "Subclassification": ["Reconnaissance"],
        "Time": "2023-09-18T20:47:23Z",
        "Acknowledged": True,
        "RemediationStatus": "",
        "Reason": "",
        "EndpointID": "",
        "EndpointUserID": "",
    }
    # Call the function with the sample data
    endpoint_users = [{"Username": "username"}]
    mocker.patch.object(RedCanary, "get_endpoint_user_context", return_value=endpoint_users)
    result = RedCanary.detections_to_entry(detection_data)
    # Assert that the result is as expected
    assert result["Contents"][0] == expected_result


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
    last_run, incidents = RedCanary.fetch_incidents(last_run_dict, 2)
    assert len(incidents) == 3
    assert last_run["time"] == "2019-12-30T22:00:50Z"

    # fetching for the second time
    last_run, incidents = RedCanary.fetch_incidents(last_run, 2)
    assert len(incidents) == 0
    assert last_run["time"] == "2019-12-30T22:00:50Z"

    # fetching for the third time
    last_run, incidents = RedCanary.fetch_incidents(last_run, 2)
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
    last_run, incidents = RedCanary.fetch_incidents(last_run_dict, 2)
    assert len(incidents) == 3
    assert last_run["time"] == "2019-12-30T22:00:50Z"

    # fetching for the second time
    mocker.patch.object(RedCanary, "get_unacknowledged_detections", return_value=data2["data"])
    last_run, incidents = RedCanary.fetch_incidents(last_run, 2)
    # only one incidents is being created out of the 2 that were fetched
    assert len(incidents) == 1
    assert last_run["time"] == latest_time_of_occurrence_of_incidents2


def test_def_get_full_timeline(mocker):
    """Unit test
    Given
    - raw response of the http request from 2 different requests
    - the data is the same but the page number is different
    When
    - keep getting the same data in different pages
    Then
    make sure the loop stops and doesn't cause a timeout
    """
    response = Mocker()
    mocker.patch.object(RedCanary, "http_get", return_value=response.execute())
    activities = RedCanary.get_full_timeline(1)
    result1 = response.execute()
    result2 = response.execute()
    # make sure the results are not the same, they are from different pages, but the data is
    assert result1 != result2
    assert result1["data"] == result2["data"]
    # make sure the loop ends
    assert activities
