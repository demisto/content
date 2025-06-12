"""Armis Integration for Cortex XSOAR - Unit Tests file
This file contains the Pytest Tests for the Armis Integration
"""

import json

import pytest
import time

import CommonServerPython
import demistomock as demisto


def test_untag_device_success(requests_mock):
    from Armis import Client, untag_device_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    requests_mock.delete("https://test.com/api/v1/devices/1/tags/", json={})

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    result = untag_device_command(client, {"device_id": "1", "tags": "test-tag"})
    assert result == "Successfully Untagged device: 1 with tags: ['test-tag']"


def test_untag_device_failure(requests_mock):
    from Armis import Client, untag_device_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    requests_mock.delete("https://test.com/api/v1/devices/1/tags/", json={}, status_code=400)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    with pytest.raises(CommonServerPython.DemistoException):
        untag_device_command(client, {"device_id": "1", "tags": "test-tag"})


def test_tag_device(requests_mock):
    from Armis import Client, tag_device_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    requests_mock.post("https://test.com/api/v1/devices/1/tags/", json={})

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    result = tag_device_command(client, {"device_id": "1", "tags": "test-tag"})
    assert result == "Successfully Tagged device: 1 with tags: ['test-tag']"


def test_update_alert_status(requests_mock):
    from Armis import Client, update_alert_status_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    requests_mock.patch("https://test.com/api/v1/alerts/1/", json={})

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    args = {"alert_id": "1", "status": "UNHANDLED"}
    assert update_alert_status_command(client, args) == "Successfully Updated Alert: 1 to status: UNHANDLED"


def test_search_alerts(requests_mock):
    from Armis import Client, search_alerts_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    url = "https://test.com/api/v1/search/?aql="
    url += "+".join(
        [
            "in%3Aalerts",
            "timeFrame%3A%223+days%22",
            "riskLevel%3AHigh%2CMedium",
            "status%3AUNHANDLED%2CRESOLVED",
            "type%3A%22Policy+Violation%22",
            "alertId%3A%281%29",
        ]
    )

    mock_results = {"data": {"results": []}}

    requests_mock.get(url, json=mock_results)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    args = {
        "severity": "High,Medium",
        "status": "UNHANDLED,RESOLVED",
        "alert_type": "Policy Violation",
        "alert_id": "1",
        "max_results": "20",
        "time_frame": "3 days",
    }
    response = search_alerts_command(client, args)
    assert response == "No results found"

    example_alerts = [
        {
            "activityIds": [19625045, 19625223, 19625984, 19626169, 19626680, 19626818, 19628162, 19628359],
            "activityUUIDs": [
                "1-uS23YBAAAC-vCTQOhA",
                "7eut23YBAAAC-vCTkOhB",
                "Oes13HYBAAAC-vCTcel0",
                "T-tU3HYBAAAC-vCTyunu",
                "mevb3HYBAAAC-vCT9-nn",
                "uev33HYBAAAC-vCTa-mg",
                "P-u33XYBAAAC-vCTlOpq",
                "SevT3XYBAAAC-vCTA-o_",
            ],
            "alertId": 1,
            "connectionIds": [845993, 846061, 846157, 846308],
            "description": "Smart TV started connection to Corporate Network",
            "deviceIds": [165722, 532],
            "severity": "Medium",
            "status": "Unhandled",
            "time": "2021-01-07T06:39:13.320893+00:00",
            "title": "Smart TV connected to Corporate network",
            "type": "System Policy Violation",
        }
    ]
    mock_results["data"]["results"] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_alerts_command(client, args)
    assert response.outputs == example_alerts


def test_search_alerts_by_aql(requests_mock):
    from Armis import Client, search_alerts_by_aql_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    url = "https://test.com/api/v1/search/?aql="
    url += "+".join(
        [
            "in%3Aalerts",
            "timeFrame%3A%223+days%22",
            "riskLevel%3AHigh%2CMedium",
            "status%3AUNHANDLED%2CRESOLVED",
            "type%3A%22Policy+Violation%22",
        ]
    )

    mock_results = {"data": {"results": []}}

    requests_mock.get(url, json=mock_results)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    args = {"aql_string": 'timeFrame:"3 days" riskLevel:High,Medium status:UNHANDLED,RESOLVED type:"Policy Violation"'}
    response = search_alerts_by_aql_command(client, args)
    assert response == "No alerts found"

    example_alerts = [
        {
            "activityIds": [19625045, 19625223, 19625984, 19626169, 19626680, 19626818, 19628162, 19628359],
            "activityUUIDs": [
                "1-uS23YBAAAC-vCTQOhA",
                "7eut23YBAAAC-vCTkOhB",
                "Oes13HYBAAAC-vCTcel0",
                "T-tU3HYBAAAC-vCTyunu",
                "mevb3HYBAAAC-vCT9-nn",
                "uev33HYBAAAC-vCTa-mg",
                "P-u33XYBAAAC-vCTlOpq",
                "SevT3XYBAAAC-vCTA-o_",
            ],
            "alertId": 1,
            "connectionIds": [845993, 846061, 846157, 846308],
            "description": "Smart TV started connection to Corporate Network",
            "deviceIds": [165722, 532],
            "severity": "Medium",
            "status": "Unhandled",
            "time": "2021-01-07T06:39:13.320893+00:00",
            "title": "Smart TV connected to Corporate network",
            "type": "System Policy Violation",
        }
    ]
    mock_results["data"]["results"] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_alerts_by_aql_command(client, args)
    assert response.outputs == example_alerts


def test_search_devices(requests_mock):
    from Armis import Client, search_devices_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    url = "https://test.com/api/v1/search/?aql=in%3Adevices+timeFrame%3A%223+days%22+deviceId%3A%281%29"
    mock_results = {"data": {"results": []}}

    requests_mock.get(url, json=mock_results)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    args = {"device_id": "1", "time_frame": "3 days"}
    response = search_devices_command(client, args)
    assert response == "No devices found"

    example_alerts = [
        {
            "accessSwitch": None,
            "category": "Network Equipment",
            "dataSources": [
                {
                    "firstSeen": "2021-01-15T03:26:56+00:00",
                    "lastSeen": "2021-01-16T18:16:32+00:00",
                    "name": "Meraki",
                    "types": ["WLC"],
                }
            ],
            "firstSeen": "2021-01-15T03:26:56+00:00",
            "id": 1,
            "ipAddress": None,
            "ipv6": None,
            "lastSeen": "2021-01-16T18:16:32+00:00",
            "macAddress": "f8:ca:59:53:91:ce",
            "manufacturer": "NetComm Wireless",
            "model": "NetComm device",
            "name": "Aussie Broadband 0079",
            "operatingSystem": None,
            "operatingSystemVersion": None,
            "riskLevel": 5,
            "sensor": {"name": "win-wap-tom-Upstairs", "type": "Access Point"},
            "site": {"location": "51 Longview Court, Thomastown Vic 3074", "name": "Winslow Workshop - Thomastown"},
            "tags": ["Access Point", "Off Network", "SSID=Aussie Broadband 0079"],
            "type": "Access Point Interface",
            "user": "",
            "visibility": "Full",
        }
    ]
    mock_results["data"]["results"] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_devices_command(client, args)
    assert response.outputs == example_alerts


def test_search_devices_by_aql(requests_mock):
    from Armis import Client, search_devices_by_aql_command

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    url = "https://test.com/api/v1/search/?aql=in%3Adevices+timeFrame%3A%223+days%22+deviceId%3A%281%29"
    mock_results = {"data": {"results": []}}

    requests_mock.get(url, json=mock_results)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    args = {"aql_string": 'timeFrame:"3 days" deviceId:(1)'}
    response = search_devices_by_aql_command(client, args)
    assert response == "No devices found"

    example_alerts = [
        {
            "accessSwitch": None,
            "category": "Network Equipment",
            "dataSources": [
                {
                    "firstSeen": "2021-01-15T03:26:56+00:00",
                    "lastSeen": "2021-01-16T18:16:32+00:00",
                    "name": "Meraki",
                    "types": ["WLC"],
                }
            ],
            "firstSeen": "2021-01-15T03:26:56+00:00",
            "id": 1,
            "ipAddress": None,
            "ipv6": None,
            "lastSeen": "2021-01-16T18:16:32+00:00",
            "macAddress": "f8:ca:59:53:91:ce",
            "manufacturer": "NetComm Wireless",
            "model": "NetComm device",
            "name": "Aussie Broadband 0079",
            "operatingSystem": None,
            "operatingSystemVersion": None,
            "riskLevel": 5,
            "sensor": {"name": "win-wap-tom-Upstairs", "type": "Access Point"},
            "site": {"location": "51 Longview Court, Thomastown Vic 3074", "name": "Winslow Workshop - Thomastown"},
            "tags": ["Access Point", "Off Network", "SSID=Aussie Broadband 0079"],
            "type": "Access Point Interface",
            "user": "",
            "visibility": "Full",
        }
    ]
    mock_results["data"]["results"] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_devices_by_aql_command(client, args)
    assert response.outputs == example_alerts


def test_fetch_incidents_no_duplicates(mocker):
    """
    Given:
    - 'client': Armis client.
    - 'last_run': Last run parameters.

    When:
    - Performing two consecutive calls to fetch incidents

    Then:
    - Ensure incident that was already fetched is not fetched again.

    """
    from Armis import Client, fetch_incidents

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    last_fetch = "2021-03-09T01:00:00.000001+00:00"
    armis_incident = {"time": "2021-03-09T01:00:00.000001+00:00", "type": "System Policy Violation"}
    response = {"results": [armis_incident], "next": "more data"}
    mocker.patch.object(client, "search_alerts", return_value=response)
    next_run, incidents = fetch_incidents(client, {"last_fetch": last_fetch}, None, "Low", [], [], "", 1)
    assert next_run["last_fetch"] == last_fetch
    assert incidents[0]["rawJSON"] == json.dumps(armis_incident)
    _, incidents = fetch_incidents(client, next_run, None, "Low", [], [], "", 1)
    assert not incidents


class MockClient:
    def __init__(self, secret: str, base_url: str, verify: bool, proxy):
        pass


def test_url_parameter(mocker):
    """
    Given:
    - Instance parameters with a base URL without `api/v1` prefix.

    When:
    - Running the main function and configured the client class.

    Then:
    - Ensure that hte base URL in the client class is with teh `api/v1` prefix.

    """
    from Armis import main

    mocker.patch.object(demisto, "params", return_value={"url": "test.com"})
    mock_client = mocker.patch("Armis.Client", side_effect=MockClient)

    main()

    assert mock_client.call_args.kwargs["base_url"] == "test.com/api/v1/"


def test_get_api_token_when_found_in_integration_context(mocker):
    """Test cases for scenario when there is api_token and expiration_time in integration context."""
    from Armis import Client

    test_integration_context = {"token": "1234567890", "token_expiration": time.ctime(time.time() + 10000)}

    mocker.patch.object(demisto, "getIntegrationContext", return_value=test_integration_context)
    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)

    api_token = client._get_token()

    assert api_token == test_integration_context["token"]


def test_get_api_token_when_expired_token_found_in_integration_context(mocker, requests_mock):
    """Test cases for scenario when there is an expired api_token in integration context."""
    from Armis import Client

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)

    api_token = client._get_token()

    assert api_token == mock_token["data"]["access_token"]


def test_retry_for_401_error(mocker, requests_mock):
    from Armis import Client, search_alerts_by_aql_command

    test_integration_context = {"token": "invalid_token", "token_expiration": time.ctime(time.time() - 10000)}

    mocker.patch.object(demisto, "getIntegrationContext", return_value=test_integration_context)

    url = "https://test.com/api/v1/search/?aql="
    url += "+".join(
        [
            "in%3Aalerts",
            "timeFrame%3A%223+days%22",
            "riskLevel%3AHigh%2CMedium",
            "status%3AUNHANDLED%2CRESOLVED",
            "type%3A%22Policy+Violation%22",
        ]
    )

    mock_results = {"message": "Invalid access token.", "success": False}

    mock_token = {"data": {"access_token": "example", "expiration_utc": time.ctime(time.time() + 10000)}}
    requests_mock.post("https://test.com/api/v1/access_token/", json=mock_token)

    example_alerts = [
        {
            "accessSwitch": None,
            "category": "Dummy Category",
            "dataSources": [
                {
                    "firstSeen": "2025-01-01T00:00:00+00:00",
                    "lastSeen": "2025-01-02T00:00:00+00:00",
                    "name": "Dummy Source",
                    "types": ["Dummy Type"],
                }
            ],
            "firstSeen": "2025-01-01T00:00:00+00:00",
            "id": 100,
            "ipAddress": "0.0.0.1",
            "ipv6": "0000:0000:0000:0000:0000:0000:0000:0001",
            "lastSeen": "2025-01-02T00:00:00+00:00",
            "macAddress": "00:00:00:00:00:01",
            "manufacturer": "Dummy Manufacturer",
            "model": "Dummy Model",
            "name": "Dummy Device",
            "operatingSystem": "Dummy OS",
            "operatingSystemVersion": "1.0",
            "riskLevel": 1,
            "sensor": {"name": "Dummy Sensor", "type": "Dummy Sensor Type"},
            "site": {"location": "Dummy Location", "name": "Dummy Site"},
            "tags": ["Dummy Tag 1", "Dummy Tag 2", "Dummy Tag 3"],
            "type": "Dummy Type",
            "user": "Dummy User",
            "visibility": "Dummy Visibility",
        }
    ]
    new_mock_results = {"data": {"results": example_alerts}}

    requests_mock.register_uri(
        "GET", url, [{"status_code": 401, "json": mock_results}, {"status_code": 200, "json": new_mock_results}]
    )

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)
    args = {"aql_string": 'timeFrame:"3 days" riskLevel:High,Medium status:UNHANDLED,RESOLVED type:"Policy Violation"'}

    response = search_alerts_by_aql_command(client, args)
    assert response.outputs == example_alerts


def test_test_module_when_is_fetch_is_true(mocker):
    """
    Given:
    - 'client': Armis client.
    - 'params': A dictionary containing the parameters provided by the user.

    When:
    - Performing calls to test_module

    Then:
    - Ensure test_module returns 'ok'

    """
    from Armis import Client, test_module as armis_test_module

    params = {
        "isFetch": True,
        "min_severity": "Low",
        "alert_type": [],
        "alert_status": [],
        "free_fetch_string": "",
        "first_fetch": "3 days",
        "max_fetch": 10,
    }

    mocker.patch.object(demisto, "params", return_value=params)

    client = Client("secret-example", "https://test.com/api/v1", verify=False, proxy=False)

    armis_incident = {"time": "2025-03-09T01:00:00.000001+00:00", "type": "test_type"}
    response = {"results": [armis_incident], "next": "more data"}
    mocker.patch.object(client, "search_alerts", return_value=response)

    assert armis_test_module(client, params) == "ok"
