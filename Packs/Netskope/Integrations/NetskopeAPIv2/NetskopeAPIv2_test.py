import json
import os
from unittest.mock import patch

import freezegun
import pytest
from CommonServerPython import *
from NetskopeAPIv2 import Client

SERVER_URL = "https://test_url.com/"
API_TOKEN = "api_token"


def util_load_json(file_name):
    with open(os.path.join("test_data", f"{file_name}.json"),
              encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL,
                  verify=False,
                  proxy=False,
                  api_token=API_TOKEN)


@pytest.mark.parametrize(
    "url, args",
    [
        (
            f"{SERVER_URL}api/v2/events/data/page",
            {
                "event_type": "page",
                "limit": 20,
                "start_time": "11-05-2023 14:30",
            },
        ),
        (
            f"{SERVER_URL}api/v2/events/data/application",
            {
                "event_type": "application",
                "page": 1,
                "limit": 4,
                "start_time": "11-05-2023 14:30",
            },
        ),
        (
            f"{SERVER_URL}api/v2/events/data/network",
            {
                "event_type": "network",
                "start_time": "11-05-2023 14:30",
                "end_time": "11-05-2023 14:30",
            },
        ),
        (
            f"{SERVER_URL}api/v2/events/data/infrastructure",
            {
                "event_type": "infrastructure",
                "query": "app eq Dropbox",
                "page": 2,
                "limit": 10,
                "insertion_start_time": "11-05-2023 14:30",
            },
        ),
        (
            f"{SERVER_URL}api/v2/events/data/audit",
            {
                "event_type": "audit",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            },
        ),
    ],
)
def test_list_event(client, requests_mock, url, args):
    """
    Scenario: List events extracted from SaaS traffic and or logs.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-event-list command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import list_event_command

    mock_response = util_load_json("events")

    requests_mock.get(url, json=mock_response)

    result = list_event_command(client, args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "Netskope.Event"

    assert result.outputs[0]["_id"] == "c4a0ad0684b73c3746e205a0"
    assert result.outputs[0]["timestamp"] == "2023-07-05T17:14:52.000Z"
    assert result.outputs[0]["type"] == "nspolicy"
    assert result.outputs[0]["access_method"] == "Client"


@pytest.mark.parametrize(
    "args",
    [
        ({
            "alert_type": "anomaly",
            "limit": 20,
            "start_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "Compromised Credential",
            "page": 1,
            "limit": 4,
            "start_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "policy",
            "start_time": "11-05-2023 14:30",
            "end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "Legal Hold",
            "query": "app eq Dropbox",
            "page": 2,
            "limit": 10,
            "insertion_start_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "malsite",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "Malware",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "DLP",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "Security Assessment",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "watchlist",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "quarantine",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "Remediation",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
        ({
            "alert_type": "uba",
            "page": 1,
            "limit": 5,
            "insertion_start_time": "11-05-2023 14:30",
            "insertion_end_time": "11-05-2023 14:30",
        }),
    ],
)
def test_list_alert(client, requests_mock, args):
    """
    Scenario: List alerts generated by Netskope, including policy, DLP, and watch list alerts.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-alert-list command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import list_alert_command

    mock_response = util_load_json("alerts")

    requests_mock.get(f"{SERVER_URL}api/v2/events/data/alert",
                      json=mock_response)

    result = list_alert_command(client, args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "Netskope.Alert"

    assert result.outputs[0]["alert_id"] == "7a30814339c73cf437653b22"
    assert result.outputs[0]["timestamp"] == "2023-07-05T17:14:52.000Z"
    assert result.outputs[0]["action"] == "block"
    assert result.outputs[0]["alert_name"] == "365 block"


def test_update_url_list(client, requests_mock):
    """
    Scenario: Update the URL List with the values provided.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-url-list-update command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import update_url_list_command

    mock_response = util_load_json("url_list")

    requests_mock.put(f"{SERVER_URL}api/v2/policy/urllist/1",
                      json=mock_response)

    result = update_url_list_command(
        client,
        {
            "url_list_id": "1",
            "name": "new_url_list",
            "urls": ["www.google.com"],
            "list_type": "Regex",
            "is_overwrite": True,
            "deploy": False,
        },
    )

    assert result.outputs_prefix == "Netskope.URLList"
    assert result.outputs[0]["name"] == "new_url_list"
    assert result.outputs[0]["urls"][0] == "www.google.com"


def test_create_url_list(client, requests_mock):
    """
    Scenario: create the URL List with the values provided.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-url-list-create command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import create_url_list_command

    mock_response = util_load_json("url_list")

    requests_mock.post(f"{SERVER_URL}api/v2/policy/urllist",
                       json=mock_response)

    result = create_url_list_command(
        client,
        {
            "name": "new_url_list",
            "urls": ["www.google.com"],
            "list_type": "Regex",
            "deploy": False,
        },
    )

    assert result.outputs_prefix == "Netskope.URLList"
    assert result.outputs[0]["name"] == "new_url_list"
    assert result.outputs[0]["urls"][0] == "www.google.com"


def test_delete_url_list(client, requests_mock):
    """
    Scenario: delete the URL List with the values provided.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-url-list-delete command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import delete_url_list_command

    mock_response = util_load_json("url_list")

    requests_mock.delete(f"{SERVER_URL}api/v2/policy/urllist/1",
                         json=mock_response)

    result = delete_url_list_command(client, {
        "url_list_id": "1",
        "deploy": False
    })

    assert result.outputs_prefix == "Netskope.URLList"
    assert result.readable_output == "The URL list 1 was deleted successfully"


def test_list_client(client, requests_mock):
    """
    Scenario: Get information about the Netskope clients.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-client-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import list_client_command

    mock_response = util_load_json("clients")

    requests_mock.get(f"{SERVER_URL}api/v2/scim/Users", json=mock_response)
    result = list_client_command(client, {
        "filter": "userName eq someUserName",
        "limit": 5
    })

    assert result.outputs_prefix == "Netskope.Client"
    assert result.outputs[0]["client_id"] == "TESTXSOAR"
    assert result.outputs[0]["active"] is True
    assert result.outputs[0]["emails"][0] == "example@tal.gu"


def test_list_dlp_incident(client, requests_mock):
    """
    Scenario: Update the URL List with the values provided.
    Given:
        - User has provided valid credentials.
    When:
        - netskope-url-list-update command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from NetskopeAPIv2 import list_dlp_incident_command

    mock_response = util_load_json("dlp_incidents")

    requests_mock.get(f"{SERVER_URL}api/v2/events/dataexport/events/incident",
                      json=mock_response)

    result = list_dlp_incident_command(
        client,
        {
            "start_time": "1 day ago",
            "end_time": "now",
        },
    )

    assert result.outputs_prefix == "Netskope.Incident"
    assert result.outputs[0]["object_id"] == "01"
    assert result.outputs[0]["status"] == "in_progress"
    assert result.outputs[0]["severity"] == "Critical"


def test_convert_client_filter():
    """
    Scenario: Convert client filter to support Netskope template.
    Given:
     - Response from Netskope.
    When:
     - Arguments include client filter.
    Then:
     - Ensure value string is correct 'key eq "value"'.
    """

    from NetskopeAPIv2 import convert_client_filter

    result = convert_client_filter("userName eq someUserName")
    assert result == 'userName eq "someUserName"'


def test_convert_client_filter_error():
    """
    Scenario: Convert client filter to support Netskope template.
    Given:
     - Response from Netskope.
    When:
     - Arguments include client filter.
    Then:
     - Ensure value string is correct 'key eq "value"'.
    """

    from NetskopeAPIv2 import convert_client_filter

    with pytest.raises(DemistoException) as de:
        convert_client_filter("someUserName")
        assert de.message == "Filter must contain 'key' eq 'value'"


def test_get_updated_client_list():
    """
    Scenario: Test the get_updated_client_list function.

    Given:
     - Response from the API containing client lists.

    When:
     - Calling get_updated_client_list function with the API response.

    Then:
     - Ensure the function returns the expected updated client list.
    """
    from NetskopeAPIv2 import get_updated_list_client

    mock_response = util_load_json("clients")

    expected_output = [{
        "client_id": "TESTXSOAR",
        "given_name": "first_name",
        "family_name": "last_name",
        "user_name": "upn1",
        "external_id": "User-Ext_id",
        "active": True,
        "emails": ["example@tal.gu"],
    }]

    assert get_updated_list_client(
        mock_response["Resources"]) == expected_output


def test_get_updated_url_list():
    """
    Scenario: Test the get_updated_url_list function.

    Given:
     - Response from the API containing URL lists.

    When:
     - Calling get_updated_url_list function with the API response.

    Then:
     - Ensure the function returns the expected updated URL list.
    """
    from NetskopeAPIv2 import get_updated_url_list

    mock_response = util_load_json("url_list")

    expected_output = [{
        "id": 1,
        "name": "new_url_list",
        "urls": ["www.google.com", "www.abc.com"],
        "type": "exact",
        "json_version": 2,
        "modify_by": "modify_by",
        "modify_type": "Edited",
        "modify_time": "modify_time",
        "pending": "applied",
    }]

    assert get_updated_url_list(mock_response) == expected_output


@pytest.mark.parametrize(
    "args, expected_output",
    [
        (
            {
                "start_time": "01-07-2023 00:00",
                "end_time": None,
                "insertion_start_time": None,
                "insertion_end_time": None,
            },
            (1673049600, 1690891200, None, None),
        ),
    ],
)
@freezegun.freeze_time(datetime(2023, 8, 1, 12))
def test_convert_time_args_to_num(args, expected_output):
    """
    Scenario: Test the convert_time_args_to_num function.

    Given:
     - Command arguments containing time-related arguments.

    When:
     - Calling convert_time_args_to_num function with the command arguments.

    Then:
     - Ensure the function returns the expected updated time arguments.
    """
    from NetskopeAPIv2 import TimeArgs, convert_time_args_to_num

    assert convert_time_args_to_num(args) == TimeArgs(*expected_output)


def test_convert_number_to_str_date():
    """
    Scenario: Test the convert_number_to_str_date function.

    Given:
     - A date number.

    When:
     - Calling convert_number_to_str_date function with the date number.

    Then:
     - Ensure the function returns the expected date string.
    """
    from NetskopeAPIv2 import convert_number_to_str_date

    date_number = 1677756000
    expected_output = "02-03-2023 11:20"

    assert convert_number_to_str_date(date_number) == expected_output


def test_fetch_incidents(client, requests_mock):
    """
    Scenario: Fetch incidents.
    Given:
     -XSOAR arguments.
    When:
     - fetch-incident called.

    Then:
     - Ensure last run and incident are correct.
    """

    from NetskopeAPIv2 import fetch_incidents

    alert_mock_response = util_load_json("alerts")
    event_mock_response = util_load_json("events")
    dlp_incidents_mock_response = util_load_json("dlp_incidents")

    requests_mock.get(f"{SERVER_URL}api/v2/events/data/alert",
                      json=alert_mock_response)
    requests_mock.get(f"{SERVER_URL}api/v2/events/data/application",
                      json=event_mock_response)
    requests_mock.get(f"{SERVER_URL}api/v2/events/data/page",
                      json=event_mock_response)
    requests_mock.get(f"{SERVER_URL}api/v2/events/dataexport/events/incident",
                      json=dlp_incidents_mock_response)

    last_run, incidents = fetch_incidents(
        client,
        {
            "max_fetch": 10,
            "fetch_events": True,
            "fetch_dlp_incidents": True,
            "first_fetch": "2023-01-01 15:00",
            "max_events_fetch": 10,
            "max_dlp_incidents_fetch": 10,
            "event_types": ["application", "page"],
            "mirror_direction": "Incoming and Outgoing",
        },
    )
    last_run["dlp_incident"]["date"] = "11-09-2024 08:00"
    last_run["dlp_incident"]["time"] = 1726041600

    assert incidents == [
        {
            "name":
            "application-event ID: c4a0ad0684b73c3746e205a0",
            "occurred":
            "2023-07-05T17:14:00Z",
            'incident_type':
            'application-event',
            'mirror_direction':
            'Both',
            'mirror_instance':
            '',
            "rawJSON":
            json.dumps(
                event_mock_response["result"][0] | {
                    'incident_type': 'application-event',
                    'mirror_direction': 'Both',
                    'mirror_instance': '',
                    'app_session_id': '8465907469530832528',
                    'browser_session_id': '4306403352624265077',
                    'incident_id': '5842546291106376750',
                    'request_id': '2613596205044864769',
                    'transaction_id': '5842546291106376750',
                }),
        },
        {
            "name":
            "page-event ID: c4a0ad0684b73c3746e205a0",
            "occurred":
            "2023-07-05T17:14:00Z",
            'incident_type':
            'page-event',
            'mirror_direction':
            'Both',
            'mirror_instance':
            '',
            "rawJSON":
            json.dumps(
                event_mock_response["result"][0] | {
                    'incident_type': 'page-event',
                    'mirror_direction': 'Both',
                    'mirror_instance': '',
                    'app_session_id': '8465907469530832528',
                    'browser_session_id': '4306403352624265077',
                    'incident_id': '5842546291106376750',
                    'request_id': '2613596205044864769',
                    'transaction_id': '5842546291106376750',
                }),
        },
        {
            "name":
            "dlp_incident ID: 01",
            "occurred":
            "2024-03-20T10:01:00Z",
            'incident_type':
            'dlp_incident',
            'mirror_direction':
            'Both',
            'mirror_instance':
            '',
            "rawJSON":
            json.dumps(
                dlp_incidents_mock_response["result"][0] | {
                    'incident_type': 'dlp_incident',
                    'mirror_direction': 'Both',
                    'mirror_instance': '',
                }),
        },
        {
            "name":
            "alert ID: 7a30814339c73cf437653b22",
            "occurred":
            "2023-07-05T17:14:00Z",
            'incident_type':
            'alert',
            'mirror_direction':
            'Both',
            'mirror_instance':
            '',
            "rawJSON":
            json.dumps(
                alert_mock_response["result"][0] | {
                    'incident_type': 'alert',
                    'mirror_direction': 'Both',
                    'mirror_instance': '',
                    'app_session_id': '8638023457299261081',
                    'browser_session_id': '4014571231818143674',
                    'connection_id': '8594277971962832463',
                    'incident_id': '6443216183026877636',
                    'request_id': '2598159462674082048',
                    'transaction_id': '6443216183026877636',
                }),
        },
    ]

    assert last_run == {
        "alert": {
            "date": "01-01-2023 15:00",
            "id": "7a30814339c73cf437653b22",
            "time": 1688577293,
        },
        "application": {
            "date": "01-01-2023 15:00",
            "id": "c4a0ad0684b73c3746e205a0",
            "time": 1688577293,
        },
        "dlp_incident": {
            "date": "11-09-2024 08:00",
            "id": "01",
            "time": 1726041600,
        },
        "page": {
            "date": "01-01-2023 15:00",
            "id": "c4a0ad0684b73c3746e205a0",
            "time": 1688577293,
        },
    }


def test_fetch_incidents_no_event_type(client, requests_mock):
    """
    Scenario: Fetch incidents and event type was not set.
    Given:
     -XSOAR arguments.
    When:
     - fetch-incident called.

    Then:
     - Ensure last run and incident are correct.
    """

    from NetskopeAPIv2 import fetch_incidents

    alert_mock_response = util_load_json("alerts")
    event_mock_response = util_load_json("events")
    dlp_incidents_mock_response = util_load_json("dlp_incidents")

    requests_mock.get(f"{SERVER_URL}api/v2/events/data/alert",
                      json=alert_mock_response)
    requests_mock.get(f"{SERVER_URL}api/v2/events/data/application",
                      json=event_mock_response)
    requests_mock.get(f"{SERVER_URL}api/v2/events/data/page",
                      json=event_mock_response)
    requests_mock.get(f"{SERVER_URL}api/v2/events/dataexport/events/incident",
                      json=dlp_incidents_mock_response)

    last_run, incidents = fetch_incidents(
        client,
        {
            "max_fetch": 10,
            "fetch_events": True,
            "fetch_dlp_incidents": True,
            "first_fetch": "2023-01-01 15:00",
            "max_events_fetch": 10,
            "max_dlp_incidents_fetch": 10,
            "mirror_direction": "Incoming and Outgoing",
        },
    )
    last_run["dlp_incident"]["date"] = "11-09-2024 08:00"
    last_run["dlp_incident"]["time"] = 1726041600

    assert incidents == [
        {
            "name":
            "dlp_incident ID: 01",
            "occurred":
            "2024-03-20T10:01:00Z",
            'incident_type':
            'dlp_incident',
            'mirror_direction':
            'Both',
            'mirror_instance':
            '',
            "rawJSON":
            json.dumps(
                dlp_incidents_mock_response["result"][0] | {
                    'incident_type': 'dlp_incident',
                    'mirror_direction': 'Both',
                    'mirror_instance': '',
                }),
        },
        {
            "name":
            "alert ID: 7a30814339c73cf437653b22",
            "occurred":
            "2023-07-05T17:14:00Z",
            'incident_type':
            'alert',
            'mirror_direction':
            'Both',
            'mirror_instance':
            '',
            "rawJSON":
            json.dumps(
                alert_mock_response["result"][0] | {
                    'incident_type': 'alert',
                    'mirror_direction': 'Both',
                    'mirror_instance': '',
                    'app_session_id': '8638023457299261081',
                    'browser_session_id': '4014571231818143674',
                    'connection_id': '8594277971962832463',
                    'incident_id': '6443216183026877636',
                    'request_id': '2598159462674082048',
                    'transaction_id': '6443216183026877636',
                }),
        },
    ]

    assert last_run == {
        "alert": {
            "date": "01-01-2023 15:00",
            "id": "7a30814339c73cf437653b22",
            "time": 1688577293,
        },
        "dlp_incident": {
            "date": "11-09-2024 08:00",
            "id": "01",
            "time": 1726041600,
        }
    }


def test_set_and_get_demisto_integration_context():
    """
    Scenario: Test the set_demisto_integration_context function.

    Given:
     - A key to be updated with new values.
     - An action to append or replace the values for the key.

    When:
     - Calling set_demisto_integration_context with an action 'append'.
     - Calling set_demisto_integration_context with an action 'replace'.

    Then:
     - Ensure the key is correctly updated in the integration context.
     - Ensure the append action adds values to the existing list.
    """
    from NetskopeAPIv2 import set_demisto_integration_context, get_demisto_integration_context

    # Mocking get_integration_context and set_integration_context

    set_demisto_integration_context('existing_key', [1, 2, 3], 'append')

    # Test append action
    mock_context = get_demisto_integration_context('existing_key', [])
    assert mock_context == [1, 2, 3]


def test_remove_duplicates():
    """
    Scenario: Test the remove_duplicates function.

    Given:
     - A list of dictionaries where some dictionaries have duplicate keys.

    When:
     - Calling remove_duplicates function with the key to check for duplicates.

    Then:
     - Ensure the function returns a list with duplicates removed.
    """
    from NetskopeAPIv2 import remove_duplicates

    dicts_list = [
        {
            "object_id": "1",
            "value": "A"
        },
        {
            "object_id": "2",
            "value": "B"
        },
        {
            "object_id": "1",
            "value": "C"
        },  # Duplicate object_id
        {
            "object_id": "3",
            "value": "D"
        }
    ]

    expected_output = [
        {
            "object_id": "1",
            "value": "C"
        },  # Last occurrence of object_id "1"
        {
            "object_id": "2",
            "value": "B"
        },
        {
            "object_id": "3",
            "value": "D"
        }
    ]

    result = remove_duplicates(dicts_list, key="object_id")
    assert result == expected_output


def test_get_hourly_timestamps():
    """
    Scenario: Test the get_hourly_timestamps function.

    Given:
     - A valid start and end timestamp.

    When:
     - Calling get_hourly_timestamps function.

    Then:
     - Ensure the function returns a list of hourly timestamps between start and end.
    """
    from NetskopeAPIv2 import get_hourly_timestamps

    start_time = 1609459200  # 2021-01-01 00:00:00 UTC
    end_time = 1609480800  # 2021-01-01 06:00:00 UTC

    expected_output = [
        1609459200,  # 2021-01-01 00:00:00
        1609462800,  # 2021-01-01 01:00:00
        1609466400,  # 2021-01-01 02:00:00
        1609470000,  # 2021-01-01 03:00:00
        1609473600,  # 2021-01-01 04:00:00
        1609477200,  # 2021-01-01 05:00:00
        1609480800  # 2021-01-01 06:00:00
    ]

    result = get_hourly_timestamps(start_time, end_time)
    assert result == expected_output


def test_get_modified_remote_data(client):
    """
    Scenario: Verify getting modified remote data.
    Given:
     - A valid Netskope API client.
     - Valid command arguments.
     - Mocked response from the client.
    When:
     - Calling the function to get modified remote data.
    Then:
     - Ensure that the returned response matches the expected format.
    """
    from NetskopeAPIv2 import get_modified_remote_data

    mock_response = {"result": [{"object_id": "1"}, {"object_id": "2"}]}

    with patch("NetskopeAPIv2.Client") as MockClient:
        client_instance = MockClient.return_value
        client_instance.list_dlp_incident.return_value = mock_response

        with patch("NetskopeAPIv2.get_demisto_integration_context"
                   ) as mock_get_context:
            mock_get_context.return_value = 123456789

            with patch("NetskopeAPIv2.get_hourly_timestamps"
                       ) as mock_get_hourly_timestamps:
                mock_get_hourly_timestamps.return_value = [123456789]

                result = get_modified_remote_data(client_instance)

                expected_response = GetModifiedRemoteDataResponse(["1", "2"])
                assert result.modified_incident_ids == expected_response.modified_incident_ids


def test_get_mapping_fields_command():
    """
    Scenario: Verify fetching mapping fields.
    Given:
     - No specific input required for this function.
    When:
     - Calling the function to fetch mapping fields.
    Then:
     - Ensure that the returned response matches the expected format.
    """
    from NetskopeAPIv2 import MIRRORING_FIELDS, get_mapping_fields_command

    result = get_mapping_fields_command()

    expected_response = GetMappingFieldsResponse()
    incident_type_scheme = SchemeTypeMapping(type_name="Netskope Incident")

    for field in MIRRORING_FIELDS:
        incident_type_scheme.add_field(field)

    expected_response.add_scheme_type(incident_type_scheme)

    assert result.scheme_types_mappings[
        0].type_name == expected_response.scheme_types_mappings[0].type_name
    assert result.scheme_types_mappings[
        0].fields == expected_response.scheme_types_mappings[0].fields


def test_get_remote_data_command():
    """
    Scenario: Verify fetching remote data.
    Given:
     - A valid Netskope API client.
     - Valid command arguments.
     - Mocked response from the client.
    When:
     - Calling the function to fetch remote data.
    Then:
     - Ensure that the returned response matches the expected format.
    """
    from NetskopeAPIv2 import get_remote_data_command

    args = {
        "id": "incident123",
        "lastUpdate": "2023-02-14 12:30:45",
    }

    with patch("NetskopeAPIv2.get_demisto_integration_context"
               ) as mock_get_context:
        mock_get_context.return_value = [{
            'incident_type': 'dlp_incident',
            "object_id": "incident123",
            "status": "closed"
        }]

        result = get_remote_data_command(args, {"close_incident": True})

        expected_response = GetRemoteDataResponse(
            {
                'incident_type': 'dlp_incident',
                "object_id": "incident123",
                "status": "closed"
            },
            [{
                "Type": 1,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Closed from Netskope."
                },
                "ContentsFormat": "json",
            }],
        )

        assert result.mirrored_object == expected_response.mirrored_object
        assert result.entries == expected_response.entries


def test_update_remote_system():
    """
    Scenario: Verify updating the remote system.
    Given:
     - A valid Netskope API client.
     - Valid command arguments.
     - Mocked response from the client.
    When:
     - Calling the function to update the remote system.
    Then:
     - Ensure that the remote incident ID is returned.
    """
    from NetskopeAPIv2 import update_remote_system

    mock_response = {
        "result": "success",
    }

    with patch("NetskopeAPIv2.Client") as MockClient:
        client_instance = MockClient.return_value
        client_instance.update_dlp_incident.return_value = mock_response

        args = {
            "data": {
                "incident_key": "incident123",
                "status": "closed",
            },
            "entries": [],
            "incidentChanged": True,
            "remoteId": "incident123",
            "delta": {
                "status": "closed",
            },
        }

        with patch("NetskopeAPIv2.UpdateRemoteSystemArgs"
                   ) as mock_UpdateRemoteSystemArgs:
            mock_UpdateRemoteSystemArgs.return_value = UpdateRemoteSystemArgs(
                args)

            result = update_remote_system(client_instance, args,
                                          {"close_netskope_incident": True})

            assert result == "incident123"
