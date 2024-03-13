import json
import os

import freezegun
import pytest
from CommonServerPython import *
from NetskopeAPIv2 import Client

SERVER_URL = "https://test_url.com/"
API_TOKEN = "api_token"


def util_load_json(file_name):
    with open(
        os.path.join("test_data", f"{file_name}.json"), encoding="utf-8"
    ) as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=False, proxy=False, api_token=API_TOKEN)


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
        (
            {
                "alert_type": "anomaly",
                "limit": 20,
                "start_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "Compromised Credential",
                "page": 1,
                "limit": 4,
                "start_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "policy",
                "start_time": "11-05-2023 14:30",
                "end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "Legal Hold",
                "query": "app eq Dropbox",
                "page": 2,
                "limit": 10,
                "insertion_start_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "malsite",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "Malware",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "DLP",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "Security Assessment",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "watchlist",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "quarantine",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "Remediation",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
        (
            {
                "alert_type": "uba",
                "page": 1,
                "limit": 5,
                "insertion_start_time": "11-05-2023 14:30",
                "insertion_end_time": "11-05-2023 14:30",
            }
        ),
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

    requests_mock.get(f"{SERVER_URL}api/v2/events/data/alert", json=mock_response)

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

    requests_mock.put(f"{SERVER_URL}api/v2/policy/urllist/1", json=mock_response)

    result = update_url_list_command(
        client,
        {
            "url_list_id": "1",
            "name": "new_url_list",
            "urls": ["www.google.com"],
            "list_type": "regex",
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

    requests_mock.post(f"{SERVER_URL}api/v2/policy/urllist", json=mock_response)

    result = create_url_list_command(
        client,
        {
            "name": "new_url_list",
            "urls": ["www.google.com"],
            "list_type": "regex",
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

    requests_mock.delete(f"{SERVER_URL}api/v2/policy/urllist/1", json=mock_response)

    result = delete_url_list_command(client, {"url_list_id": "1", "deploy": False})

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
    result = list_client_command(
        client, {"filter": "userName eq someUserName", "limit": 5}
    )

    assert result.outputs_prefix == "Netskope.Client"
    assert result.outputs[0]["client_id"] == "TESTXSOAR"
    assert result.outputs[0]["active"] is True
    assert result.outputs[0]["emails"][0] == "example@tal.gu"


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

    expected_output = [
        {
            "client_id": "TESTXSOAR",
            "given_name": "first_name",
            "family_name": "last_name",
            "user_name": "upn1",
            "external_id": "User-Ext_id",
            "active": True,
            "emails": ["example@tal.gu"],
        }
    ]

    assert get_updated_list_client(mock_response["Resources"]) == expected_output


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

    expected_output = [
        {
            "id": 1,
            "name": "new_url_list",
            "urls": ["www.google.com", "www.abc.com"],
            "type": "exact",
            "json_version": 2,
            "modify_by": "modify_by",
            "modify_type": "Edited",
            "modify_time": "modify_time",
            "pending": "applied",
        }
    ]

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
    requests_mock.get(f"{SERVER_URL}api/v2/events/data/alert", json=alert_mock_response)
    event_mock_response = util_load_json("events")
    requests_mock.get(
        f"{SERVER_URL}api/v2/events/data/application", json=event_mock_response
    )
    requests_mock.get(f"{SERVER_URL}api/v2/events/data/page", json=event_mock_response)

    last_run, incidents = fetch_incidents(
        client,
        {
            "max_fetch": 10,
            "fetch_events": True,
            "first_fetch": "2023-01-01 15:00",
            "max_events_fetch": 10,
            "event_types": ["application", "page"],
        },
    )

    assert incidents == [
        {
            "name": "application-event ID: c4a0ad0684b73c3746e205a0",
            "occurred": "2023-07-05T17:14:00Z",
            "rawJSON": json.dumps(
                event_mock_response["result"][0] | {"incident_type": "application"}
            ),
        },
        {
            "name": "page-event ID: c4a0ad0684b73c3746e205a0",
            "occurred": "2023-07-05T17:14:00Z",
            "rawJSON": json.dumps(
                event_mock_response["result"][0] | {"incident_type": "page"}
            ),
        },
        {
            "name": "alert ID: 7a30814339c73cf437653b22",
            "occurred": "2023-07-05T17:14:00Z",
            "rawJSON": json.dumps(
                alert_mock_response["result"][0] | {"incident_type": "policy"}
            ),
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
        "page": {
            "date": "01-01-2023 15:00",
            "id": "c4a0ad0684b73c3746e205a0",
            "time": 1688577293,
        },
    }
