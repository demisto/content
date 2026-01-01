import json
from datetime import datetime, timezone

import pytest
from pytest_mock import MockerFixture
from CommonServerPython import CommandResults, DemistoException
from ExabeamSecOpsPlatform import Client
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class MockClient(Client):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        pass

    def event_search_command(self) -> None:
        return


def test_event_search_command_success(mocker: MockerFixture):
    """
    GIVEN:
        A mocked Exabeam client and valid search query arguments.

    WHEN:
        'event_search_command' function is called with the provided arguments.

    THEN:
        It should search for logs using the Exabeam client and return a CommandResults object containing
        the search results in both structured and human-readable formats.
    """
    from ExabeamSecOpsPlatform import event_search_command

    # Mock the response from the client's search_request method
    mock_response = {
        "rows": [
            {
                "id": "123",
                "rawLogIds": "1",
                "tier": "Tier",
                "parsed": "false",
                "rawLogs": "fictive",
                "time": "2024-01-30T11:20:07.000000+00:00",
                "message": "Log message 1",
                "activity": "trigger",
                "platform": "blackberry protect",
                "vendor": "BlackBerry",
            },
            {
                "id": "456",
                "time": "2024-01-30T11:21:06.976000+00:00",
                "message": "Log message 2",
                "activity": "trigger",
                "platform": "blackberry protect",
                "vendor": "BlackBerry",
            },
        ]
    }

    client = MockClient("", "", "", False, False)

    mocker.patch.object(client, "event_search_request", return_value=mock_response)

    # Define test arguments
    args = {
        "query": "",
        "fields": "message",
        "limit": "50",
        "start_time": "2024-05-01T00:00:00",
        "end_time": "2024-05-08T00:00:00",
    }

    # Call the event_search_command function
    response = event_search_command(client, args)

    assert isinstance(response, CommandResults)
    assert response.outputs_prefix == "ExabeamPlatform.Event"
    assert response.outputs == mock_response["rows"]
    expected_readable_output = (
        "### Logs\n"
        "|Id|Is Parsed|Raw Log Ids|Raw Logs|Tier|Time|\n"
        "|---|---|---|---|---|---|\n"
        "| 123 | false | 1 | fictive | Tier | 2024-01-30T11:20:07.000000+00:00 |\n"
        "| 456 |  |  |  |  | 2024-01-30T11:21:06.976000+00:00 |\n"
    )
    assert expected_readable_output in response.readable_output


def test_event_search_command_failure(mocker: MockerFixture):
    """
    GIVEN:
        A mocked Exabeam client and invalid search query arguments.

    WHEN:
        'event_search_command' function is called with invalid arguments.

    THEN:
        It should raise a DemistoException.
    """
    from ExabeamSecOpsPlatform import event_search_command

    # Mocking the client to simulate a response with errors
    client = MockClient("", "", "", False, False)
    mocker.patch.object(client, "event_search_request", return_value={"errors": {"message": "Error occurred"}})

    args = {
        "query": "",
        "fields": "message",
        "limit": "50",
        "start_time": "2024-05-01T00:00:00",
        "end_time": "2024-05-08T00:00:00",
    }

    with pytest.raises(DemistoException, match="Error occurred"):
        event_search_command(client, args)


def test_get_date(mocker: MockerFixture):
    """
    GIVEN:
        a mocked CommonServerPython.arg_to_datetime function returning a specific time string,

    WHEN:
        'get_date' function is called with the provided time string,

    THEN:
        it should return the date part of the provided time string in the 'YYYY-MM-DD' format.
    """
    from ExabeamSecOpsPlatform import get_date

    time = "2024.05.01T14:00:00"
    expected_result = "2024-05-01T14:00:00Z"

    with mocker.patch("CommonServerPython.arg_to_datetime", return_value=time):
        result = get_date(time, "start_time")

    assert result == expected_result


@pytest.mark.parametrize(
    "input_str, expected_output", [("key:Some Value", 'key:"Some Value"'), ("key:TrUe", "key:true"), ("key:false", "key:false")]
)
def test_transform_string(input_str, expected_output):
    """
    GIVEN:
        An input string to be transformed.
    WHEN:
        The 'transform_string' function is called with the input string.
    THEN:
        It should transform the input string according to the specified rules.
    """
    from ExabeamSecOpsPlatform import transform_string

    assert transform_string(input_str) == expected_output


@pytest.mark.parametrize(
    "input_str, expected_output",
    [
        ("key1:true AND key2:false OR key3:true TO key4:false", "key1:true AND key2:false OR key3:true TO key4:false"),
        ("key1:true", "key1:true"),
        ("", ""),
        ("key1:true AND key2:some value OR key3:another value", 'key1:true AND key2:"some value" OR key3:"another value"'),
    ],
)
def test_process_string(input_str, expected_output):
    """
    GIVEN:
        An input string to be processed.
    WHEN:
        The 'process_string' function is called with the input string.
    THEN:
        It should correctly process the input string, splitting it based on logical operators and transforming each part using
        the 'transform_string' function.
    """
    from ExabeamSecOpsPlatform import process_string

    assert process_string(input_str) == expected_output


def test_event_search_request(mocker):
    """
    GIVEN:
        A dictionary containing data to be sent in the request.
        A mocked '_http_request' method of the YourClass class.
        A base URL and an access token.
    WHEN:
        The 'search_request' method of the YourClass class is called with the data dictionary.
    THEN:
        It should send a POST request to the specified URL with the provided data and headers.
    """
    mocker.patch("ExabeamSecOpsPlatform.Client._authenticate")
    mock_http_request = mocker.patch("ExabeamSecOpsPlatform.Client._http_request")
    base_url = "https://example-api.com"
    client_id = "your_client_id"
    client_secret = "your_client_secret"

    instance = Client(base_url=base_url, client_id=client_id, client_secret=client_secret, verify=False, proxy=False)
    instance.access_token = "dummy_token"
    data_dict = {"key": "value"}
    expected_url = "https://example-api.com/search/v2/events"
    expected_headers = {
        "Authorization": "Bearer dummy_token",
        "Content-Type": "application/json",
        "accept": "application/json",
    }
    mocked_response = {"response_key": "response_value"}
    mock_http_request.return_value = mocked_response
    result = instance.event_search_request(data_dict)

    mock_http_request.assert_called_once_with(
        method="POST",
        full_url=expected_url,
        data=json.dumps(data_dict),
        headers=expected_headers,
    )
    assert result == mocked_response


@pytest.mark.parametrize(
    "args, expected_output", [({}, 50), ({"limit": None}, 50), ({"limit": 1000}, 1000), ({"limit": 5000}, 3000)]
)
def test_get_limit(args, expected_output):
    """
    GIVEN:
        a dictionary containing the 'limit' argument with various values.

    WHEN:
        'get_limit' function is called with the provided dictionary.

    THEN:
        it should return the limit value if specified and less than or equal to 3000;
        otherwise, it should return 3000 as the maximum limit.
        If the 'limit' argument is not present in the dictionary or is None, it should return 50 as the default limit.
    """
    from ExabeamSecOpsPlatform import get_limit

    assert get_limit(args) == expected_output


def test_parse_group_by():
    """
    GIVEN:
        an entry dictionary containing information about an item with various attributes.

    WHEN:
        '_parse_group_by' function is called with the provided entry dictionary and a list of titles.

    THEN:
        it should return a parsed dictionary with non-empty elements based on the provided titles;
        empty elements should be removed.
    """
    from ExabeamSecOpsPlatform import _parse_group_by

    entry = {
        "Id": "123",
        "Vendor": "Vendor X",
        "Product": "",
        "Created_at": "2024-05-26T12:00:00",
        "Message": "This is a message.",
    }
    titles = ["Id", "Vendor", "Created_at", "Message"]
    expected_result = {"Id": "123", "Vendor": "Vendor X", "Created_at": "2024-05-26T12:00:00", "Message": "This is a message."}
    assert _parse_group_by(entry, titles) == expected_result


valid_expiry_time = (datetime(2024, 7, 23, 13, 0, tzinfo=timezone.utc)).isoformat()  # noqa: UP017
expired_expiry_time = (datetime(2024, 7, 23, 11, 0, tzinfo=timezone.utc)).isoformat()  # noqa: UP017


@pytest.mark.parametrize(
    "access_token, expiry_time_str, expected_result",
    [
        ("token", valid_expiry_time, True),
        ("token", expired_expiry_time, False),
        (None, valid_expiry_time, False),
        ("token", None, False),
    ],
)
@freeze_time("2024-07-23 12:00:00")
def test_is_token_valid(mocker: MockerFixture, access_token, expiry_time_str, expected_result):
    mocker.patch.object(Client, "_http_request", return_value={"access_token": "token", "expires_in": 0})
    client = Client(base_url="https://api.exabeam.com", client_id="abc123", client_secret="ABC123", verify=False, proxy=False)

    result = client._is_token_valid(access_token, expiry_time_str)
    assert result == expected_result


@pytest.mark.parametrize(
    "expected_response, expected_token",
    [
        (
            {"access_token": "token", "expires_in": 3600},
            "token",
        ),
    ],
)
def test_get_new_token(mocker: MockerFixture, expected_response, expected_token):
    http_request = mocker.patch.object(Client, "_http_request", return_value=expected_response)
    client = Client(base_url="https://api.exabeam.com", client_id="abc123", client_secret="ABC123", verify=False, proxy=False)

    client._get_new_token()
    http_request.assert_called_with(
        method="POST",
        full_url="https://api.exabeam.com/auth/v1/token",
        data={
            "client_id": "abc123",
            "client_secret": "ABC123",
            "grant_type": "client_credentials",
        },
    )


@pytest.mark.parametrize(
    "args, mock_response, expected_outputs, expected_readable_output",
    [
        (
            {
                "case_id": "123",
            },
            {
                "caseId": "123",
                "alertId": "456",
                "riskScore": 75,
                "groupedbyKey": "Src Ip",
                "srcIps": ["1.1.1.1"],
                "priority": "LOW",
                "stage": "NEW",
                "queue": "Tier 1 Analyst",
                "rules": [{"ruleSource": "CR"}],
            },
            [
                {
                    "caseId": "123",
                    "alertId": "456",
                    "riskScore": 75,
                    "groupedbyKey": "Src Ip",
                    "srcIps": ["1.1.1.1"],
                    "priority": "LOW",
                    "stage": "NEW",
                    "queue": "Tier 1 Analyst",
                }
            ],
            "### Case\n"
            "|Alert ID|Case ID|Grouped by Key|Priority|Queue|Risk Score|Rules|Stage|\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| 456 | 123 | Src Ip | LOW | Tier 1 Analyst | 75 | 1 | NEW |\n",
        ),
        (
            {"limit": "1"},
            {
                "rows": [
                    {
                        "caseId": "123",
                        "alertId": "456",
                        "riskScore": 75,
                        "groupedbyKey": "Src Ip",
                        "srcIps": ["1.1.1.1"],
                        "priority": "LOW",
                        "stage": "NEW",
                        "queue": "Tier 1 Analyst",
                        "rules": [{"ruleSource": "CR"}],
                    }
                ],
                "totalRows": 1,
            },
            [
                {
                    "caseId": "123",
                    "alertId": "456",
                    "riskScore": 75,
                    "groupedbyKey": "Src Ip",
                    "srcIps": ["1.1.1.1"],
                    "priority": "LOW",
                    "stage": "NEW",
                    "queue": "Tier 1 Analyst",
                }
            ],
            "### Cases\n"
            "|Alert ID|Case ID|Grouped by Key|Priority|Queue|Risk Score|Rules|Stage|\n"
            "|---|---|---|---|---|---|---|---|\n"
            "| 456 | 123 | Src Ip | LOW | Tier 1 Analyst | 75 | 1 | NEW |\n",
        ),
    ],
)
def test_case_search_command(mocker: MockerFixture, args, mock_response, expected_outputs, expected_readable_output):
    from ExabeamSecOpsPlatform import case_search_command

    client = MockClient("", "", "", False, False)
    mocker.patch.object(client, "case_search_request", return_value=mock_response)
    mocker.patch.object(client, "get_case_request", return_value=mock_response)

    result = case_search_command(client, args)

    assert result.outputs_prefix == "ExabeamPlatform.Case"
    assert result.outputs == expected_outputs
    assert result.readable_output == expected_readable_output


def test_case_search_request(mocker: MockerFixture):
    data_dict = {
        "startTime": "2024-05-01T13:05:07.774Z",
        "endTime": "2024-06-21T13:05:07.774Z",
    }

    base_url = "https://example.com"
    client = Client(base_url, "", "", False, False)
    request = mocker.patch.object(client, "request", return_value={})

    client.case_search_request(data_dict)

    request.assert_called_with(
        method="POST",
        full_url=f"{base_url}/threat-center/v1/search/cases",
        data=json.dumps(data_dict),
    )


@pytest.mark.parametrize(
    "args, mock_response, expected_outputs, expected_readable_output",
    [
        (
            {"table_id": "123"},
            {"id": "123", "name": "Sample Table", "attributes": {"attr1": "value1"}},
            {"id": "123", "name": "Sample Table", "attributes": {"attr1": "value1"}},
            "### Table\n|Id|Name|\n|---|---|\n| 123 | Sample Table |\n",
        ),
        (
            {"limit": "1", "include_attributes": "Yes"},
            [
                {"id": "123", "name": "Table 1", "attributes": {"attr1": "value1"}},
                {"id": "124", "name": "Table 2", "attributes": {"attr2": "value2"}},
            ],
            [{"id": "123", "name": "Table 1", "attributes": {"attr1": "value1"}}],
            "### Tables\n|Id|Name|\n|---|---|\n| 123 | Table 1 |\n",
        ),
    ],
)
def test_context_table_list_command(mocker: MockerFixture, args, mock_response, expected_outputs, expected_readable_output):
    from ExabeamSecOpsPlatform import context_table_list_command

    client = MockClient("example.com", "", "", False, False)

    if "table_id" in args:
        mock_get = mocker.patch.object(client, "get_context_table", return_value=mock_response)
    else:
        mock_list = mocker.patch.object(client, "list_context_table", return_value=mock_response)

    result = context_table_list_command(client, args)

    if "table_id" in args:
        mock_get.assert_called_once_with(args["table_id"])
    else:
        mock_list.assert_called_once()

    assert result.outputs == expected_outputs
    assert result.readable_output == expected_readable_output


@pytest.mark.parametrize(
    "args, mock_response, expected_output",
    [
        (
            {"table_id": "12345", "delete_unused_custom_attributes": "True"},
            {"id": "1234"},
            "The context table with ID 1234 has been successfully deleted.",
        ),
        (
            {"table_id": "12345", "delete_unused_custom_attributes": "False"},
            {"id": "12345"},
            "The context table with ID 12345 has been successfully deleted.",
        ),
    ],
)
def test_context_table_delete_command(mocker: MockerFixture, args, mock_response, expected_output):
    from ExabeamSecOpsPlatform import context_table_delete_command

    client = MockClient("example.com", "", "", False, False)
    mock_delete = mocker.patch.object(client, "delete_context_table", return_value=mock_response)

    result = context_table_delete_command(client, args)

    assert result.readable_output == expected_output
    mock_delete.assert_called_once_with(
        args["table_id"], {"deleteUnusedCustomAttributes": str(args["delete_unused_custom_attributes"])}
    )


@pytest.mark.parametrize(
    "args, mock_response, expected_output",
    [
        (
            {"table_id": "12345", "limit": "2"},
            {"records": [{"id": "1", "name": "Record1"}, {"id": "2", "name": "Record2"}]},
            [
                {"id": "1", "name": "Record1"},
                {"id": "2", "name": "Record2"},
            ],
        )
    ],
)
def test_table_record_list_command(mocker: MockerFixture, args, mock_response, expected_output):
    from ExabeamSecOpsPlatform import table_record_list_command

    client = MockClient("example.com", "", "", False, False)
    mock_get = mocker.patch.object(client, "get_table_record_list", return_value=mock_response)

    result = table_record_list_command(client, args)

    assert result.outputs == expected_output
    mock_get.assert_called_once_with("12345", {"limit": 2, "offset": 0})


@pytest.mark.parametrize(
    "args, item_type, mock_response, expected_output, expected_prefix",
    [
        # with item_id
        (
            {"case_id": "123"},
            "case",
            {"id": "123", "name": "Test Case", "riskScore": "80"},
            [{"id": "123", "name": "Test Case", "riskScore": "80"}],
            "ExabeamPlatform.Case",
        ),
        (
            {"alert_id": "456"},
            "alert",
            {"id": "456", "name": "Test Alert", "riskScore": "80"},
            [{"id": "456", "name": "Test Alert", "riskScore": "80"}],
            "ExabeamPlatform.Alert",
        ),
        #  without item_id
        (
            {},
            "case",
            {"rows": [{"id": "123", "name": "Test Case", "riskScore": "80"}]},
            [{"id": "123", "name": "Test Case", "riskScore": "80"}],
            "ExabeamPlatform.Case",
        ),
    ],
)
def test_generic_search_command(mocker: MockerFixture, args, item_type, mock_response, expected_output, expected_prefix):
    from ExabeamSecOpsPlatform import generic_search_command

    client = MockClient("example.com", "", "", False, False)

    if f"{item_type}_id" in args:
        request = mocker.patch.object(client, f"get_{item_type}_request", return_value=mock_response)
    else:
        request = mocker.patch.object(client, f"{item_type}_search_request", return_value=mock_response)

    result = generic_search_command(client, args, item_type)

    assert result.outputs == expected_output
    assert result.outputs_prefix == expected_prefix

    if f"{item_type}_id" in args:
        request.assert_called_once_with(args[f"{item_type}_id"])
    else:
        request.assert_called_once()


@pytest.mark.parametrize(
    "dict_input, dict_expected",
    [
        (
            {"name": ["Alice", "Bob", "Charlie"], "age": ["25", "30", "35"], "city": ["city1", "city2", "city3"]},
            [
                {"name": "Alice", "age": "25", "city": "city1"},
                {"name": "Bob", "age": "30", "city": "city2"},
                {"name": "Charlie", "age": "35", "city": "city3"},
            ],
        ),
    ],
)
def test_transform_dicts(dict_input, dict_expected):
    from ExabeamSecOpsPlatform import transform_dicts

    result = transform_dicts(dict_input)
    assert result == dict_expected


@pytest.mark.parametrize(
    "attributes_input, key_suffix, expected_output",
    [
        pytest.param(
            {"caseCreationTimestamp": 1672531200000000, "lastModifiedTimestamp": 1672617600000000},
            "",
            {"caseCreationTimestamp": "2023-01-01T00:00:00Z", "lastModifiedTimestamp": "2023-01-02T00:00:00Z"},
            id="No suffix. Expect keys overwritten",
        ),
        pytest.param(
            {"approxLogTime": 1755685620000000},
            "Formatted",
            {"approxLogTime": 1755685620000000, "approxLogTimeFormatted": "2025-08-20T10:27:00Z"},
            id="'Formatted' suffix. Expect new keys added",
        ),
    ],
)
def test_convert_all_timestamp_to_datestring(attributes_input: dict, key_suffix: str, expected_output: dict):
    from ExabeamSecOpsPlatform import convert_all_timestamp_to_datestring

    result = convert_all_timestamp_to_datestring(attributes_input, key_suffix=key_suffix)
    assert result == expected_output


def test_last_case_time_and_ids():
    from ExabeamSecOpsPlatform import get_last_case_time_and_ids

    formatted_cases = [
        {"caseId": "A", "_time": "2025-01-01T00:00:00Z"},
        {"caseId": "B", "_time": "2025-01-01T01:01:00Z"},
        {"caseId": "C", "_time": "2025-01-01T01:01:00Z"},
    ]

    last_case_time, last_case_ids = get_last_case_time_and_ids(formatted_cases)

    assert last_case_time == "2025-01-01T01:01:00Z"
    assert last_case_ids == ["B", "C"]


@pytest.mark.parametrize(
    "mock_response, params, last_run, expected_incidents, expected_last_run",
    [
        pytest.param(
            CommandResults(
                outputs_prefix="ExabeamPlatform.Case",
                readable_output="",
                outputs=[
                    {
                        "caseId": "aa11",
                        "alertName": "alert1",
                        "caseCreationTimestamp": 1723212955501076,
                    },
                    {
                        "caseId": "bb22",
                        "alertName": "alert2",
                        "caseCreationTimestamp": 1723212955501077,
                    },
                ],
            ),
            {"fetch_query": "priority:LOW", "max_fetch": "2", "first_fetch": "3 days"},
            {"time": "2024-08-12T01:55:35Z", "last_ids": ["aa11"]},
            [
                {
                    "Name": "alert2",
                    "rawJSON": '{"caseId": "bb22", "alertName": "alert2", "caseCreationTimestamp": "2024-08-09T14:15:55Z"}',
                }
            ],
            {"time": "2024-08-09T14:15:55Z", "last_ids": ["bb22"]},
            id="different incident creation time",
        ),
        pytest.param(
            CommandResults(
                outputs_prefix="ExabeamPlatform.Case",
                readable_output="",
                outputs=[
                    {
                        "caseId": "aa11",
                        "alertName": "alert1",
                        "caseCreationTimestamp": 1723212955501077,
                    },
                    {
                        "caseId": "bb22",
                        "alertName": "alert2",
                        "caseCreationTimestamp": 1723212955501077,
                    },
                ],
            ),
            {"fetch_query": "priority:LOW", "max_fetch": "2", "first_fetch": "3 days"},
            {"time": "2024-08-09T14:15:55Z", "last_ids": ["aa11"]},
            [
                {
                    "Name": "alert2",
                    "rawJSON": '{"caseId": "bb22", "alertName": "alert2", "caseCreationTimestamp": "2024-08-09T14:15:55Z"}',
                },
            ],
            {"time": "2024-08-09T14:15:55Z", "last_ids": ["aa11", "bb22"]},
            id="same incident creation time, expected to add bb22 to last run and create incident just for bb22",
        ),
        pytest.param(
            CommandResults(
                outputs_prefix="ExabeamPlatform.Case",
                readable_output="",
                outputs=[
                    {
                        "caseId": "aa11",
                        "alertName": "alert1",
                        "caseCreationTimestamp": 1723212955501077,
                    }
                ],
            ),
            {"fetch_query": "priority:LOW", "max_fetch": "2", "first_fetch": "3 days"},
            {"time": "2024-08-09T14:15:55Z", "last_ids": ["aa11"]},
            [],
            {"time": "2024-08-09T14:15:55Z", "last_ids": ["aa11"]},
            id="same incident again, expected to keep it in last run and not create incident",
        ),
        pytest.param(
            CommandResults(
                outputs_prefix="ExabeamPlatform.Case",
                readable_output="",
                outputs=[{"caseId": "cc33", "alertName": "alert3", "caseCreationTimestamp": 1723213855501000}],
            ),
            {"fetch_query": "priority:LOW", "max_fetch": "2", "first_fetch": "3 days"},
            {"time": "2024-08-09T14:15:55Z", "last_ids": ["aa11", "bb22"]},
            [
                {
                    "Name": "alert3",
                    "rawJSON": '{"caseId": "cc33", "alertName": "alert3", "caseCreationTimestamp": "2024-08-09T14:30:55Z"}',
                },
            ],
            {"time": "2024-08-09T14:30:55Z", "last_ids": ["cc33"]},
            id="new incident, expected to create incident and update last run",
        ),
    ],
)
def test_fetch_incidents(mocker: MockerFixture, mock_response, params, last_run, expected_incidents, expected_last_run):
    from ExabeamSecOpsPlatform import fetch_incidents

    client = MockClient("example.com", "", "", False, False)

    mocker.patch("ExabeamSecOpsPlatform.case_search_command", return_value=mock_response)

    incidents, updated_last_run = fetch_incidents(client, params, last_run)

    assert incidents == expected_incidents
    assert updated_last_run == expected_last_run


@freeze_time("2025-01-01T01:10:00Z")
def test_fetch_events_success(mocker: MockerFixture):
    from ExabeamSecOpsPlatform import fetch_events

    mock_events = [
        {"caseId": "B", "_time": "2025-01-01T00:00:00Z"},
        {"caseId": "C", "_time": "2025-01-01T01:01:00Z"},
        {"caseId": "D", "_time": "2025-01-01T01:02:00Z"},
    ]
    mock_new_start_time = "2025-01-01T01:02:00.000Z"
    mock_new_last_fetched_ids = ["D"]
    mock_get_cases_in_batches = mocker.patch(
        "ExabeamSecOpsPlatform.get_cases_in_batches",
        return_value=(mock_events, mock_new_start_time, mock_new_last_fetched_ids),
    )

    mock_client = MockClient("example.com", "", "", False, False)
    max_fetch = 1000
    prev_start_time = "2025-01-01T00:00:00Z"
    prev_last_fetched_ids = ["A"]
    last_run = {"time": prev_start_time, "last_ids": prev_last_fetched_ids}

    events, next_run = fetch_events(mock_client, max_fetch, last_run)

    assert events == mock_events
    assert next_run == {"time": mock_new_start_time, "last_ids": mock_new_last_fetched_ids}

    assert mock_get_cases_in_batches.call_count == 1
    assert mock_get_cases_in_batches.call_args.kwargs == {
        "client": mock_client,
        "start_time": prev_start_time,
        "end_time": "2025-01-01T01:10:00Z",  # Same as frozen time
        "last_fetched_ids": prev_last_fetched_ids,
        "max_fetch": max_fetch,
    }


@pytest.mark.parametrize(
    "test_data_file_name",
    [
        pytest.param("fetch-events-no-cases.json", id="Empty batch"),
        pytest.param("fetch-events-partial-batch.json", id="Partial batch"),
        pytest.param("fetch-events-max-fetch.json", id="Max fetch less than batch size"),
        pytest.param("fetch-events-duplicate-cases.json", id="Batch with duplicates"),
    ],
)
def test_get_cases_in_batches(mocker: MockerFixture, test_data_file_name: str):
    """
    GIVEN:
        - Responses from Exabeam API for case search.
    WHEN:
        - The `get_cases_in_batches` function is called.
    THEN:
        - Ensure the function returns the expected events and the correct start time and last fetched IDs.
    """
    from ExabeamSecOpsPlatform import get_cases_in_batches

    test_data = util_load_json(f"test_data/{test_data_file_name}")

    mock_client = MockClient("example.com", "", "", False, False)
    mocker.patch.object(MockClient, "case_search_request", side_effect=test_data["mock_responses"])

    events, start_time, last_fetched_ids = get_cases_in_batches(
        client=mock_client,
        start_time="2025-04-04T01:07:33Z",
        end_time="2025-09-01T00:00:00Z",
        last_fetched_ids=test_data["prev_last_fetched_ids"],
        max_fetch=test_data["max_fetch"],
    )

    assert events == test_data["expected_events"]
    assert start_time == test_data["expected_new_start_time"]
    assert sorted(last_fetched_ids) == sorted(test_data["expected_new_last_fetched_ids"])


@freeze_time("2025-01-01T01:10:00Z")
def test_get_events_command(mocker: MockerFixture):
    """
    GIVEN:
        - A mock client and arguments for the get_events function.
    WHEN:
        - The `get_events_command` function is called.
    THEN:
        - Ensure get_cases_in_batches is called with the correct arguments.
        - Ensure tableToMarkdown is called with the correct arguments.
        - Ensure the function returns the expected events and CommandResults.
    """
    from ExabeamSecOpsPlatform import get_events_command

    mock_client = MockClient("example.com", "", "", False, False)
    mock_events_data = [{"caseId": "123", "name": "Test Event", "_time": "2025-01-02T00:00:00Z"}]

    mock_get_cases_in_batches = mocker.patch(
        "ExabeamSecOpsPlatform.get_cases_in_batches",
        return_value=(mock_events_data, "2025-01-02T00:00:00Z", ["123"]),
    )
    mock_table_to_markdown = mocker.patch("ExabeamSecOpsPlatform.tableToMarkdown")

    args = {
        "start_time": "1 day ago",
        "end_time": "now",
        "limit": "100",
    }

    events, results = get_events_command(mock_client, args)

    assert events == mock_events_data
    assert isinstance(results, CommandResults)

    assert mock_get_cases_in_batches.call_count == 1
    assert mock_get_cases_in_batches.call_args_list[0][1] == {
        "client": mock_client,
        "start_time": "2024-12-31T01:10:00Z",  # 1 day ago compared to frozen time
        "end_time": "2025-01-01T01:10:00Z",  # current frozen time
        "last_fetched_ids": [],
        "max_fetch": 100,
    }

    assert mock_table_to_markdown.call_args_list[0][0] == ("Events", mock_events_data)
