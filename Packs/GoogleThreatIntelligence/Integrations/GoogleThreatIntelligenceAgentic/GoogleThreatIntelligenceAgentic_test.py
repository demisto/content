import copy
import json
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from GoogleThreatIntelligenceAgentic import (
    BACKOFF_FACTOR,
    BASE_URL,
    BOOLEAN_HR_LIST,
    ENDPOINTS,
    ERROR_MESSAGES,
    FLOW_EXECUTION_HR_TITLE,
    FLOW_EXECUTION_RELATIONSHIP_CONTEXT_KEY,
    FLOW_EXECUTION_RELATIONSHIP_HR_LIST,
    FLOW_EXECUTION_SORT_FIELD_HR_LIST,
    FLOW_EXECUTION_STATUS_HR_LIST,
    FLOW_RELATIONSHIP_CONTEXT_KEY,
    FLOW_RELATIONSHIP_HR_LIST,
    FLOW_SORT_FIELD_HR_LIST,
    INTEGRATION_TOOL,
    MAX_LIMIT,
    MAX_RETRIES,
    MAX_SESSION_LIMIT,
    MESSAGES,
    OK_CODES,
    OUTPUT_PREFIX,
    SCHEDULE_FREQUENCY_HR_LIST,
    SESSION_MESSAGE_TIMEOUT,
    SORT_ORDER_HR_LIST,
    STATUS_CODE_TO_RETRY,
    Client,
)

MINIMAL_FLOW_NODES = [
    {"id": "n1", "type": "NODE_TYPE_SCHEDULE_TIME", "schedule_node": {"cron_expression": "0 9 * * *"}},
    {"id": "n2", "type": "NODE_TYPE_RUN_PROMPT", "run_prompt_node": {"prompt": "Summarise."}},
]

BUILT_SCHEDULE_NODE = {
    "id": "n1",
    "type": "NODE_TYPE_SCHEDULE_TIME",
    "name": "Schedule",
    "schedule_node": {"cron_expression": "0 9 * * *", "timezone": "UTC"},
}
RAW_FLOW_NODES = [
    {
        "id": "n1",
        "type": "NODE_TYPE_SCHEDULE_TIME",
        "name": "Every morning",
        "schedule_node": {"cron_expression": "0 9 * * *", "timezone": "UTC"},
    },
    {"id": "n2", "type": "NODE_TYPE_RUN_PROMPT", "name": "Summarise", "run_prompt_node": {"prompt": "Summarise."}},
    {
        "id": "n3",
        "type": "NODE_TYPE_SEND_EMAIL",
        "name": "Notify",
        "send_email_node": {"notification_emails": ["soc@example.com"]},
    },
]
CHAINED_CONNECTIONS = [
    {"source_node_id": "n1", "target_node_id": "n2", "source_handle": ""},
    {"source_node_id": "n2", "target_node_id": "n3", "source_handle": ""},
]
BUILT_GRAPH_ARGS = {
    "name": "Daily malicious-URL digest",
    "prompt": "Summarise.",
    "schedule_time": "2026-09-25T09:00:00Z",
}

# A dummy API key, which the tests pass to the client and to the integration parameters.
TEST_API_KEY = "test_api_key"
# A dummy share token of an agentic session, which the tests expect from the gti-agentic-session-token-get command.
TEST_SESSION_SHARE_TOKEN = "dummy-session-share-token"
# The Flow Execution whose related objects the tests retrieve.
FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID = "22222222-2222-2222-2222-222222222222"

FLOW_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW']}(val.id && val.id == obj.id)"
FLOW_PAGE_TOKEN_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW_PAGE_TOKEN']}(true)"
FLOW_EXECUTION_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW_EXECUTION']}(val.id && val.id == obj.id)"
FLOW_EXECUTION_PAGE_TOKEN_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW_EXECUTION_PAGE_TOKEN']}(true)"
FLOW_RELATIONSHIP_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP']}{FLOW_RELATIONSHIP_CONTEXT_KEY}"
FLOW_RELATIONSHIP_PAGE_TOKEN_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP_PAGE_TOKEN']}(true)"
FLOW_RELATIONSHIP_DESCRIPTOR_OUTPUT_KEY = f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP_DESCRIPTOR']}{FLOW_RELATIONSHIP_CONTEXT_KEY}"
SESSION_OUTPUT_KEY = f"{OUTPUT_PREFIX['SESSION']}(val.id && val.id == obj.id)"
SESSION_PAGE_TOKEN_OUTPUT_KEY = f"{OUTPUT_PREFIX['SESSION_PAGE_TOKEN']}(true)"
FLOW_EXECUTION_RELATIONSHIP_OUTPUT_KEY = (
    f"{OUTPUT_PREFIX['FLOW_EXECUTION_RELATIONSHIP']}{FLOW_EXECUTION_RELATIONSHIP_CONTEXT_KEY}"
)


# Helper Functions
def util_load_json(path):
    """Load JSON data from file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_text(path):
    """Load text data from file."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def util_mock_params(api_key: str = TEST_API_KEY, **params) -> dict:
    """Return the integration parameters, with the API key set in the credentials parameter."""
    return {"credentials": {"password": api_key}, **params}


def util_request_params(request):
    """Return the query parameters of a request, preserving the case of the values."""
    return {key: value[0] for key, value in parse_qs(urlparse(request.url).query).items()}


def util_nodes_args(nodes, connections=None) -> dict:
    """Return the arguments of the gti-agentic-flow-create command that provide the Flow graph."""
    args = {"name": "Daily malicious-URL digest", "nodes": json.dumps(nodes)}

    if connections is not None:
        args["connections"] = json.dumps(connections)

    return args


def util_command_outputs(result) -> dict:
    """Return the context outputs of a CommandResults object, keyed as they are reported to the platform."""
    return result.to_context()["EntryContext"]


def util_readable_output(result) -> str:
    """Return the human readable output of a CommandResults object."""
    return result.readable_output  # type: ignore[return-value]


@pytest.fixture
def mock_client():
    """Create a mocked client for testing."""
    return Client(verify_certificate=False, proxy=False, api_key=TEST_API_KEY)


def test_client_initialization():
    """Test that the Client sets the base URL and the authentication headers."""
    client = Client(verify_certificate=True, proxy=False, api_key="test_key_123")

    assert client._base_url == BASE_URL
    assert client._verify is True
    assert client._headers["x-apikey"] == "test_key_123"
    assert client._headers["x-tool"] == INTEGRATION_TOOL
    assert client._headers["Accept"] == "application/json"
    assert client._headers["Content-Type"] == "application/json"
    # The group header is sent only when the Group ID parameter is configured.
    assert "X-Active-Group" not in client._headers


def test_client_initialization_with_group_id():
    """Test that the Client sends the group header when a Group ID is configured."""
    client = Client(verify_certificate=False, proxy=False, api_key="test_key_123", group_id="my-group")

    assert client._headers["X-Active-Group"] == "my-group"


def test_client_initialization_with_empty_group_id():
    """Test that the Client omits the group header when the Group ID is empty."""
    client = Client(verify_certificate=False, proxy=False, api_key="test_key_123", group_id="")

    assert "X-Active-Group" not in client._headers


def test_retry_configuration():
    """Test that the retry mechanism covers the 429 and the 5XX status codes."""
    assert MAX_RETRIES == 4
    assert 429 in STATUS_CODE_TO_RETRY
    assert 500 in STATUS_CODE_TO_RETRY
    assert 502 in STATUS_CODE_TO_RETRY
    assert 503 in STATUS_CODE_TO_RETRY
    assert 504 in STATUS_CODE_TO_RETRY
    assert 404 not in STATUS_CODE_TO_RETRY


def test_list_flows_success(mock_client, requests_mock):
    """Test that list_flows returns the parsed response of the API."""
    expected_response = util_load_json("test_data/flow_list.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=expected_response, status_code=200)

    response = mock_client.list_flows({"limit": 1})

    assert response == expected_response
    assert requests_mock.last_request.qs == {"limit": ["1"]}


def test_list_flows_sends_group_header(requests_mock):
    """Test that the Group ID is sent in the X-Active-Group header of the request."""
    client = Client(verify_certificate=False, proxy=False, api_key=TEST_API_KEY, group_id="my-group")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_list.json"), status_code=200)

    client.list_flows({"limit": 1})

    assert requests_mock.last_request.headers["X-Active-Group"] == "my-group"


def test_test_module_success(mock_client, requests_mock):
    """Test that test_module returns 'ok' when the API call succeeds."""
    from GoogleThreatIntelligenceAgentic import test_module

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_list.json"), status_code=200)

    assert test_module(client=mock_client) == "ok"


def test_test_module_requests_a_single_flow(mock_client, requests_mock):
    """Test that test_module requests the flow list with the minimum page size."""
    from GoogleThreatIntelligenceAgentic import test_module

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_list.json"), status_code=200)

    test_module(client=mock_client)

    assert requests_mock.last_request.qs == {"limit": ["1"]}


def test_test_module_invalid_api_key(mock_client, requests_mock):
    """Test that an invalid API key raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import test_module

    response = util_load_json("test_data/error_unauthorized.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=response, status_code=401)

    with pytest.raises(DemistoException) as e:
        test_module(client=mock_client)

    assert str(e.value) == ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, str(response))


def test_test_module_unauthorized_non_json_response(mock_client, requests_mock):
    """Test that a non JSON 401 response falls back to the raw response body."""
    from GoogleThreatIntelligenceAgentic import test_module

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", text="Unauthorized", status_code=401)

    with pytest.raises(DemistoException) as e:
        test_module(client=mock_client)

    assert str(e.value) == ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "Unauthorized")


@pytest.mark.parametrize(
    "status_code, test_data_file, error_message_key",
    [
        (400, "test_data/error_bad_request.json", "BAD_REQUEST"),
        (403, "test_data/error_forbidden.json", "FORBIDDEN"),
        (404, "test_data/error_not_found.json", "NOT_FOUND"),
    ],
)
def test_error_handling(mock_client, requests_mock, status_code, test_data_file, error_message_key):
    """Test that the documented status codes raise the error message of the API."""
    response = util_load_json(test_data_file)
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        mock_client.list_flows({"limit": 1})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_error_handling_other_client_error(mock_client, requests_mock):
    """Test that a 4XX status code other than the documented ones reports the error message of the API."""
    response = {"error": {"code": "ConflictError", "message": "The flow is already running."}}
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=response, status_code=409)

    with pytest.raises(DemistoException) as e:
        mock_client.list_flows({"limit": 1})

    assert str(e.value) == ERROR_MESSAGES["GENERIC_ERROR"].format(409, "The flow is already running.")


def test_error_handling_without_error_message(mock_client, requests_mock):
    """Test that the raw body is reported when the response has no 'error.message' field."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json={"unexpected": "body"}, status_code=400)

    with pytest.raises(DemistoException) as e:
        mock_client.list_flows({"limit": 1})

    assert str(e.value) == ERROR_MESSAGES["BAD_REQUEST"].format(400, '{"unexpected": "body"}')


def test_error_handling_non_json_response(mock_client, requests_mock):
    """Test that a non JSON error response falls back to the raw response body."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", text="Bad Gateway HTML page", status_code=404)

    with pytest.raises(DemistoException) as e:
        mock_client.list_flows({"limit": 1})

    assert str(e.value) == ERROR_MESSAGES["NOT_FOUND"].format(404, "Bad Gateway HTML page")


def test_http_request_passes_retry_configuration(mock_client, mocker):
    """Test that the request is issued with the retry mechanism for the 429 and the 5XX status codes.

    The retry itself is performed by the urllib3 adapter, which 'requests_mock' replaces, so the
    configuration that is handed to BaseClient._http_request is asserted instead.
    """
    from GoogleThreatIntelligenceAgentic import handle_error_response

    http_request_mock = mocker.patch.object(BaseClient, "_http_request", return_value=mocker.Mock())

    mock_client.list_flows({"limit": 1}, response_type="response")

    kwargs = http_request_mock.call_args.kwargs
    assert kwargs["retries"] == MAX_RETRIES
    assert kwargs["backoff_factor"] == BACKOFF_FACTOR
    assert kwargs["status_list_to_retry"] == STATUS_CODE_TO_RETRY
    assert kwargs["raise_on_status"] is True
    assert kwargs["ok_codes"] == OK_CODES
    assert kwargs["error_handler"] is handle_error_response


def test_http_request_invalid_json_response(mock_client, requests_mock):
    """Test that an unparsable success response raises a descriptive error."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", text="not a json", status_code=200)

    with pytest.raises(DemistoException) as e:
        mock_client.list_flows({"limit": 1})

    assert "Failed to parse json object from response" in str(e.value)


@pytest.mark.parametrize("status_code", [200, 201])
@pytest.mark.parametrize(
    "response_kwargs, expected_response",
    [
        (
            {"json": {"data": {"id": "44444444-4444-4444-4444-000000000009"}}},
            {"data": {"id": "44444444-4444-4444-4444-000000000009"}},
        ),
        ({"content": b""}, {}),
    ],
    ids=["json body", "empty body"],
)
def test_http_request_success_status_codes(mock_client, requests_mock, status_code, response_kwargs, expected_response):
    """Test that both the 200 and the 201 status codes are treated as a success, with or without a response body."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", status_code=status_code, **response_kwargs)

    assert mock_client.list_flows({"limit": 1}) == expected_response


def test_http_request_returns_response_object(mock_client, requests_mock):
    """Test that the raw response object is returned when the response type is not 'json'."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json={"data": []}, status_code=200)

    response = mock_client.list_flows({"limit": 1}, response_type="response")

    assert response.status_code == 200


def test_http_request_masks_api_key_in_debug_log(mock_client, requests_mock, mocker):
    """Test that the API key is masked in the debug logs."""
    debug_mock = mocker.patch.object(demisto, "debug")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json={"data": []}, status_code=200)

    mock_client.list_flows({"limit": 1})

    logged_messages = " ".join(str(call.args[0]) for call in debug_mock.call_args_list)
    assert "***********" in logged_messages
    assert TEST_API_KEY not in logged_messages


def test_http_request_omits_body_values_in_debug_log(mock_client, requests_mock, mocker):
    """Test that only the keys of the request body are logged, as its values can carry the emails and the prompt."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_create_command

    debug_mock = mocker.patch.object(demisto, "debug")
    raw_response = util_load_json("test_data/flow_create.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flows']}", json=raw_response, status_code=200)

    gti_agentic_flow_create_command(
        client=mock_client,
        args={
            "name": "Daily malicious-URL digest",
            "prompt": "Summarise the new detections.",
            "schedule_time": "2026-09-25T09:00:00Z",
            "notification_emails": "soc@example.com",
        },
    )

    logged_messages = " ".join(str(call.args[0]) for call in debug_mock.call_args_list)
    assert "body keys:['data']" in logged_messages
    assert "soc@example.com" not in logged_messages
    assert "Summarise the new detections." not in logged_messages


def test_trim_spaces_from_args():
    """Test that the leading and the trailing spaces are removed from the string values."""
    from GoogleThreatIntelligenceAgentic import trim_spaces_from_args

    assert trim_spaces_from_args({"group_id": "  my-group  ", "limit": 10, "flag": None}) == {
        "group_id": "my-group",
        "limit": 10,
        "flag": None,
    }


@pytest.mark.parametrize("value", [None, "2026-09-15T09:04:24Z", True])
def test_convert_epoch_to_iso_non_epoch_value(value):
    """Test that a value that is not an epoch timestamp is returned unchanged."""
    from GoogleThreatIntelligenceAgentic import convert_epoch_to_iso

    assert convert_epoch_to_iso(value) == value


@pytest.mark.parametrize(
    "value, expected",
    [
        ("digest", 'name:"digest"'),
        ("daily digest", 'name:"daily digest"'),
        ('a" OR enabled:true', 'name:"a\\" OR enabled:true"'),
        ('daily "digest"', 'name:"daily \\"digest\\""'),
    ],
)
def test_build_search_modifier(value, expected):
    """Test that the value is always quoted and that the embedded double quotes are escaped."""
    from GoogleThreatIntelligenceAgentic import build_search_modifier

    assert build_search_modifier("name", value) == expected


@pytest.mark.parametrize(
    "schedule_time, schedule_frequency, expected",
    [
        pytest.param("2026-09-25T09:00:00Z", "Weekdays", "0 9 * * 1-5", id="weekdays"),
        pytest.param("2026-09-25T09:00:00Z", "Weekends", "0 9 * * 0,6", id="weekends"),
        pytest.param("2026-09-27T09:00:00Z", "weekly", "0 9 * * 0", id="weekly on a Sunday, case insensitive"),
        pytest.param("2026-09-25T09:05:00Z", "Monthly", "5 9 25 * *", id="monthly"),
    ],
)
def test_build_schedule_cron_expression(schedule_time, schedule_frequency, expected):
    """Test that the date or time and the frequency build the cron expression of the schedule node."""
    from GoogleThreatIntelligenceAgentic import build_schedule_cron_expression

    assert build_schedule_cron_expression(schedule_time, schedule_frequency) == expected


@pytest.mark.parametrize(
    "raw_response, expected",
    [
        ({"meta": {"cursor": "eyJvZmZzZXQiOjEwfQ==", "count": 25}}, {"next_cursor": "eyJvZmZzZXQiOjEwfQ==", "total_count": 25}),
        ({"meta": {"count": 0}}, {"total_count": 0}),
        ({"meta": {"cursor": ""}}, {}),
        ({}, {}),
    ],
)
def test_build_page_token(raw_response, expected):
    """Test that the page token reports only the cursor and the total count that the API returns, including a zero count."""
    from GoogleThreatIntelligenceAgentic import build_page_token

    assert build_page_token(raw_response) == expected


def test_build_flow_filter_escapes_quotes_in_name():
    """Test that a name containing a double quote cannot break out of the quoted literal."""
    from GoogleThreatIntelligenceAgentic import build_flow_filter

    assert build_flow_filter(name='a" OR enabled:true', enabled=None, filter_expression="") == 'name:"a\\" OR enabled:true"'


@pytest.mark.parametrize(
    "flow_id, status, filter_expression, expected",
    [
        pytest.param(
            "11111111-1111-1111-1111-111111111111", "", "", "flow_id:11111111-1111-1111-1111-111111111111", id="flow_id only"
        ),
        pytest.param("", "Failed", "", "status:failed", id="status only"),
        pytest.param("", "", "status:failed OR status:cancelled", "status:failed OR status:cancelled", id="filter only"),
        pytest.param(
            "11111111-1111-1111-1111-111111111111",
            "Completed",
            "duration:10+",
            "flow_id:11111111-1111-1111-1111-111111111111 status:completed (duration:10+)",
            id="all three",
        ),
        pytest.param(
            "11111111-1111-1111-1111-111111111111",
            "",
            "status:failed OR status:cancelled",
            "flow_id:11111111-1111-1111-1111-111111111111 (status:failed OR status:cancelled)",
            id="OR expression is parenthesized",
        ),
        pytest.param("", "", "", "", id="no filter"),
    ],
)
def test_build_flow_execution_filter(flow_id, status, filter_expression, expected):
    """Test that the conditions are space separated and that an OR in the user expression cannot absorb them."""
    from GoogleThreatIntelligenceAgentic import build_flow_execution_filter

    assert build_flow_execution_filter(flow_id, status, filter_expression) == expected


def test_gti_agentic_flow_list_command_success(mock_client, requests_mock):
    """Test that the command sends the provided arguments and reports the context and the human readable output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_list_command

    raw_response = util_load_json("test_data/flow_list.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=raw_response, status_code=200)

    result = gti_agentic_flow_list_command(
        client=mock_client,
        args={
            "name": "daily digest",
            "enabled": "True",
            "filter": "private:true",
            "sort_field": "Creation Date",
            "sort_order": "Asc",
            "limit": "2",
            "cursor": "eyJvZmZzZXQiOjEwfQ==",
        },
    )

    assert util_request_params(requests_mock.last_request) == {
        "limit": "2",
        "order": "creation_date+",
        "filter": '(name:"daily digest" OR enabled:true) private:true',
        "cursor": "eyJvZmZzZXQiOjEwfQ==",
    }

    outputs = util_command_outputs(result)

    assert outputs[FLOW_OUTPUT_KEY] == util_load_json("test_data/flow_list_context.json")
    assert outputs[FLOW_PAGE_TOKEN_OUTPUT_KEY] == {"next_cursor": "eyJvZmZzZXQiOjEwfQ==", "total_count": 2}
    assert util_readable_output(result) == util_load_text("test_data/flow_list_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_flow_list_command_no_results(mock_client, requests_mock):
    """Test that the command reports the no records message when the API returns no Flows."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_list_command

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_list_empty.json"), status_code=200)

    result = gti_agentic_flow_list_command(client=mock_client, args={})

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Flows")
    assert not result.outputs


def test_gti_agentic_flow_list_command_invalid_arguments(mock_client):
    """Test that all the invalid arguments are reported in a single error message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_list_command(
            client=mock_client, args={"limit": "0", "enabled": "maybe", "sort_field": "Priority", "sort_order": "Ascending"}
        )

    error_message = str(e.value)
    assert ERROR_MESSAGES["INVALID_LIMIT"].format(0, MAX_LIMIT) in error_message
    assert ERROR_MESSAGES["INVALID_ARGUMENT"].format("maybe", "enabled", BOOLEAN_HR_LIST) in error_message
    assert ERROR_MESSAGES["INVALID_ARGUMENT"].format("Priority", "sort_field", FLOW_SORT_FIELD_HR_LIST) in error_message
    assert ERROR_MESSAGES["INVALID_ARGUMENT"].format("Ascending", "sort_order", SORT_ORDER_HR_LIST) in error_message


def test_main_gti_agentic_flow_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-list command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"limit": "1", "name": " digest "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_list.json"), status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert util_request_params(requests_mock.last_request) == {
        "limit": "1",
        "order": "trigger_state.last_run_at-",
        "filter": 'name:"digest"',
    }
    assert FLOW_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_get_flow_success(mock_client, requests_mock):
    """Test that get_flow requests the Flow endpoint and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/flow_get.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=expected_response, status_code=200)

    response = mock_client.get_flow(flow_id)

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}"


def test_gti_agentic_flow_get_command_success(mock_client, requests_mock):
    """Test that the command reports the context and the human readable output of the requested Flow."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_get_command

    raw_response = util_load_json("test_data/flow_get.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=raw_response, status_code=200)

    result = gti_agentic_flow_get_command(client=mock_client, args={"flow_id": flow_id})

    outputs = util_command_outputs(result)

    assert outputs[FLOW_OUTPUT_KEY] == util_load_json("test_data/flow_get_context.json")
    assert util_readable_output(result) == util_load_text("test_data/flow_get_hr.md")
    assert result.raw_response == raw_response


def test_build_flow_detail_output_without_graph():
    """Test that the node and the connection tables are omitted when the Flow has no graph."""
    from GoogleThreatIntelligenceAgentic import build_flow_detail_output

    _, readable_output = build_flow_detail_output(
        {"id": "f2e7c4a0", "type": "flow", "attributes": {"name": "Weekly infrastructure review", "enabled": False}},
        "GTI Agentic Flow Information",
    )

    assert "### GTI Agentic Flow Information" in readable_output
    assert "### Nodes" not in readable_output
    assert "### Connections" not in readable_output


def test_build_flow_detail_output_reports_the_source_handle():
    """Test that the source handle of a connection is reported when the API populates it."""
    from GoogleThreatIntelligenceAgentic import build_flow_detail_output

    _, readable_output = build_flow_detail_output(
        {
            "id": "f2e7c4a0",
            "type": "flow",
            "attributes": {"connections": [{"source_node_id": "n1", "target_node_id": "n2", "source_handle": "on_success"}]},
        },
        "GTI Agentic Flow Information",
    )

    assert "|Source Node ID|Target Node ID|Source Handle|" in readable_output
    assert "| n1 | n2 | on_success |" in readable_output


@pytest.mark.parametrize("args", [{}, {"flow_id": ""}])
def test_gti_agentic_flow_get_command_missing_flow_id(mock_client, args):
    """Test that an absent or an empty 'flow_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_get_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_get_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id")


def test_gti_agentic_flow_get_command_no_records(mock_client, requests_mock):
    """Test that an empty Flow object reports the no records message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_get_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}",
        json=util_load_json("test_data/flow_get_empty.json"),
        status_code=200,
    )

    result = gti_agentic_flow_get_command(client=mock_client, args={"flow_id": flow_id})

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Flows")
    assert not util_command_outputs(result)


def test_gti_agentic_flow_get_command_not_found(mock_client, requests_mock):
    """Test that an unknown Flow ID reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_get_command

    flow_id = "00000000-0000-0000-0000-000000000000"
    response = util_load_json("test_data/error_not_found.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=response, status_code=404)

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_get_command(client=mock_client, args={"flow_id": flow_id})

    assert str(e.value) == ERROR_MESSAGES["NOT_FOUND"].format(404, response["error"]["message"])


def test_main_gti_agentic_flow_get(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-get command."""
    import GoogleThreatIntelligenceAgentic

    flow_id = "11111111-1111-1111-1111-111111111111"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"flow_id": f" {flow_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-get")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=util_load_json("test_data/flow_get.json"), status_code=200
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}"
    assert FLOW_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_create_flow_success(mock_client, requests_mock):
    """Test that create_flow posts the payload to the Flow endpoint and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/flow_create.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flows']}", json=expected_response, status_code=200)

    payload = {"data": {"type": "flow", "attributes": {"name": "Daily malicious-URL digest"}}}
    response = mock_client.create_flow(payload)

    assert response == expected_response
    assert requests_mock.last_request.json() == payload


@pytest.mark.parametrize(
    "args, expected_attributes, response_file, context_file, hr_file",
    [
        pytest.param(
            {
                "name": "Daily malicious-URL digest",
                "enabled": "False",
                "nodes": json.dumps(RAW_FLOW_NODES),
                "connections": json.dumps(CHAINED_CONNECTIONS),
                # The individual node arguments are ignored when the graph is provided.
                "prompt": "Ignored prompt",
                "schedule_time": "2026-09-25T09:00:00Z",
                "notification_emails": "ignored@example.com",
            },
            {
                "name": "Daily malicious-URL digest",
                "enabled": False,
                "nodes": RAW_FLOW_NODES,
                "connections": CHAINED_CONNECTIONS,
            },
            "test_data/flow_create.json",
            "test_data/flow_create_context.json",
            "test_data/flow_create_hr.md",
            id="provided graph sent as it is",
        ),
        pytest.param(
            # The values taken from the context are already parsed, and a single object is not wrapped in a list.
            {"name": "Ad hoc investigation", "nodes": MINIMAL_FLOW_NODES, "connections": CHAINED_CONNECTIONS[0]},
            {
                "name": "Ad hoc investigation",
                "enabled": True,
                "nodes": MINIMAL_FLOW_NODES,
                "connections": CHAINED_CONNECTIONS[:1],
            },
            "test_data/flow_create.json",
            "test_data/flow_create_context.json",
            "test_data/flow_create_hr.md",
            id="graph taken from the context",
        ),
        pytest.param(
            {
                "name": "Daily malicious-URL digest",
                "schedule_time": "2026-09-25T09:00:00Z",
                "prompt": "Summarise the new detections.",
                "reuse_session": "True",
                "notification_emails": "soc@example.com, ir@example.com",
                "email_subject": "Daily malicious-URL digest",
                "email_message": "See attached summary.",
            },
            {
                "name": "Daily malicious-URL digest",
                "enabled": True,
                "nodes": [
                    BUILT_SCHEDULE_NODE,
                    {
                        "id": "n2",
                        "type": "NODE_TYPE_RUN_PROMPT",
                        "name": "Run Prompt",
                        "run_prompt_node": {"prompt": "Summarise the new detections.", "reuse_session": True},
                    },
                    {
                        "id": "n3",
                        "type": "NODE_TYPE_SEND_EMAIL",
                        "name": "Send Email",
                        "send_email_node": {
                            "notification_emails": ["soc@example.com", "ir@example.com"],
                            "email_subject": "Daily malicious-URL digest",
                            "message": "See attached summary.",
                        },
                    },
                ],
                "connections": CHAINED_CONNECTIONS,
            },
            "test_data/flow_create.json",
            "test_data/flow_create_context.json",
            "test_data/flow_create_hr.md",
            id="graph built from the individual arguments",
        ),
        pytest.param(
            {
                "name": "Ad hoc investigation",
                "prompt": "Summarise.",
                "schedule_time": "2026-09-25T14:30:00+05:30",
                "notification_emails": "soc@example.com",
            },
            {
                "name": "Ad hoc investigation",
                "enabled": True,
                "nodes": [
                    # The schedule time is converted into UTC, and the default frequency is daily.
                    BUILT_SCHEDULE_NODE,
                    {
                        "id": "n2",
                        "type": "NODE_TYPE_RUN_PROMPT",
                        "name": "Run Prompt",
                        "run_prompt_node": {"prompt": "Summarise.", "reuse_session": False},
                    },
                    # The empty subject and message are omitted from the email node.
                    {
                        "id": "n3",
                        "type": "NODE_TYPE_SEND_EMAIL",
                        "name": "Send Email",
                        "send_email_node": {"notification_emails": ["soc@example.com"]},
                    },
                ],
                "connections": CHAINED_CONNECTIONS,
            },
            "test_data/flow_create_empty.json",
            None,
            None,
            id="graph built with the defaults, and empty response",
        ),
    ],
)
def test_gti_agentic_flow_create_command_success(
    mock_client, requests_mock, args, expected_attributes, response_file, context_file, hr_file
):
    """Test that the Flow graph is sent as expected, and that the created Flow is reported when the API returns it."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_create_command

    raw_response = util_load_json(response_file)
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flows']}", json=raw_response, status_code=200)

    result = gti_agentic_flow_create_command(client=mock_client, args=args)

    assert requests_mock.last_request.json() == {"data": {"type": "flow", "attributes": expected_attributes}}
    # Without the details of the Flow in the response, only the success message is reported.
    assert result.outputs == (util_load_json(context_file) if context_file else None)
    assert util_readable_output(result) == (util_load_text(hr_file) if hr_file else MESSAGES["FLOW_CREATED"])
    assert result.raw_response == raw_response


@pytest.mark.parametrize(
    "args, expected_error",
    [
        # Arguments of the command.
        pytest.param({"prompt": "Summarise."}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("name"), id="absent name"),
        pytest.param(
            {"name": "Daily malicious-URL digest", "prompt": "Summarise."},
            ERROR_MESSAGES["MISSING_FLOW_GRAPH"],
            id="neither graph nor schedule time",
        ),
        pytest.param(
            {**BUILT_GRAPH_ARGS, "enabled": "maybe"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("maybe", "enabled", BOOLEAN_HR_LIST),
            id="invalid boolean",
        ),
        pytest.param(
            {**BUILT_GRAPH_ARGS, "schedule_time": "not a date"},
            ERROR_MESSAGES["INVALID_SCHEDULE_TIME"].format("not a date"),
            id="invalid schedule time",
        ),
        pytest.param(
            {**BUILT_GRAPH_ARGS, "schedule_frequency": "Hourly"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Hourly", "schedule_frequency", SCHEDULE_FREQUENCY_HR_LIST),
            id="invalid schedule frequency",
        ),
        pytest.param(
            {**BUILT_GRAPH_ARGS, "notification_emails": "soc[at]example.com"},
            ERROR_MESSAGES["INVALID_EMAIL"].format("soc[at]example.com"),
            id="invalid notification email",
        ),
        pytest.param(
            {**BUILT_GRAPH_ARGS, "email_subject": "Digest"},
            ERROR_MESSAGES["MISSING_NOTIFICATION_EMAILS"],
            id="email subject without addresses",
        ),
        # JSON format of the graph arguments, whose value is not echoed back.
        pytest.param(
            {"name": "Daily malicious-URL digest", "nodes": '[{"id": "n1"},]'},
            ERROR_MESSAGES["INVALID_JSON_LIST"].format("nodes", " Error: Expecting value at position 14."),
            id="nodes not a json",
        ),
        pytest.param(
            {"name": "Daily malicious-URL digest", "nodes": '["n1", "n2"]'},
            ERROR_MESSAGES["INVALID_JSON_LIST"].format("nodes", ""),
            id="nodes not a list of objects",
        ),
        # Nodes of the graph, whose errors are reported together.
        pytest.param(
            util_nodes_args(
                [
                    {"type": "NODE_TYPE_SCHEDULE_TIME"},
                    {"id": "n2", "type": "NODE_TYPE_SCHEDULE_TIME", "schedule_node": "0 9 * * *"},
                    {"id": ["n3"], "type": "NODE_TYPE_SEND_EMAIL"},
                    {"id": "n4", "type": ["NODE_TYPE_SEND_EMAIL"]},
                    {"id": "n5"},
                    {"id": "n6", "type": "NODE_TYPE_UNKNOWN"},
                    {"id": "n7", "type": "NODE_TYPE_SEND_EMAIL", "send_email_node": {"notification_emails": "soc@example.com"}},
                    {
                        "id": "n7",
                        "type": "NODE_TYPE_SEND_EMAIL",
                        "send_email_node": {"notification_emails": ["soc[at]example.com"]},
                    },
                ]
            ),
            "\n\n".join(
                [
                    ERROR_MESSAGES["MISSING_NODE_ID"],
                    ERROR_MESSAGES["MISSING_NODE_FIELD"].format("cron_expression", "schedule_node", "at index 0"),
                    ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format("schedule_node", "'n2'", "a JSON object"),
                    ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format("id", "at index 2", "a string"),
                    ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format("type", "'n4'", "a string"),
                    ERROR_MESSAGES["MISSING_NODE_TYPE"].format("'n5'"),
                    ERROR_MESSAGES["INVALID_NODE_TYPE"].format(
                        "NODE_TYPE_UNKNOWN", "'n6'", ["NODE_TYPE_SCHEDULE_TIME", "NODE_TYPE_RUN_PROMPT", "NODE_TYPE_SEND_EMAIL"]
                    ),
                    ERROR_MESSAGES["INVALID_NODE_FIELD_TYPE"].format("notification_emails", "'n7'", "a list"),
                    ERROR_MESSAGES["DUPLICATE_NODE_ID"].format("n7"),
                    ERROR_MESSAGES["INVALID_EMAIL"].format("soc[at]example.com"),
                    ERROR_MESSAGES["MISSING_REQUIRED_NODE"].format("NODE_TYPE_RUN_PROMPT"),
                ]
            ),
            id="every node error reported together",
        ),
        # Connections of the graph, whose errors are reported together.
        pytest.param(util_nodes_args(MINIMAL_FLOW_NODES), ERROR_MESSAGES["MISSING_CONNECTIONS"], id="absent connections"),
        pytest.param(
            util_nodes_args(
                MINIMAL_FLOW_NODES,
                [{"source_node_id": "n1"}, {"target_node_id": "n2"}, {"source_node_id": ["n1"], "target_node_id": "n9"}],
            ),
            "\n\n".join(
                [
                    ERROR_MESSAGES["MISSING_CONNECTION_FIELD"].format("target_node_id"),
                    ERROR_MESSAGES["MISSING_CONNECTION_FIELD"].format("source_node_id"),
                    ERROR_MESSAGES["INVALID_CONNECTION_FIELD_TYPE"].format("source_node_id"),
                    ERROR_MESSAGES["INVALID_CONNECTION_NODE"].format("n9", "target_node_id"),
                ]
            ),
            id="every connection error reported together",
        ),
        pytest.param(
            util_nodes_args(MINIMAL_FLOW_NODES, [{"source_node_id": "n2", "target_node_id": "n1"}]),
            ERROR_MESSAGES["UNREACHABLE_PROMPT_NODE"],
            id="prompt node not reachable from the schedule",
        ),
        # Error reported by the API.
        pytest.param(
            BUILT_GRAPH_ARGS,
            ERROR_MESSAGES["BAD_REQUEST"].format(400, "Invalid filter expression provided."),
            id="bad request",
        ),
    ],
)
def test_gti_agentic_flow_create_command_failure(mock_client, requests_mock, args, expected_error):
    """Test that invalid arguments raise a descriptive error before the API is called, and that API errors are reported."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_create_command

    post_mock = requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/error_bad_request.json"), status_code=400
    )

    with pytest.raises((ValueError, DemistoException)) as e:
        gti_agentic_flow_create_command(client=mock_client, args=args)

    assert str(e.value) == expected_error
    # Only the errors of the API are raised after the request.
    assert post_mock.called == isinstance(e.value, DemistoException)


def test_main_gti_agentic_flow_create(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-create command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "name": " Daily malicious-URL digest ",
            "prompt": " Summarise the new detections. ",
            "schedule_time": " 2026-09-25T09:00:00Z ",
        },
    )
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-create")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_create.json"), status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    attributes = requests_mock.last_request.json()["data"]["attributes"]
    assert attributes["name"] == "Daily malicious-URL digest"
    assert attributes["nodes"][0]["schedule_node"]["cron_expression"] == "0 9 * * *"
    assert attributes["nodes"][1]["run_prompt_node"]["prompt"] == "Summarise the new detections."
    assert FLOW_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


UPDATE_FLOW_ID = "11111111-1111-1111-1111-111111111111"
UPDATE_FLOW_URL = f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(UPDATE_FLOW_ID)}"
# The graph of the Flow of 'test_data/flow_get.json', which the command retrieves before it changes the existing nodes.
EXISTING_SCHEDULE_NODE: dict[str, Any] = {
    "id": "n1",
    "type": "NODE_TYPE_SCHEDULE_TIME",
    "name": "Every morning",
    "schedule_node": {"cron_expression": "0 9 * * *", "timezone": "UTC"},
}
EXISTING_PROMPT_NODE: dict[str, Any] = {
    "id": "n2",
    "type": "NODE_TYPE_RUN_PROMPT",
    "name": "Summarise new detections",
    "run_prompt_node": {
        "prompt": "Summarise URLs first seen in the last 24h that are flagged malicious by 5+ engines.",
        "reuse_session": False,
    },
}
EXISTING_EMAIL_NODE: dict[str, Any] = {
    "id": "n3",
    "type": "NODE_TYPE_SEND_EMAIL",
    "name": "Email the SOC",
    "send_email_node": {
        "notification_emails": ["soc@example.com"],
        "email_subject": "Daily malicious-URL digest",
        "message": "See attached summary.",
    },
}
# The API does not report the source handle of the connections.
EXISTING_CONNECTIONS = [
    {"source_node_id": "n1", "target_node_id": "n2"},
    {"source_node_id": "n2", "target_node_id": "n3"},
]


def util_flow_get_response(nodes=None, connections=None) -> dict:
    """Return the response of the API for the retrieved Flow, optionally with the given graph."""
    response = util_load_json("test_data/flow_get.json")

    if nodes is not None:
        response["data"]["attributes"]["nodes"] = nodes

    if connections is not None:
        response["data"]["attributes"]["connections"] = connections

    return response


def test_update_flow_success(mock_client, requests_mock):
    """Test that update_flow patches the Flow endpoint with the payload and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/flow_update.json")
    requests_mock.patch(UPDATE_FLOW_URL, json=expected_response, status_code=200)

    payload = {"data": {"type": "flow", "attributes": {"enabled": False}}}
    response = mock_client.update_flow(UPDATE_FLOW_ID, payload)

    assert response == expected_response
    assert requests_mock.last_request.method == "PATCH"
    assert requests_mock.last_request.json() == payload


@pytest.mark.parametrize(
    "args, get_response, expected_attributes",
    [
        pytest.param(
            {"name": "Weekly digest", "enabled": "False"},
            None,
            {"name": "Weekly digest", "enabled": False},
            id="name and enabled state without retrieving the flow",
        ),
        pytest.param(
            {
                "nodes": json.dumps(RAW_FLOW_NODES),
                "connections": json.dumps(CHAINED_CONNECTIONS),
                # The individual node arguments are ignored when the nodes are provided.
                "prompt": "Ignored prompt",
                "schedule_time": "not a date",
                "schedule_frequency": "Hourly",
                "notification_emails": "ignored[at]example.com",
            },
            None,
            {"nodes": RAW_FLOW_NODES, "connections": CHAINED_CONNECTIONS},
            id="provided graph replaces the existing one",
        ),
        pytest.param(
            # The values taken from the context are already parsed.
            {"nodes": MINIMAL_FLOW_NODES},
            util_flow_get_response(connections=EXISTING_CONNECTIONS[:1]),
            {"nodes": MINIMAL_FLOW_NODES},
            id="provided nodes keep the existing connections",
        ),
        pytest.param(
            {"connections": CHAINED_CONNECTIONS[0]},
            util_flow_get_response(),
            {"connections": CHAINED_CONNECTIONS[:1]},
            id="provided connections refer to the existing nodes",
        ),
        pytest.param(
            {
                "schedule_time": "2026-09-24T18:30:00Z",
                "schedule_frequency": "Weekly",
                "prompt": "Summarise the new detections.",
                "reuse_session": "True",
                "email_subject": "Weekly digest",
            },
            util_flow_get_response(),
            {
                "nodes": [
                    # Only the provided fields change, and the other fields of the existing nodes are kept.
                    {**EXISTING_SCHEDULE_NODE, "schedule_node": {"cron_expression": "30 18 * * 4", "timezone": "UTC"}},
                    {
                        **EXISTING_PROMPT_NODE,
                        "run_prompt_node": {"prompt": "Summarise the new detections.", "reuse_session": True},
                    },
                    {
                        **EXISTING_EMAIL_NODE,
                        "send_email_node": {**EXISTING_EMAIL_NODE["send_email_node"], "email_subject": "Weekly digest"},
                    },
                ],
            },
            id="existing nodes changed by the individual arguments",
        ),
        pytest.param(
            {"schedule_time": "09:00", "schedule_frequency": "Daily"},
            util_flow_get_response(
                nodes=[
                    {**EXISTING_SCHEDULE_NODE, "schedule_node": {"cron_expression": "0 9 * * *", "timezone": "Asia/Kolkata"}},
                    EXISTING_PROMPT_NODE,
                ]
            ),
            {
                "nodes": [
                    # The cron expression is built in UTC, hence the existing timezone is replaced along with it.
                    {**EXISTING_SCHEDULE_NODE, "schedule_node": {"cron_expression": "0 9 * * *", "timezone": "UTC"}},
                    EXISTING_PROMPT_NODE,
                ],
            },
            id="schedule node in a non-UTC timezone",
        ),
        pytest.param(
            {"notification_emails": "soc@example.com, ir@example.com", "email_message": "See attached summary."},
            util_flow_get_response(
                # The identifiers are not sequential, hence the new node takes the first free one.
                nodes=[EXISTING_SCHEDULE_NODE, {**EXISTING_PROMPT_NODE, "id": "n3"}],
                connections=[{"source_node_id": "n1", "target_node_id": "n3"}],
            ),
            {
                "nodes": [
                    EXISTING_SCHEDULE_NODE,
                    {**EXISTING_PROMPT_NODE, "id": "n3"},
                    {
                        "id": "n4",
                        "type": "NODE_TYPE_SEND_EMAIL",
                        "name": "Send Email",
                        "send_email_node": {
                            "notification_emails": ["soc@example.com", "ir@example.com"],
                            "message": "See attached summary.",
                        },
                    },
                ],
                "connections": [
                    {"source_node_id": "n1", "target_node_id": "n3"},
                    {"source_node_id": "n3", "target_node_id": "n4", "source_handle": ""},
                ],
            },
            id="email node added after the prompt node",
        ),
    ],
)
def test_gti_agentic_flow_update_command_success(mock_client, requests_mock, args, get_response, expected_attributes):
    """Test that only the changed attributes are sent, and that the Flow is retrieved only when its graph is required."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_update_command

    get_mock = requests_mock.get(UPDATE_FLOW_URL, json=get_response or {}, status_code=200)
    raw_response = util_load_json("test_data/flow_update.json")
    patch_mock = requests_mock.patch(UPDATE_FLOW_URL, json=raw_response, status_code=200)

    result = gti_agentic_flow_update_command(client=mock_client, args={"flow_id": UPDATE_FLOW_ID, **args})

    assert get_mock.called == (get_response is not None)
    assert patch_mock.last_request.json() == {"data": {"type": "flow", "attributes": expected_attributes}}
    assert result.outputs == util_load_json("test_data/flow_update_context.json")
    assert result.outputs_prefix == OUTPUT_PREFIX["FLOW"]
    assert result.outputs_key_field == "id"
    assert util_readable_output(result) == util_load_text("test_data/flow_update_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_flow_update_command_empty_response(mock_client, requests_mock):
    """Test that only the success message is reported when the API does not report the details of the Flow."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_update_command

    raw_response = util_load_json("test_data/flow_update_empty.json")
    requests_mock.patch(UPDATE_FLOW_URL, json=raw_response, status_code=200)

    result = gti_agentic_flow_update_command(client=mock_client, args={"flow_id": UPDATE_FLOW_ID, "enabled": "True"})

    assert result.outputs is None
    assert util_readable_output(result) == MESSAGES["FLOW_UPDATED"]
    assert result.raw_response == raw_response


@pytest.mark.parametrize(
    "args, get_response, expected_error",
    [
        # Arguments of the command.
        pytest.param({"name": "Weekly digest"}, None, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id"), id="absent flow id"),
        pytest.param({"flow_id": UPDATE_FLOW_ID}, None, ERROR_MESSAGES["MISSING_UPDATE_ARGUMENT"], id="nothing to update"),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "name": "Weekly digest", "schedule_frequency": "Weekly"},
            None,
            ERROR_MESSAGES["MISSING_SCHEDULE_ARGUMENT"],
            id="schedule frequency without schedule time",
        ),
        pytest.param(
            # The existing frequency is not kept, hence the time alone would reset a Weekdays Flow to Daily.
            {"flow_id": UPDATE_FLOW_ID, "schedule_time": "10:00"},
            None,
            ERROR_MESSAGES["MISSING_SCHEDULE_ARGUMENT"],
            id="schedule time without schedule frequency",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "enabled": "maybe"},
            None,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("maybe", "enabled", BOOLEAN_HR_LIST),
            id="invalid enabled state",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "reuse_session": "maybe"},
            None,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("maybe", "reuse_session", BOOLEAN_HR_LIST),
            id="invalid reuse session",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "schedule_time": "not a date", "schedule_frequency": "Daily"},
            None,
            ERROR_MESSAGES["INVALID_SCHEDULE_TIME"].format("not a date"),
            id="invalid schedule time",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "schedule_time": "09:00", "schedule_frequency": "Hourly"},
            None,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Hourly", "schedule_frequency", SCHEDULE_FREQUENCY_HR_LIST),
            id="invalid schedule frequency",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "notification_emails": "soc[at]example.com"},
            None,
            ERROR_MESSAGES["INVALID_EMAIL"].format("soc[at]example.com"),
            id="invalid notification email",
        ),
        # Graph arguments, which are validated before the Flow is retrieved.
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "nodes": '[{"id": "n1"},]'},
            None,
            ERROR_MESSAGES["INVALID_JSON_LIST"].format("nodes", " Error: Expecting value at position 14."),
            id="nodes not a json",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "connections": '{"source_node_id": "n1"'},
            None,
            ERROR_MESSAGES["INVALID_JSON_LIST"].format("connections", " Error: Expecting ',' delimiter at position 23."),
            id="connections not a json",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "nodes": MINIMAL_FLOW_NODES[:1]},
            None,
            ERROR_MESSAGES["MISSING_REQUIRED_NODE"].format("NODE_TYPE_RUN_PROMPT"),
            id="nodes without a prompt node",
        ),
        pytest.param(
            {
                "flow_id": UPDATE_FLOW_ID,
                "nodes": MINIMAL_FLOW_NODES,
                "connections": [{"source_node_id": "n1", "target_node_id": "n9"}],
            },
            None,
            ERROR_MESSAGES["INVALID_CONNECTION_NODE"].format("n9", "target_node_id"),
            id="connection to an absent node",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "nodes": MINIMAL_FLOW_NODES, "connections": "[]"},
            None,
            ERROR_MESSAGES["UNREACHABLE_PROMPT_NODE"],
            id="prompt node not reachable from the schedule",
        ),
        # Graph of the retrieved Flow.
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "nodes": MINIMAL_FLOW_NODES},
            util_flow_get_response(),
            ERROR_MESSAGES["INVALID_EXISTING_CONNECTIONS"].format(
                ERROR_MESSAGES["INVALID_CONNECTION_NODE"].format("n3", "target_node_id")
            ),
            id="existing connections refer to a replaced node",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "connections": [{"source_node_id": "n2", "target_node_id": "n1"}]},
            util_flow_get_response(),
            ERROR_MESSAGES["UNREACHABLE_PROMPT_NODE"],
            id="provided connections do not reach the existing prompt node",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "prompt": "Summarise."},
            util_flow_get_response(nodes=[EXISTING_SCHEDULE_NODE]),
            ERROR_MESSAGES["MISSING_FLOW_NODE"].format("NODE_TYPE_RUN_PROMPT"),
            id="flow without the node to update",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "schedule_time": "09:00", "schedule_frequency": "Daily"},
            util_flow_get_response(nodes=[EXISTING_SCHEDULE_NODE, {**EXISTING_SCHEDULE_NODE, "id": "n4"}]),
            ERROR_MESSAGES["MULTIPLE_FLOW_NODES"].format("NODE_TYPE_SCHEDULE_TIME"),
            id="flow with an ambiguous node to update",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "email_subject": "Weekly digest"},
            util_flow_get_response(nodes=[EXISTING_SCHEDULE_NODE, EXISTING_PROMPT_NODE]),
            ERROR_MESSAGES["MISSING_EMAIL_NODE"],
            id="email subject without an email node",
        ),
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "notification_emails": "soc@example.com"},
            util_flow_get_response(nodes=[EXISTING_SCHEDULE_NODE]),
            ERROR_MESSAGES["MISSING_FLOW_NODE"].format("NODE_TYPE_RUN_PROMPT"),
            id="email node added without a prompt node",
        ),
        # Error reported by the API.
        pytest.param(
            {"flow_id": UPDATE_FLOW_ID, "enabled": "False"},
            None,
            ERROR_MESSAGES["NOT_FOUND"].format(404, "Flow with ID 'invalid-flow-id' not found."),
            id="flow not found",
        ),
    ],
)
def test_gti_agentic_flow_update_command_failure(mock_client, requests_mock, args, get_response, expected_error):
    """Test that invalid arguments or graphs raise an error before the Flow is updated, and that API errors are reported."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_update_command

    get_mock = requests_mock.get(UPDATE_FLOW_URL, json=get_response or {}, status_code=200)
    patch_mock = requests_mock.patch(UPDATE_FLOW_URL, json=util_load_json("test_data/error_not_found.json"), status_code=404)

    with pytest.raises((ValueError, DemistoException)) as e:
        gti_agentic_flow_update_command(client=mock_client, args=args)

    assert str(e.value) == expected_error
    # The Flow is retrieved only when its graph is required, and only the errors of the API are raised after the update.
    assert get_mock.called == (get_response is not None)
    assert patch_mock.called == isinstance(e.value, DemistoException)


def test_main_gti_agentic_flow_update(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-update command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"flow_id": f" {UPDATE_FLOW_ID} ", "name": " Weekly digest "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-update")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.patch(UPDATE_FLOW_URL, json=util_load_json("test_data/flow_update.json"), status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.json() == {"data": {"type": "flow", "attributes": {"name": "Weekly digest"}}}
    assert FLOW_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_delete_flow_success(mock_client, requests_mock):
    """Test that delete_flow issues a DELETE request on the Flow endpoint and tolerates the empty response body."""
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", content=b"", status_code=200)

    response = mock_client.delete_flow(flow_id)

    # The API responds with an empty body, which cannot be parsed as JSON.
    assert response == {}
    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}"


def test_delete_flow_documented_empty_data_object(mock_client, requests_mock):
    """Test that delete_flow returns the empty data object that the API documentation reports."""
    expected_response = util_load_json("test_data/flow_delete.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=expected_response, status_code=200)

    assert mock_client.delete_flow(flow_id) == expected_response


def test_gti_agentic_flow_delete_command_success(mock_client, requests_mock):
    """Test that the command reports the success message and does not set any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_delete_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", content=b"", status_code=200)

    result = gti_agentic_flow_delete_command(client=mock_client, args={"flow_id": flow_id})

    assert util_readable_output(result) == MESSAGES["FLOW_DELETED"].format(flow_id)
    # The API returns no content, hence the command does not publish any context output.
    assert not util_command_outputs(result)
    assert result.raw_response == {}


@pytest.mark.parametrize("args", [{}, {"flow_id": ""}])
def test_gti_agentic_flow_delete_command_missing_flow_id(mock_client, args):
    """Test that an absent or an empty 'flow_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_delete_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_delete_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id")


def test_gti_agentic_flow_delete_command_not_found(mock_client, requests_mock):
    """Test that an unknown Flow ID reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_delete_command

    flow_id = "00000000-0000-0000-0000-000000000000"
    response = util_load_json("test_data/error_not_found.json")
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=response, status_code=404)

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_delete_command(client=mock_client, args={"flow_id": flow_id})

    assert str(e.value) == ERROR_MESSAGES["NOT_FOUND"].format(404, response["error"]["message"])


def test_gti_agentic_flow_delete_command_forbidden(mock_client, requests_mock):
    """Test that a Flow that is not accessible by the configured API key reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_delete_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    response = util_load_json("test_data/error_forbidden.json")
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", json=response, status_code=403)

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_delete_command(client=mock_client, args={"flow_id": flow_id})

    assert str(e.value) == ERROR_MESSAGES["FORBIDDEN"].format(403, response["error"]["message"])


def test_main_gti_agentic_flow_delete(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-delete command."""
    import GoogleThreatIntelligenceAgentic

    flow_id = "11111111-1111-1111-1111-111111111111"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"flow_id": f" {flow_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-delete")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['flow_by_id'].format(flow_id)}", content=b"", status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}"
    assert util_readable_output(return_results_mock.call_args.args[0]) == MESSAGES["FLOW_DELETED"].format(flow_id)


def test_execute_flow_success(mock_client, requests_mock):
    """Test that execute_flow issues a POST request without a body on the execute endpoint of the Flow."""
    expected_response = util_load_json("test_data/flow_execute.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execute'].format(flow_id)}", json=expected_response, status_code=200)

    response = mock_client.execute_flow(flow_id)

    assert response == expected_response
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}/execute"
    assert not requests_mock.last_request.body


def test_gti_agentic_flow_execute_command_success(mock_client, requests_mock):
    """Test that the command reports the context and the human readable output of the created Flow Execution."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execute_command

    raw_response = util_load_json("test_data/flow_execute.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execute'].format(flow_id)}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execute_command(client=mock_client, args={"flow_id": flow_id})

    outputs = util_command_outputs(result)

    assert outputs[FLOW_EXECUTION_OUTPUT_KEY] == util_load_json("test_data/flow_execute_context.json")
    assert util_readable_output(result) == util_load_text("test_data/flow_execute_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_flow_execute_command_empty_response(mock_client, requests_mock):
    """Test that an empty Flow Execution object reports the success message without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execute_command

    raw_response = util_load_json("test_data/flow_execute_empty.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execute'].format(flow_id)}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execute_command(client=mock_client, args={"flow_id": flow_id})

    assert util_readable_output(result) == MESSAGES["FLOW_EXECUTION_STARTED"]
    assert not util_command_outputs(result)
    assert result.raw_response == raw_response


def test_gti_agentic_flow_execute_command_without_steps(mock_client, requests_mock):
    """Test that a failed Flow Execution without any step reports a neutral title and no step table."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execute_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    raw_response = {"data": {"type": "flow_execution", "id": "9a1b2c3d", "attributes": {"status": "EXECUTION_STATUS_FAILED"}}}
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execute'].format(flow_id)}", json=raw_response, status_code=200)

    readable_output = util_readable_output(gti_agentic_flow_execute_command(client=mock_client, args={"flow_id": flow_id}))

    assert readable_output.startswith(f"### {FLOW_EXECUTION_HR_TITLE}\n")
    execution_link = "https://www.virustotal.com/gui/agentic/flows/execution-log?filter=9a1b2c3d"
    assert f"| [9a1b2c3d]({execution_link}) | EXECUTION_STATUS_FAILED |" in readable_output
    assert MESSAGES["FLOW_EXECUTION_STARTED"] not in readable_output
    assert "### Steps" not in readable_output


def test_build_flow_execution_output_without_steps():
    """Test that a pending Flow Execution, which has no step yet, is reported without the steps."""
    from GoogleThreatIntelligenceAgentic import build_flow_execution_output

    context = build_flow_execution_output(
        {
            "type": "flow_execution",
            "id": "9a1b2c3d",
            "attributes": {"flow_id": "f2e7c4a0", "status": "EXECUTION_STATUS_PENDING", "steps": [], "creation_date": 0},
        }
    )

    assert context == {
        "type": "flow_execution",
        "id": "9a1b2c3d",
        "flow_id": "f2e7c4a0",
        "status": "EXECUTION_STATUS_PENDING",
        "creation_date": "1970-01-01T00:00:00Z",
    }


def test_build_flow_execution_output_running_step():
    """Test that the end of a step that is still running is not reported, and the other step fields are kept."""
    from GoogleThreatIntelligenceAgentic import build_flow_execution_output

    context = build_flow_execution_output(
        {
            "id": "9a1b2c3d",
            "attributes": {"steps": [{"step_id": "s1", "status": "STEP_STATUS_RUNNING", "started_at": 1790586005}]},
        }
    )

    assert context["steps"] == [{"step_id": "s1", "status": "STEP_STATUS_RUNNING", "started_at": "2026-09-28T09:00:05Z"}]


def test_build_flow_execution_output_step_timestamps():
    """Test that every epoch timestamp of a step is converted, and that an RFC 3339 timestamp is kept as received."""
    from GoogleThreatIntelligenceAgentic import build_flow_execution_output

    context = build_flow_execution_output(
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "attributes": {
                "steps": [
                    {
                        "step_id": "33333333-3333-3333-3333-333333333331",
                        "enqueued_at": 1790586000,
                        "started_at": 1790586005,
                        "ended_at": 1790586040,
                        "expires_at": 1790586900,
                    },
                    {
                        "step_id": "33333333-3333-3333-3333-333333333332",
                        "enqueued_at": "2026-09-28T09:00:00.336720448Z",
                        "started_at": "2026-09-28T09:00:00.414575744Z",
                        "ended_at": "2026-09-28T09:00:33.261625963Z",
                        "expires_at": "2026-09-28T09:15:00.414575744Z",
                    },
                ]
            },
        }
    )

    assert context["steps"] == [
        {
            "step_id": "33333333-3333-3333-3333-333333333331",
            "enqueued_at": "2026-09-28T09:00:00Z",
            "started_at": "2026-09-28T09:00:05Z",
            "ended_at": "2026-09-28T09:00:40Z",
            "expires_at": "2026-09-28T09:15:00Z",
        },
        {
            "step_id": "33333333-3333-3333-3333-333333333332",
            "enqueued_at": "2026-09-28T09:00:00.336720448Z",
            "started_at": "2026-09-28T09:00:00.414575744Z",
            "ended_at": "2026-09-28T09:00:33.261625963Z",
            "expires_at": "2026-09-28T09:15:00.414575744Z",
        },
    ]


@pytest.mark.parametrize("args", [{}, {"flow_id": ""}])
def test_gti_agentic_flow_execute_command_missing_flow_id(mock_client, args):
    """Test that an absent or an empty 'flow_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execute_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_execute_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id")


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, util_load_json("test_data/error_not_found.json"), "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
        (
            400,
            {"error": {"code": "BadRequestError", "message": "The Flow does not contain any executable node."}},
            "BAD_REQUEST",
        ),
    ],
)
def test_gti_agentic_flow_execute_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that a Flow that does not exist, is not accessible or cannot be executed reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execute_command

    flow_id = "00000000-0000-0000-0000-000000000000"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execute'].format(flow_id)}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execute_command(client=mock_client, args={"flow_id": flow_id})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_flow_execute(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-execute command."""
    import GoogleThreatIntelligenceAgentic

    flow_id = "11111111-1111-1111-1111-111111111111"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"flow_id": f" {flow_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-execute")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flow_execute'].format(flow_id)}",
        json=util_load_json("test_data/flow_execute.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}/execute"
    assert FLOW_EXECUTION_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_list_flow_related_objects_success(mock_client, requests_mock):
    """Test that list_flow_related_objects requests the relationship endpoint of the Flow with the query parameters."""
    expected_response = util_load_json("test_data/flow_object_list_flow_executions.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship'].format(flow_id, 'flow_executions')}", json=expected_response, status_code=200
    )

    response = mock_client.list_flow_related_objects(flow_id, "flow_executions", {"limit": 1, "cursor": "eyJvZmZzZXQiOjB9"})

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}/flow_executions"
    assert util_request_params(requests_mock.last_request) == {"limit": "1", "cursor": "eyJvZmZzZXQiOjB9"}


def test_gti_agentic_flow_object_list_command_success(mock_client, requests_mock):
    """Test that the command reports the related objects as received, the page token and the human readable output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_list_command

    raw_response = util_load_json("test_data/flow_object_list_flow_executions.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship'].format(flow_id, 'flow_executions')}", json=raw_response, status_code=200
    )

    result = gti_agentic_flow_object_list_command(
        client=mock_client,
        args={"flow_id": flow_id, "relationship": "Flow Executions", "limit": "1", "cursor": "eyJvZmZzZXQiOjB9"},
    )

    outputs = util_command_outputs(result)

    assert outputs == util_load_json("test_data/flow_object_list_flow_executions_context.json")
    assert outputs[FLOW_RELATIONSHIP_OUTPUT_KEY]["type"] == "flow_execution"
    # The attributes are stored as they are received, hence the epoch timestamps are not converted.
    assert outputs[FLOW_RELATIONSHIP_OUTPUT_KEY]["data"] == raw_response["data"]
    assert outputs[FLOW_RELATIONSHIP_PAGE_TOKEN_OUTPUT_KEY] == {
        "next_cursor": raw_response["meta"]["cursor"],
        "total_count": raw_response["meta"]["count"],
    }
    assert util_readable_output(result) == util_load_text("test_data/flow_object_list_flow_executions_hr.md")
    assert result.raw_response == raw_response
    assert util_request_params(requests_mock.last_request) == {"limit": "1", "cursor": "eyJvZmZzZXQiOjB9"}


def test_gti_agentic_flow_object_list_command_group(mock_client, requests_mock):
    """Test that the single group object of the Flow is reported as a list, with the default limit and no next cursor."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_list_command

    raw_response = util_load_json("test_data/flow_object_list_group.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_relationship'].format(flow_id, 'group')}", json=raw_response, status_code=200)

    result = gti_agentic_flow_object_list_command(client=mock_client, args={"flow_id": flow_id, "relationship": "group"})

    outputs = util_command_outputs(result)

    assert outputs == util_load_json("test_data/flow_object_list_group_context.json")
    assert outputs[FLOW_RELATIONSHIP_OUTPUT_KEY]["data"][0]["id"] == raw_response["data"]["id"]
    # The secrets of the group reach neither the context nor the raw response.
    for field in ("group_token", "scim_token"):
        assert field in raw_response["data"]["attributes"]
        assert field not in outputs[FLOW_RELATIONSHIP_OUTPUT_KEY]["data"][0]["attributes"]
        assert field not in result.raw_response["data"]["attributes"]  # type: ignore[index]
    # The API reports the total count without a cursor, as the group relationship has a single page.
    assert outputs[FLOW_RELATIONSHIP_PAGE_TOKEN_OUTPUT_KEY] == {"total_count": 1}
    assert util_readable_output(result) == util_load_text("test_data/flow_object_list_group_hr.md")
    assert util_request_params(requests_mock.last_request) == {"limit": "10"}


@pytest.mark.parametrize(
    "raw_response, expected",
    [
        ({"data": {"type": "group", "id": "acmecorp"}}, [{"type": "group", "id": "acmecorp"}]),
        (
            {"data": [{"type": "flow_execution", "id": "22222222-2222-2222-2222-222222222222"}, "unexpected", None]},
            [{"type": "flow_execution", "id": "22222222-2222-2222-2222-222222222222"}],
        ),
        ({"data": "unexpected"}, []),
    ],
)
def test_get_flow_related_objects(raw_response, expected):
    """Test that a single related object is wrapped in a list and that the items of an unexpected shape are dropped."""
    from GoogleThreatIntelligenceAgentic import get_flow_related_objects

    assert get_flow_related_objects(raw_response) == expected


def test_build_flow_relationship_outputs_without_related_objects():
    """Test that the outputs report an empty type, rather than failing, when no related object is given."""
    from GoogleThreatIntelligenceAgentic import build_flow_relationship_outputs

    outputs = build_flow_relationship_outputs(
        OUTPUT_PREFIX["FLOW_RELATIONSHIP"],
        OUTPUT_PREFIX["FLOW_RELATIONSHIP_PAGE_TOKEN"],
        "11111111-1111-1111-1111-111111111111",
        [],
        {},
    )

    assert outputs == {
        FLOW_RELATIONSHIP_OUTPUT_KEY: {"flow_id": "11111111-1111-1111-1111-111111111111", "type": "", "data": []},
        FLOW_RELATIONSHIP_PAGE_TOKEN_OUTPUT_KEY: {},
    }


def test_build_flow_group_hr_without_quota_and_role():
    """Test that a group without the active Flows quota or the role of the caller reports those columns empty."""
    from GoogleThreatIntelligenceAgentic import build_flow_group_hr

    hr_content = build_flow_group_hr(
        [{"id": "acmecorp", "type": "group", "attributes": {"organization": "Acme Corp", "quotas": {"active_flows": {}}}}]
    )

    assert hr_content == [
        {
            "Group ID": "acmecorp",
            "Organization": "Acme Corp",
            "Domain Name": "",
            "Country": "",
            "Industry": "",
            "GTI GCP Project": "",
            "Role": "",
            "Active Flows (Used/Allowed)": "",
        }
    ]


def test_gti_agentic_flow_object_list_command_no_records(mock_client, requests_mock):
    """Test that an empty page after a page with a cursor reports the no records message and clears the next cursor."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_list_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    url = f"{BASE_URL}{ENDPOINTS['flow_relationship'].format(flow_id, 'flow_executions')}"
    args = {"flow_id": flow_id, "relationship": "Flow Executions"}

    requests_mock.get(url, json=util_load_json("test_data/flow_object_list_flow_executions.json"), status_code=200)
    result = gti_agentic_flow_object_list_command(client=mock_client, args=args)

    assert "next_cursor" in util_command_outputs(result)[FLOW_RELATIONSHIP_PAGE_TOKEN_OUTPUT_KEY]

    empty_response = util_load_json("test_data/flow_object_list_empty.json")
    requests_mock.get(url, json=empty_response, status_code=200)
    result = gti_agentic_flow_object_list_command(client=mock_client, args={**args, "cursor": "eyJvZmZzZXQiOjF9"})

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("related objects")
    # The page token replaces the one of the earlier run, and holds no next cursor.
    assert util_command_outputs(result) == {FLOW_RELATIONSHIP_PAGE_TOKEN_OUTPUT_KEY: {"total_count": 0}}
    assert result.raw_response == empty_response


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"relationship": "Group"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id")),
        ({"flow_id": "", "relationship": "Group"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id")),
        ({"flow_id": "f2e7c4a0"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("relationship")),
        (
            {"flow_id": "f2e7c4a0", "relationship": "comments"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("comments", "relationship", FLOW_RELATIONSHIP_HR_LIST),
        ),
        ({"flow_id": "f2e7c4a0", "relationship": "Group", "limit": "0"}, ERROR_MESSAGES["INVALID_LIMIT"].format(0, MAX_LIMIT)),
        ({"flow_id": "f2e7c4a0", "relationship": "Group", "limit": "-1"}, ERROR_MESSAGES["INVALID_LIMIT"].format(-1, MAX_LIMIT)),
        ({"flow_id": "f2e7c4a0", "relationship": "Group", "limit": "41"}, ERROR_MESSAGES["INVALID_LIMIT"].format(41, MAX_LIMIT)),
        (
            {"flow_id": "f2e7c4a0", "relationship": "comments", "limit": "41"},
            ERROR_MESSAGES["INVALID_LIMIT"].format(41, MAX_LIMIT)
            + "\n\n"
            + ERROR_MESSAGES["INVALID_ARGUMENT"].format("comments", "relationship", FLOW_RELATIONSHIP_HR_LIST),
        ),
    ],
)
def test_gti_agentic_flow_object_list_command_invalid_arguments(mock_client, args, expected_error):
    """Test that the invalid arguments raise a descriptive error before any request is made."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_object_list_command(client=mock_client, args=args)

    assert str(e.value) == expected_error


def test_gti_agentic_flow_object_list_command_invalid_limit_type(mock_client):
    """Test that a limit that is not a number raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_list_command

    with pytest.raises(ValueError, match="limit"):
        gti_agentic_flow_object_list_command(
            client=mock_client, args={"flow_id": "f2e7c4a0", "relationship": "Group", "limit": "ten"}
        )


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, util_load_json("test_data/error_not_found.json"), "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
        (400, {"error": {"code": "BadRequestError", "message": "Invalid cursor."}}, "BAD_REQUEST"),
    ],
)
def test_gti_agentic_flow_object_list_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that an unknown or inaccessible Flow, or an invalid cursor, reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_list_command

    flow_id = "00000000-0000-0000-0000-000000000000"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship'].format(flow_id, 'flow_executions')}", json=response, status_code=status_code
    )

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_object_list_command(
            client=mock_client, args={"flow_id": flow_id, "relationship": "Flow Executions", "cursor": "invalid"}
        )

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_flow_object_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-object-list command."""
    import GoogleThreatIntelligenceAgentic

    flow_id = "11111111-1111-1111-1111-111111111111"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"flow_id": f" {flow_id} ", "relationship": " Flow Executions "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-object-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship'].format(flow_id, 'flow_executions')}",
        json=util_load_json("test_data/flow_object_list_flow_executions.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}/flow_executions"
    assert FLOW_RELATIONSHIP_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_list_flow_related_descriptors_success(mock_client, requests_mock):
    """Test that list_flow_related_descriptors requests the relationships endpoint of the Flow with the query parameters."""
    expected_response = util_load_json("test_data/flow_object_descriptor_list_flow_executions.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship_descriptor'].format(flow_id, 'flow_executions')}",
        json=expected_response,
        status_code=200,
    )

    response = mock_client.list_flow_related_descriptors(flow_id, "flow_executions", {"limit": 1, "cursor": "eyJvZmZzZXQiOjB9"})

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}/relationships/flow_executions"
    assert util_request_params(requests_mock.last_request) == {"limit": "1", "cursor": "eyJvZmZzZXQiOjB9"}


@pytest.mark.parametrize(
    "relationship, api_relationship, test_data_name, args",
    [
        ("flow executions", "flow_executions", "flow_executions", {"limit": "1", "cursor": "eyJvZmZzZXQiOjB9"}),
        ("GROUP", "group", "group", {}),
    ],
)
def test_gti_agentic_flow_object_descriptor_list_command_success(
    mock_client, requests_mock, relationship, api_relationship, test_data_name, args
):
    """Test that the command reports the descriptors of every relationship, in any case, as received with the page token."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_descriptor_list_command

    raw_response = util_load_json(f"test_data/flow_object_descriptor_list_{test_data_name}.json")
    flow_id = "11111111-1111-1111-1111-111111111111"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship_descriptor'].format(flow_id, api_relationship)}",
        json=raw_response,
        status_code=200,
    )

    result = gti_agentic_flow_object_descriptor_list_command(
        client=mock_client, args={"flow_id": flow_id, "relationship": relationship, **args}
    )

    assert util_command_outputs(result) == util_load_json(f"test_data/flow_object_descriptor_list_{test_data_name}_context.json")
    assert util_readable_output(result) == util_load_text(f"test_data/flow_object_descriptor_list_{test_data_name}_hr.md")
    assert result.raw_response == raw_response
    assert util_request_params(requests_mock.last_request) == {"limit": args.get("limit", "10"), **args}


def test_gti_agentic_flow_object_descriptor_list_command_last_page(mock_client, requests_mock):
    """Test that a last page without metadata still writes the page token, so the earlier next cursor is cleared."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_descriptor_list_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    url = f"{BASE_URL}{ENDPOINTS['flow_relationship_descriptor'].format(flow_id, 'flow_executions')}"
    args = {"flow_id": flow_id, "relationship": "Flow Executions"}
    page_token_key = f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP_DESCRIPTOR_PAGE_TOKEN']}(true)"

    first_page = util_load_json("test_data/flow_object_descriptor_list_flow_executions.json")
    requests_mock.get(url, json=first_page, status_code=200)
    result = gti_agentic_flow_object_descriptor_list_command(client=mock_client, args=args)

    assert util_command_outputs(result)[page_token_key] == {"next_cursor": "eyJvZmZzZXQiOjF9", "total_count": 1}

    last_page = util_load_json("test_data/flow_object_descriptor_list_flow_executions.json")
    del last_page["meta"]
    requests_mock.get(url, json=last_page, status_code=200)
    result = gti_agentic_flow_object_descriptor_list_command(client=mock_client, args={**args, "cursor": "eyJvZmZzZXQiOjF9"})

    # The page token replaces the one of the earlier run, and holds no next cursor.
    assert util_command_outputs(result)[page_token_key] == {}
    assert MESSAGES["NEXT_CURSOR"].format("eyJvZmZzZXQiOjF9") not in util_readable_output(result)


def test_gti_agentic_flow_object_descriptor_list_command_no_records(mock_client, requests_mock):
    """Test that an empty page of related object descriptors reports the no records message and clears the next cursor."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_descriptor_list_command

    flow_id = "11111111-1111-1111-1111-111111111111"
    empty_response = util_load_json("test_data/flow_object_descriptor_list_empty.json")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship_descriptor'].format(flow_id, 'flow_executions')}",
        json=empty_response,
        status_code=200,
    )

    result = gti_agentic_flow_object_descriptor_list_command(
        client=mock_client, args={"flow_id": flow_id, "relationship": "Flow Executions"}
    )

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("related object descriptors")
    # The page token replaces the one of an earlier run, and holds no next cursor.
    assert util_command_outputs(result) == {
        f"{OUTPUT_PREFIX['FLOW_RELATIONSHIP_DESCRIPTOR_PAGE_TOKEN']}(true)": {"total_count": 0}
    }
    assert result.raw_response == empty_response


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"relationship": "Group"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("flow_id")),
        ({"flow_id": "f2e7c4a0", "relationship": ""}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("relationship")),
        (
            {"flow_id": "f2e7c4a0", "relationship": "comments"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("comments", "relationship", FLOW_RELATIONSHIP_HR_LIST),
        ),
        ({"flow_id": "f2e7c4a0", "relationship": "Group", "limit": "0"}, ERROR_MESSAGES["INVALID_LIMIT"].format(0, MAX_LIMIT)),
        ({"flow_id": "f2e7c4a0", "relationship": "Group", "limit": "abc"}, 'Invalid number: "limit"="abc"'),
    ],
)
def test_gti_agentic_flow_object_descriptor_list_command_invalid_arguments(mock_client, args, expected_error):
    """Test that the invalid arguments raise a descriptive error before any request is made."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_descriptor_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_object_descriptor_list_command(client=mock_client, args=args)

    assert str(e.value) == expected_error


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, util_load_json("test_data/error_not_found.json"), "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
        (400, {"error": {"code": "BadRequestError", "message": "Invalid cursor."}}, "BAD_REQUEST"),
    ],
)
def test_gti_agentic_flow_object_descriptor_list_command_api_error(
    mock_client, requests_mock, status_code, response, error_message_key
):
    """Test that an unknown or inaccessible Flow, or an invalid cursor, reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_object_descriptor_list_command

    flow_id = "00000000-0000-0000-0000-000000000000"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship_descriptor'].format(flow_id, 'flow_executions')}",
        json=response,
        status_code=status_code,
    )

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_object_descriptor_list_command(
            client=mock_client, args={"flow_id": flow_id, "relationship": "Flow Executions", "cursor": "invalid"}
        )

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_flow_object_descriptor_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-object-descriptor-list command."""
    import GoogleThreatIntelligenceAgentic

    flow_id = "11111111-1111-1111-1111-111111111111"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"flow_id": f" {flow_id} ", "relationship": " Group "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-object-descriptor-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_relationship_descriptor'].format(flow_id, 'group')}",
        json=util_load_json("test_data/flow_object_descriptor_list_group.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/flows/{flow_id}/relationships/group"
    assert FLOW_RELATIONSHIP_DESCRIPTOR_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_list_flow_executions_success(mock_client, requests_mock):
    """Test that list_flow_executions requests the Flow Execution collection with the query parameters."""
    expected_response = util_load_json("test_data/flow_execution_list.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=expected_response, status_code=200)

    response = mock_client.list_flow_executions({"limit": 2, "order": "creation_date-"})

    assert response == expected_response
    assert requests_mock.last_request.path == "/api/v3/flow_executions"
    assert util_request_params(requests_mock.last_request) == {"limit": "2", "order": "creation_date-"}


def test_gti_agentic_flow_execution_list_command_success(mock_client, requests_mock):
    """Test that the command sends the filters, converts the epoch timestamps and reports the page token."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    raw_response = util_load_json("test_data/flow_execution_list.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_list_command(
        client=mock_client,
        args={
            "flow_id": "11111111-1111-1111-1111-111111111111",
            "status": "Completed",
            "filter": "duration:10+",
            "sort_field": "Last Modification Date",
            "sort_order": "Asc",
            "limit": "2",
            "cursor": "eyJvZmZzZXQiOjB9",
        },
    )

    assert util_request_params(requests_mock.last_request) == {
        "limit": "2",
        "order": "last_modification_date+",
        "filter": "flow_id:11111111-1111-1111-1111-111111111111 status:completed (duration:10+)",
        "cursor": "eyJvZmZzZXQiOjB9",
    }

    outputs = util_command_outputs(result)

    assert outputs == util_load_json("test_data/flow_execution_list_context.json")
    assert outputs[FLOW_EXECUTION_OUTPUT_KEY][0]["creation_date"] == "2026-09-28T09:00:00Z"
    assert outputs[FLOW_EXECUTION_PAGE_TOKEN_OUTPUT_KEY] == {"next_cursor": "eyJvZmZzZXQiOjJ9", "total_count": 5}
    assert util_readable_output(result) == util_load_text("test_data/flow_execution_list_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_flow_execution_list_command_default_arguments(mock_client, requests_mock):
    """Test that the command sorts by the latest creation date and sends no filter by default."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=util_load_json("test_data/flow_execution_list.json"), status_code=200
    )

    gti_agentic_flow_execution_list_command(client=mock_client, args={})

    assert util_request_params(requests_mock.last_request) == {"limit": "10", "order": "creation_date-"}


@pytest.mark.parametrize(
    "args, expected_params",
    [
        (
            {"status": "completed", "sort_field": "creation date", "sort_order": "asc"},
            {"limit": "10", "order": "creation_date+", "filter": "status:completed"},
        ),
        (
            {"status": "CANCELLED", "sort_field": "LAST MODIFICATION DATE", "sort_order": "DESC"},
            {"limit": "10", "order": "last_modification_date-", "filter": "status:cancelled"},
        ),
    ],
)
def test_gti_agentic_flow_execution_list_command_case_insensitive_arguments(mock_client, requests_mock, args, expected_params):
    """Test that the status, the sort field and the sort order are matched case insensitively."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=util_load_json("test_data/flow_execution_list.json"), status_code=200
    )

    gti_agentic_flow_execution_list_command(client=mock_client, args=args)

    assert util_request_params(requests_mock.last_request) == expected_params


def test_gti_agentic_flow_execution_list_command_last_page(mock_client, requests_mock):
    """Test that the last page reports only the total count in the page token and no next cursor message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    raw_response = util_load_json("test_data/flow_execution_list.json")
    del raw_response["meta"]["cursor"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_list_command(client=mock_client, args={})

    assert util_command_outputs(result)[FLOW_EXECUTION_PAGE_TOKEN_OUTPUT_KEY] == {"total_count": 5}
    assert util_readable_output(result) == util_load_text("test_data/flow_execution_list_hr.md").split("\n\n")[0] + "\n"


def test_gti_agentic_flow_execution_list_command_without_steps(mock_client, requests_mock):
    """Test that a Flow Execution without any step reports zero steps in the human readable output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    raw_response = {
        "data": [
            {
                "type": "flow_execution",
                "id": "22222222-2222-2222-2222-222222222222",
                "attributes": {"status": "EXECUTION_STATUS_PENDING", "flow_id": "11111111-1111-1111-1111-111111111111"},
            }
        ],
        "meta": {"count": 1},
    }
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_list_command(client=mock_client, args={})

    assert "| EXECUTION_STATUS_PENDING | 0 |" in util_readable_output(result)


def test_gti_agentic_flow_execution_list_command_no_records(mock_client, requests_mock):
    """Test that an empty page of Flow Executions reports the no records message and clears the cursor of an earlier run."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    raw_response = util_load_json("test_data/flow_execution_list_empty.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_list_command(client=mock_client, args={"status": "Cancelled"})

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Flow Executions")
    assert util_command_outputs(result) == {FLOW_EXECUTION_PAGE_TOKEN_OUTPUT_KEY: {"total_count": 0}}
    assert result.raw_response == raw_response


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"limit": "0"}, ERROR_MESSAGES["INVALID_LIMIT"].format(0, MAX_LIMIT)),
        ({"limit": "41"}, ERROR_MESSAGES["INVALID_LIMIT"].format(41, MAX_LIMIT)),
        ({"status": "Done"}, ERROR_MESSAGES["INVALID_ARGUMENT"].format("Done", "status", FLOW_EXECUTION_STATUS_HR_LIST)),
        (
            {"sort_field": "Status"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Status", "sort_field", FLOW_EXECUTION_SORT_FIELD_HR_LIST),
        ),
        ({"sort_order": "Up"}, ERROR_MESSAGES["INVALID_ARGUMENT"].format("Up", "sort_order", SORT_ORDER_HR_LIST)),
        (
            {"limit": "41", "status": "Done"},
            ERROR_MESSAGES["INVALID_LIMIT"].format(41, MAX_LIMIT)
            + "\n\n"
            + ERROR_MESSAGES["INVALID_ARGUMENT"].format("Done", "status", FLOW_EXECUTION_STATUS_HR_LIST),
        ),
    ],
)
def test_gti_agentic_flow_execution_list_command_invalid_arguments(mock_client, args, expected_error):
    """Test that the invalid arguments raise a descriptive error before any request is made."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_execution_list_command(client=mock_client, args=args)

    assert str(e.value) == expected_error


@pytest.mark.parametrize(
    "response, error_message_key",
    [
        ({"error": {"code": "BadRequestError", "message": "Invalid cursor."}}, "BAD_REQUEST"),
        (util_load_json("test_data/error_bad_request.json"), "BAD_REQUEST"),
    ],
)
def test_gti_agentic_flow_execution_list_command_api_error(mock_client, requests_mock, response, error_message_key):
    """Test that an invalid cursor or filter expression reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_list_command

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=response, status_code=400)

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execution_list_command(client=mock_client, args={"filter": "invalid:", "cursor": "invalid"})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(400, response["error"]["message"])


def test_main_gti_agentic_flow_execution_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-execution-list command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"status": " Failed "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-execution-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_executions']}", json=util_load_json("test_data/flow_execution_list.json"), status_code=200
    )

    GoogleThreatIntelligenceAgentic.main()

    assert util_request_params(requests_mock.last_request)["filter"] == "status:failed"
    assert FLOW_EXECUTION_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_get_flow_execution_success(mock_client, requests_mock):
    """Test that get_flow_execution requests the Flow Execution endpoint and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/flow_execution_get.json")
    execution_id = expected_response["data"]["id"]
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_by_id'].format(execution_id)}", json=expected_response, status_code=200
    )

    response = mock_client.get_flow_execution(execution_id)

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}"


def test_gti_agentic_flow_execution_get_command_success(mock_client, requests_mock):
    """Test that the command reports the Flow Execution with ISO 8601 dates and a step table with the step outputs."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_get_command

    raw_response = util_load_json("test_data/flow_execution_get.json")
    execution_id = raw_response["data"]["id"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_execution_by_id'].format(execution_id)}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_get_command(client=mock_client, args={"execution_id": execution_id})

    outputs = util_command_outputs(result)

    assert outputs[FLOW_EXECUTION_OUTPUT_KEY] == util_load_json("test_data/flow_execution_get_context.json")
    assert outputs[FLOW_EXECUTION_OUTPUT_KEY]["creation_date"] == "2026-09-28T09:00:00Z"
    assert util_readable_output(result) == util_load_text("test_data/flow_execution_get_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_flow_execution_get_command_without_steps(mock_client, requests_mock):
    """Test that a Flow Execution without any step is reported without the step table."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_get_command

    execution_id = "9a1b2c3d"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_by_id'].format(execution_id)}",
        json={"data": {"type": "flow_execution", "id": execution_id, "attributes": {"status": "EXECUTION_STATUS_PENDING"}}},
        status_code=200,
    )

    readable_output = util_readable_output(
        gti_agentic_flow_execution_get_command(client=mock_client, args={"execution_id": execution_id})
    )

    assert "### GTI Agentic Flow Execution Information" in readable_output
    assert "### Flow Execution Steps" not in readable_output


@pytest.mark.parametrize(
    "step, expected_output",
    [
        (
            {"run_prompt_output": {"session_id": "1", "gti_agentic_response": "Found 12 new malicious URLs."}},
            "Session ID: [1](https://www.virustotal.com/gui/agentic/sessions/1)\nSee the agent response below.",
        ),
        ({"run_prompt_output": {"session_id": "1"}}, "Session ID: [1](https://www.virustotal.com/gui/agentic/sessions/1)"),
        ({"run_prompt_output": {"gti_agentic_response": "Found 12 new malicious URLs."}}, "See the agent response below."),
        ({"run_prompt_output": {}}, ""),
        ({"send_email_output": {"dispatched": True}}, "dispatched: true"),
        ({"send_email_output": {"dispatched": False}}, "dispatched: false"),
        ({"node_type": "NODE_TYPE_SCHEDULE_TIME"}, ""),
    ],
)
def test_get_flow_execution_step_output(step, expected_output):
    """Test that the output of every step type is reported in the step table."""
    from GoogleThreatIntelligenceAgentic import get_flow_execution_step_output

    assert get_flow_execution_step_output(step) == expected_output


def test_build_flow_execution_agent_response_hr():
    """Test that every agent response is rendered in its own section and that the other steps are skipped."""
    from GoogleThreatIntelligenceAgentic import build_flow_execution_agent_response_hr

    steps = [
        {"step_id": "s1", "run_prompt_output": {"gti_agentic_response": "## Report\n\n- Found 12 new malicious URLs."}},
        {"step_id": "s2", "send_email_output": {"dispatched": True}},
        {"step_id": "s3", "run_prompt_output": {"session_id": "1"}},
        {"step_id": "s4", "run_prompt_output": {"gti_agentic_response": "No new threats."}},
    ]

    assert build_flow_execution_agent_response_hr(steps) == (
        "### Agent Response of Step s1\n## Report\n\n- Found 12 new malicious URLs.\n"
        "\n"
        "### Agent Response of Step s4\nNo new threats.\n"
    )
    assert build_flow_execution_agent_response_hr(steps[1:3]) == ""


def test_gti_agentic_flow_execution_get_command_no_records(mock_client, requests_mock):
    """Test that an empty Flow Execution object reports the no records message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_get_command

    execution_id = "9a1b2c3d"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_by_id'].format(execution_id)}",
        json=util_load_json("test_data/flow_execution_get_empty.json"),
        status_code=200,
    )

    result = gti_agentic_flow_execution_get_command(client=mock_client, args={"execution_id": execution_id})

    assert util_readable_output(result) == MESSAGES["NO_RECORD_FOUND"].format("GTI Agentic Flow Execution")
    assert not util_command_outputs(result)


@pytest.mark.parametrize("args", [{}, {"execution_id": ""}])
def test_gti_agentic_flow_execution_get_command_missing_execution_id(mock_client, args):
    """Test that an absent or an empty 'execution_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_get_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_execution_get_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("execution_id")


def test_gti_agentic_flow_execution_get_command_not_found(mock_client, requests_mock):
    """Test that an unknown Flow Execution ID, or one whose Flow is not visible, reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_get_command

    execution_id = "00000000-0000-0000-0000-000000000000"
    response = {"error": {"code": "NotFoundError", "message": "Not found."}}
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_execution_by_id'].format(execution_id)}", json=response, status_code=404)

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execution_get_command(client=mock_client, args={"execution_id": execution_id})

    assert str(e.value) == ERROR_MESSAGES["NOT_FOUND"].format(404, "Not found.")


def test_main_gti_agentic_flow_execution_get(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-execution-get command."""
    import GoogleThreatIntelligenceAgentic

    raw_response = util_load_json("test_data/flow_execution_get.json")
    execution_id = raw_response["data"]["id"]
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"execution_id": f" {execution_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-execution-get")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flow_execution_by_id'].format(execution_id)}", json=raw_response, status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}"
    assert FLOW_EXECUTION_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_get_flow_execution_related_object_success(mock_client, requests_mock):
    """Test that get_flow_execution_related_object requests the relationship endpoint of the Flow Execution."""
    expected_response = util_load_json("test_data/flow_execution_object_list_flow.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, 'flow_snapshot')}",
        json=expected_response,
        status_code=200,
    )

    response = mock_client.get_flow_execution_related_object(execution_id, "flow_snapshot")

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}/flow_snapshot"


@pytest.mark.parametrize(
    "relationship, api_relationship, test_data_name",
    [
        ("Flow", "flow", "flow"),
        ("Flow Snapshot", "flow_snapshot", "flow_snapshot"),
        ("group", "group", "group"),
        ("Owner", "owner", "owner"),
    ],
)
def test_gti_agentic_flow_execution_object_list_command_success(
    mock_client, requests_mock, relationship, api_relationship, test_data_name
):
    """Test that the command stores the related object as received and reports the columns of its type."""
    from GoogleThreatIntelligenceAgentic import RELATED_OBJECT_SECRET_FIELDS, gti_agentic_flow_execution_object_list_command

    raw_response = util_load_json(f"test_data/flow_execution_object_list_{test_data_name}.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, api_relationship)}",
        json=raw_response,
        status_code=200,
    )

    result = gti_agentic_flow_execution_object_list_command(
        client=mock_client, args={"execution_id": execution_id, "relationship": relationship}
    )

    outputs = util_command_outputs(result)
    # The secrets of the group are the only attributes that are removed.
    expected_response = copy.deepcopy(raw_response)
    for field in RELATED_OBJECT_SECRET_FIELDS.get(raw_response["data"]["type"], []):
        expected_response["data"]["attributes"].pop(field, None)

    assert outputs == util_load_json(f"test_data/flow_execution_object_list_{test_data_name}_context.json")
    # The attributes are stored as they are received, hence the epoch timestamps are not converted.
    assert outputs[FLOW_EXECUTION_RELATIONSHIP_OUTPUT_KEY]["data"] == [expected_response["data"]]
    assert util_readable_output(result) == util_load_text(f"test_data/flow_execution_object_list_{test_data_name}_hr.md")
    assert result.raw_response == expected_response


def test_gti_agentic_flow_execution_object_list_command_flow_and_snapshot_keys(mock_client, requests_mock):
    """Test that the Flow and its snapshot, which both report a 'flow' object, are stored under different keys."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_list_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    entries = []

    for relationship, api_relationship in [("Flow", "flow"), ("Flow Snapshot", "flow_snapshot")]:
        requests_mock.get(
            f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, api_relationship)}",
            json=util_load_json(f"test_data/flow_execution_object_list_{api_relationship}.json"),
            status_code=200,
        )
        result = gti_agentic_flow_execution_object_list_command(
            client=mock_client, args={"execution_id": execution_id, "relationship": relationship}
        )
        entries.append(util_command_outputs(result)[FLOW_EXECUTION_RELATIONSHIP_OUTPUT_KEY])

    assert [entry["type"] for entry in entries] == ["flow", "flow"]
    assert [entry["relationship"] for entry in entries] == ["flow", "flow_snapshot"]
    assert list(util_command_outputs(result)) == [FLOW_EXECUTION_RELATIONSHIP_OUTPUT_KEY]


def test_gti_agentic_flow_execution_object_list_command_removes_owner_api_key(mock_client, requests_mock):
    """Test that the API key of the owner reaches neither the context nor the raw response."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_list_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    response = util_load_json("test_data/flow_execution_object_list_owner.json")
    response["data"]["attributes"]["apikey"] = TEST_API_KEY
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, 'owner')}", json=response, status_code=200
    )

    result = gti_agentic_flow_execution_object_list_command(
        client=mock_client, args={"execution_id": execution_id, "relationship": "Owner"}
    )

    assert util_command_outputs(result) == util_load_json("test_data/flow_execution_object_list_owner_context.json")
    assert TEST_API_KEY not in json.dumps(util_command_outputs(result))
    assert TEST_API_KEY not in json.dumps(result.raw_response)
    assert TEST_API_KEY not in util_readable_output(result)


def test_gti_agentic_flow_execution_object_list_command_removes_group_tokens(mock_client, requests_mock):
    """Test that the tokens of the group reach neither the context nor the raw response."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_list_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    response = util_load_json("test_data/flow_execution_object_list_group.json")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, 'group')}", json=response, status_code=200
    )

    result = gti_agentic_flow_execution_object_list_command(
        client=mock_client, args={"execution_id": execution_id, "relationship": "Group"}
    )

    attributes = util_command_outputs(result)[FLOW_EXECUTION_RELATIONSHIP_OUTPUT_KEY]["data"][0]["attributes"]
    for field in ("group_token", "scim_token"):
        assert field in response["data"]["attributes"]
        assert field not in attributes
        assert field not in result.raw_response["data"]["attributes"]  # type: ignore[index]
    assert "dummy-group-token" not in util_readable_output(result)


def test_build_flow_execution_related_object_hr_unknown_type():
    """Test that an object of a type without dedicated columns is reported with its identity only."""
    from GoogleThreatIntelligenceAgentic import FLOW_EXECUTION_RELATED_OBJECT_HR_HEADERS, build_flow_execution_related_object_hr

    rows, headers = build_flow_execution_related_object_hr([{"id": "abc", "type": "collection", "attributes": {"name": "x"}}])

    assert rows == [{"Object ID": "abc", "Type": "collection"}]
    assert headers == FLOW_EXECUTION_RELATED_OBJECT_HR_HEADERS


def test_gti_agentic_flow_execution_object_list_command_no_records(mock_client, requests_mock):
    """Test that an empty related object reports the no records message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_list_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, 'flow_snapshot')}",
        json=util_load_json("test_data/flow_execution_object_list_empty.json"),
        status_code=200,
    )

    result = gti_agentic_flow_execution_object_list_command(
        client=mock_client, args={"execution_id": execution_id, "relationship": "Flow Snapshot"}
    )

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("related objects")
    assert not util_command_outputs(result)


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"relationship": "Flow"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("execution_id")),
        ({"execution_id": "", "relationship": "Flow"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("execution_id")),
        ({"execution_id": "9a1b2c3d"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("relationship")),
        (
            {"execution_id": "9a1b2c3d", "relationship": "Steps"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Steps", "relationship", FLOW_EXECUTION_RELATIONSHIP_HR_LIST),
        ),
    ],
)
def test_gti_agentic_flow_execution_object_list_command_invalid_arguments(mock_client, args, expected_error):
    """Test that the absent, the empty and the unsupported arguments raise a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_execution_object_list_command(client=mock_client, args=args)

    assert str(e.value) == expected_error


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_flow_execution_object_list_command_api_error(
    mock_client, requests_mock, status_code, response, error_message_key
):
    """Test that an unknown or inaccessible Flow Execution reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_list_command

    execution_id = "00000000-0000-0000-0000-000000000000"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, 'flow')}",
        json=response,
        status_code=status_code,
    )

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execution_object_list_command(
            client=mock_client, args={"execution_id": execution_id, "relationship": "Flow"}
        )

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_flow_execution_object_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-execution-object-list command."""
    import GoogleThreatIntelligenceAgentic

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"execution_id": f" {execution_id} ", "relationship": " Owner "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-execution-object-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship'].format(execution_id, 'owner')}",
        json=util_load_json("test_data/flow_execution_object_list_owner.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}/owner"
    assert util_command_outputs(return_results_mock.call_args.args[0]) == util_load_json(
        "test_data/flow_execution_object_list_owner_context.json"
    )


def test_list_flow_execution_related_descriptors_success(mock_client, requests_mock):
    """Test that list_flow_execution_related_descriptors requests the relationships endpoint of the Flow Execution."""
    expected_response = util_load_json("test_data/flow_execution_object_descriptor_list_flow.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship_descriptor'].format(execution_id, 'flow')}",
        json=expected_response,
        status_code=200,
    )

    response = mock_client.list_flow_execution_related_descriptors(execution_id, "flow")

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}/relationships/flow"
    assert util_request_params(requests_mock.last_request) == {}


@pytest.mark.parametrize(
    "relationship, api_relationship, test_data_name",
    [
        ("Flow", "flow", "flow"),
        ("Flow Snapshot", "flow_snapshot", "flow_snapshot"),
        ("owner", "owner", "owner"),
        ("Group", "group", "group"),
    ],
)
def test_gti_agentic_flow_execution_object_descriptor_list_command_success(
    mock_client, requests_mock, relationship, api_relationship, test_data_name
):
    """Test that the command reports the descriptors of every relationship as received."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_descriptor_list_command

    raw_response = util_load_json(f"test_data/flow_execution_object_descriptor_list_{test_data_name}.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship_descriptor'].format(execution_id, api_relationship)}",
        json=raw_response,
        status_code=200,
    )

    result = gti_agentic_flow_execution_object_descriptor_list_command(
        client=mock_client, args={"execution_id": execution_id, "relationship": relationship}
    )

    assert util_command_outputs(result) == util_load_json(
        f"test_data/flow_execution_object_descriptor_list_{test_data_name}_context.json"
    )
    assert util_readable_output(result) == util_load_text(
        f"test_data/flow_execution_object_descriptor_list_{test_data_name}_hr.md"
    )
    assert result.raw_response == raw_response
    assert util_request_params(requests_mock.last_request) == {}


def test_gti_agentic_flow_execution_object_descriptor_list_command_no_records(mock_client, requests_mock):
    """Test that an empty descriptor reports the no records message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_descriptor_list_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    empty_response = util_load_json("test_data/flow_execution_object_descriptor_list_empty.json")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship_descriptor'].format(execution_id, 'flow_snapshot')}",
        json=empty_response,
        status_code=200,
    )

    result = gti_agentic_flow_execution_object_descriptor_list_command(
        client=mock_client, args={"execution_id": execution_id, "relationship": "Flow Snapshot"}
    )

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("related object descriptors")
    assert result.outputs is None
    assert result.raw_response == empty_response


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"relationship": "Flow"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("execution_id")),
        ({"execution_id": "9a1b2c3d", "relationship": ""}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("relationship")),
        (
            {"execution_id": "9a1b2c3d", "relationship": "Steps"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Steps", "relationship", FLOW_EXECUTION_RELATIONSHIP_HR_LIST),
        ),
    ],
)
def test_gti_agentic_flow_execution_object_descriptor_list_command_invalid_arguments(mock_client, args, expected_error):
    """Test that the invalid arguments raise a descriptive error before any request is made."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_descriptor_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_execution_object_descriptor_list_command(client=mock_client, args=args)

    assert str(e.value) == expected_error


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_flow_execution_object_descriptor_list_command_api_error(
    mock_client, requests_mock, status_code, response, error_message_key
):
    """Test that an unknown or inaccessible Flow Execution reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_object_descriptor_list_command

    execution_id = "00000000-0000-0000-0000-000000000000"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship_descriptor'].format(execution_id, 'flow')}",
        json=response,
        status_code=status_code,
    )

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execution_object_descriptor_list_command(
            client=mock_client, args={"execution_id": execution_id, "relationship": "Flow"}
        )

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_flow_execution_object_descriptor_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-execution-object-descriptor-list command."""
    import GoogleThreatIntelligenceAgentic

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"execution_id": f" {execution_id} ", "relationship": " Group "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-execution-object-descriptor-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['flow_execution_relationship_descriptor'].format(execution_id, 'group')}",
        json=util_load_json("test_data/flow_execution_object_descriptor_list_group.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}/relationships/group"
    assert util_command_outputs(return_results_mock.call_args.args[0]) == util_load_json(
        "test_data/flow_execution_object_descriptor_list_group_context.json"
    )


def test_cancel_flow_execution_success(mock_client, requests_mock):
    """Test that cancel_flow_execution issues a POST request without a body on the cancel endpoint of the Flow Execution."""
    expected_response = util_load_json("test_data/flow_execution_cancel.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}", json=expected_response, status_code=200
    )

    response = mock_client.cancel_flow_execution(execution_id)

    assert response == expected_response
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}/cancel"
    assert not requests_mock.last_request.body


def test_gti_agentic_flow_execution_cancel_command_success(mock_client, requests_mock):
    """Test that the command reports the cancelled Flow Execution with the success title and ISO 8601 dates."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    raw_response = util_load_json("test_data/flow_execution_cancel.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_cancel_command(client=mock_client, args={"execution_id": execution_id})

    outputs = util_command_outputs(result)

    assert outputs[FLOW_EXECUTION_OUTPUT_KEY] == util_load_json("test_data/flow_execution_cancel_context.json")
    assert outputs[FLOW_EXECUTION_OUTPUT_KEY]["last_modification_date"] == "2026-09-28T09:00:34Z"
    assert util_readable_output(result) == util_load_text("test_data/flow_execution_cancel_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_flow_execution_cancel_command_not_yet_cancelled(mock_client, requests_mock):
    """Test that a Flow Execution that the API does not report as cancelled is reported with a neutral title."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    raw_response = util_load_json("test_data/flow_execution_cancel.json")
    raw_response["data"]["attributes"]["status"] = "EXECUTION_STATUS_RUNNING"
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}", json=raw_response, status_code=200)

    readable_output = util_readable_output(
        gti_agentic_flow_execution_cancel_command(client=mock_client, args={"execution_id": execution_id})
    )

    assert readable_output.startswith(f"### {FLOW_EXECUTION_HR_TITLE}\n")
    assert MESSAGES["FLOW_EXECUTION_CANCELLED"] not in readable_output
    assert "EXECUTION_STATUS_RUNNING" in readable_output


def test_gti_agentic_flow_execution_cancel_command_without_steps(mock_client, requests_mock):
    """Test that a Flow Execution that was cancelled before any step ran is reported without the step table."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}",
        json={"data": {"type": "flow_execution", "id": execution_id, "attributes": {"status": "EXECUTION_STATUS_CANCELLED"}}},
        status_code=200,
    )

    readable_output = util_readable_output(
        gti_agentic_flow_execution_cancel_command(client=mock_client, args={"execution_id": execution_id})
    )

    assert readable_output.startswith(f"### {MESSAGES['FLOW_EXECUTION_CANCELLED']}\n")
    assert "### Flow Execution Steps" not in readable_output


def test_gti_agentic_flow_execution_cancel_command_empty_response(mock_client, requests_mock):
    """Test that an empty Flow Execution object reports the cancellation request without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    raw_response = util_load_json("test_data/flow_execution_cancel_empty.json")
    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}", json=raw_response, status_code=200)

    result = gti_agentic_flow_execution_cancel_command(client=mock_client, args={"execution_id": execution_id})

    assert util_readable_output(result) == MESSAGES["FLOW_EXECUTION_CANCEL_REQUESTED"].format(execution_id)
    assert not util_command_outputs(result)
    assert result.raw_response == raw_response


@pytest.mark.parametrize("args", [{}, {"execution_id": ""}])
def test_gti_agentic_flow_execution_cancel_command_missing_execution_id(mock_client, args):
    """Test that an absent or an empty 'execution_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    with pytest.raises(ValueError) as e:
        gti_agentic_flow_execution_cancel_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("execution_id")


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
        (400, {"error": {"code": "BadRequestError", "message": "Invalid Flow Execution ID."}}, "BAD_REQUEST"),
    ],
)
def test_gti_agentic_flow_execution_cancel_command_api_error(
    mock_client, requests_mock, status_code, response, error_message_key
):
    """Test that an unknown, inaccessible or already finished Flow Execution reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    execution_id = "00000000-0000-0000-0000-000000000000"
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}", json=response, status_code=status_code
    )

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execution_cancel_command(client=mock_client, args={"execution_id": execution_id})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_gti_agentic_flow_execution_cancel_command_not_in_progress(mock_client, requests_mock):
    """Test that a conflict, which the API reports for a Flow Execution that is not in progress, reports that the Flow
    Execution cannot be cancelled, along with the reason of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_flow_execution_cancel_command

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    response = util_load_json("test_data/error_execution_not_in_progress.json")
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}",
        json=response,
        status_code=409,
    )

    with pytest.raises(DemistoException) as e:
        gti_agentic_flow_execution_cancel_command(client=mock_client, args={"execution_id": execution_id})

    assert str(e.value) == (
        f"{ERROR_MESSAGES['EXECUTION_NOT_IN_PROGRESS'].format(409, execution_id)} Reason: {response['error']['message']}"
    )


def test_main_gti_agentic_flow_execution_cancel(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-flow-execution-cancel command."""
    import GoogleThreatIntelligenceAgentic

    execution_id = FLOW_EXECUTION_RELATIONSHIP_EXECUTION_ID
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"execution_id": f" {execution_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-flow-execution-cancel")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['flow_execution_cancel'].format(execution_id)}",
        json=util_load_json("test_data/flow_execution_cancel.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.path == f"/api/v3/flow_executions/{execution_id}/cancel"
    assert FLOW_EXECUTION_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_list_sessions_success(mock_client, requests_mock):
    """Test that list_sessions requests the agentic session collection with the query parameters."""
    expected_response = util_load_json("test_data/session_list.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=expected_response, status_code=200)

    response = mock_client.list_sessions({"limit": 2, "cursor": "eyJvZmZzZXQiOjB9"})

    assert response == expected_response
    assert requests_mock.last_request.path == "/api/v3/agentspace/sessions"
    assert util_request_params(requests_mock.last_request) == {"limit": "2", "cursor": "eyJvZmZzZXQiOjB9"}


def test_gti_agentic_session_list_command_success(mock_client, requests_mock):
    """Test that the command sends the limit and the cursor, and reports the sessions and the page token."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    raw_response = util_load_json("test_data/session_list.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=raw_response, status_code=200)

    result = gti_agentic_session_list_command(client=mock_client, args={"limit": "2", "cursor": "eyJvZmZzZXQiOjB9"})

    assert util_request_params(requests_mock.last_request) == {"limit": "2", "cursor": "eyJvZmZzZXQiOjB9"}
    assert util_command_outputs(result) == util_load_json("test_data/session_list_context.json")
    assert util_command_outputs(result)[SESSION_PAGE_TOKEN_OUTPUT_KEY] == {"next_cursor": "eyJvZmZzZXQiOjJ9"}
    assert util_readable_output(result) == util_load_text("test_data/session_list_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_session_list_command_maximum_limit(mock_client, requests_mock):
    """Test that the maximum limit of the agentic sessions, which is higher than that of the other objects, is accepted."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_list.json"), status_code=200)

    gti_agentic_session_list_command(client=mock_client, args={"limit": "50"})

    assert util_request_params(requests_mock.last_request) == {"limit": "50"}


def test_gti_agentic_session_list_command_default_arguments(mock_client, requests_mock):
    """Test that the command requests 5 sessions and sends no cursor by default."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_list.json"), status_code=200)

    gti_agentic_session_list_command(client=mock_client, args={})

    assert util_request_params(requests_mock.last_request) == {"limit": "5"}


def test_gti_agentic_session_list_command_last_page(mock_client, requests_mock):
    """Test that the last page reports the creation date and an empty page token."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    raw_response = {
        "data": [
            {
                "id": "44444444-4444-4444-4444-444444444444",
                "type": "agentic_session",
                "attributes": {
                    "title": "Malware analysis",
                    "creation_date": "2026-09-16T06:00:00Z",
                    "last_modification_date": "2026-09-16T06:01:30Z",
                },
            }
        ],
        "meta": {},
    }
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=raw_response, status_code=200)

    result = gti_agentic_session_list_command(client=mock_client, args={})

    assert util_command_outputs(result)[SESSION_PAGE_TOKEN_OUTPUT_KEY] == {}
    assert util_readable_output(result) == (
        "### GTI Agentic Session List\n"
        "|Session ID|Title|Creation Date|Last Modification Date|\n"
        "|---|---|---|---|\n"
        "| [44444444-4444-4444-4444-444444444444]"
        "(https://www.virustotal.com/gui/agentic/sessions/44444444-4444-4444-4444-444444444444) "
        "| Malware analysis | 2026-09-16T06:00:00Z | 2026-09-16T06:01:30Z |\n"
    )


def test_build_session_hr_without_id():
    """Test that a session without an ID reports an empty Session ID cell rather than a broken link."""
    from GoogleThreatIntelligenceAgentic import build_session_hr

    assert build_session_hr({"title": "Malware analysis"}) == {
        "Session ID": "",
        "Title": "Malware analysis",
        "Creation Date": "",
        "Last Modification Date": "",
    }


def test_gti_agentic_session_list_command_no_records(mock_client, requests_mock):
    """Test that an empty page reports the no records message and clears the cursor of an earlier run."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    raw_response = util_load_json("test_data/session_list_empty.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=raw_response, status_code=200)

    result = gti_agentic_session_list_command(client=mock_client, args={})

    assert util_readable_output(result) == MESSAGES["NO_RECORDS_FOUND"].format("GTI Agentic Sessions")
    assert util_command_outputs(result) == {SESSION_PAGE_TOKEN_OUTPUT_KEY: {}}
    assert result.raw_response == raw_response


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"limit": "0"}, ERROR_MESSAGES["INVALID_LIMIT"].format(0, MAX_SESSION_LIMIT)),
        ({"limit": "-1"}, ERROR_MESSAGES["INVALID_LIMIT"].format(-1, MAX_SESSION_LIMIT)),
        ({"limit": "51"}, ERROR_MESSAGES["INVALID_LIMIT"].format(51, MAX_SESSION_LIMIT)),
        ({"limit": "abc"}, 'Invalid number: "limit"="abc"'),
    ],
)
def test_gti_agentic_session_list_command_invalid_limit(mock_client, args, expected_error):
    """Test that an invalid limit raises a descriptive error before any request is made."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_list_command(client=mock_client, args=args)

    assert str(e.value) == expected_error


def test_gti_agentic_session_list_command_invalid_cursor(mock_client, requests_mock):
    """Test that an invalid cursor reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_list_command

    response = {"error": {"code": "BadRequestError", "message": "Invalid cursor."}}
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=response, status_code=400)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_list_command(client=mock_client, args={"cursor": "invalid"})

    assert str(e.value) == ERROR_MESSAGES["BAD_REQUEST"].format(400, "Invalid cursor.")


def test_main_gti_agentic_session_list(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-list command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"limit": " 2 "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-list")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_list.json"), status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert util_request_params(requests_mock.last_request) == {"limit": "2"}
    assert SESSION_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_create_session_success(mock_client, requests_mock, tmp_path):
    """Test that create_session posts the message and the attachments as a multipart form, without retries."""
    expected_response = util_load_json("test_data/session_create.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=expected_response, status_code=200)
    attachment = tmp_path / "report.txt"
    attachment.write_bytes(b"suspicious content")

    response = mock_client.create_session("What is GTI?", [("report.txt", str(attachment))])

    request = requests_mock.last_request
    body = request.body.decode()
    assert response == expected_response
    assert request.path == "/api/v3/agentspace/sessions"
    # The multipart boundary is set by the requests library, rather than the JSON content type of the client.
    assert request.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert 'name="message"\r\n\r\nWhat is GTI?' in body
    assert 'name="files"; filename="report.txt"' in body
    assert "suspicious content" in body
    # The JSON content type of the other requests is kept.
    assert mock_client._headers["Content-Type"] == "application/json"


def test_create_session_without_attachments(mock_client, requests_mock):
    """Test that the message is sent as a multipart form, even when no file is attached."""
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_create.json"))

    mock_client.create_session("What is GTI?")

    request = requests_mock.last_request
    assert request.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert 'name="files"' not in request.body.decode()


def test_create_session_with_extended_timeout(mock_client, mocker):
    """Test that a session is created with the extended timeout, as the agent answers synchronously."""
    http_request_mock = mocker.patch.object(BaseClient, "_http_request", return_value=mocker.Mock())

    mock_client.create_session("What is GTI?", response_type="response")

    kwargs = http_request_mock.call_args.kwargs
    assert kwargs["timeout"] == SESSION_MESSAGE_TIMEOUT


@pytest.mark.parametrize("status_code", [200, 201])
def test_gti_agentic_session_create_command_success(mock_client, requests_mock, status_code):
    """Test that the command reports the created session, its conversation and the answer of the agent."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    raw_response = util_load_json("test_data/session_create.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=raw_response, status_code=status_code)

    result = gti_agentic_session_create_command(client=mock_client, args={"message": "What is GTI?"})

    assert util_command_outputs(result) == util_load_json("test_data/session_create_context.json")
    assert util_readable_output(result) == util_load_text("test_data/session_create_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_session_create_command_with_attachments(mock_client, requests_mock, mocker, tmp_path):
    """Test that the files of the War Room entries are attached to the message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    files = {}
    for entry_id, name in [("1@2", "first.txt"), ("3@4", "second.txt")]:
        path = tmp_path / name
        path.write_bytes(name.encode())
        files[entry_id] = {"id": entry_id, "path": str(path), "name": name}
    mocker.patch.object(demisto, "getFilePath", side_effect=lambda entry_id: files[entry_id])
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_create.json"))

    gti_agentic_session_create_command(client=mock_client, args={"message": "Analyze these files.", "entry_id": "1@2, 3@4"})

    body = requests_mock.last_request.body.decode()
    assert 'name="files"; filename="first.txt"' in body
    assert 'name="files"; filename="second.txt"' in body


@pytest.mark.parametrize(
    "get_file_path_mock",
    [
        {"side_effect": ValueError("Entry not found.")},
        {"return_value": {}},
        {"return_value": None},
    ],
    ids=["missing entry", "entry without a file", "no entry details"],
)
def test_gti_agentic_session_create_command_invalid_entry_id(mock_client, requests_mock, mocker, get_file_path_mock):
    """Test that an entry without a file raises a descriptive error before any session is created."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    mocker.patch.object(demisto, "getFilePath", **get_file_path_mock)
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_create.json"))

    with pytest.raises(ValueError) as e:
        gti_agentic_session_create_command(client=mock_client, args={"message": "Analyze this file.", "entry_id": "9@9"})

    assert str(e.value) == ERROR_MESSAGES["INVALID_ENTRY_ID"].format("9@9")
    assert not requests_mock.called


@pytest.mark.parametrize("extra_bytes, is_valid", [(0, True), (1, False)], ids=["at the limit", "over the limit"])
def test_gti_agentic_session_create_command_file_size(mock_client, requests_mock, mocker, tmp_path, extra_bytes, is_valid):
    """Test that a file larger than the maximum allowed size raises a descriptive error before any session is created."""
    from GoogleThreatIntelligenceAgentic import MAX_SESSION_FILE_SIZE_MB, gti_agentic_session_create_command

    path = tmp_path / "large.bin"
    with path.open("wb") as file:
        file.truncate(MAX_SESSION_FILE_SIZE_MB * 1024 * 1024 + extra_bytes)
    mocker.patch.object(demisto, "getFilePath", return_value={"id": "5@6", "path": str(path), "name": "large.bin"})
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_create.json"))
    args = {"message": "Analyze this file.", "entry_id": "5@6"}

    if is_valid:
        gti_agentic_session_create_command(client=mock_client, args=args)
        assert requests_mock.called
        return

    with pytest.raises(ValueError) as e:
        gti_agentic_session_create_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["INVALID_ENTRY_FILE_SIZE"].format("5@6", MAX_SESSION_FILE_SIZE_MB)
    assert not requests_mock.called


@pytest.mark.parametrize("args", [{}, {"message": ""}, {"entry_id": "1@2"}])
def test_gti_agentic_session_create_command_missing_message(mock_client, args):
    """Test that a missing message raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_create_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("message")


def test_gti_agentic_session_create_command_without_session(mock_client, requests_mock):
    """Test that a response without the session reports the creation without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json={}, status_code=200)

    result = gti_agentic_session_create_command(client=mock_client, args={"message": "What is GTI?"})

    assert util_readable_output(result) == MESSAGES["SESSION_CREATED"]
    assert not util_command_outputs(result)


def test_gti_agentic_session_create_command_without_events(mock_client, requests_mock):
    """Test that a session without events reports the session table only."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    raw_response = util_load_json("test_data/session_create.json")
    del raw_response["data"]["attributes"]["events"]
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=raw_response, status_code=200)

    result = gti_agentic_session_create_command(client=mock_client, args={"message": "What is GTI?"})

    # The session table reports no events, and the conversation table and the agent response sections are not added.
    assert util_readable_output(result) == (
        "### Session created successfully.\n"
        "|Session ID|Title|Events|Creation Date|Last Modification Date|\n"
        "|---|---|---|---|---|\n"
        "| [44444444-4444-4444-4444-000000000003]"
        "(https://www.virustotal.com/gui/agentic/sessions/44444444-4444-4444-4444-000000000003)"
        " | Overview of Google Threat Intelligence | 0 | 2026-10-05T09:00:00.123456Z | 2026-10-05T09:00:42.654321Z |\n"
    )


def test_gti_agentic_session_create_command_api_error(mock_client, requests_mock):
    """Test that an error of the API is reported with its message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_create_command

    response = {"error": {"code": "BadRequestError", "message": "The attached file type is not supported."}}
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=response, status_code=400)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_create_command(client=mock_client, args={"message": "What is GTI?"})

    assert str(e.value) == ERROR_MESSAGES["BAD_REQUEST"].format(400, "The attached file type is not supported.")


@pytest.mark.parametrize(
    "event, expected_row",
    [
        (
            {
                "id": "e1",
                "message_type": "USER_MESSAGE",
                "user_message": {
                    "widgets": [
                        {"widget_type": "MARKDOWN_TEXT", "markdown_text_widget": {"text": "First part."}},
                        {"widget_type": "IMAGE"},
                        {"widget_type": "MARKDOWN_TEXT", "markdown_text_widget": {"text": "Second part."}},
                    ]
                },
            },
            {"Event ID": "e1", "Message Type": "USER_MESSAGE", "Agent ID": "", "Message": "First part.\n\nSecond part."},
        ),
        (
            {"id": "e2", "message_type": "AGENT_FINAL_RESPONSE", "agent_final_response": {"agent_id": "a1", "widgets": []}},
            {"Event ID": "e2", "Message Type": "AGENT_FINAL_RESPONSE", "Agent ID": "a1", "Message": ""},
        ),
        (
            {"id": "e3", "message_type": "AGENT_THOUGHT"},
            {"Event ID": "e3", "Message Type": "AGENT_THOUGHT", "Agent ID": "", "Message": ""},
        ),
        ({"id": "e4"}, {"Event ID": "e4", "Message Type": "", "Agent ID": "", "Message": ""}),
    ],
    ids=["joined widgets", "agent response without text", "event without payload", "event without type"],
)
def test_build_session_event_hr(event, expected_row):
    """Test that every event is reported with the text of its widgets, and that an empty agent response is not pointed to."""
    from GoogleThreatIntelligenceAgentic import build_session_agent_response_hr, build_session_event_hr

    assert build_session_event_hr([event]) == [expected_row]
    assert build_session_agent_response_hr([event]) == ""


def test_main_gti_agentic_session_create(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-create command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"message": "What is GTI?"})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-create")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['sessions']}", json=util_load_json("test_data/session_create.json"))

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "POST"
    assert SESSION_OUTPUT_KEY in util_command_outputs(return_results_mock.call_args.args[0])


def test_get_session_success(mock_client, requests_mock):
    """Test that get_session requests the agentic session endpoint and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/session_get.json")
    session_id = expected_response["data"]["id"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=expected_response, status_code=200)

    response = mock_client.get_session(session_id)

    assert response == expected_response
    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}"


def test_gti_agentic_session_get_command_success(mock_client, requests_mock):
    """Test that the command reports the session, its complete conversation and every answer of the agent."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    raw_response = util_load_json("test_data/session_get.json")
    session_id = raw_response["data"]["id"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_get_command(client=mock_client, args={"session_id": session_id})

    assert util_command_outputs(result) == util_load_json("test_data/session_get_context.json")
    assert util_readable_output(result) == util_load_text("test_data/session_get_hr.md")
    assert result.raw_response == raw_response


def test_gti_agentic_session_get_command_no_records(mock_client, requests_mock):
    """Test that an empty agentic session object reports the no record message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    session_id = "44444444-4444-4444-4444-000000000004"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json={"data": {}}, status_code=200)

    result = gti_agentic_session_get_command(client=mock_client, args={"session_id": session_id})

    assert util_readable_output(result) == MESSAGES["NO_RECORD_FOUND"].format("GTI Agentic Session")
    assert not util_command_outputs(result)
    assert result.raw_response == {"data": {}}


def test_gti_agentic_session_get_command_without_events(mock_client, requests_mock):
    """Test that a session without events reports the session table only."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    raw_response = util_load_json("test_data/session_get.json")
    del raw_response["data"]["attributes"]["events"]
    session_id = raw_response["data"]["id"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_get_command(client=mock_client, args={"session_id": session_id})

    # The session table reports no events, and the conversation table and the agent response sections are not added.
    assert util_readable_output(result) == (
        "### GTI Agentic Session Information\n"
        "|Session ID|Title|Events|Creation Date|Last Modification Date|\n"
        "|---|---|---|---|---|\n"
        f"| [{session_id}](https://www.virustotal.com/gui/agentic/sessions/{session_id})"
        " | Malware analysis of a suspicious file | 0 | 2026-10-05T09:00:00.123456Z | 2026-10-05T09:05:48.654321Z |\n"
    )
    assert "events" not in util_command_outputs(result)[SESSION_OUTPUT_KEY]


def test_gti_agentic_session_get_command_unknown_message_type(mock_client, requests_mock):
    """Test that an event of an unknown message type is reported in the conversation table with an empty message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    raw_response = util_load_json("test_data/session_get.json")
    event = {"id": "55555555-5555-5555-5555-000000000007", "message_type": "TOOL_CALL", "tool_call": {"name": "lookup"}}
    raw_response["data"]["attributes"]["events"].insert(1, event)
    session_id = raw_response["data"]["id"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_get_command(client=mock_client, args={"session_id": session_id})

    readable_output = util_readable_output(result)
    assert "| 55555555-5555-5555-5555-000000000007 | TOOL_CALL |  |  |" in readable_output
    # Only the two agent final responses of the fixture are rendered in their own sections.
    assert readable_output.count("### Agent Response of Event") == 2
    assert util_command_outputs(result)[SESSION_OUTPUT_KEY]["events"][1] == event


@pytest.mark.parametrize("timestamp_seconds", ["not-a-timestamp", None], ids=["non-numeric timestamp", "missing timestamp"])
def test_gti_agentic_session_get_command_user_message_timestamp(mock_client, requests_mock, timestamp_seconds):
    """Test that the timestamp of a user message is kept as received, whether it is non-numeric or missing."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    raw_response = util_load_json("test_data/session_get.json")
    user_message = raw_response["data"]["attributes"]["events"][0]["user_message"]
    if timestamp_seconds is None:
        del user_message["timestamp_seconds"]
    else:
        user_message["timestamp_seconds"] = timestamp_seconds
    session_id = raw_response["data"]["id"]
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_get_command(client=mock_client, args={"session_id": session_id})

    assert util_command_outputs(result)[SESSION_OUTPUT_KEY]["events"][0]["user_message"] == user_message
    assert util_readable_output(result) == util_load_text("test_data/session_get_hr.md")


@pytest.mark.parametrize(
    "event, expected_message",
    [
        (
            {"message_type": "FUNCTION_CALL", "function_call": {"name": "search_iocs", "function_call_id": "call_1"}},
            "Function: search_iocs\nCall ID: call_1",
        ),
        (
            {"message_type": "FUNCTION_CALL", "function_call": {"name": "search_iocs", "args_json": '{"limit": 10}'}},
            'Function: search_iocs\nArguments: {"limit": 10}',
        ),
        ({"message_type": "FUNCTION_RESPONSE", "function_response": {"function_call_id": "call_1"}}, "Call ID: call_1"),
        (
            {
                "message_type": "FUNCTION_RESPONSE",
                "function_response": {
                    "function_call_id": "call_1",
                    "displayable_ui_messages": [
                        {
                            "message_type": "AGENT_FINAL_RESPONSE",
                            "agent_final_response": {"widgets": [{"markdown_text_widget": {"text": "Found 2 campaigns."}}]},
                        },
                        {"message_type": "AGENT_FINAL_RESPONSE", "agent_final_response": {"widgets": []}},
                    ],
                },
            },
            "Call ID: call_1\nResponse: Found 2 campaigns.",
        ),
        (
            {"message_type": "AGENT_FINAL_RESPONSE", "agent_final_response": {"widgets": []}},
            "",
        ),
    ],
)
def test_get_session_event_message(event, expected_message):
    """Test that the function events and the agent response report only the fields that are present."""
    from GoogleThreatIntelligenceAgentic import get_session_event_message

    assert get_session_event_message(event) == expected_message


@pytest.mark.parametrize("args", [{}, {"session_id": ""}])
def test_gti_agentic_session_get_command_missing_session_id(mock_client, args):
    """Test that a missing session ID raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_get_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("session_id")


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Session not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_session_get_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that an unknown or inaccessible agentic session reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_get_command

    session_id = "44444444-4444-4444-4444-000000000000"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_get_command(client=mock_client, args={"session_id": session_id})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_session_get(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-get command."""
    import GoogleThreatIntelligenceAgentic

    session_id = "44444444-4444-4444-4444-000000000004"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"session_id": f" {session_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-get")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}",
        json=util_load_json("test_data/session_get.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}"
    assert util_command_outputs(return_results_mock.call_args.args[0]) == util_load_json("test_data/session_get_context.json")


def test_post_session_message_success(mock_client, requests_mock, tmp_path):
    """Test that post_session_message posts the message and the attachments to the session as a multipart form."""
    expected_response = util_load_json("test_data/session_message_post.json")
    session_id = expected_response["data"]["id"]
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=expected_response, status_code=200)
    attachment = tmp_path / "headers.eml"
    attachment.write_bytes(b"suspicious headers")

    response = mock_client.post_session_message(
        session_id, "Which threat actors are linked to it?", [("headers.eml", str(attachment))]
    )

    request = requests_mock.last_request
    body = request.body.decode()
    assert response == expected_response
    assert request.path == f"/api/v3/agentspace/sessions/{session_id}"
    # The multipart boundary is set by the requests library, rather than the JSON content type of the client.
    assert request.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert 'name="message"\r\n\r\nWhich threat actors are linked to it?' in body
    assert 'name="files"; filename="headers.eml"' in body
    assert "suspicious headers" in body


def test_post_session_message_with_extended_timeout(mock_client, mocker):
    """Test that a message is posted with the extended timeout, as the agent answers synchronously."""
    http_request_mock = mocker.patch.object(BaseClient, "_http_request", return_value=mocker.Mock())

    mock_client.post_session_message("44444444-4444-4444-4444-000000000005", "What is GTI?", response_type="response")

    kwargs = http_request_mock.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["timeout"] == SESSION_MESSAGE_TIMEOUT


def test_gti_agentic_session_message_post_command_success(mock_client, requests_mock):
    """Test that the command reports the updated session, its conversation and the latest answer of the agent."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_message_post_command

    raw_response = util_load_json("test_data/session_message_post.json")
    session_id = raw_response["data"]["id"]
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=raw_response, status_code=200)
    args = {"session_id": session_id, "message": "Which threat actors are linked to it?"}

    result = gti_agentic_session_message_post_command(client=mock_client, args=args)

    assert util_command_outputs(result) == util_load_json("test_data/session_message_post_context.json")
    assert util_readable_output(result) == util_load_text("test_data/session_message_post_hr.md")
    assert result.raw_response == raw_response
    assert 'name="files"' not in requests_mock.last_request.body.decode()


def test_gti_agentic_session_message_post_command_with_attachments(mock_client, requests_mock, mocker, tmp_path):
    """Test that the files of the War Room entries are attached to the message."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_message_post_command

    files = {}
    for entry_id, name in [("1@2", "first.txt"), ("3@4", "second.txt")]:
        path = tmp_path / name
        path.write_bytes(name.encode())
        files[entry_id] = {"id": entry_id, "path": str(path), "name": name}
    mocker.patch.object(demisto, "getFilePath", side_effect=lambda entry_id: files[entry_id])
    session_id = "44444444-4444-4444-4444-000000000005"
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=util_load_json("test_data/session_message_post.json")
    )
    args = {"session_id": session_id, "message": "Analyze these files.", "entry_id": "1@2, 3@4"}

    gti_agentic_session_message_post_command(client=mock_client, args=args)

    body = requests_mock.last_request.body.decode()
    assert 'name="files"; filename="first.txt"' in body
    assert 'name="files"; filename="second.txt"' in body


@pytest.mark.parametrize(
    "get_file_path_mock",
    [
        {"side_effect": ValueError("Entry not found.")},
        {"return_value": {}},
        {"return_value": None},
    ],
    ids=["missing entry", "entry without a file", "no entry details"],
)
def test_gti_agentic_session_message_post_command_invalid_entry_id(mock_client, requests_mock, mocker, get_file_path_mock):
    """Test that an entry without a file raises a descriptive error before the message is posted."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_message_post_command

    mocker.patch.object(demisto, "getFilePath", **get_file_path_mock)
    session_id = "44444444-4444-4444-4444-000000000005"
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=util_load_json("test_data/session_message_post.json")
    )
    args = {"session_id": session_id, "message": "Analyze this file.", "entry_id": "9@9"}

    with pytest.raises(ValueError) as e:
        gti_agentic_session_message_post_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["INVALID_ENTRY_ID"].format("9@9")
    assert not requests_mock.called


@pytest.mark.parametrize(
    "args, arg_name",
    [
        ({}, "session_id"),
        ({"session_id": "", "message": "What is GTI?"}, "session_id"),
        ({"session_id": "44444444-4444-4444-4444-000000000005"}, "message"),
        ({"session_id": "44444444-4444-4444-4444-000000000005", "message": "", "entry_id": "1@2"}, "message"),
    ],
    ids=["no arguments", "empty session ID", "missing message", "empty message"],
)
def test_gti_agentic_session_message_post_command_missing_argument(mock_client, args, arg_name):
    """Test that a missing session ID or message raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_message_post_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_message_post_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format(arg_name)


def test_gti_agentic_session_message_post_command_without_session(mock_client, requests_mock):
    """Test that a response without the session reports the posted message without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_message_post_command

    session_id = "44444444-4444-4444-4444-000000000005"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json={}, status_code=200)

    result = gti_agentic_session_message_post_command(client=mock_client, args={"session_id": session_id, "message": "Hi"})

    assert util_readable_output(result) == MESSAGES["SESSION_MESSAGE_POSTED"]
    assert not util_command_outputs(result)


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Session not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
        (400, {"error": {"code": "BadRequestError", "message": "The attached file type is not supported."}}, "BAD_REQUEST"),
    ],
)
def test_gti_agentic_session_message_post_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that an unknown or inaccessible agentic session, or a rejected message, reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_message_post_command

    session_id = "44444444-4444-4444-4444-000000000000"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_message_post_command(client=mock_client, args={"session_id": session_id, "message": "Hi"})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_session_message_post(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-message-post command."""
    import GoogleThreatIntelligenceAgentic

    session_id = "44444444-4444-4444-4444-000000000005"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"session_id": f" {session_id} ", "message": "What is GTI?"})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-message-post")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}",
        json=util_load_json("test_data/session_message_post.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}"
    assert util_command_outputs(return_results_mock.call_args.args[0]) == util_load_json(
        "test_data/session_message_post_context.json"
    )


def test_update_session_success(mock_client, requests_mock):
    """Test that update_session patches the agentic session endpoint with the JSON payload."""
    expected_response = util_load_json("test_data/session_update.json")
    session_id = expected_response["data"]["id"]
    requests_mock.patch(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=expected_response, status_code=200)

    response = mock_client.update_session(session_id, {"data": {"seen": True}})

    request = requests_mock.last_request
    assert response == expected_response
    assert request.method == "PATCH"
    assert request.path == f"/api/v3/agentspace/sessions/{session_id}"
    assert request.json() == {"data": {"seen": True}}


@pytest.mark.parametrize("seen, expected_seen, expected_state", [("True", True, "seen"), ("false", False, "unseen")])
def test_gti_agentic_session_update_command_success(mock_client, requests_mock, seen, expected_seen, expected_state):
    """Test that the command sends the seen flag and reports the updated session details without the conversation."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_update_command

    raw_response = util_load_json("test_data/session_update.json")
    session_id = raw_response["data"]["id"]
    requests_mock.patch(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_update_command(client=mock_client, args={"session_id": session_id, "seen": seen})

    assert requests_mock.last_request.json() == {"data": {"seen": expected_seen}}
    assert util_command_outputs(result) == util_load_json("test_data/session_update_context.json")
    assert util_readable_output(result) == util_load_text("test_data/session_update_hr.md").replace(
        "marked as seen", f"marked as {expected_state}"
    )
    assert result.raw_response == raw_response


def test_gti_agentic_session_update_command_without_session(mock_client, requests_mock):
    """Test that a response without the session reports the update without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_update_command

    session_id = "44444444-4444-4444-4444-000000000006"
    requests_mock.patch(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json={}, status_code=200)

    result = gti_agentic_session_update_command(client=mock_client, args={"session_id": session_id, "seen": "True"})

    assert util_readable_output(result) == MESSAGES["SESSION_UPDATED"].format("seen")
    assert not util_command_outputs(result)


@pytest.mark.parametrize(
    "args, arg_name",
    [
        ({}, "session_id"),
        ({"session_id": "", "seen": "True"}, "session_id"),
        ({"session_id": "44444444-4444-4444-4444-000000000006"}, "seen"),
        ({"session_id": "44444444-4444-4444-4444-000000000006", "seen": ""}, "seen"),
    ],
    ids=["no arguments", "empty session ID", "missing seen", "empty seen"],
)
def test_gti_agentic_session_update_command_missing_argument(mock_client, args, arg_name):
    """Test that a missing session ID or seen flag raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_update_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_update_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format(arg_name)


def test_gti_agentic_session_update_command_invalid_seen(mock_client, requests_mock):
    """Test that an unsupported value of the seen flag raises a descriptive error before the session is updated."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_update_command

    session_id = "44444444-4444-4444-4444-000000000006"
    requests_mock.patch(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json={}, status_code=200)

    with pytest.raises(ValueError) as e:
        gti_agentic_session_update_command(client=mock_client, args={"session_id": session_id, "seen": "maybe"})

    assert str(e.value) == ERROR_MESSAGES["INVALID_ARGUMENT"].format("maybe", "seen", BOOLEAN_HR_LIST)
    assert not requests_mock.called


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Session not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_session_update_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that an unknown or inaccessible agentic session reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_update_command

    session_id = "44444444-4444-4444-4444-000000000000"
    requests_mock.patch(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_update_command(client=mock_client, args={"session_id": session_id, "seen": "True"})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_session_update(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-update command."""
    import GoogleThreatIntelligenceAgentic

    session_id = "44444444-4444-4444-4444-000000000006"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"session_id": f" {session_id} ", "seen": "True"})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-update")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}",
        json=util_load_json("test_data/session_update.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "PATCH"
    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}"
    assert util_command_outputs(return_results_mock.call_args.args[0]) == util_load_json("test_data/session_update_context.json")


@pytest.mark.parametrize(
    "response_kwargs, expected_response",
    [({"content": b""}, {}), ({"json": {"data": {}}}, {"data": {}})],
    ids=["empty body", "empty data object"],
)
def test_delete_session_success(mock_client, requests_mock, response_kwargs, expected_response):
    """Test that delete_session issues a DELETE request and handles both the empty body and the empty data object."""
    session_id = "44444444-4444-4444-4444-000000000007"
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", status_code=200, **response_kwargs)

    response = mock_client.delete_session(session_id)

    assert response == expected_response
    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}"


def test_gti_agentic_session_delete_command_success(mock_client, requests_mock):
    """Test that the command reports the success message and does not set any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_delete_command

    session_id = "44444444-4444-4444-4444-000000000007"
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", content=b"", status_code=200)

    result = gti_agentic_session_delete_command(client=mock_client, args={"session_id": session_id})

    assert util_readable_output(result) == f"The session with ID {session_id} is deleted successfully."
    # The API returns no content, hence the command does not publish any context output.
    assert not util_command_outputs(result)
    assert result.raw_response == {}


@pytest.mark.parametrize("args", [{}, {"session_id": ""}])
def test_gti_agentic_session_delete_command_missing_session_id(mock_client, args):
    """Test that an absent or an empty 'session_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_delete_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_delete_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("session_id")


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Session not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_session_delete_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that an unknown or inaccessible agentic session reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_delete_command

    session_id = "44444444-4444-4444-4444-000000000000"
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_delete_command(client=mock_client, args={"session_id": session_id})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_session_delete(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-delete command."""
    import GoogleThreatIntelligenceAgentic

    session_id = "44444444-4444-4444-4444-000000000007"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"session_id": f" {session_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-delete")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.delete(f"{BASE_URL}{ENDPOINTS['session_by_id'].format(session_id)}", content=b"", status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}"
    assert util_readable_output(return_results_mock.call_args.args[0]) == MESSAGES["SESSION_DELETED"].format(session_id)


def test_get_session_token_success(mock_client, requests_mock):
    """Test that get_session_token requests the token endpoint of the session and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/session_token_get.json")
    session_id = "44444444-4444-4444-4444-000000000008"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_token'].format(session_id)}", json=expected_response, status_code=200)

    response = mock_client.get_session_token(session_id)

    assert response == expected_response
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}/token"


def test_gti_agentic_session_token_get_command_success(mock_client, requests_mock):
    """Test that the command reports the share token along with the ID of its session."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_token_get_command

    raw_response = util_load_json("test_data/session_token_get.json")
    session_id = "44444444-4444-4444-4444-000000000008"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_token'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_token_get_command(client=mock_client, args={"session_id": session_id})

    assert util_command_outputs(result) == {
        f"{OUTPUT_PREFIX['SESSION_TOKEN']}(val.id && val.id == obj.id)": {"id": session_id, "token": TEST_SESSION_SHARE_TOKEN}
    }
    assert util_readable_output(result) == util_load_text("test_data/session_token_get_hr.md")
    assert result.raw_response == raw_response


@pytest.mark.parametrize("raw_response", [{}, {"token": ""}], ids=["empty response", "empty token"])
def test_gti_agentic_session_token_get_command_no_token(mock_client, requests_mock, raw_response):
    """Test that a response without a token reports the no record message without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_token_get_command

    session_id = "44444444-4444-4444-4444-000000000008"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_token'].format(session_id)}", json=raw_response, status_code=200)

    result = gti_agentic_session_token_get_command(client=mock_client, args={"session_id": session_id})

    assert util_readable_output(result) == MESSAGES["NO_RECORD_FOUND"].format("GTI Agentic Session share token")
    assert not util_command_outputs(result)


@pytest.mark.parametrize("args", [{}, {"session_id": ""}])
def test_gti_agentic_session_token_get_command_missing_session_id(mock_client, args):
    """Test that an absent or an empty 'session_id' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_token_get_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_token_get_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("session_id")


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (404, {"error": {"code": "NotFoundError", "message": "Session not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_session_token_get_command_api_error(mock_client, requests_mock, status_code, response, error_message_key):
    """Test that an unknown or inaccessible agentic session reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_token_get_command

    session_id = "44444444-4444-4444-4444-000000000000"
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['session_token'].format(session_id)}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_token_get_command(client=mock_client, args={"session_id": session_id})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_main_gti_agentic_session_token_get(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-token-get command."""
    import GoogleThreatIntelligenceAgentic

    session_id = "44444444-4444-4444-4444-000000000008"
    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"session_id": f" {session_id} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-token-get")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['session_token'].format(session_id)}",
        json=util_load_json("test_data/session_token_get.json"),
        status_code=200,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == f"/api/v3/agentspace/sessions/{session_id}/token"
    assert util_command_outputs(return_results_mock.call_args.args[0]) == {
        f"{OUTPUT_PREFIX['SESSION_TOKEN']}(val.id && val.id == obj.id)": {"id": session_id, "token": TEST_SESSION_SHARE_TOKEN}
    }


def test_create_session_from_token_success(mock_client, requests_mock):
    """Test that create_session_from_token posts the share token and returns the parsed response of the API."""
    expected_response = util_load_json("test_data/session_from_token_create.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_from_token']}", json=expected_response, status_code=201)

    response = mock_client.create_session_from_token(TEST_SESSION_SHARE_TOKEN)

    assert response == expected_response
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.path == "/api/v3/agentspace/sessions/token"
    assert requests_mock.last_request.json() == {"token": TEST_SESSION_SHARE_TOKEN}


def test_create_session_from_token_does_not_log_token(mock_client, requests_mock, mocker):
    """Test that the share token is not written to the debug log, as it grants access to the source session."""
    debug_mock = mocker.patch.object(demisto, "debug")
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['session_from_token']}",
        json=util_load_json("test_data/session_from_token_create.json"),
        status_code=201,
    )

    mock_client.create_session_from_token(TEST_SESSION_SHARE_TOKEN)

    logged_messages = " ".join(str(call.args[0]) for call in debug_mock.call_args_list)
    assert "body keys:['token']" in logged_messages
    assert TEST_SESSION_SHARE_TOKEN not in logged_messages


@pytest.mark.parametrize("status_code", [200, 201])
def test_gti_agentic_session_from_token_create_command_success(mock_client, requests_mock, status_code):
    """Test that the command reports the new session along with its copied conversation."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_from_token_create_command

    raw_response = util_load_json("test_data/session_from_token_create.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_from_token']}", json=raw_response, status_code=status_code)

    result = gti_agentic_session_from_token_create_command(client=mock_client, args={"token": TEST_SESSION_SHARE_TOKEN})

    assert util_command_outputs(result) == util_load_json("test_data/session_from_token_create_context.json")
    assert util_readable_output(result) == util_load_text("test_data/session_from_token_create_hr.md")
    assert result.raw_response == raw_response


@pytest.mark.parametrize("raw_response", [{}, {"data": {}}], ids=["empty response", "empty session"])
def test_gti_agentic_session_from_token_create_command_without_session(mock_client, requests_mock, raw_response):
    """Test that a response without the new session reports the success message without any context output."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_from_token_create_command

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_from_token']}", json=raw_response, status_code=201)

    result = gti_agentic_session_from_token_create_command(client=mock_client, args={"token": TEST_SESSION_SHARE_TOKEN})

    assert util_readable_output(result) == MESSAGES["SESSION_CREATED_FROM_TOKEN"]
    assert not util_command_outputs(result)
    assert result.raw_response == raw_response


def test_gti_agentic_session_from_token_create_command_without_events(mock_client, requests_mock):
    """Test that a new session without events reports the session table only."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_from_token_create_command

    raw_response = util_load_json("test_data/session_from_token_create.json")
    del raw_response["data"]["attributes"]["events"]
    session_id = raw_response["data"]["id"]
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_from_token']}", json=raw_response, status_code=201)

    result = gti_agentic_session_from_token_create_command(client=mock_client, args={"token": TEST_SESSION_SHARE_TOKEN})

    # The session table reports no events, and the conversation table and the agent response sections are not added.
    assert util_readable_output(result) == (
        "### Session created successfully from the shared token.\n"
        "|Session ID|Title|Events|Creation Date|Last Modification Date|\n"
        "|---|---|---|---|---|\n"
        f"| [{session_id}](https://www.virustotal.com/gui/agentic/sessions/{session_id})"
        " | Malware analysis of a shared file | 0 | 2026-10-12T10:00:00.123456Z | 2026-10-12T10:00:00.123456Z |\n"
    )
    assert "events" not in util_command_outputs(result)[SESSION_OUTPUT_KEY]


@pytest.mark.parametrize("args", [{}, {"token": ""}])
def test_gti_agentic_session_from_token_create_command_missing_token(mock_client, args):
    """Test that an absent or an empty 'token' argument raises a descriptive error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_from_token_create_command

    with pytest.raises(ValueError) as e:
        gti_agentic_session_from_token_create_command(client=mock_client, args=args)

    assert str(e.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("token")


@pytest.mark.parametrize(
    "status_code, response, error_message_key",
    [
        (400, util_load_json("test_data/error_invalid_token.json"), "BAD_REQUEST"),
        (404, {"error": {"code": "NotFoundError", "message": "Session not found."}}, "NOT_FOUND"),
        (403, util_load_json("test_data/error_forbidden.json"), "FORBIDDEN"),
    ],
)
def test_gti_agentic_session_from_token_create_command_api_error(
    mock_client, requests_mock, status_code, response, error_message_key
):
    """Test that an invalid or expired share token reports the error message of the API."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_from_token_create_command

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_from_token']}", json=response, status_code=status_code)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_from_token_create_command(client=mock_client, args={"token": TEST_SESSION_SHARE_TOKEN})

    assert str(e.value) == ERROR_MESSAGES[error_message_key].format(status_code, response["error"]["message"])


def test_gti_agentic_session_from_token_create_command_unauthorized(mock_client, requests_mock):
    """Test that an invalid API key reports the unauthorized error."""
    from GoogleThreatIntelligenceAgentic import gti_agentic_session_from_token_create_command

    response = util_load_json("test_data/error_unauthorized.json")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['session_from_token']}", json=response, status_code=401)

    with pytest.raises(DemistoException) as e:
        gti_agentic_session_from_token_create_command(client=mock_client, args={"token": TEST_SESSION_SHARE_TOKEN})

    assert str(e.value) == ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, str(response))


def test_main_gti_agentic_session_from_token_create(mocker, requests_mock):
    """Test that main dispatches the gti-agentic-session-from-token-create command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={"token": f" {TEST_SESSION_SHARE_TOKEN} "})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-session-from-token-create")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['session_from_token']}",
        json=util_load_json("test_data/session_from_token_create.json"),
        status_code=201,
    )

    GoogleThreatIntelligenceAgentic.main()

    assert requests_mock.last_request.path == "/api/v3/agentspace/sessions/token"
    assert requests_mock.last_request.json() == {"token": TEST_SESSION_SHARE_TOKEN}
    assert util_command_outputs(return_results_mock.call_args.args[0]) == util_load_json(
        "test_data/session_from_token_create_context.json"
    )


def test_main_test_module(mocker, requests_mock):
    """Test that main dispatches the test-module command."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(
        demisto,
        "params",
        return_value=util_mock_params(api_key=f" {TEST_API_KEY} ", group_id=" my-group ", insecure=False, proxy=False),
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    return_results_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_results")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/flow_list.json"), status_code=200)

    GoogleThreatIntelligenceAgentic.main()

    assert return_results_mock.call_args.args[0] == "ok"
    assert requests_mock.last_request.headers["X-Active-Group"] == "my-group"
    assert requests_mock.last_request.headers["x-apikey"] == TEST_API_KEY


def test_main_command_not_implemented(mocker):
    """Test that an unknown command returns a descriptive error."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="gti-agentic-unknown-command")
    return_error_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_error")

    GoogleThreatIntelligenceAgentic.main()

    assert "Command gti-agentic-unknown-command is not implemented" in return_error_mock.call_args.args[0]


def test_main_returns_error_on_failure(mocker, requests_mock):
    """Test that main reports the API failure through return_error."""
    import GoogleThreatIntelligenceAgentic

    mocker.patch.object(demisto, "params", return_value=util_mock_params())
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    return_error_mock = mocker.patch.object(GoogleThreatIntelligenceAgentic, "return_error")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['flows']}", json=util_load_json("test_data/error_forbidden.json"), status_code=403)

    GoogleThreatIntelligenceAgentic.main()

    error_message = return_error_mock.call_args.args[0]
    assert "Failed to execute test-module command." in error_message
    assert "403 Forbidden: You are not authorized to perform the requested operation." in error_message
