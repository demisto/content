from GoogleThreatIntelligenceASMIssues import (
    Client,
    BASE_URL,
    ENDPOINTS,
    ERROR_MESSAGES,
    MESSAGES,
    ASM_ISSUE_STATUS_HUMAN_READABLE,
)
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import json
import pytest


# Helper Functions
def util_load_json(path):
    """Load JSON data from file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client(mocker):
    """Create a mocked client for testing."""
    return Client(verify_certificate=False, proxy=False, api_key="test_api_key", project_id="1234")


def test_test_module_success(mock_client, requests_mock):
    """Test test_module function returns 'ok' when API call succeeds."""
    from GoogleThreatIntelligenceASMIssues import test_module

    requests_mock.get(
        f'{BASE_URL}/{ENDPOINTS["issue_list"].format("status_new:open")}',
        json={"success": True, "result": {"hits": []}},
        status_code=200,
    )
    result = test_module(client=mock_client)

    # Verify the function returns "ok"
    assert result == "ok"


def test_test_module_invalid_api_key(mock_client, requests_mock):
    """Test test_module function returns 'ok' when API call succeeds."""
    from GoogleThreatIntelligenceASMIssues import test_module

    requests_mock.get(
        f'{BASE_URL}/{ENDPOINTS["issue_list"].format("status_new:open")}',
        json={"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}},
        status_code=401,
    )
    with pytest.raises(DemistoException) as e:
        test_module(client=mock_client)

    assert (
        str(e.value) == "401 Unauthorized request: Invalid API key provided "
        "{'error': {'code': 'WrongCredentialsError', 'message': 'Wrong API key'}}."
    )


def test_main_test_module_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and test-module command.

    When:
    - Running the main function.

    Then:
    - Validate that test_module is called and returns 'ok'.
    """
    from GoogleThreatIntelligenceASMIssues import main

    # Mock demisto functions
    mock_params = {"credentials": {"password": "test_api_key"}, "insecure": False, "proxy": False}
    mock_demisto = mocker.patch("GoogleThreatIntelligenceASMIssues.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = "test-module"
    mock_demisto.args.return_value = {}
    mock_demisto.debug = mocker.Mock()

    # Mock return_results and return_error
    mock_return_results = mocker.patch("GoogleThreatIntelligenceASMIssues.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceASMIssues.return_error")

    # Mock the API call for test_module
    requests_mock.get(
        f'{BASE_URL}/{ENDPOINTS["issue_list"].format("status_new:open")}',
        json={"success": True, "result": {"hits": []}},
        status_code=200,
    )

    # Call main
    main()

    # Assertions
    mock_demisto.command.assert_called_once()
    mock_return_results.assert_called_once_with("ok")
    mock_return_error.assert_not_called()


@pytest.mark.parametrize(
    "command, args, mock_api_response, expected_result_type",
    [
        ("test-module", {}, {}, str),
        ("gti-asm-issue-get", {"issue_id": "test_123"}, "asm_issue_get.json", type(None)),
    ],
)
def test_main_try_block_success_paths(mocker, requests_mock, command, args, mock_api_response, expected_result_type):
    """
    Given:
    - Valid parameters and different commands.

    When:
    - Running the main function try block.

    Then:
    - Validate that the appropriate command is executed and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import main

    # Mock demisto functions
    mock_params = {"credentials": {"password": "test_api_key"}, "insecure": False, "proxy": False, "project_id": "test_project"}
    mock_demisto = mocker.patch("GoogleThreatIntelligenceASMIssues.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = command
    mock_demisto.args.return_value = args
    mock_demisto.debug = mocker.Mock()

    # Mock return_results and return_error
    mock_return_results = mocker.patch("GoogleThreatIntelligenceASMIssues.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceASMIssues.return_error")

    # Mock API responses based on command
    if command == "test-module":
        requests_mock.get(
            f'{BASE_URL}/{ENDPOINTS["issue_list"].format("status_new:open")}',
            json={"success": True, "result": {"hits": []}},
            status_code=200,
        )
    elif command == "gti-asm-issue-get":
        mock_response = util_load_json(f"test_data/{mock_api_response}")
        requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_get'].format(args['issue_id'])}", json=mock_response)

    # Call main
    main()

    # Assertions
    mock_return_results.assert_called_once()
    mock_return_error.assert_not_called()

    # Verify the result type if needed
    if command == "test-module":
        mock_return_results.assert_called_with("ok")


def test_main_try_block_unknown_command_exception(mocker):
    """
    Given:
    - An unknown command that raises NotImplementedError.

    When:
    - Running the main function with unknown command.

    Then:
    - Validate that NotImplementedError is caught and return_error is called.
    """
    from GoogleThreatIntelligenceASMIssues import main

    # Mock demisto functions
    mock_params = {"credentials": {"password": "test_api_key"}, "insecure": False, "proxy": False, "project_id": "test_project"}
    mock_demisto = mocker.patch("GoogleThreatIntelligenceASMIssues.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = "unknown-command"
    mock_demisto.args.return_value = {}

    # Mock return functions
    mock_return_results = mocker.patch("GoogleThreatIntelligenceASMIssues.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceASMIssues.return_error")

    # Call main
    main()

    # Verify exception handling
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]

    # Verify error message contains expected content
    assert "Failed to execute unknown-command command" in error_message
    assert "Command unknown-command is not implemented" in error_message

    mock_return_results.assert_not_called()


def test_get_asm_issue_command_success(mock_client, requests_mock):
    """
    Given:
    - Valid parameters and get-asm-issue command.

    When:
    - Running the main function with get-asm-issue command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_get_command

    mock_response = util_load_json("test_data/asm_issue_get.json")

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/asm_issue_get_human_readable.md")) as f:
        asm_issue_get_hr = f.read()

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_get'].format('dummy_uid')}", json=mock_response)

    results = gti_asm_issue_get_command(client=mock_client, args={"issue_id": "dummy_uid", "project_id": "test_project"})

    assert results.readable_output == asm_issue_get_hr
    assert results.outputs == [mock_response["result"]]


@pytest.mark.parametrize(
    "args, exception, error", [({"issue_id": ""}, ValueError, MESSAGES["REQUIRED_ARGUMENT"].format("issue_id"))]
)
def test_gti_asm_issue_get_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input

    When:
    - Running the !gti-asm-issue-get command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_get_command

    with pytest.raises(exception) as e:
        gti_asm_issue_get_command(mock_client, args)

    assert str(e.value) == error


def test_gti_asm_issue_get_command_no_record_found(mock_client, requests_mock):
    """
    Given:
    - Valid parameters and get-asm-issue command.

    When:
    - Running the main function with get-asm-issue command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_get_command

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_get'].format('dummy_uid')}", json={})

    results = gti_asm_issue_get_command(client=mock_client, args={"issue_id": "dummy_uid", "project_id": "test_project"})

    assert results.readable_output == "No ASM Issue was found for the given argument(s)."
    assert results.outputs is None


def test_gti_asm_issue_status_update_command_success(mock_client, requests_mock):
    """
    Given:
    - Valid parameters and get-asm-issue-status-update command.

    When:
    - Running the main function with get-asm-issue-status-update command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_status_update_command

    mock_response = util_load_json("test_data/asm_issue_update_status.json")

    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/asm_issue_status_update_human_readable.md")
    ) as f:
        asm_issue_status_update_hr = f.read()

    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('dummy_uid')}", json=mock_response)

    results = gti_asm_issue_status_update_command(
        client=mock_client, args={"issue_id": "dummy_uid", "project_id": "test_project", "status": "Open"}
    )

    assert results.readable_output == asm_issue_status_update_hr
    assert results.outputs == [mock_response]


def test_gti_asm_issue_status_update_command_no_record_found(mock_client, requests_mock):
    """
    Given:
    - Valid parameters and get-asm-issue-status-update command.

    When:
    - Running the main function with get-asm-issue-status-update command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_status_update_command

    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('dummy_uid')}", json={"success": False})

    results = gti_asm_issue_status_update_command(
        client=mock_client, args={"issue_id": "dummy_uid", "project_id": "test_project", "status": "Open"}
    )

    assert results.readable_output == "No ASM Issue status was updated."
    assert results.outputs is None


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"issue_id": "", "status": "Open"}, ValueError, MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
        ({"issue_id": "dummy_uid", "status": ""}, ValueError, MESSAGES["REQUIRED_ARGUMENT"].format("status")),
        (
            {"issue_id": "dummy_uid", "status": "open_new"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("open_new", "status", ASM_ISSUE_STATUS_HUMAN_READABLE),
        ),
    ],
)
def test_gti_asm_issue_status_update_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid parameters and get-asm-issue-status-update command.

    When:
    - Running the main function with get-asm-issue-status-update command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_status_update_command

    with pytest.raises(exception) as e:
        gti_asm_issue_status_update_command(mock_client, args)

    assert str(e.value) == error


def test_gti_asm_issue_list_command_success(mock_client, requests_mock):
    """
    Given:
    - Valid parameters and get-asm-issue-list command.

    When:
    - Running the main function with get-asm-issue-list command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_list_command

    mock_response = util_load_json("test_data/asm_issue_list.json")

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/asm_issue_list_human_readable.md")) as f:
        asm_issue_list_hr = f.read()

    search_string = "collection:google entity_type:uri"

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_list'].format(search_string)}", json=mock_response)

    results = gti_asm_issue_list_command(client=mock_client, args={"project_id": "test_project", "search_string": search_string})

    assert results.readable_output == asm_issue_list_hr
    assert results.outputs == mock_response["result"]["hits"]


def test_gti_asm_issue_list_command_no_record_found(mock_client, requests_mock):
    """
    Given:
    - Valid parameters and get-asm-issue-list command.

    When:
    - Running the main function with get-asm-issue-list command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_list_command

    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('collection:actiontocreatecollection_i4qlbqg')}",
        json={"success": True, "result": {"hits": []}},
    )

    results = gti_asm_issue_list_command(
        client=mock_client, args={"project_id": "test_project", "search_string": "collection:actiontocreatecollection_i4qlbqg"}
    )

    assert results.readable_output == "No ASM Issues were found for the given argument(s)."
    assert results.outputs is None


@pytest.mark.parametrize(
    "args, exception, error",
    [
        (
            {"search_string": "collection:abc"},
            ValueError,
            "Failed to retrieve ASM issues from Google Threat Intelligence API."
            " Verify the search string and project ID are correct, and try again."
            " Provided Search string: 'collection:abc', Project ID: '1234'",
        ),
        ({"page_size": "10000"}, ValueError, ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(10000)),
        ({"page_size": "-1"}, ValueError, ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(-1)),
    ],
)
def test_gti_asm_issue_list_command_when_invalid_input(mock_client, requests_mock, args, exception, error):
    """
    Given:
    - Invalid parameters and get-asm-issue-list command.

    When:
    - Running the main function with get-asm-issue-list command.

    Then:
    - Validate that get_asm_issue_command is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import gti_asm_issue_list_command

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_list'].format('collection:abc')}", json={"success": False})

    with pytest.raises(exception) as e:
        gti_asm_issue_list_command(mock_client, args)

    assert str(e.value) == error


def test_fetch_incidents_asm_issue_test_connectivity(mock_client, requests_mock, mocker):
    """
    Given:
    - Valid parameters and fetch-incidents command.

    When:
    - Running the main function with fetch-incidents command.

    Then:
    - Validate that fetch_incidents is called and return_results is called.
    """
    from GoogleThreatIntelligenceASMIssues import test_module

    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('last_seen_after:2025-09-29T08:59:20.494Z')}",
        json={"success": True, "result": {"hits": []}},
    )
    params = {
        "isFetch": True,
        "max_fetch": "10",
        "first_fetch": "2025-09-29T08:59:20.494Z",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    result = test_module(mock_client)

    assert result == "ok"


@pytest.mark.parametrize(
    "max_fetch_value, expected_error",
    [
        (0, ERROR_MESSAGES["INVALID_MAX_FETCH"].format(0)),
        (-1, ERROR_MESSAGES["INVALID_MAX_FETCH"].format(-1)),
        (250, ERROR_MESSAGES["INVALID_MAX_FETCH"].format(250)),
    ],
)
def test_fetch_incidents_asm_issue_max_fetch_params_invalid(mock_client, max_fetch_value, expected_error):
    """
    Test fetch_incidents with invalid max_fetch values.

    Given:
    - Invalid max_fetch parameters (negative, zero, exceeding limit)

    When:
    - Running fetch_incidents function

    Then:
    - Validate that ValueError is raised with appropriate error messages
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "3 days",
        "max_fetch": max_fetch_value,
        "search_string": "",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    with pytest.raises(ValueError) as e:
        fetch_incidents(client=mock_client, last_run={}, params=params)

    assert str(e.value) == expected_error


def test_fetch_incidents_asm_issue_success_with_no_last_run(mock_client, requests_mock, mocker):
    """
    Test fetch_incidents with no last_run.

    Given:
    - No last_run provided

    When:
    - Running fetch_incidents function

    Then:
    - Validate that fetch_incidents returns expected results
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    search_string = "collection:google severity:5 last_seen_after:2025-09-30T09:45:30.711Z"
    params = {
        "first_fetch": "2025-09-01T09:45:30.711Z",
        "max_fetch": "4",
        "search_string": search_string,
        "project_id": "12345",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = util_load_json("test_data/fetch_asm_issue_success_response.json")

    fetched_incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_asm_issue_success_incidents.json")
    )
    issue_ids = [alert["uid"] for alert in mock_response["result"]["hits"]]

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('collection:google severity:5 last_seen_after:2025-09-01T09:45:30.711Z')}",
        json=mock_response,
    )

    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run={}, params=params)

    # Assert expected results
    assert incidents == fetched_incidents
    assert new_last_run["max_fetch"] == 4
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:51.000Z"
    assert new_last_run["index"] == 1
    assert new_last_run["issue_ids"] == issue_ids
    assert new_last_run["search_string"] == params["search_string"]


def test_fetch_incidents_asm_issue_success_with_no_issue_data(mock_client, requests_mock, mocker):
    """
    Test fetch_incidents with no data.

    Given:
    - No data in the response

    When:
    - Running fetch_incidents function

    Then:
    - Validate that fetch_incidents returns expected results
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "2025-06-30T09:45:30.711Z",
        "max_fetch": "4",
        "project_id": "12345",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = {"success": True, "result": {"hits": []}}
    last_run = {
        "max_fetch": 4,
        "asm_latest_issue_last_seen": "2025-07-14T15:18:51.000Z",
        "index": 1,
        "issue_ids": ["dummy_uid"],
        "search_string": "",
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('last_seen_after:2025-07-14T15:18:51.000Z')}", json=mock_response
    )

    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    # Assert expected results
    assert incidents == []
    assert new_last_run["max_fetch"] == 4
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:51.000Z"
    assert new_last_run["index"] == 1
    assert new_last_run["issue_ids"] == ["dummy_uid"]
    assert new_last_run["search_string"] == ""


def test_fetch_incidents_asm_issue_index_increment_with_same_last_seen_timestamp(mock_client, requests_mock, mocker):
    """
    Test fetch_incidents with same last seen timestamp.

    Given:
    - Same last seen timestamp in the response

    When:
    - Running fetch_incidents function

    Then:
    - Validate that fetch_incidents returns expected results
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "2025-06-30T09:45:30.711Z",
        "max_fetch": "2",
        "project_id": "12345",
        "search_string": "",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = util_load_json("test_data/fetch_asm_issue_success_response.json")

    fetched_incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_asm_issue_skip_duplicates.json")
    )
    last_run = {
        "max_fetch": 2,
        "asm_latest_issue_last_seen": "2025-07-14T15:18:51.000Z",
        "index": 2,
        "issue_ids": ["dummy_uid_01", "dummy_uid_02"],
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('last_seen_after:2025-07-14T15:18:51.000Z')}", json=mock_response
    )
    issue_ids = [issue["uid"] for issue in mock_response["result"]["hits"]]
    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    # Assert expected results
    assert incidents == fetched_incidents
    assert new_last_run["max_fetch"] == 2
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:51.000Z"
    assert new_last_run["index"] == 3
    assert new_last_run["issue_ids"] == issue_ids
    assert new_last_run["search_string"] == ""


def test_fetch_incidents_asm_issue_issue_data_less_than_max_fetch(mock_client, requests_mock, mocker):
    """
    Test fetch_incidents with issue data less than max fetch.

    Given:
    - Issue data less than max fetch

    When:
    - Running fetch_incidents function

    Then:
    - Validate that fetch_incidents returns expected results
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "2025-06-30T09:45:30.711Z",
        "max_fetch": "3",
        "project_id": "12345",
        "search_string": "",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = util_load_json("test_data/fetch_asm_issue_success_response.json")

    fetched_incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_asm_issue_skip_duplicates.json")
    )
    last_run = {
        "max_fetch": 3,
        "asm_latest_issue_last_seen": "2025-07-14T15:18:51.000Z",
        "index": 2,
        "issue_ids": ["dummy_uid_01", "dummy_uid_02"],
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('last_seen_after:2025-07-14T15:18:51.000Z')}", json=mock_response
    )
    issue_ids = [issue["uid"] for issue in mock_response["result"]["hits"]]
    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    # Assert expected results
    assert incidents == fetched_incidents
    assert new_last_run["max_fetch"] == 3
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:52.000Z"
    assert new_last_run["index"] == 1
    assert new_last_run["issue_ids"] == issue_ids
    assert new_last_run["search_string"] == ""


def test_fetch_incidents_asm_issue_index_limit_reached_timestamp_bump(mock_client, requests_mock, mocker):
    """
    Test fetch_incidents when index limit is reached and timestamp should be bumped.

    Given:
    - Index at maximum limit (MAX_ISSUE_SIZE // max_fetch)
    - Same timestamp in response as last_run

    When:
    - Running fetch_incidents function

    Then:
    - Validate that timestamp is bumped by 1 second
    - Validate that index is reset to 1
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "2025-06-30T09:45:30.711Z",
        "max_fetch": 100,
        "project_id": "12345",
        "search_string": "",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = util_load_json("test_data/fetch_asm_issue_success_response.json")

    fetched_incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_asm_issue_skip_duplicates.json")
    )

    # Set index to max_index (1000 // 100 = 10)
    last_run = {
        "max_fetch": 100,
        "asm_latest_issue_last_seen": "2025-07-14T15:18:51.000Z",
        "index": 10,
        "issue_ids": ["dummy_uid_01", "dummy_uid_02"],
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('last_seen_after:2025-07-14T15:18:51.000Z')}", json=mock_response
    )

    issue_ids = [issue["uid"] for issue in mock_response["result"]["hits"]]

    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    assert incidents == fetched_incidents
    assert new_last_run["max_fetch"] == 100
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:52.000Z"
    assert new_last_run["index"] == 1
    assert new_last_run["issue_ids"] == issue_ids
    assert new_last_run["search_string"] == ""


@pytest.mark.parametrize(
    "old_max_fetch, new_max_fetch, old_index, expected_new_index",
    [
        # max_fetch increased scenarios
        (2, 3, 2, 1),  # (2-1)*2=2, 2//3+1=2
        # max_fetch decreased scenarios
        (3, 2, 2, 2),  # (2-1)*3=3, 3//2+1=2
    ],
)
def test_fetch_incidents_asm_issue_max_fetch_change_index_recalculation(
    mock_client, requests_mock, mocker, old_max_fetch, new_max_fetch, old_index, expected_new_index
):
    """
    Test fetch_incidents when max_fetch parameter changes and index is recalculated.

    Given:
    - Different max_fetch values (increased/decreased)
    - Existing last_run with old max_fetch and index

    When:
    - Running fetch_incidents function with new max_fetch

    Then:
    - Validate that index is recalculated correctly
    - Formula: new_index = ((old_index - 1) * old_max_fetch) // new_max_fetch + 1
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "2025-06-30T09:45:30.711Z",
        "max_fetch": new_max_fetch,
        "project_id": "12345",
        "search_string": "collection:google",
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = util_load_json("test_data/fetch_asm_issue_success_response.json")

    fetched_incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_asm_issue_success_incidents.json")
    )

    # Set up last_run with old max_fetch and index
    last_run = {
        "max_fetch": old_max_fetch,
        "asm_latest_issue_last_seen": "2025-07-14T15:18:51.000Z",
        "index": old_index,
        "search_string": "collection:google",
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format('collection:google last_seen_after:2025-07-14T15:18:51.000Z')}",
        json=mock_response,
    )

    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    # Assert expected results
    assert incidents == fetched_incidents
    assert new_last_run["max_fetch"] == new_max_fetch
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:51.000Z"
    assert new_last_run["index"] == expected_new_index + 1
    assert new_last_run["search_string"] == "collection:google"


@pytest.mark.parametrize(
    "old_search_string, new_search_string, old_index, expected_new_index, old_max_fetch, new_max_fetch",
    [
        ("collection:google severity_gte:2", "collection:google severity_gte:3", 3, 1, 2, 2),
        ("collection:google severity_gte:2", "collection:google severity_gte:3", 3, 1, 2, 3),
    ],
)
def test_fetch_incidents_when_search_string_changes(
    mock_client,
    requests_mock,
    mocker,
    old_search_string,
    new_search_string,
    old_index,
    expected_new_index,
    old_max_fetch,
    new_max_fetch,
):
    """
    Test fetch_incidents when search string changes.

    Given:
    - Different search strings
    - Existing last_run with old search string

    When:
    - Running fetch_incidents function with new search string

    Then:
    - Validate that index is reset to 1
    """
    from GoogleThreatIntelligenceASMIssues import fetch_incidents

    params = {
        "first_fetch": "2025-06-30T09:45:30.711Z",
        "max_fetch": new_max_fetch,
        "project_id": "12345",
        "search_string": new_search_string,
        "mirror_direction": "Outgoing",
        "note_tag": "note",
    }

    mock_response = util_load_json("test_data/fetch_asm_issue_success_response.json")

    fetched_incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_asm_issue_success_incidents.json")
    )

    # Set up last_run with old search string
    last_run = {
        "max_fetch": old_max_fetch,
        "asm_latest_issue_last_seen": "2025-07-09T15:18:51.000Z",
        "index": old_index,
        "search_string": old_search_string,
    }

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['issue_list'].format(new_search_string + ' last_seen_after:2025-07-09T15:18:51.000Z')}",
        json=mock_response,
    )

    # Call fetch_incidents
    incidents, new_last_run = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    # Assert expected results
    assert incidents == fetched_incidents
    assert new_last_run["max_fetch"] == new_max_fetch
    assert new_last_run["asm_latest_issue_last_seen"] == "2025-07-14T15:18:51.000Z"
    assert new_last_run["index"] == expected_new_index
    assert new_last_run["search_string"] == new_search_string


def test_update_remote_system_command_incident_closed_status_update(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status DONE (closed)

    When:
    - Running update_remote_system_command

    Then:
    - Issue status should be updated to 'closed' via POST request.
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"}
    mock_args.inc_status = 2  # IncidentStatus.DONE
    mock_args.delta = {}
    mock_args.incident_changed = True
    mock_args.entries = []

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoint for status update
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"},
        "inc_status": 2,  # IncidentStatus.DONE
        "delta": {},
        "incident_changed": True,
        "entries": [],
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify the POST request was made with the correct payload
    history = requests_mock.request_history
    assert len(history) == 1
    assert history[0].method == "POST"
    expected_update = {"status": "closed"}
    assert history[0].json() == expected_update


def test_update_remote_system_command_success(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status DONE, tags in delta, and new entries

    When:
    - Running update_remote_system_command

    Then:
    - Issue status should be updated to 'closed'
    - New tags should be added to the issue
    - New notes should be added to the issue
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"}
    mock_args.inc_status = 2  # IncidentStatus.DONE
    mock_args.delta = {"tags": ["urgent"]}
    mock_args.incident_changed = True
    mock_args.entries = [{"id": "entry_1", "type": "note", "contents": "Investigation completed", "user": "analyst1"}]

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoints
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_tags'].format('issue_456')}", json={"result": []})
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_tags'].format('issue_456')}", json={"success": True})
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_update_notes'].format('issue_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"},
        "inc_status": 2,  # IncidentStatus.DONE
        "delta": {"tags": ["urgent"]},
        "incident_changed": True,
        "entries": [{"id": "entry_1", "type": "note", "contents": "Investigation completed", "user": "analyst1"}],
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify all API requests were made
    history = requests_mock.request_history
    assert len(history) == 4  # status update + get tags + tag updates + note update

    # Verify status update request
    status_request = history[0]
    assert status_request.method == "POST"
    assert "status" in status_request.url
    assert status_request.json() == {"status": "closed"}

    # Verify tags get request
    tags_get_request = history[1]
    assert tags_get_request.method == "GET"
    assert "tags" in tags_get_request.url

    # Verify tag update requests
    tag_update_1 = history[2]
    assert tag_update_1.method == "POST"
    assert "tags" in tag_update_1.url
    assert tag_update_1.json() == {"tag_name": "urgent"}

    # Verify note update request
    note_request = history[3]
    assert note_request.method == "POST"
    assert "notes" in note_request.url
    expected_note = "[Mirrored From XSOAR] | Incident ID: xsoar_incident_123 | Note: Investigation completed | Added By: analyst1"
    assert note_request.json() == {"note_text": expected_note}

    assert note_request.json() == {"note_text": expected_note}


def test_update_remote_system_command_note_exceeds_limit(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with new entries containing note content exceeding MAX_OUTGOING_NOTE_LIMIT

    When:
    - Running update_remote_system_command

    Then:
    - Note should be skipped and not sent to API
    - Info message should be logged about skipping the note
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command, MAX_OUTGOING_NOTE_LIMIT

    # Create note content that exceeds the limit
    long_note_content = "x" * (MAX_OUTGOING_NOTE_LIMIT + 100)

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {}
    mock_args.incident_changed = True
    mock_args.entries = [{"id": "entry_1", "type": "note", "contents": long_note_content, "user": "analyst1"}]

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock demisto.info to capture the log message
    mock_info = mocker.patch("GoogleThreatIntelligenceASMIssues.demisto.info")

    # No API endpoints should be called for notes since it exceeds limit
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_update_notes'].format('issue_456')}", json={"success": True})
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})
    args = {
        "remote_incident_id": "remote_123",
        "data": {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {},
        "incident_changed": True,
        "entries": [{"id": "entry_1", "type": "note", "contents": long_note_content, "user": "analyst1"}],
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify no API requests were made (status update, no note update)
    history = requests_mock.request_history
    assert len(history) == 1  # only status update

    # Verify info message was logged about skipping the note
    mock_info.assert_called_once_with(
        "Skipping outgoing mirroring for issue note with XSOAR Incident ID:xsoar_incident_123, "
        "because the note length exceeds 8000 characters."
    )


def test_update_remote_system_command_status_update_only_no_delta(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status ACTIVE and empty delta

    When:
    - Running update_remote_system_command

    Then:
    - Only status should be updated to 'open_in_progress'
    - No tags or notes should be processed
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {}
    mock_args.incident_changed = True
    mock_args.entries = []

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoint for status update only
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {},
        "incident_changed": True,
        "entries": [],
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify only one API request was made (status update only)
    history = requests_mock.request_history
    assert len(history) == 1

    # Verify status update request
    status_request = history[0]
    assert status_request.method == "POST"
    assert "status" in status_request.url
    assert status_request.json() == {"status": "open_in_progress"}


def test_update_remote_system_command_tags_update_mixed_existing_new(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with two tags in delta: one new tag and one existing tag

    When:
    - Running update_remote_system_command

    Then:
    - Only the new tag should be added via API call
    - The existing tag should be skipped (no API call for it)
    - Debug message should be logged for the existing tag
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {"tags": ["urgent", "existing"]}
    mock_args.incident_changed = True
    mock_args.entries = []

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock demisto.debug to capture the log message for existing tag
    mock_debug = mocker.patch("GoogleThreatIntelligenceASMIssues.demisto.debug")

    # Mock API endpoints
    # Return existing tags where "existing" tag already exists (case-insensitive)
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['issue_tags'].format('issue_456')}", json={"result": ["Existing", "Critical"]})
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_tags'].format('issue_456')}", json={"success": True})
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {"tags": ["urgent", "existing"]},
        "incident_changed": True,
        "entries": [],
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify API requests: get tags + only one tag update (for "urgent")
    history = requests_mock.request_history
    assert len(history) == 2  # (get tags, update tags)

    # Verify tags get request
    tags_get_request = history[0]
    assert tags_get_request.method == "GET"
    assert "tags" in tags_get_request.url

    # Verify only one tag update request (for "urgent" tag)
    tag_update_request = history[1]
    assert tag_update_request.method == "POST"
    assert "tags" in tag_update_request.url
    assert tag_update_request.json() == {"tag_name": "urgent"}

    # Verify debug message was logged for existing tag
    mock_debug.assert_any_call("Tag existing already exists for issue issue_456")


def test_update_remote_system_command_incident_reopen(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status ACTIVE and incident reopen.

    When:
    - Running update_remote_system_command

    Then:
    - Only status should be updated to 'open_in_progress'
    - No tags or notes should be processed
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {"closingUserId": "", "runStatus": ""}
    mock_args.incident_changed = True
    mock_args.entries = []

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoint for status update only
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"gtiasmissueuid": "issue_456", "id": "xsoar_incident_123"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {"closingUserId": "", "runStatus": ""},
        "incident_changed": True,
        "entries": [],
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify only one API request was made (status update only)
    history = requests_mock.request_history
    assert len(history) == 1

    # Verify status update request
    status_request = history[0]
    assert status_request.method == "POST"
    assert "status" in status_request.url
    assert status_request.json() == {"status": "open_in_progress"}


def test_update_remote_system_command_no_mirror_issue_id(mocker, requests_mock, mock_client):
    """
    Given:
    - Arguments with missing mirror Issue ID

    When:
    - Running update_remote_system_command

    Then:
    - No update should be made and no API calls should be sent.
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {}  # No issueID
    mock_args.inc_status = 2
    mock_args.delta = {"tags": ["test"]}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    args = {
        "remote_incident_id": "remote_123",
        "data": {},  # No issueID
        "inc_status": 2,
        "delta": {"tags": ["test"]},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify no API calls were made
    assert requests_mock.call_count == 0


def test_update_remote_system_command_closing_notes_mirroring(mocker, requests_mock, mock_client):
    """
    Given:
    - Incident is DONE and delta contains 'closingUserId'

    When:
    - Running update_remote_system_command

    Then:
    - Status should be updated to 'closed'
    - A closing note should be sent with the expected payload
    """
    from GoogleThreatIntelligenceASMIssues import update_remote_system_command

    # Mock UpdateRemoteSystemArgs to simulate a closed incident with closingUserId
    mock_args = mocker.Mock(
        remote_incident_id="remote_123",
        data={
            "gtiasmissueuid": "issue_456",
            "id": "xsoar_incident_123",
            "closeNotes": "All good",
            "closeReason": "Resolved",
            "closingUserId": "user_789",
        },
        inc_status=2,  # IncidentStatus.DONE
        delta={"closingUserId": "user_789"},
        incident_changed=True,
        entries=[],
    )
    mocker.patch("GoogleThreatIntelligenceASMIssues.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoints
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_status_update'].format('issue_456')}", json={"success": True})
    requests_mock.post(f"{BASE_URL}/{ENDPOINTS['issue_update_notes'].format('issue_456')}", json={"success": True})

    # Execute
    result = update_remote_system_command(
        mock_client,
        {
            "remote_incident_id": "remote_123",
            "data": mock_args.data,
            "inc_status": 2,
            "delta": {"closingUserId": "user_789"},
            "incident_changed": True,
            "entries": [],
        },
    )

    # Assert
    assert result == "remote_123"
    history = requests_mock.request_history
    assert history[0].json() == {"status": "closed"}
    expected_note = (
        "[Mirrored From XSOAR] | Incident ID: xsoar_incident_123 | Close Reason: Resolved |"
        "Closed By: user_789 | Close Notes: All good"
    )
    assert history[1].json() == {"note_text": expected_note}
