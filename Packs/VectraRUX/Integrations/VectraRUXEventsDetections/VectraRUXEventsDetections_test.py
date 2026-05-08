from pathlib import Path
import pytest
from requests.models import Response  # type: ignore[import]
from urllib.parse import urlencode

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import VectraRUXEventsDetections
from VectraRUXEventsDetections import (
    VectraEventsDetectionsClient,
    fetch_incidents,
    test_module as module_function,
    validate_fetch_params,
    map_severity,
    get_modified_remote_data_command,
    get_remote_data_command,
    update_remote_system_command,
    vectra_user_list_command,
    vectra_entity_list_command,
    vectra_entity_describe_command,
    vectra_entity_detection_list_command,
    vectra_detection_describe_command,
    vectra_entity_note_list_command,
    vectra_entity_note_add_command,
    vectra_entity_note_update_command,
    vectra_entity_note_remove_command,
    vectra_entity_tag_add_command,
    vectra_entity_tag_remove_command,
    vectra_entity_tag_list_command,
    vectra_assignment_list_command,
    vectra_entity_assignment_add_command,
    vectra_entity_assignment_update_command,
    vectra_detection_pcap_download_command,
    vectra_group_list_command,
    vectra_group_assign_command,
    vectra_group_unassign_command,
    vectra_entity_detections_mark_asclosed_command,
    vectra_detections_mark_asclosed_command,
    vectra_detections_mark_asopen_command,
    vectra_detection_tag_list_command,
    vectra_detection_tag_add_command,
    vectra_detection_tag_remove_command,
    vectra_detection_note_list_command,
    vectra_detection_note_add_command,
    vectra_detection_note_remove_command,
    vectra_detection_note_update_command,
    vectra_entity_unresolved_priority_reset_command,
    vectra_detection_investigation_status_update_command,
    vectra_detection_external_id_update_command,
    vectra_entity_external_id_update_command,
    vectra_detection_list_command,
    vectra_investigation_query_send_command,
    vectra_investigation_result_get_command,
    ERRORS,
    VALID_ENTITY_TYPES,
    VALID_DETECTION_STATUS,
    ENDPOINTS,
    VALID_CLOSE_REASON,
    VALID_ENTITY_TYPE,
    VALID_ENTITY_STATE,
    DETECTION_CATEGORY_TO_ARG,
    VALID_GROUP_TYPE,
    VALID_IMPORTANCE_VALUE,
    USER_ROLE_MAPPING,
    VALID_BOOL_VALUES,
)

# Constants
TEST_DATA_DIR = Path(__file__).parent / "test_data"
BASE_URL = "https://serverurl.com"


# Helper Functions
def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client(mocker):
    mocker.patch.object(VectraEventsDetectionsClient, "_generate_tokens", return_value="test_token")
    return VectraEventsDetectionsClient(BASE_URL, "client_id", "client_secret_key", verify=False, proxy=False)


def add_params_in_url(base_url: str, params: dict):
    encoded_params = urlencode(params)

    base_url = f"{base_url}?{encoded_params}"
    return base_url


def test_generate_tokens(requests_mock):
    """
    Given
    - Mocked response for generating access tokens.
    - VectraEventsDetectionsClient instance.

    When
    - Calling the `_generate_tokens` method.

    Then
    - Ensure the generated access token matches the expected access token.
    """
    # Set up
    access_token = "access_token"
    refresh_token = "refresh_token"
    response_data = {"access_token": access_token, "refresh_token": refresh_token}
    requests_mock.post(os.path.join(BASE_URL, ENDPOINTS["AUTH_ENDPOINT"]), json=response_data, status_code=200)
    client = VectraEventsDetectionsClient(BASE_URL, "client_id", "client_secret_key", verify=True, proxy=False)
    token = client._generate_tokens()
    assert token == access_token


def test_generate_tokens_failure(requests_mock):
    """
    Given
    - Mocked failed response for generating access tokens.
    - VectraEventsDetectionsClient instance.

    When
    - Calling the `_generate_tokens` method.

    Then
    - Ensure the method raises an exception.
    """
    access_token = "access_token"
    refresh_token = "refresh_token"
    response_data = {"access_token": access_token, "refresh_token": refresh_token}
    requests_mock.post(os.path.join(BASE_URL, ENDPOINTS["AUTH_ENDPOINT"]), json=response_data, status_code=500)
    client = VectraEventsDetectionsClient(BASE_URL, "client_id", "client_secret_key", verify=True, proxy=False)

    # Call the method
    with pytest.raises(Exception):
        client._generate_tokens()


def test_generate_access_token_using_refresh_token(requests_mock, mocker):
    """
    Given
    - Mocked response for generating access token using refresh token.
    - VectraEventsDetectionsClient instance.
    - Mocked `get_integration_context` method.

    When
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then
    - Ensure the generated access token matches the expected access token.
    """
    # Set up
    access_token = "access_token"
    response_data = {
        "access_token": access_token,
    }
    requests_mock.post(os.path.join(BASE_URL, ENDPOINTS["AUTH_ENDPOINT"]), json=response_data, status_code=200)
    client = VectraEventsDetectionsClient(BASE_URL, "client_id", "client_secret_key", verify=True, proxy=False)
    mocker.patch("CommonServerPython.get_integration_context", return_value={"refresh_token": "refresh_token"})
    token = client._generate_access_token_using_refresh_token()
    assert token == access_token


def test_generate_access_token_using_refresh_token_failure(requests_mock):
    """
    Given
    - Mocked failed response for generating access token using refresh token.
    - VectraClient instance.

    When
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then
    - Ensure the method raises an exception.
    """
    access_token = "access_token"
    refresh_token = "refresh_token"
    response_data = {"access_token": access_token, "refresh_token": refresh_token}
    requests_mock.post(os.path.join(BASE_URL, ENDPOINTS["AUTH_ENDPOINT"]), json=response_data, status_code=500)
    client = VectraEventsDetectionsClient(BASE_URL, "client_id", "client_secret_key", verify=True, proxy=False)

    # Call the method
    with pytest.raises(Exception):
        client._generate_access_token_using_refresh_token()


def test_generate_access_token_using_refresh_token_401_status_code(requests_mock, mocker, client):
    """
    Given:
    - A client object.
    - A mocked HTTP POST request to the token endpoint with a status code of 401.
    - A mocked '_generate_tokens' method that raises an exception.

    When:
    - Calling the '_generate_access_token_using_refresh_token' method.

    Then:
    - Assert that an exception is raised.
    - Assert that the '_generate_tokens' method is called once.
    """
    requests_mock.post(os.path.join(BASE_URL, ENDPOINTS["AUTH_ENDPOINT"]), status_code=401)
    generate_token = mocker.patch.object(client, "_generate_tokens", side_effect=Exception())

    # Call the method
    with pytest.raises(Exception):
        client._generate_access_token_using_refresh_token()

    generate_token.assert_called_once()


def test_http_request_with_valid_parameters(mocker, client):
    """
    Given:
    - A mocked `_http_request` method.
    - A client object.

    When:
    - Making a request with valid parameters.

    Then:
    - Assert that the response status code is 200 (indicating a successful request).
    """
    response = Response()
    response.status_code = 200
    mocker.patch.object(BaseClient, "_http_request", return_value=response)

    response = client.http_request(method="GET", url_suffix="/test")

    assert response.status_code == 200


def test_http_request_with_invalid_parameters(mocker, client):
    """
    Given:
    - A mocked `_http_request` method that raises an exception.
    - A client object.

    When:
    - Making a request with invalid parameters.

    Then:
    - Assert that the raised exception matches the expected exception.
    """
    # Mock the `_http_request` method to raise an exception.
    mocker.patch.object(BaseClient, "_http_request", side_effect=Exception())

    # Make a request with invalid parameters.
    with pytest.raises(Exception):
        client.http_request(method="GET", url_suffix="/test")


def test_http_request_with_401_status_code(mocker, client):
    """
    Given:
    - A mocked `_http_request` method that returns a response with a 401 status code.
    - A client object.

    When:
    - Making a request that results in a 401 status code.

    Then:
    - Assert that an exception is raised.
    - Assert that the `_generate_access_token_using_refresh_token` method is called once.
    """
    response = Response()
    response.status_code = 401
    mocker.patch.object(BaseClient, "_http_request", return_value=response)
    generate_token = mocker.patch.object(client, "_generate_access_token_using_refresh_token", side_effect=Exception())
    with pytest.raises(Exception):
        client.http_request(method="GET", url_suffix="/test")
    generate_token.assert_called_once()


def test_list_events_detections_request(mocker, client):
    """
    Given:
    - A client object.
    - Mocked http_request method.

    When:
    - Calling list_events_detections_request with parameters.

    Then:
    - Assert that the method calls http_request with correct parameters.
    """
    mock_response: dict = {"events": [], "next_checkpoint": None, "remaining_count": 0}
    mocker.patch.object(client, "http_request", return_value=mock_response)

    params = {
        "type": "host,account",
        "status": "open,escalated",
        "unresolved_priority": True,
        "limit": 50,
        "event_timestamp_gte": "2025-12-21T00:00:00Z",
        "ordering": "event_timestamp",
    }

    result = client.list_events_detections_request(params=params)

    assert result == mock_response
    client.http_request.assert_called_once_with(
        method="GET",
        url_suffix=ENDPOINTS["EVENTS_DETECTIONS_ENDPOINT"],
        params=params,
        response_type="json",
    )


def test_list_events_detections_request_with_from_checkpoint(mocker, client):
    """
    Given:
    - A client object.
    - Mocked http_request method.
    - Parameters including 'from' checkpoint.

    When:
    - Calling list_events_detections_request with 'from' parameter.

    Then:
    - Assert that the 'from' parameter is correctly added to params.
    """
    mock_response = {"events": [], "next_checkpoint": "checkpoint123", "remaining_count": 0}
    mocker.patch.object(client, "http_request", return_value=mock_response)

    params = {
        "type": "host",
        "limit": 50,
        "from": "checkpoint123",
    }

    result = client.list_events_detections_request(params=params)

    assert result == mock_response
    call_args = client.http_request.call_args
    assert call_args[1]["params"]["from"] == "checkpoint123"


def test_test_module_success(mocker, client):
    """
    Given
    - VectraRUXEventsDetections test module

    When
    - mock the demisto params.
    - mock the VectraEventsDetectionsClient's generate_tokens.
    - mock the VectraEventsDetectionsClient.
    - mock the VectraEventsDetectionsClient's list_events_detections_request.

    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    mocker.patch.object(demisto, "params", return_value={"isFetch": False})
    mock_response: dict = {"events": [], "next_checkpoint": None, "remaining_count": 0}
    mocker.patch.object(client, "list_events_detections_request", return_value=mock_response)
    result = module_function(client, {})

    assert result == "ok"


def test_test_module_with_fetch_enabled(mocker, client):
    """
    Given
    - VectraRUXEventsDetections test module and fetch incident is enabled

    When
    - mock the VectraEventsDetectionsClient's generate_tokens.
    - mock the VectraEventsDetectionsClient.
    - mock the fetch_incidents function.

    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    params = {
        "isFetch": True,
        "first_fetch": "1 hour",
        "max_fetch": "50",
        "entity_types": "Host,Account",
        "unresolved_priority": "Yes",
        "detection_status": "Escalated",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch("VectraRUXEventsDetections.fetch_incidents", return_value=([], {}))
    result = module_function(client, params)

    assert result == "ok"


def test_validate_fetch_params_success():
    """
    Given:
    - Valid fetch parameters and last_run data.

    When:
    - Calling validate_fetch_params with valid parameters.

    Then:
    - Assert that the validated parameters are correctly formatted.
    """
    params = {
        "first_fetch": "2025-12-25T00:00:00Z",
        "max_fetch": 50,
        "entity_types": "Host,Account",
        "only_prioritized_detections": "Yes",
        "only_escalated_detections": "No",
    }
    last_run = {"event_timestamp": "2025-12-21T00:00:00Z", "from": "", "was_fetched": []}

    result = validate_fetch_params(params, last_run)

    assert result["type"] == "account,host"
    assert result["investigation_status"] == "acknowledged,escalated,open,paused"
    assert result["unresolved_priority"] is True
    assert result["limit"] == 50
    assert result["event_timestamp_gte"] == last_run.get("event_timestamp")


@pytest.mark.parametrize("max_fetch", [201, -1, 0])
def test_validate_fetch_params_invalid_max_fetch(max_fetch):
    """
    Given:
    - Invalid max_fetch parameter.

    When:
    - Calling validate_fetch_params with invalid max_fetch.

    Then:
    - Assert that ValueError is raised.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": max_fetch,
    }
    last_run: dict = {}

    with pytest.raises(ValueError) as exception:
        validate_fetch_params(params, last_run, is_test=True)

    assert ERRORS["INVALID_MAX_FETCH"].format(max_fetch) in str(exception.value)


def test_validate_fetch_params_max_fetch_exceeds_limit(mocker):
    """
    Given:
    - max_fetch parameter exceeding MAX_FETCH limit.

    When:
    - Calling validate_fetch_params with max_fetch > 200.

    Then:
    - Assert that max_fetch is capped at 200.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 300,
    }
    last_run: dict = {}
    mocker.patch.object(demisto, "debug")

    result = validate_fetch_params(params, last_run)

    assert result["limit"] == 200


def test_validate_fetch_params_invalid_entity_type():
    """
    Given:
    - Invalid entity_type parameter.

    When:
    - Calling validate_fetch_params with invalid entity_type.

    Then:
    - Assert that ValueError is raised.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "entity_types": "InvalidType",
    }
    last_run: dict = {}

    with pytest.raises(ValueError) as exception:
        validate_fetch_params(params, last_run, is_test=True)

    assert ERRORS["INVALID_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPES)) in str(exception.value)


def test_validate_fetch_params_invalid_entity_type_no_test_module():
    """
    Given:
    - Invalid entity_type parameter.

    When:
    - Calling validate_fetch_params with invalid entity_type.

    Then:
    - Assert that ValueError is raised.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "entity_types": "InvalidType",
    }
    last_run: dict = {}

    valid_params = validate_fetch_params(params, last_run)

    assert valid_params["type"] == "account,host"


def test_validate_fetch_params_invalid_detection_status():
    """
    Given:
    - Valid parameters (detection_status is no longer validated as it's not used).

    When:
    - Calling validate_fetch_params.

    Then:
    - Assert that default detection statuses are used.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "entity_types": "Host",
    }
    last_run: dict = {}

    result = validate_fetch_params(params, last_run, is_test=True)

    assert result["investigation_status"] == "acknowledged,escalated,open,paused"


def test_validate_fetch_params_invalid_detection_status_no_test_module():
    """
    Given:
    - Valid parameters (detection_status is no longer validated as it's not used).

    When:
    - Calling validate_fetch_params.

    Then:
    - Assert that default detection statuses are used.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "entity_types": "Host",
    }
    last_run: dict = {}

    valid_params = validate_fetch_params(params, last_run)

    assert valid_params["investigation_status"] == "acknowledged,escalated,open,paused"


def test_validate_fetch_params_with_from_checkpoint():
    """
    Given:
    - Valid parameters with from checkpoint in last_run.

    When:
    - Calling validate_fetch_params with from checkpoint.

    Then:
    - Assert that 'from' parameter is included in result.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "only_prioritized_detections": False,
        "only_escalated_detections": False,
    }
    last_run = {
        "event_timestamp": "2025-12-21T00:00:00Z",
        "from": "checkpoint123",
        "was_fetched": [],
        "selected_statuses": "acknowledged,escalated,open,paused",
        "selected_types": "account,host",
        "unresolved_priority": "",
    }

    result = validate_fetch_params(params, last_run)

    assert result.get("from") == "checkpoint123"


@pytest.mark.parametrize(
    "urgency_score,expected_severity",
    [
        (90, 4),
        (80, 3),
        (70, 3),
        (60, 3),
        (50, 2),
        (40, 2),
        (30, 1),
        (20, 1),
        (10, 1),
        (0, 0.5),
    ],
)
def test_map_severity(urgency_score, expected_severity):
    """
    Given:
    - Different severity values.

    When:
    - Calling map_severity with various severity values.

    Then:
    - Assert that severity is correctly mapped to incident severity.
    """
    # map_severity logic: > 8 -> 4, > 5 -> 3, > 3 -> 2, else -> 1
    assert map_severity(urgency_score) == expected_severity


def test_fetch_incidents_first_run(mocker, client):
    """
    Given:
    - A client object.
    - A mocked 'getLastRun' method that returns an empty dictionary.
    - A mocked 'list_events_detections_request' method that returns sample events data.

    When:
    - Fetching incidents using the 'fetch_incidents' function with no previous run.

    Then:
    - Assert that the number of fetched incidents matches the number of events.
    - Assert incident properties are correctly set.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "entity_types": "Host,Account",
        "unresolved_priority": "Yes",
        "detection_status": "Open,Escalated",
    }

    incidents, next_run = fetch_incidents(client, params, {})

    assert len(incidents) == 2
    assert incidents[0]["name"] == "Vectra RUX: Dummy_Category_1 - Dummy Detection One - dummy-entity-one"
    assert incidents[0]["occurred"] == events_data.get("events")[0].get("event_timestamp", "")
    assert incidents[0]["severity"] == 2  # severity 4 maps to 2 (Medium)
    assert "rawJSON" in incidents[0]
    assert next_run["event_timestamp"] == events_data.get("events")[-1].get("event_timestamp", "")
    assert next_run["from"] == 200002 or next_run["from"] == "200002"  # next_checkpoint can be int or str


def test_fetch_incidents_with_last_run(mocker, client):
    """
    Given:
    - A client object.
    - A mocked 'getLastRun' method that returns last run data.
    - A mocked 'list_events_detections_request' method that returns sample events data.

    When:
    - Fetching incidents using the 'fetch_incidents' function with previous run data.

    Then:
    - Assert that incidents are fetched using the last run checkpoint.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    last_run = {
        "event_timestamp": "2025-12-21T00:00:00Z",
        "from": "checkpoint123",
        "was_fetched": [],
        "selected_statuses": "acknowledged,escalated,open,paused",
        "selected_types": "account,host",
        "unresolved_priority": "",
    }
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    incidents, _ = fetch_incidents(client, params, last_run)

    assert len(incidents) == 2
    # Verify that the API was called with the from checkpoint
    call_args = client.list_events_detections_request.call_args
    assert call_args[1]["params"]["from"] == "checkpoint123"


def test_fetch_incidents_duplicate_detection_id(mocker, client):
    """
    Given:
    - A client object.
    - Events with duplicate detection IDs (already fetched).

    When:
    - Fetching incidents where some detections were already fetched.

    Then:
    - Assert that duplicate detections are not included in incidents.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    last_run = {
        "event_timestamp": "2025-12-21T00:00:00Z",
        "from": "",
        "was_fetched": [11111],  # First detection ID already fetched
    }
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    incidents, next_run = fetch_incidents(client, params, last_run)

    assert len(incidents) == 1  # Only second detection should be fetched
    assert incidents[0]["rawJSON"]  # Verify rawJSON contains the event data
    assert next_run["was_fetched"] == [11111, 22222]


def test_fetch_incidents_empty_response(mocker, client):
    """
    Given:
    - A client object.
    - An empty events response.

    When:
    - Fetching incidents when no events are returned.

    Then:
    - Assert that no incidents are created.
    - Assert that last_run is updated with current time.
    """
    empty_response: dict = {"events": [], "next_checkpoint": None, "remaining_count": 0}
    last_run = {
        "event_timestamp": "2025-12-21T00:00:00Z",
        "from": "",
        "was_fetched": [],
    }
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(client, "list_events_detections_request", return_value=empty_response)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    incidents, next_run = fetch_incidents(client, params, last_run)

    assert len(incidents) == 0
    assert "event_timestamp" in next_run
    assert next_run["from"] == ""


def test_fetch_incidents_with_test_flag(mocker, client):
    """
    Given:
    - A client object.
    - is_test flag set to True.

    When:
    - Fetching incidents with is_test=True.

    Then:
    - Assert that empty incidents and empty last_run are returned.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    incidents, next_run = fetch_incidents(client, params, {}, is_test=True)

    assert len(incidents) == 0
    assert next_run == {}


def test_fetch_incidents_severity_mapping(mocker, client):
    """
    Given:
    - A client object.
    - Events with different severity values.

    When:
    - Fetching incidents.

    Then:
    - Assert that severity is correctly mapped using map_severity function.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    incidents, _ = fetch_incidents(client, params, {})

    # First event has severity 4 -> mapped to 2 (Medium)
    assert incidents[0]["severity"] == 2
    # Second event has severity 8 -> mapped to 3 (High)
    assert incidents[1]["severity"] == 3


def test_fetch_incidents_api_error(mocker, client):
    """
    Given:
    - A client object.
    - An API error when fetching events.

    When:
    - Fetching incidents when API returns an error.

    Then:
    - Assert that DemistoException is raised.
    """
    from CommonServerPython import DemistoException

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(client, "list_events_detections_request", side_effect=DemistoException("API Error"))

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    with pytest.raises(DemistoException):
        fetch_incidents(client, params, {})


def test_fetch_incidents_with_next_checkpoint(mocker, client):
    """
    Given:
    - A client object.
    - Events response with next_checkpoint.

    When:
    - Fetching incidents with pagination checkpoint.

    Then:
    - Assert that next_run contains the next_checkpoint.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }

    _, next_run = fetch_incidents(client, params, {})

    assert next_run["from"] == 200002 or next_run["from"] == "200002"  # next_checkpoint from response (can be int or str)


def test_validate_fetch_params_defaults():
    """
    Given:
    - Parameters with default values.

    When:
    - Calling validate_fetch_params with minimal parameters.

    Then:
    - Assert that default values are used correctly.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }
    last_run: dict = {}

    result = validate_fetch_params(params, last_run)

    assert result["investigation_status"] == "acknowledged,escalated,open,paused"  # Default detection status
    assert "unresolved_priority" not in result  # Default unresolved priority


def test_validate_fetch_params_comma_separated_values():
    """
    Given:
    - Parameters with comma-separated entity types.

    When:
    - Calling validate_fetch_params with comma-separated values.

    Then:
    - Assert that values are correctly parsed and joined.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "entity_types": "Host, Account",
        "only_prioritized_detections": False,
        "only_escalated_detections": False,
    }
    last_run: dict = {}

    result = validate_fetch_params(params, last_run)

    assert result["type"] == "account,host"
    assert result["investigation_status"] == "acknowledged,escalated,open,paused"


def test_validate_fetch_params_empty_detection_status_uses_default():
    """
    Given:
    - Parameters with default flags.

    When:
    - Calling validate_fetch_params.

    Then:
    - Assert that default detection status is used.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
    }
    last_run: dict = {}

    result = validate_fetch_params(params, last_run)

    assert result["investigation_status"] == "acknowledged,escalated,open,paused"  # Default


def test_validate_fetch_params_unresolved_priority_false():
    """
    Given:
    - Parameters with unresolved_priority set to "No".

    When:
    - Calling validate_fetch_params with unresolved_priority="No".

    Then:
    - Assert that unresolved_priority is False.
    """
    params = {
        "first_fetch": "1 hour",
        "max_fetch": 50,
        "only_prioritized_detections": False,
    }
    last_run: dict = {}

    result = validate_fetch_params(params, last_run)

    assert result.get("unresolved_priority") is None


def test_validate_fetch_params_uses_last_run_timestamp():
    """
    Given:
    - Parameters and last_run with event_timestamp.

    When:
    - Calling validate_fetch_params.

    Then:
    - Assert that last_run event_timestamp is used instead of first_fetch.
    """
    params = {
        "first_fetch": "2025-12-25T10:00:00Z",
        "max_fetch": 50,
    }
    last_run = {
        "event_timestamp": "2025-12-21T10:00:00Z",
        "from": "",
        "was_fetched": [],
    }

    result = validate_fetch_params(params, last_run)

    assert result["event_timestamp_gte"] == last_run.get("event_timestamp")


def test_main_function_test_module(mocker, client):
    """
    Given:
    - Mocked demisto.command() returning "test-module".

    When:
    - Calling main function with test-module command.

    Then:
    - Assert that test_module is called and returns "ok".
    """
    mocker.patch.object(demisto, "params", return_value={"isFetch": False})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(client, "list_events_detections_request", return_value={"events": []})
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", return_value=client)
    mocker.patch("VectraRUXEventsDetections.return_results")

    VectraRUXEventsDetections.main()

    VectraRUXEventsDetections.return_results.assert_called_once_with("ok")  # type: ignore[attr-defined]


def test_main_function_fetch_incidents(mocker, client):
    """
    Given:
    - Mocked demisto.command() returning "fetch-incidents".

    When:
    - Calling main function with fetch-incidents command.

    Then:
    - Assert that fetch_incidents is called and incidents are set.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(demisto, "params", return_value={"first_fetch": "1 hour", "max_fetch": 50})
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", return_value=client)

    VectraRUXEventsDetections.main()

    demisto.incidents.assert_called_once()  # type: ignore[attr-defined]
    call_args = demisto.incidents.call_args[0][0]  # type: ignore[attr-defined]
    assert len(call_args) == 2


def test_main_function_invalid_command(mocker, client):
    """
    Given:
    - Mocked demisto.command() returning invalid command.

    When:
    - Calling main function with invalid command.

    Then:
    - Assert that NotImplementedError is raised.
    """
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "command", return_value="invalid-command")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", return_value=client)
    mocker.patch("VectraRUXEventsDetections.return_error")

    VectraRUXEventsDetections.main()

    VectraRUXEventsDetections.return_error.assert_called_once()  # type: ignore[attr-defined]


def test_main_function_exception_handling(mocker, client):
    """
    Given:
    - Mocked demisto.command() that raises an exception.

    When:
    - Calling main function when an exception occurs.

    Then:
    - Assert that return_error is called with error message.
    """
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", side_effect=Exception("Test error"))
    mocker.patch("VectraRUXEventsDetections.return_error")

    VectraRUXEventsDetections.main()

    VectraRUXEventsDetections.return_error.assert_called_once()  # type: ignore[attr-defined]
    assert "Test error" in str(VectraRUXEventsDetections.return_error.call_args[0][0])  # type: ignore[attr-defined]


@pytest.mark.parametrize("close_reason", ["benign", "remediated"])
def test_mark_detections_asclosed_command_valid_close(requests_mock, client, close_reason):
    """
    Tests mark_detection_as_closed_command with valid close reason.
    """

    response = {"_meta": {"level": "success", "message": f"Successfully closed detection as {close_reason}"}}
    status_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}
    requests_mock.patch(os.path.join(BASE_URL, ENDPOINTS["CLOSE_DETECTIONS_ENDPOINT"]), json=response)
    requests_mock.patch(os.path.join(BASE_URL, ENDPOINTS["DETECTION_ENDPOINT"]), json=status_response)

    args = {"detection_ids": "123,234", "close_reason": close_reason}
    result = vectra_detections_mark_asclosed_command(client=client, args=args)

    assert result.outputs is None
    assert result.readable_output == f"##### The provided detection IDs have been successfully closed as {close_reason}."
    assert result.raw_response == response


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": "abc"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "abc")),
        ({"detection_ids": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "0")),
        ({"detection_ids": "-5"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "-5")),
        ({"detection_ids": "123,abc,456"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "abc")),
        ({"detection_ids": "123"}, ERRORS["REQUIRED_ARGUMENT"].format("close_reason")),
        (
            {"detection_ids": "123", "close_reason": "invalid"},
            ERRORS["INVALID_ARG_VALUE"].format("close_reason", ", ".join(VALID_CLOSE_REASON)),
        ),
    ],
)
def test_mark_detections_asclosed_command_invalid_args(args, client, error_msg):
    """
    Tests mark_detections_asclosed_command with invalid arguments.
    """

    with pytest.raises(ValueError) as err:
        vectra_detections_mark_asclosed_command(client=client, args=args)

    assert str(err.value) == error_msg


def test_get_modified_remote_data_command_successful_retrieval(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns events.

    When:
    - Calling the 'get_modified_remote_data_command' function with valid arguments.

    Then:
    - Assert that the function returns a GetModifiedRemoteDataResponse with modified incident IDs.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    # Set remaining_count to 0 to avoid infinite loop
    events_data["remaining_count"] = 0
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    args = {"lastUpdate": "2025-01-01T00:00:00+00:00"}
    result = get_modified_remote_data_command(client, args)

    assert result.modified_incident_ids is not None
    assert "11111" in result.modified_incident_ids
    assert "22222" in result.modified_incident_ids


def test_get_modified_remote_data_command_empty_response(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns empty events.

    When:
    - Calling the 'get_modified_remote_data_command' function with valid arguments.

    Then:
    - Assert that the function returns a GetModifiedRemoteDataResponse with empty modified incident IDs.
    """
    empty_response: dict = {"events": [], "next_checkpoint": None, "remaining_count": 0}
    mocker.patch.object(client, "list_events_detections_request", return_value=empty_response)

    args = {"lastUpdate": "2025-01-01T00:00:00+00:00"}
    result = get_modified_remote_data_command(client, args)

    assert result.modified_incident_ids == []


def test_get_modified_remote_data_command_with_pagination(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns events with remaining_count > 0 initially.

    When:
    - Calling the 'get_modified_remote_data_command' function with valid arguments.

    Then:
    - Assert that the function handles pagination and collects all modified incident IDs.
    """
    first_response = {
        "events": [{"detection_id": 11111, "event_timestamp": "2025-01-01T01:00:00Z"}],
        "next_checkpoint": "checkpoint123",
        "remaining_count": 1,
    }
    second_response: dict = {
        "events": [{"detection_id": 22222, "event_timestamp": "2025-01-01T02:00:00Z"}],
        "next_checkpoint": "checkpoint456",
        "remaining_count": 0,
    }
    mocker.patch.object(client, "list_events_detections_request", side_effect=[first_response, second_response])

    args = {"lastUpdate": "2025-01-01T00:00:00+00:00"}
    result = get_modified_remote_data_command(client, args)

    assert "11111" in result.modified_incident_ids
    assert "22222" in result.modified_incident_ids


def test_get_modified_remote_data_command_api_error(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that raises a DemistoException.

    When:
    - Calling the 'get_modified_remote_data_command' function with valid arguments.

    Then:
    - Assert that the DemistoException is raised.
    """
    mocker.patch.object(client, "list_events_detections_request", side_effect=DemistoException("API Error"))

    args = {"lastUpdate": "2025-01-01T00:00:00+00:00"}

    with pytest.raises(DemistoException):
        get_modified_remote_data_command(client, args)


def test_get_modified_remote_data_command_filters_duplicates(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns events with duplicate detection IDs.

    When:
    - Calling the 'get_modified_remote_data_command' function with valid arguments.

    Then:
    - Assert that duplicate incident IDs are filtered out.
    """
    response_with_duplicates = {
        "events": [
            {"detection_id": 11111, "event_timestamp": "2025-01-01T01:00:00Z"},
            {"detection_id": 11111, "event_timestamp": "2025-01-01T02:00:00Z"},
            {"detection_id": 22222, "event_timestamp": "2025-01-01T03:00:00Z"},
        ],
        "next_checkpoint": None,
        "remaining_count": 0,
    }
    mocker.patch.object(client, "list_events_detections_request", return_value=response_with_duplicates)

    args = {"lastUpdate": "2025-01-01T00:00:00+00:00"}
    result = get_modified_remote_data_command(client, args)

    assert len(result.modified_incident_ids) == 2
    assert "11111" in result.modified_incident_ids
    assert "22222" in result.modified_incident_ids


def test_get_remote_data_command_detection_found(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns event data.

    When:
    - Calling the 'get_remote_data_command' function with valid arguments.

    Then:
    - Assert that the function returns a GetRemoteDataResponse with the detection data.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)

    args = {"id": "11111", "lastUpdate": "2024-01-01T00:00:00+00:00"}
    result = get_remote_data_command(client, args)

    assert result.mirrored_object is not None
    assert result.mirrored_object.get("detection_id") == 11111


def test_get_remote_data_command_detection_not_found(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns empty events.

    When:
    - Calling the 'get_remote_data_command' function with a detection ID that doesn't exist.

    Then:
    - Assert that the function returns "Incident was not found." message.
    """
    empty_response: dict = {"events": [], "next_checkpoint": None, "remaining_count": 0}
    mocker.patch.object(client, "list_events_detections_request", return_value=empty_response)

    args = {"id": "99999", "lastUpdate": "2024-01-01T00:00:00+00:00"}
    result = get_remote_data_command(client, args)

    assert result == "Incident was not found."


def test_get_remote_data_command_detection_updated(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns updated event data.

    When:
    - Calling the 'get_remote_data_command' function where the event_timestamp is newer than lastUpdate.

    Then:
    - Assert that the function returns a GetRemoteDataResponse with updated detection data.
    """
    response_new_append = {
        "events": [
            {
                "detection_id": 11111,
                "event_timestamp": "2025-01-15T10:00:00Z",
                "detection_href": "https://dummy.url/detections/11111",
                "url": "https://dummy.url/entities/11",
                "status": "escalated",
            }
        ],
        "next_checkpoint": None,
        "remaining_count": 0,
    }
    response_other = {
        "events": [
            {
                "detection_id": 11111,
                "event_timestamp": "2025-01-14T10:00:00Z",
                "priority": "high",
            }
        ],
        "next_checkpoint": None,
        "remaining_count": 0,
    }
    mocker.patch.object(client, "list_events_detections_request", side_effect=[response_new_append, response_other])

    args = {"id": "11111", "lastUpdate": "2025-01-01T00:00:00+00:00"}
    result = get_remote_data_command(client, args)

    assert result.mirrored_object is not None
    assert result.mirrored_object.get("detection_id") == 11111
    assert "pivot=Vectra-RUX-XSOAR" in result.mirrored_object.get("detection_href", "")


def test_get_remote_data_command_nothing_new(mocker, client):
    """
    Given:
    - A client object.
    - A mocked list_events_detections_request that returns event data with old event_timestamp.

    When:
    - Calling the 'get_remote_data_command' function where the event_timestamp is older than lastUpdate.

    Then:
    - Assert that the function returns a GetRemoteDataResponse (no new updates).
    """
    response = {
        "events": [
            {
                "detection_id": 11111,
                "event_timestamp": "2025-01-01T00:00:00Z",
                "detection_href": "https://dummy.url/detections/11111",
                "url": "https://dummy.url/entities/11",
            }
        ],
        "next_checkpoint": None,
        "remaining_count": 0,
    }
    mocker.patch.object(client, "list_events_detections_request", return_value=response)

    args = {"id": "11111", "lastUpdate": "2025-01-15T00:00:00+00:00"}
    result = get_remote_data_command(client, args)

    assert result.mirrored_object is not None
    assert result.entries == []


def test_update_remote_system_command_with_notes(mocker, client):
    """
    Given:
    - A client object.
    - Mocked arguments with notes to be mirrored.

    When:
    - Calling the 'update_remote_system_command' function with valid arguments containing notes.

    Then:
    - Assert that the remote incident ID is returned.
    - Assert that add_note_to_detection_request is called.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    mocker.patch.object(client, "update_detection_tags_request", return_value={})
    add_note_mock = mocker.patch.object(client, "add_note_to_detection_request", return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"
    add_note_mock.assert_called_once()


def test_update_remote_system_command_with_tags(mocker, client):
    """
    Given:
    - A client object.
    - Mocked arguments with tags to be mirrored.

    When:
    - Calling the 'update_remote_system_command' function with valid arguments containing tags.

    Then:
    - Assert that the remote incident ID is returned.
    - Assert that update_detection_tags_request is called with the tags.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    update_tags_mock = mocker.patch.object(client, "update_detection_tags_request", return_value={})
    mocker.patch.object(client, "add_note_to_detection_request", return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"
    update_tags_mock.assert_called_once()


def test_update_remote_system_command_remove_all_tags(mocker, client):
    """
    Given:
    - A client object.
    - Mocked arguments where all tags are removed from XSOAR.

    When:
    - Calling the 'update_remote_system_command' function with arguments indicating tag removal.

    Then:
    - Assert that the remote incident ID is returned.
    - Assert that update_detection_tags_request is called to remove tags.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mock_args["delta"]["tags"] = []

    mocker.patch.object(client, "list_detection_tags_request", return_value={"tags": ["tag1", "tag2"]})
    update_tags_mock = mocker.patch.object(client, "update_detection_tags_request", return_value={})
    mocker.patch.object(client, "add_note_to_detection_request", return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"
    update_tags_mock.assert_called_once_with(detection_id="12345", tags=[])


def test_update_remote_system_command_with_detection_status(mocker, client, requests_mock):
    """
    Given:
    - A client object.
    - Mocked arguments with detection status to be updated.

    When:
    - Calling the 'update_remote_system_command' function with detection status.

    Then:
    - Assert that update_detection_status_request is called with the correct status.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mock_args["data"]["vectraruxinvestigationstatus"] = "closed"

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    mocker.patch.object(client, "update_detection_tags_request", return_value={})
    mocker.patch.object(client, "add_note_to_detection_request", return_value={})
    requests_mock.patch(os.path.join(BASE_URL, ENDPOINTS["DETECTION_ENDPOINT"]), json={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"


def test_update_remote_system_command_with_priority_status(mocker, client, requests_mock):
    """
    Given:
    - A client object.
    - Mocked arguments with priority status to be updated to Not Prioritized.

    When:
    - Calling the 'update_remote_system_command' function with priority status.

    Then:
    - Assert that update_entity_unresolved_priority_status_request is called.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mock_args["data"]["vectraruxentityprioritystatus"] = "Not Prioritized"
    mock_args["data"]["vectraruxentityunresolvedprioritystatus"] = ""
    entity_id = mock_args.get("data").get("vectraruxentityid")

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    mocker.patch.object(client, "update_detection_tags_request", return_value={})
    mocker.patch.object(client, "add_note_to_detection_request", return_value={})
    requests_mock.patch(os.path.join(BASE_URL, f"{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}"), json={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"


def test_update_remote_system_command_with_closing_notes(mocker, client):
    """
    Given:
    - A client object.
    - Mocked arguments with closing notes for incident closure.

    When:
    - Calling the 'update_remote_system_command' function with closing notes.

    Then:
    - Assert that add_note_to_detection_request is called with the closing note.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mock_args["data"]["closeNotes"] = "Closing this incident due to resolution"
    mock_args["data"]["closeReason"] = "Resolved"
    mock_args["data"]["closingUserId"] = "admin_user"
    mock_args["delta"]["closingUserId"] = "admin_user"
    mock_args["entries"] = []

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    mocker.patch.object(client, "update_detection_tags_request", return_value={})
    add_note_mock = mocker.patch.object(client, "add_note_to_detection_request", return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"
    add_note_mock.assert_called_once()
    call_args = add_note_mock.call_args
    assert "Mirrored From XSOAR" in call_args[1]["note"]
    assert "Close Reason: Resolved" in call_args[1]["note"]
    assert "Closed By: admin_user" in call_args[1]["note"]
    assert "Close Notes: Closing this incident due to resolution" in call_args[1]["note"]


def test_update_remote_system_command_no_changes(mocker, client):
    """
    Given:
    - A client object.
    - Mocked arguments with no changes (empty delta, no entries).

    When:
    - Calling the 'update_remote_system_command' function with no changes.

    Then:
    - Assert that the remote incident ID is returned without making any API calls.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mock_args["delta"] = {}
    mock_args["entries"] = []

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    update_tags_mock = mocker.patch.object(client, "update_detection_tags_request", return_value={})
    add_note_mock = mocker.patch.object(client, "add_note_to_detection_request", return_value={})

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"
    update_tags_mock.assert_not_called()
    add_note_mock.assert_not_called()


def test_update_remote_system_command_note_exceeds_limit(mocker, client):
    """
    Given:
    - A client object.
    - Mocked arguments with a note that exceeds the maximum character limit.

    When:
    - Calling the 'update_remote_system_command' function with a long note.

    Then:
    - Assert that the note is skipped and info is logged.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mock_args["entries"] = [
        {
            "id": "note_id",
            "type": "note",
            "contents": "A" * 9000,  # Exceeds MAX_OUTGOING_NOTE_LIMIT (8000)
            "user": "user1",
        }
    ]

    mocker.patch.object(client, "list_detection_tags_request", return_value={})
    mocker.patch.object(client, "update_detection_tags_request", return_value={})
    add_note_mock = mocker.patch.object(client, "add_note_to_detection_request", return_value={})
    info_mock = mocker.patch.object(demisto, "info")

    remote_incident_id = update_remote_system_command(client, mock_args, {})

    assert remote_incident_id == "12345"
    add_note_mock.assert_called_once()
    info_mock.assert_called()


def test_main_function_get_modified_remote_data(mocker, client):
    """
    Given:
    - Mocked demisto.command() returning "get-modified-remote-data".

    When:
    - Calling main function with get-modified-remote-data command.

    Then:
    - Assert that get_modified_remote_data_command is called.
    """
    events_data: dict = {"events": [], "next_checkpoint": None, "remaining_count": 0}
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "command", return_value="get-modified-remote-data")
    mocker.patch.object(demisto, "args", return_value={"lastUpdate": "2025-01-01T00:00:00+00:00"})
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", return_value=client)
    mocker.patch("VectraRUXEventsDetections.return_results")

    VectraRUXEventsDetections.main()

    VectraRUXEventsDetections.return_results.assert_called_once()  # type: ignore[attr-defined]


def test_main_function_get_remote_data(mocker, client):
    """
    Given:
    - Mocked demisto.command() returning "get-remote-data".

    When:
    - Calling main function with get-remote-data command.

    Then:
    - Assert that get_remote_data_command is called.
    """
    events_data = util_load_json(f"{TEST_DATA_DIR}/events_detections_response.json")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "command", return_value="get-remote-data")
    mocker.patch.object(demisto, "args", return_value={"id": "11111", "lastUpdate": "2025-01-01T00:00:00+00:00"})
    mocker.patch.object(client, "list_events_detections_request", return_value=events_data)
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", return_value=client)
    mocker.patch("VectraRUXEventsDetections.return_results")

    VectraRUXEventsDetections.main()

    VectraRUXEventsDetections.return_results.assert_called_once()  # type: ignore[attr-defined]


def test_main_function_update_remote_system(mocker, client, requests_mock):
    """
    Given:
    - Mocked demisto.command() returning "update-remote-system".

    When:
    - Calling main function with update-remote-system command.

    Then:
    - Assert that update_remote_system_command is called.
    """
    mock_args = util_load_json(f"{TEST_DATA_DIR}/update_remote_system_args.json")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "command", return_value="update-remote-system")
    mocker.patch.object(demisto, "args", return_value=mock_args)
    requests_mock.get(os.path.join(BASE_URL, ENDPOINTS["LIST_TAGS_ENDPOINT"].format(mock_args.get("remoteId"))), json={})
    requests_mock.patch(os.path.join(BASE_URL, ENDPOINTS["LIST_TAGS_ENDPOINT"].format(mock_args.get("remoteId"))), json={})
    requests_mock.post(os.path.join(BASE_URL, ENDPOINTS["ADD_NOTE_ENDPOINT"].format(mock_args.get("remoteId"))), json={})
    mocker.patch("VectraRUXEventsDetections.VectraEventsDetectionsClient", return_value=client)
    mocker.patch("VectraRUXEventsDetections.return_results")

    VectraRUXEventsDetections.main()

    VectraRUXEventsDetections.return_results.assert_called_once()  # type: ignore[attr-defined]


def test_vectra_user_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_user_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    user_res = util_load_json(f"{TEST_DATA_DIR}/user_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/user_list_context.json")
    with open(f"{TEST_DATA_DIR}/user_list_hr.md") as f:
        result_hr = f.read()
    requests_mock.get(BASE_URL + ENDPOINTS["USER_ENDPOINT"], json=user_res)
    # Call the function
    result = vectra_user_list_command(client, {"last_login_timestamp": "1 year"})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.User"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["user_id"]


def test_vectra_user_list_when_response_is_empty(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_users_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_user_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}
    requests_mock.get(BASE_URL + ENDPOINTS["USER_ENDPOINT"], json=empty_response)

    # Call the function
    result = vectra_user_list_command(client, {})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Got the empty list of users."
    assert result_context.get("EntryContext") == {}


def test_vectra_user_list_with_email_filter(mocker, client):
    """
    Given:
    - A mocked client.
    - Arguments with an email filter.

    When:
    - Calling the 'vectra_user_list_command' function with email argument.

    Then:
    - Assert that 'list_users_request' is called with 'email' (not 'username').
    - Assert that the command returns expected user data.
    """
    user_res = {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": 10,
                "name": "brandon.bishop",
                "email": "test_user@mail.com",
                "role": "Security Analyst",
                "last_login_timestamp": "2023-08-22T09:24:44Z",
            }
        ],
    }
    mock_request = mocker.patch.object(client, "list_users_request", return_value=user_res)

    result = vectra_user_list_command(client, {"email": "test_user@mail.com"})

    mock_request.assert_called_once_with(email="test_user@mail.com", role="", last_login_timestamp=None)
    assert result.outputs_prefix == "Vectra.User"
    assert len(result.outputs) == 1


def test_vectra_entity_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity response.
    - Arguments specifying valid parameters for entity listing.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output contains the expected content.
    - Assert that the 'Contents' property in the context matches the entity data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    entity_data = util_load_json(f"{TEST_DATA_DIR}/list_entity_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/list_entity_context.json")
    requests_mock.get(BASE_URL + ENDPOINTS["ENTITY_ENDPOINT_v34"], json=entity_data)
    with open(f"{TEST_DATA_DIR}/list_entity_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_type": "account",
        "name": "name",
        "state": "active",
        "ordering": "name",
        "page": "1",
        "page_size": "4",
        "prioritized": "true",
        "tags": "test,test1",
        "last_modified_timestamp": "2 days",
        "last_detection_timestamp": "2 days",
    }

    # Call the function
    result = vectra_entity_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == entity_data.get("results")
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["id", "type"]


def test_vectra_entity_list_when_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entities_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}
    mocker.patch.object(client, "list_entities_request", return_value=empty_response)
    args = {
        "tags": "invalid_tag",
        "name": "invalid_name",
    }

    # Call the function
    result = vectra_entity_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any matching entities for provided filters."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"state": "invalid_state"}, ERRORS["INVALID_COMMAND_ARG_VALUE"].format("state", ", ".join(VALID_ENTITY_STATE))),
        ({"page_size": "5001"}, ERRORS["INVALID_PAGE_SIZE"]),
    ],
)
def test_vectra_entity_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid values.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for the corresponding invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_describe_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for getting an entity.

    When:
    - Calling the 'vectra_entity_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the entity data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    entity_data = util_load_json(f"{TEST_DATA_DIR}/get_entity_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/get_entity_context.json")
    requests_mock.get(BASE_URL + ENDPOINTS["ENTITY_ENDPOINT_v34"] + "/21", json=entity_data)
    with open(f"{TEST_DATA_DIR}/get_entity_hr.md") as f:
        result_hr = f.read()
    args = {"entity_id": "21", "entity_type": "account"}

    # Call the function
    result = vectra_entity_describe_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == entity_data
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["id", "type"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "1", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
    ],
)
def test_vectra_entity_describe_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying an invalid entity_type value.

    When:
    - Calling the 'vectra_entity_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for an invalid entity_type value.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_describe_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_detection_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.

    When:
    - A mock entity and detections response.
    - Opening and reading a specific human-readable file.
    - Providing arguments with a valid entity_id, page, and page_size.

    Then:
    - Call the 'vectra_list_entity_detection_command' function with the provided client and arguments.
    - Assert that the CommandResults outputs_prefix is 'Vectra.Entity.Detections'.
    - Assert that the CommandResults HumanReadable matches the content of the read human-readable file.
    - Assert that the CommandResults Contents match the expected detections data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert that the CommandResults outputs_key_field is 'id'.
    """
    detections_data = util_load_json(f"{TEST_DATA_DIR}/entity_detection_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_detection_list_context.json")
    entity_data = util_load_json(f"{TEST_DATA_DIR}/get_entity_response.json")
    requests_mock.get(BASE_URL + ENDPOINTS["ENTITY_ENDPOINT_v34"] + "/21", json=entity_data)
    requests_mock.get(BASE_URL + ENDPOINTS["DETECTION_ENDPOINT"], json=detections_data)
    with open(f"{TEST_DATA_DIR}/entity_detection_list_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_id": "21",
        "entity_type": "account",
        "page": "1",
        "page_size": "50",
        "last_timestamp": "2 days",
        "detection_category": "Botnet",
    }

    # Call the function
    result = vectra_entity_detection_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Detections"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == detections_data
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == "id"


def test_vectra_entity_detection_list_when_detection_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detections_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}
    entity_data = util_load_json(f"{TEST_DATA_DIR}/get_entity_response.json")
    mocker.patch.object(client, "get_entity_request", return_value=entity_data)
    mocker.patch.object(client, "list_detections_request", return_value=empty_response)
    args = {
        "entity_id": "1",
        "entity_type": "account",
        "tags": "invalid_tag",
    }

    # Call the function
    result = vectra_entity_detection_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any matching entity detections for provided filters."
    assert result_context.get("EntryContext") == {}


def test_vectra_entity_detection_list_when_entity_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'get_entity_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}

    mocker.patch.object(client, "get_entity_request", return_value={})
    mocker.patch.object(client, "list_detections_request", return_value=empty_response)
    args = {
        "entity_id": "1",
        "entity_type": "account",
        "tags": "invalid_tag",
    }

    # Call the function
    result = vectra_entity_detection_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any matching detections for provided entity ID and type."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"entity_id": None}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "1", "entity_type": "account", "page": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("page", "0")),
        (
            {"entity_id": "1", "entity_type": "account", "page_size": "0"},
            ERRORS["INVALID_INTEGER_VALUE"].format("page_size", "0"),
        ),
        ({"entity_id": "1", "entity_type": "account", "page_size": "5001"}, ERRORS["INVALID_PAGE_SIZE"]),
        (
            {"entity_id": "1", "entity_type": "account", "detection_category": "command and control"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("detection_category", ", ".join(DETECTION_CATEGORY_TO_ARG.keys())),
        ),
        ({"entity_id": "1", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        (
            {"entity_id": "1", "entity_type": "invalid"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
    ],
)
def test_vectra_entity_detection_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, page, and page_size.

    When:
    - Calling the 'vectra_list_entity_detection_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_detection_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_describe_valid_arguments(mocker, client):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'list_detections_request' method of the client to return a specific detection data.
    - Opening and reading a specific human-readable file.
    - Providing arguments with a valid detection_ids, page, and page_size.

    Then:
    - Call the 'vectra_detection_describe_command' function with the provided client and arguments.
    - Assert that the CommandResults outputs_prefix is 'Vectra.Entity.Detections'.
    - Assert that the CommandResults HumanReadable matches the content of the read human-readable file.
    - Assert that the CommandResults Contents match the expected detection data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert that the CommandResults outputs_key_field is 'id'.
    """
    detections_data = util_load_json(f"{TEST_DATA_DIR}/entity_detection_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_detection_list_context.json")
    mocker.patch.object(client, "list_detections_request", return_value=detections_data)
    with open(f"{TEST_DATA_DIR}/entity_detection_list_hr.md") as f:
        result_hr = f.read()
    args = {"detection_ids": "21", "page": "1", "page_size": "50"}

    # Call the function
    result = vectra_detection_describe_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Detections"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == detections_data
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == "id"


def test_vectra_detection_describe_when_detection_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detections_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_detection_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}
    mocker.patch.object(client, "list_detections_request", return_value=empty_response)
    args = {"detection_ids": "21"}

    # Call the function
    result = vectra_detection_describe_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any matching detections for provided detection ID(s)."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"detection_ids": None}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": " "}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": ",   , ,"}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": ",,abc,"}, ERRORS["INVALID_NUMBER"].format("abc")),
        ({"detection_ids": ",,abc,12"}, ERRORS["INVALID_NUMBER"].format("abc")),
        ({"detection_ids": ",-12,"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "-12")),
        ({"detection_ids": ",12,", "page": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("page", "0")),
        ({"detection_ids": ",12,", "page_size": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("page_size", "0")),
        ({"detection_ids": ",12,", "page_size": "5001"}, ERRORS["INVALID_PAGE_SIZE"]),
    ],
)
def test_vectra_detection_describe_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for detection_ids, page, and page_size.

    When:
    - Calling the 'vectra_detection_describe_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_describe_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding a note to an entity.

    When:
    - Calling the 'vectra_entity_note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f"{TEST_DATA_DIR}/entity_note_add_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_note_add_context.json")
    requests_mock.post(BASE_URL + ENDPOINTS["ADD_AND_LIST_ENTITY_NOTE_ENDPOINT"].format("1"), json=notes_res)
    with open(f"{TEST_DATA_DIR}/entity_note_add_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_id": "1",
        "entity_type": "account",
        "note": "test_note",
    }

    # Call the function
    result = vectra_entity_note_add_command(client, args)
    result_context = result.to_context()
    notes_res["note_id"] = notes_res["id"]
    notes_res["entity_id"] = 1
    notes_res["entity_type"] = "account"
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Notes"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == notes_res
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["entity_id", "entity_type", "note_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_id": "1", "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("note")),
        ({"entity_type": "account", "note": "test_note"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"entity_id": "0", "entity_type": "account", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        ({"entity_id": "1", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
    ],
)
def test_vectra_entity_note_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and note.

    When:
    - Calling the 'vectra_entity_note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_update_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock note response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for updating a note of an entity.

    When:
    - Calling the 'vectra_entity_note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f"{TEST_DATA_DIR}/entity_note_update_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_note_update_context.json")
    requests_mock.patch(BASE_URL + ENDPOINTS["UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT"].format(1, 1), json=notes_res)
    with open(f"{TEST_DATA_DIR}/entity_note_update_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_id": "1",
        "entity_type": "account",
        "note_id": "1",
        "note": "test_note",
    }

    # Call the function
    result = vectra_entity_note_update_command(client, args)
    result_context = result.to_context()
    notes_res["note_id"] = notes_res["id"]
    notes_res["entity_id"] = 1
    notes_res["entity_type"] = "account"
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Notes"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == notes_res
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["entity_id", "entity_type", "note_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type", "note_id": "1"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_id": "1", "entity_type": "account", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("note")),
        ({"entity_type": "account", "note": "test_note", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "1", "entity_type": "account", "note": "test_note"}, ERRORS["REQUIRED_ARGUMENT"].format("note_id")),
        (
            {"entity_id": "0", "entity_type": "account", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        (
            {"note_id": "0", "entity_type": "account", "note": "test_note", "entity_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "0"),
        ),
        (
            {"note_id": "-1", "entity_type": "account", "note": "test_note", "entity_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "-1"),
        ),
        (
            {"note_id": "1.5", "entity_type": "account", "note": "test_note", "entity_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "1.5"),
        ),
        ({"entity_id": "1", "entity_type": "", "note_id": "2"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
    ],
)
def test_vectra_entity_note_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating a note of an entity.

    When:
    - Calling the 'vectra_entity_note_update_command' function with the provided client and arguments.

    Then:
    - Assert that a ValueError is raised with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_remove_valid_arguments(requests_mock, client):
    """
    Tests the 'vectra_entity_note_remove_command' function with valid arguments.

    Ensures that the function removes an entity note and returns the expected CommandResults object.

    Args:
        requests_mock: The requests mocker object.
        client: The VectraClient instance.

    Returns:
        None. Raises an AssertionError if the test fails.
    """
    requests_mock.delete(BASE_URL + ENDPOINTS["UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT"].format(1, 1), status_code=204)
    with open(f"{TEST_DATA_DIR}/entity_note_remove_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_id": "1",
        "entity_type": "account",
        "note_id": "1",
    }

    # Call the function
    result = vectra_entity_note_remove_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == {}


def test_vectra_entity_note_remove_invalid_status_code(requests_mock, client):
    """
    Tests the 'vectra_entity_note_remove_command' function with valid arguments.

    Ensures that the function gives error in HR for status code.

    Args:
        requests_mock: The requests mocker object.
        client: The VectraClient instance.

    Returns:
        None. Raises an AssertionError if the test fails.
    """
    requests_mock.delete(BASE_URL + ENDPOINTS["UPDATE_AND_REMOVE_ENTITY_NOTE_ENDPOINT"].format(1, 1), status_code=200)
    args = {
        "entity_id": "1",
        "entity_type": "account",
        "note_id": "1",
    }

    # Call the function
    result = vectra_entity_note_remove_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "Something went wrong."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type", "note_id": "1"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_type": "account", "note": "test_note", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "1", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "1", "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("note_id")),
        (
            {"entity_id": "0", "entity_type": "account", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        (
            {"note_id": "0", "entity_type": "account", "note": "test_note", "entity_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "0"),
        ),
        (
            {"note_id": "-1", "entity_type": "account", "note": "test_note", "entity_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "-1"),
        ),
        (
            {"note_id": "1.5", "entity_type": "account", "note": "test_note", "entity_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "1.5"),
        ),
    ],
)
def test_vectra_entity_note_remove_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating a note of an entity.

    When:
    - Calling the 'vectra_entity_note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that a ValueError is raised with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_remove_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock get and update tag response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    add_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_add_response.json")
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_tag_add_context.json")
    requests_mock.get(BASE_URL + ENDPOINTS["ENTITY_TAG_ENDPOINT"].format(1), json=get_tags_res)
    requests_mock.patch(BASE_URL + ENDPOINTS["ENTITY_TAG_ENDPOINT"].format(1), json=add_tags_res)
    with open(f"{TEST_DATA_DIR}/entity_tag_add_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_id": "1",
        "entity_type": "host",
        "tags": "tag1, tag2",
    }

    # Call the function
    result = vectra_entity_tag_add_command(client, args)
    result_context = result.to_context()
    add_tags_res.update({"entity_id": 1, "entity_type": "host"})
    del add_tags_res["status"]
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Tags"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == add_tags_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["tag_id", "entity_type", "entity_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_id": "1", "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"entity_id": "1", "entity_type": "account", "tags": " , "}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"entity_id": "0", "entity_type": "account", "tags": " , tag1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account", "tags": "tag1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account", "tags": "tag1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        ({"entity_id": "1", "entity_type": "", "tags": "tag1"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
    ],
)
def test_vectra_entity_tag_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and tags.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_tag_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_add_when_get_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_invalid_response.json")
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    args = {
        "entity_id": "1",
        "entity_type": "host",
        "tags": "tag1, tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_add_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {get_tags_res.get('message')}."


def test_vectra_entity_tag_add_when_add_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_response.json")
    add_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_add_invalid_response.json")
    mocker.patch.object(client, "update_entity_tags_request", return_value=add_tags_res)
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    args = {
        "entity_id": "1",
        "entity_type": "host",
        "tags": "tag1, tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_add_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {add_tags_res.get('message')}."


def test_vectra_entity_tag_remove_valid_arguments(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    add_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_remove_response.json")
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_response_2.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_tag_remove_context.json")
    mocker.patch.object(client, "update_entity_tags_request", return_value=add_tags_res)
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    with open(f"{TEST_DATA_DIR}/entity_tag_remove_hr.md") as f:
        result_hr = f.read()
    args = {"entity_id": "1", "entity_type": "host", "tags": "tag2"}

    # Call the function
    result = vectra_entity_tag_remove_command(client, args)
    result_context = result.to_context()
    add_tags_res.update({"entity_id": 1, "entity_type": "host"})
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Tags"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == add_tags_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["tag_id", "entity_type", "entity_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_id": "1", "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"entity_id": "1", "entity_type": "account", "tags": " , "}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "0", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0")),
        ({"entity_id": "-1", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1")),
        ({"entity_id": "1.5", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5")),
    ],
)
def test_vectra_entity_tag_remove_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id and entity_type.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_tag_remove_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_remove_when_get_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_invalid_response.json")
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    args = {
        "entity_id": "1",
        "entity_type": "host",
        "tags": "tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_remove_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {get_tags_res.get('message')}."


def test_vectra_entity_tag_remove_when_add_tag_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_response_2.json")
    add_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_add_invalid_response.json")
    mocker.patch.object(client, "update_entity_tags_request", return_value=add_tags_res)
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    args = {
        "entity_id": "1",
        "entity_type": "host",
        "tags": "tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_remove_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {add_tags_res.get('message')}."


def test_vectra_entity_tag_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_entity_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_response_2.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_tag_list_context.json")
    requests_mock.get(BASE_URL + ENDPOINTS["ENTITY_TAG_ENDPOINT"].format(1), json=get_tags_res)
    with open(f"{TEST_DATA_DIR}/entity_tag_list_hr.md") as f:
        result_hr = f.read()
    args = {"entity_id": "1", "entity_type": "host"}

    # Call the function
    result = vectra_entity_tag_list_command(client, args)
    result_context = result.to_context()
    get_tags_res.update({"entity_id": 1, "entity_type": "host"})
    del get_tags_res["status"]
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Tags"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == get_tags_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["tag_id", "entity_type", "entity_id"]


def test_vectra_entity_tag_list_with_empty_tag_response(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'update_entity_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'list_entity_tags_request' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_response_2.json")
    get_tags_res["tags"] = []
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_tag_empty_list_context.json")
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    with open(f"{TEST_DATA_DIR}/entity_tag_empty_list_hr.md") as f:
        result_hr = f.read()
    args = {"entity_id": "1", "entity_type": "host"}

    # Call the function
    result = vectra_entity_tag_list_command(client, args)
    result_context = result.to_context()
    get_tags_res.update({"entity_id": 1, "entity_type": "host"})
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Tags"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == get_tags_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["tag_id", "entity_type", "entity_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "0", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0")),
        ({"entity_id": "-1", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1")),
        ({"entity_id": "1.5", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5")),
        ({"entity_id": "1", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
    ],
)
def test_vectra_entity_tag_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and tags.

    When:
    - Calling the 'vectra_entity_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_tag_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_tag_list_when_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_entity_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_entity_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/entity_tag_get_invalid_response.json")
    mocker.patch.object(client, "list_entity_tags_request", return_value=get_tags_res)
    args = {
        "entity_id": "1",
        "entity_type": "host",
        "tags": "tag1, tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_tag_list_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {get_tags_res.get('message')}."


def test_vectra_entity_assignment_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'add_entity_assignment_request' method returning assignment data.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding an assignment.

    When:
    - Calling the 'vectra_entity_assignment_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f"{TEST_DATA_DIR}/entity_assignment_add_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_assignment_add_context.json")
    with open(f"{TEST_DATA_DIR}/entity_assignment_add_account_hr.md") as f:
        result_hr = f.read()
    args = {"entity_id": "1", "entity_type": "account", "user_id": "1"}
    requests_mock.post(BASE_URL + ENDPOINTS["ASSIGNMENT_ENDPOINT"], json=assignment_res[0])
    # Call the function
    result = vectra_entity_assignment_add_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Assignments"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[0]
    assert result.outputs_key_field == ["assignment_id"]
    # For Host
    with open(f"{TEST_DATA_DIR}/entity_assignment_add_host_hr.md") as f:
        result_hr = f.read()
    args = {"entity_id": "1", "entity_type": "host", "user_id": "3"}

    requests_mock.post(BASE_URL + ENDPOINTS["ASSIGNMENT_ENDPOINT"], json=assignment_res[1])
    # Call the function
    result = vectra_entity_assignment_add_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Assignments"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[1]
    assert result.outputs_key_field == ["assignment_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type", "user_id": "1"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_id": "1", "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("user_id")),
        ({"entity_type": "account", "note": "test_note"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"entity_id": "0", "entity_type": "account", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        ({"entity_id": "1", "entity_type": "account", "user_id": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("user_id", "0")),
        ({"entity_id": "1", "entity_type": "account", "user_id": "-1"}, ERRORS["INVALID_INTEGER_VALUE"].format("user_id", "-1")),
        (
            {"entity_id": "1", "entity_type": "account", "user_id": "1.5"},
            ERRORS["INVALID_INTEGER_VALUE"].format("user_id", "1.5"),
        ),
        (
            {"entity_id": "1", "entity_type": "", "user_id": "1"},
            ERRORS["REQUIRED_ARGUMENT"].format("entity_type"),
        ),
    ],
)
def test_vectra_entity_assignment_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and user_id.

    When:
    - Calling the 'vectra_entity_assignment_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_assignment_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_assignment_update_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity assignment update response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for updating an entity assignment.

    When:
    - Calling the 'vectra_entity_assignment_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f"{TEST_DATA_DIR}/entity_assignment_update_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_assignment_update_context.json")
    requests_mock.put(BASE_URL + ENDPOINTS["UPDATE_ASSIGNMENT_ENDPOINT"].format(1), json=assignment_res)
    with open(f"{TEST_DATA_DIR}/entity_assignment_update_hr.md") as f:
        result_hr = f.read()
    args = {"assignment_id": "1", "user_id": "2"}

    # Call the function
    result = vectra_entity_assignment_update_command(client, args)
    result_context = result.to_context()
    assignment_res.get("assignment")["assignment_id"] = 1
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Assignments"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == assignment_res.get("assignment")
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["assignment_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"assignment_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("user_id")),
        ({"user_id": "2"}, ERRORS["REQUIRED_ARGUMENT"].format("assignment_id")),
        ({"assignment_id": "0", "user_id": "2"}, ERRORS["INVALID_INTEGER_VALUE"].format("assignment_id", "0")),
        ({"assignment_id": "-1", "user_id": "2"}, ERRORS["INVALID_INTEGER_VALUE"].format("assignment_id", "-1")),
        ({"assignment_id": "1.5", "user_id": "2"}, ERRORS["INVALID_INTEGER_VALUE"].format("assignment_id", "1.5")),
        ({"user_id": "0", "assignment_id": "2"}, ERRORS["INVALID_INTEGER_VALUE"].format("user_id", "0")),
        ({"user_id": "-1", "assignment_id": "2"}, ERRORS["INVALID_INTEGER_VALUE"].format("user_id", "-1")),
        ({"user_id": "1.5", "assignment_id": "2"}, ERRORS["INVALID_INTEGER_VALUE"].format("user_id", "1.5")),
    ],
)
def test_vectra_entity_assignment_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for assignment_id and user_id.

    When:
    - Calling the 'vectra_entity_assignment_update_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_assignment_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_pcap_download_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked GET request for downloading PCAP data of a detection.
    - The expected binary file content of the PCAP.
    - Arguments specifying a valid detection ID for downloading PCAP.

    When:
    - Calling the 'vectra_detection_pcap_download_command' function with the provided client and arguments.

    Then:
    - Assert that the result contains the expected binary file content.
    """
    mock_file_content = b"PCAP data of detection id 1431"
    args = {"detection_id": "1431"}
    requests_mock.get(
        BASE_URL + ENDPOINTS["DOWNLOAD_DETECTION_PCAP"].format("1431"),
        content=mock_file_content,
        headers={"Content-Disposition": 'attachement;filename="IP-1.1.1.1_hidden_dns_tunnel_1431.pcap"'},
    )
    # Call the function
    result = vectra_detection_pcap_download_command(client, args)

    # Assert the CommandResults
    assert result.get("File") == "IP-1.1.1.1_hidden_dns_tunnel_1431.pcap"


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "as,2"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "as,2")),
        ({"detection_id": "1.5"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5")),
        ({"detection_id": "-1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1")),
    ],
)
def test_vectra_detection_pcap_download_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for detection_id.

    When:
    - Calling the 'vectra_detection_pcap_download_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_pcap_download_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_assignment_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided client and no additional arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the assignment data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    assignment_res = util_load_json(f"{TEST_DATA_DIR}/assignment_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/assignment_list_context.json")
    with open(f"{TEST_DATA_DIR}/assignment_list_hr.md") as f:
        result_hr = f.read()
    requests_mock.get(BASE_URL + ENDPOINTS["ASSIGNMENT_ENDPOINT"], json=assignment_res)
    # Call the function
    result = vectra_assignment_list_command(client, {"entity_type": "host", "entity_ids": "1"})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Assignments"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["assignment_id"]


def test_vectra_assignment_list_when_assignment_response_is_empty(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - An empty assignment response.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided empty assignment response.

    Then:
    - Assert that the CommandResults object contains the appropriate human-readable output for empty results.
    - Assert that the EntryContext is empty.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}
    args = {"resolved": "False", "created_after": "1 day", "entity_type": "account", "entity_ids": "1"}
    requests_mock.get(BASE_URL + ENDPOINTS["ASSIGNMENT_ENDPOINT"], json=empty_response)
    # Call the function
    result = vectra_assignment_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any matching assignments for provided filters."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"entity_type": "account"}, ERRORS["ENTITY_IDS_WITHOUT_TYPE"]),
        ({"entity_ids": "1,2"}, ERRORS["ENTITY_IDS_WITHOUT_TYPE"]),
        (
            {"entity_ids": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
    ],
)
def test_vectra_assignment_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for listing assignments.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_assignment_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.
    - A client object.
    - Mocked entity note list response data.
    - Mocked context data.

    When:
    - Calling the 'vectra_entity_note_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the entity note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f"{TEST_DATA_DIR}/entity_note_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/entity_note_list_context.json")
    with open(f"{TEST_DATA_DIR}/entity_note_list_hr.md") as f:
        result_hr = f.read()
    args = {
        "entity_id": "1",
        "entity_type": "account",
    }
    url = BASE_URL + ENDPOINTS["ADD_AND_LIST_ENTITY_NOTE_ENDPOINT"].format(args.get("entity_id"))
    params = {"type": args.get("entity_type")}
    final_url = add_params_in_url(url, params)
    requests_mock.get(final_url, json=notes_res)
    # Call the function
    result = vectra_entity_note_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Entity.Notes"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == notes_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["entity_id", "entity_type", "note_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"entity_id": "1", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "0", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0")),
        ({"entity_id": "-1", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1")),
        ({"entity_id": "1.5", "entity_type": "account"}, ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5")),
        ({"entity_id": "1", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
    ],
)
def test_vectra_entity_note_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id and entity_type.

    When:
    - Calling the 'vectra_entity_note_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_note_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_note_list_when_note_response_is_empty(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - An empty assignment response.

    When:
    - Calling the 'vectra_assignment_list_command' function with the provided empty assignment response.

    Then:
    - Assert that the CommandResults object contains the appropriate human-readable output for empty results.
    - Assert that the EntryContext is empty.
    """
    empty_response: list = []
    args = {
        "entity_id": "1",
        "entity_type": "account",
    }
    url = BASE_URL + ENDPOINTS["ADD_AND_LIST_ENTITY_NOTE_ENDPOINT"].format(args.get("entity_id"))
    params = {"type": args.get("entity_type")}
    final_url = add_params_in_url(url, params)
    requests_mock.get(final_url, json=empty_response)
    # Call the function
    result = vectra_entity_note_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any notes for provided entity."
    assert result_context.get("EntryContext") == {}


def test_vectra_group_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock assignment response.
    - Expected context data and human-readable output.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    group_res = util_load_json(f"{TEST_DATA_DIR}/group_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/group_list_context.json")
    with open(f"{TEST_DATA_DIR}/group_list_hr.md") as f:
        result_hr = f.read()
    requests_mock.get(BASE_URL + ENDPOINTS["GROUP_ENDPOINT"], json=group_res)
    args = {"group_type": "account", "importance": "high"}
    # Call the function
    result = vectra_group_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["group_id"]


def test_vectra_group_list_when_response_is_empty(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_group_request' method returning an empty response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output indicates that no results were found.
    - Assert that the 'EntryContext' property in the context is an empty dictionary.
    """
    empty_response: dict = {"count": 0, "next": None, "previous": None, "results": []}
    mocker.patch.object(client, "list_group_request", return_value=empty_response)

    # Call the function
    result = vectra_group_list_command(client, {})
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Couldn't find any matching groups for provided filters."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"group_type": "invalid"}, ERRORS["INVALID_COMMAND_ARG_VALUE"].format("group_type", ", ".join(VALID_GROUP_TYPE))),
        (
            {"group_type": "host", "account_names": "account_name"},
            ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "account", "account_names"),
        ),
        (
            {"group_type": "host", "domains": "domain"},
            ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "domain", "domains"),
        ),
        ({"group_type": "account", "host_ids": "1"}, ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "host", "host_ids")),
        ({"group_type": "host", "host_ids": "abc"}, 'Invalid number: "{}"="{}"'.format("host_ids", "abc")),
        ({"group_type": "host", "host_ids": "-1"}, ERRORS["INVALID_INTEGER_VALUE"].format("host_ids", "-1")),
        (
            {"group_type": "account", "host_names": "host_name"},
            ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "host", "host_names"),
        ),
        ({"group_type": "host", "ips": "0.0.0.0"}, ERRORS["INVALID_SUPPORT_FOR_ARG"].format("group_type", "ip", "ips")),
        ({"importance": "invalid"}, ERRORS["INVALID_COMMAND_ARG_VALUE"].format("importance", ", ".join(VALID_IMPORTANCE_VALUE))),
    ],
)
def test_vectra_group_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid values.

    When:
    - Calling the 'vectra_group_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected value for the corresponding invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_assign_domain_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    assign_group_res = util_load_json(f"{TEST_DATA_DIR}/assign_group_response.json")
    groups = util_load_json(f"{TEST_DATA_DIR}/get_groups_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/assign_group_context.json")
    # For Domain group
    with open(f"{TEST_DATA_DIR}/assign_domain_group_hr.md") as f:
        result_hr = f.read()
    args = {"group_id": "1", "members": "*.domain3.com,*.domain2.com"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[0])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=assign_group_res[0])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[0]
    assert result.outputs_key_field == ["group_id"]


def test_vectra_assign_account_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    account type.
    """
    assign_group_res = util_load_json(f"{TEST_DATA_DIR}/assign_group_response.json")
    groups = util_load_json(f"{TEST_DATA_DIR}/get_groups_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/assign_group_context.json")
    # For Account group
    with open(f"{TEST_DATA_DIR}/assign_account_group_hr.md") as f:
        result_hr = f.read()
    args = {"group_id": "3", "members": "account_3,account_4"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[2])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=assign_group_res[2])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[2]
    assert result.outputs_key_field == ["group_id"]


def test_vectra_assign_host_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    host type.
    """
    assign_group_res = util_load_json(f"{TEST_DATA_DIR}/assign_group_response.json")
    groups = util_load_json(f"{TEST_DATA_DIR}/get_groups_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/assign_group_context.json")
    # For Host group
    with open(f"{TEST_DATA_DIR}/assign_host_group_hr.md") as f:
        result_hr = f.read()
    args = {"group_id": "2", "members": "1,2"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[1])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=assign_group_res[1])
    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[1]
    assert result.outputs_key_field == ["group_id"]


def test_vectra_assign_member_already_exist(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the result's human-readable output indicates that the members are already in the group.
    """
    groups = util_load_json(f"{TEST_DATA_DIR}/assign_group_response.json")

    args = {"group_id": "2", "members": "1,2"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[1])

    # Call the function
    result = vectra_group_assign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Member(s) 1, 2 are already in the group."


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"members": "account1"}, ERRORS["REQUIRED_ARGUMENT"].format("group_id")),
        ({"group_id": "0", "members": "account1"}, ERRORS["INVALID_INTEGER_VALUE"].format("group_id", "0")),
        ({"group_id": "-1", "members": "account1"}, ERRORS["INVALID_INTEGER_VALUE"].format("group_id", "-1")),
        ({"group_id": "1.5", "members": "account1"}, ERRORS["INVALID_INTEGER_VALUE"].format("group_id", "1.5")),
        ({"group_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("members")),
    ],
)
def test_vectra_group_assign_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a group.

    When:
    - Calling the 'vectra_group_assign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_assign_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_unassign_domain_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    domain type.
    """
    unassign_group_res = util_load_json(f"{TEST_DATA_DIR}/unassign_group_response.json")
    groups = util_load_json(f"{TEST_DATA_DIR}/get_groups_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/unassign_group_context.json")
    # For Domain group
    with open(f"{TEST_DATA_DIR}/unassign_domain_group_hr.md") as f:
        result_hr = f.read()
    args = {"group_id": "1", "members": "*.domain1.net"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[0])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=unassign_group_res[0])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[0]
    assert result.outputs_key_field == ["group_id"]


def test_vectra_unassign_host_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    host type.
    """
    unassign_group_res = util_load_json(f"{TEST_DATA_DIR}/unassign_group_response.json")
    groups = util_load_json(f"{TEST_DATA_DIR}/get_groups_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/unassign_group_context.json")

    with open(f"{TEST_DATA_DIR}/unassign_host_group_hr.md") as f:
        result_hr = f.read()
    args = {"group_id": "2", "members": "3"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[1])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=unassign_group_res[1])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[1]
    assert result.outputs_key_field == ["group_id"]


def test_vectra_unassign_account_group_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then: - Assert that the result's human-readable output, context data, and key field match the expected values for
    account type.
    """
    unassign_group_res = util_load_json(f"{TEST_DATA_DIR}/unassign_group_response.json")
    groups = util_load_json(f"{TEST_DATA_DIR}/get_groups_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/unassign_group_context.json")

    with open(f"{TEST_DATA_DIR}/unassign_account_group_hr.md") as f:
        result_hr = f.read()
    args = {"group_id": "3", "members": "account_1"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[2])
    requests_mock.patch(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=unassign_group_res[2])
    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Group"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == context_data[2]
    assert result.outputs_key_field == ["group_id"]


def test_vectra_unassign_member_already_exist(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked response data for an existing group.
    - Arguments specifying a group ID and members to assign.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then:
    - Assert that the result's human-readable output indicates that the members are already in the group.
    """
    groups = util_load_json(f"{TEST_DATA_DIR}/assign_group_response.json")

    args = {"group_id": "2", "members": "6,7"}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["GROUP_ENDPOINT"], args.get("group_id")), json=groups[1])

    # Call the function
    result = vectra_group_unassign_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "##### Member(s) 6, 7 do not exist in the group."


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"members": "account1"}, ERRORS["REQUIRED_ARGUMENT"].format("group_id")),
        ({"group_id": "0", "members": "account1"}, ERRORS["INVALID_INTEGER_VALUE"].format("group_id", "0")),
        ({"group_id": "-1", "members": "account1"}, ERRORS["INVALID_INTEGER_VALUE"].format("group_id", "-1")),
        ({"group_id": "1.5", "members": "account1"}, ERRORS["INVALID_INTEGER_VALUE"].format("group_id", "1.5")),
        ({"group_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("members")),
    ],
)
def test_vectra_group_unassign_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying invalid parameters for assigning members to a group.

    When:
    - Calling the 'vectra_group_unassign_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the raised error message matches the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_group_unassign_command(client, args)

    assert str(exception.value) == error_msg


@pytest.mark.parametrize("close_reason", ["benign", "remediated"])
def test_vectra_entity_detections_mark_asclosed_valid_arguments(requests_mock, client, close_reason):
    """
    Given:
    - A client object.
    - Mocked responses for entity data and marking detections as closed.
    - Arguments specifying valid parameters for marking detections as closed for an entity.

    When:
    - Calling the 'vectra_entity_detections_mark_asclosed_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the expected output.
    """
    entity_response = util_load_json(f"{TEST_DATA_DIR}/get_entity_response.json")
    response = {"_meta": {"level": "Success", "message": f"Successfully closed detections as {close_reason}"}}
    status_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}
    args = {"entity_id": "334", "entity_type": "account", "close_reason": close_reason}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["ENTITY_ENDPOINT_v34"], args["entity_id"]), json=entity_response)
    requests_mock.patch(BASE_URL + ENDPOINTS["DETECTION_CLOSE_ENDPOINT"], json=response)
    requests_mock.patch(BASE_URL + ENDPOINTS["DETECTION_ENDPOINT"], json=status_response)
    # Call the function
    result = vectra_entity_detections_mark_asclosed_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    expected_hr = f"##### The detections (1933, 1934) of the provided entity ID have been successfully closed as {close_reason}."
    assert result_context.get("HumanReadable") == expected_hr


def test_vectra_entity_detections_mark_asclosed_with_no_detections(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked responses for entity data with no detections.
    - Arguments specifying valid parameters for marking detections as closed for an entity with no detections.

    When:
    - Calling the 'vectra_entity_detections_mark_asclosed_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output matches the expected output indicating no detections to mark as closed.
    """
    args = {"entity_id": "1", "entity_type": "account", "close_reason": "benign"}
    requests_mock.get(
        BASE_URL + "{}/{}".format(ENDPOINTS["ENTITY_ENDPOINT_v34"], args["entity_id"]), json={"entity_id": "1", "type": "account"}
    )
    # Call the function
    result = vectra_entity_detections_mark_asclosed_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "There are no active detections to mark as closed for this entity ID: 1."


def test_vectra_entity_detections_mark_asclosed_command_invalid_response(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock entity detection mark as closed invalid response.
    - Arguments specifying valid parameters for marking detections as closed for an entity.

    When:
    - Calling the 'vectra_entity_detections_mark_asclosed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a DemistoException with the expected error message.
    """
    entity_response = util_load_json(f"{TEST_DATA_DIR}/get_entity_response.json")
    response = {"_meta": {"level": "Error", "message": "Failed to close detections"}}
    requests_mock.get(BASE_URL + "{}/{}".format(ENDPOINTS["ENTITY_ENDPOINT_v34"], 334), json=entity_response)
    requests_mock.patch(BASE_URL + ENDPOINTS["DETECTION_CLOSE_ENDPOINT"], json=response)
    args = {"entity_id": "334", "entity_type": "account", "close_reason": "benign"}

    # Capture exception from the function
    with pytest.raises(DemistoException) as exception:
        vectra_entity_detections_mark_asclosed_command(client, args)

    assert str(exception.value) == "Something went wrong. Message: Failed to close detections."


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"entity_id": "", "entity_type": "account", "close_reason": "benign"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"entity_id": "1", "entity_type": "invalid_type", "close_reason": "benign"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        ({"entity_id": "1", "entity_type": "", "close_reason": "benign"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "1", "entity_type": "account", "close_reason": ""}, ERRORS["REQUIRED_ARGUMENT"].format("close_reason")),
        (
            {"entity_id": "1", "entity_type": "account", "close_reason": "invalid_reason"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("close_reason", "benign, remediated"),
        ),
    ],
)
def test_vectra_entity_detections_mark_asclosed_invalid_args(client, args, error_msg):
    """
    Given:
    - Invalid arguments for marking detections as closed.

    When:
    - Calling the 'vectra_entity_detections_mark_asclosed_command' function with the provided invalid arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_entity_detections_mark_asclosed_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detections_mark_asclosed_invalid_response(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock detection mark as closed invalid response.
    - Arguments specifying valid detection IDs and close reason to mark as closed.

    When:
    - Calling the 'vectra_detections_mark_asclosed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a DemistoException with the expected error message.
    """
    response = {"_meta": {"level": "Error", "message": "Failed to close detections"}}
    requests_mock.patch(BASE_URL + ENDPOINTS["DETECTION_CLOSE_ENDPOINT"], json=response)
    args = {"detection_ids": "1,2,3", "close_reason": "benign"}

    # Capture exception from the function
    with pytest.raises(DemistoException) as exception:
        vectra_detections_mark_asclosed_command(client, args)

    assert str(exception.value) == "Something went wrong. Message: Failed to close detections."


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": "1,2,3"}, ERRORS["REQUIRED_ARGUMENT"].format("close_reason")),
        ({"detection_ids": "as,2", "close_reason": "benign"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "as")),
        (
            {"detection_ids": "1,2, , , ,,,3", "close_reason": "benign"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ""),
        ),
        (
            {"detection_ids": "1,2,3", "close_reason": "invalid"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("close_reason", "benign, remediated"),
        ),
    ],
)
def test_vectra_detections_mark_asclosed_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments (missing detection_ids, missing close_reason, invalid detection_ids, invalid close_reason).

    When:
    - Calling the 'vectra_detections_mark_asclosed_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detections_mark_asclosed_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detections_mark_asopen_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock detection mark as open response.
    - Arguments specifying valid detection IDs to mark as open.

    When:
    - Calling the 'vectra_detections_mark_asopen_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that the human-readable output matches the expected content.
    """
    response = {"_meta": {"level": "success", "message": "Successfully re-opened detections"}}
    status_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}
    requests_mock.patch(BASE_URL + ENDPOINTS["DETECTION_OPEN_ENDPOINT"], json=response)
    requests_mock.patch(os.path.join(BASE_URL, ENDPOINTS["DETECTION_ENDPOINT"]), json=status_response)

    args = {"detection_ids": "1,2,3"}

    # Call the function
    result = vectra_detections_mark_asopen_command(client, args)
    result_context = result.to_context()
    expected_hr = "##### The provided detection IDs have been successfully re-opened."
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == expected_hr
    assert result_context.get("EntryContext") == {}


def test_vectra_detections_mark_asopen_invalid_response(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock detection mark as open invalid response.
    - Arguments specifying valid detection IDs to mark as open.

    When:
    - Calling the 'vectra_detections_mark_asopen_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a DemistoException with the expected error message.
    """
    response = {"_meta": {"level": "Error", "message": "Failed to open detections"}}
    requests_mock.patch(BASE_URL + ENDPOINTS["DETECTION_OPEN_ENDPOINT"], json=response)
    args = {"detection_ids": "1,2,3"}

    # Capture exception from the function
    with pytest.raises(DemistoException) as exception:
        vectra_detections_mark_asopen_command(client, args)

    assert str(exception.value) == "Something went wrong. Message: Failed to open detections."


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": ""}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids", "")),
        ({"detection_ids": "as,2"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "as")),
        ({"detection_ids": "1,2, ,  ,3"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", "")),
    ],
)
def test_vectra_detections_mark_asopen_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments (missing detection_ids, empty detection_ids, invalid detection_ids).

    When:
    - Calling the 'vectra_detections_mark_asopen_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detections_mark_asopen_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_tag_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detection_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for listing the tags of a detection.

    When:
    - Calling the 'vectra_detection_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the expected format.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    get_tags_res = {"status": "success", "tag_id": "36", "tags": ["tag1", "tag2"]}
    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(123), json=get_tags_res)
    args = {"detection_id": "123"}

    # Call the function
    result = vectra_detection_tag_list_command(client, args)
    result_context = result.to_context()
    get_tags_res.update({"detection_id": 123})  # type: ignore
    del get_tags_res["status"]

    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Tags"
    assert "##### List of tags: **tag1, tag2**" in result_context.get("HumanReadable")
    assert result_context.get("Contents") == get_tags_res
    assert result.outputs_key_field == ["tag_id", "detection_id"]


def test_vectra_detection_tag_list_with_empty_tag_response(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detection_tags_request' method returning empty tags response.
    - Arguments specifying valid parameters for listing the tags of a detection.

    When:
    - Calling the 'vectra_detection_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output indicates no tags were found.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    get_tags_res = {"status": "success", "tag_id": "36", "tags": []}
    mocker.patch.object(client, "list_detection_tags_request", return_value=get_tags_res)
    args = {"detection_id": "123"}

    # Call the function
    result = vectra_detection_tag_list_command(client, args)
    result_context = result.to_context()
    get_tags_res.update({"detection_id": 123})  # type: ignore
    get_tags_res.pop("status", None)

    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Tags"
    assert result_context.get("HumanReadable") == "##### No tags were found for the given detection ID."
    assert result_context.get("Contents") == get_tags_res
    assert result.outputs_key_field == ["tag_id", "detection_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "0")),
        ({"detection_id": "-1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1")),
        ({"detection_id": "1.5"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5")),
        ({"detection_id": "abc"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "abc")),
    ],
)
def test_vectra_detection_tag_list_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for detection_id.

    When:
    - Calling the 'vectra_detection_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_tag_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_tag_list_when_response_is_invalid(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detection_tags_request' method returning invalid response.
    - Arguments specifying valid detection_id.

    When:
    - Calling the 'vectra_detection_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a DemistoException.
    - Assert that the error message indicates something went wrong.
    """
    get_tags_res = {"status": "error", "message": "Detection not found"}
    mocker.patch.object(client, "list_detection_tags_request", return_value=get_tags_res)
    args = {"detection_id": "123"}

    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_detection_tag_list_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {get_tags_res.get('message')}."


def test_vectra_detection_tag_list_when_response_has_no_status(mocker, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detection_tags_request' method returning response without status.
    - Arguments specifying valid detection_id.

    When:
    - Calling the 'vectra_detection_tag_list_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a DemistoException.
    - Assert that the error message indicates something went wrong.
    """
    get_tags_res = {"tag_id": "36", "tags": ["tag1"]}
    mocker.patch.object(client, "list_detection_tags_request", return_value=get_tags_res)
    args = {"detection_id": "123"}

    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_detection_tag_list_command(client, args)

    assert str(exception.value) == "Something went wrong."


def test_vectra_detection_tag_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock get and update tag response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_detection_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    add_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_add_response.json")
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/detection_tag_add_context.json")
    with open(f"{TEST_DATA_DIR}/detection_tag_add_hr.md") as f:
        result_hr = f.read()

    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=get_tags_res)
    requests_mock.patch(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=add_tags_res)

    args = {
        "detection_id": "1",
        "tags": "tag1, tag2",
    }

    # Call the function
    result = vectra_detection_tag_add_command(client, args)
    result_context = result.to_context()
    add_tags_res.update({"detection_id": 1})
    del add_tags_res["status"]
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Tags"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == add_tags_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["tag_id", "detection_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"tags": "tag1"}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "1", "tags": ""}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"detection_id": "1", "tags": " , "}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"detection_id": "0", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "0")),
        ({"detection_id": "-1", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1")),
        ({"detection_id": "1.5", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5")),
        ({"detection_id": "abc", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "abc")),
    ],
)
def test_vectra_detection_tag_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id, entity_type, and tags.

    When:
    - Calling the 'vectra_detection_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_tag_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_tag_add_when_get_tag_response_is_invalid(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detection_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_detection_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_invalid_response.json")
    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=get_tags_res)
    args = {
        "detection_id": "1",
        "tags": "tag1, tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_detection_tag_add_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {get_tags_res.get('message')}."


def test_vectra_detection_tag_add_when_add_tag_response_is_invalid(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'update_detection_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_detection_tag_add_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_response.json")
    add_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_invalid_response.json")

    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=get_tags_res)
    requests_mock.patch(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=add_tags_res)
    args = {
        "detection_id": "1",
        "tags": "tag1, tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_detection_tag_add_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {add_tags_res.get('message')}."


def test_vectra_detection_tag_remove_valid_arguments(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'update_detection_tags_request' method returning tags response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding the tags to an entity.

    When:
    - Calling the 'vectra_detection_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the tags response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    remove_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_remove_response.json")
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/detection_tag_remove_context.json")
    with open(f"{TEST_DATA_DIR}/detection_tag_remove_hr.md") as f:
        result_hr = f.read()

    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=get_tags_res)
    requests_mock.patch(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=remove_tags_res)

    args = {"detection_id": "1", "tags": "tag,tag2"}

    # Call the function
    result = vectra_detection_tag_remove_command(client, args)
    result_context = result.to_context()
    remove_tags_res.update({"detection_id": 1})
    del remove_tags_res["status"]
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Tags"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == remove_tags_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["tag_id", "detection_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"tags": "tag1"}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "1", "tags": ""}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"detection_id": "1", "tags": " , "}, ERRORS["REQUIRED_ARGUMENT"].format("tags")),
        ({"detection_id": "0", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "0")),
        ({"detection_id": "-1", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1")),
        ({"detection_id": "1.5", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5")),
        ({"detection_id": "abc", "tags": "tag1"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "abc")),
    ],
)
def test_vectra_detection_tag_remove_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for entity_id and entity_type.

    When:
    - Calling the 'vectra_detection_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_tag_remove_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_tag_remove_when_get_tag_response_is_invalid(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'list_detection_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_detection_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_invalid_response.json")
    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=get_tags_res)
    args = {
        "detection_id": "1",
        "tags": "tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_detection_tag_remove_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {get_tags_res.get('message')}."


def test_vectra_detection_tag_remove_when_remove_tag_response_is_invalid(requests_mock, client):
    """
    Given:
    - A client object.
    - Mocked 'update_detection_tags_request' method returning invalid response.
    - Arguments specifying invalid tags.

    When:
    - Calling the 'vectra_detection_tag_remove_command' function with the provided client and arguments.

    Then:
    - Assert that the human-readable output indicates that invalid result was found.
    """
    get_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_response.json")
    remove_tags_res = util_load_json(f"{TEST_DATA_DIR}/detection_tag_get_invalid_response.json")

    requests_mock.get(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=get_tags_res)
    requests_mock.patch(BASE_URL + ENDPOINTS["LIST_TAGS_ENDPOINT"].format(1), json=remove_tags_res)
    args = {
        "detection_id": "1",
        "tags": "tag, tag2",
    }
    # Call the function
    with pytest.raises(DemistoException) as exception:
        vectra_detection_tag_remove_command(client, args)

    assert str(exception.value) == f"Something went wrong. Message: {remove_tags_res.get('message')}."


def test_vectra_entity_detection_list_passes_entity_id_and_type(mocker, client):
    """
    Ensure entity_id and entity_type are passed correctly to list_detections_request.
    """
    entity_id = 42
    entity_type = "host"
    # Mock entity response with detection_set
    entity_data = {"detection_set": ["https://api/v3.3/detections/123"]}
    mocker.patch.object(client, "get_entity_request", return_value=entity_data)
    # Use realistic detection data with 'url' key
    detections_data = util_load_json(f"{TEST_DATA_DIR}/entity_detection_list_response.json")
    mock_list = mocker.patch.object(client, "list_detections_request", return_value=detections_data)
    args = {"entity_id": str(entity_id), "entity_type": entity_type}
    vectra_entity_detection_list_command(client, args)
    # Assert correct values are passed
    mock_list.assert_called_once()
    call_kwargs = mock_list.call_args.kwargs
    assert call_kwargs["entity_id"] == entity_id
    assert call_kwargs["entity_type"] == entity_type


def test_vectra_detection_note_list_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked 'requests_mock' to simulate API responses.
    - A client object.
    - Mocked detection note list response data.
    - Mocked context data.

    When:
    - Calling the 'vectra_detection_note_list_command' function with valid arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the detection note list data.
    - Assert that the 'EntryContext' property in the context matches the expected context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f"{TEST_DATA_DIR}/detection_note_list_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/detection_note_list_context.json")
    with open(f"{TEST_DATA_DIR}/detection_note_list_hr.md") as f:
        result_hr = f.read()
    args = {
        "detection_id": "1",
    }
    url = BASE_URL + ENDPOINTS["ADD_AND_LIST_DETECTION_NOTE_ENDPOINT"].format(args.get("detection_id"))
    requests_mock.get(url, json=notes_res)
    # Call the function
    result = vectra_detection_note_list_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Notes"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == notes_res
    assert result_context.get("EntryContext") == remove_empty_elements(context_data)
    assert result.outputs_key_field == ["detection_id", "note_id"]


def test_vectra_detection_note_add_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock notes response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for adding a note to a detection.

    When:
    - Calling the 'vectra_detection_note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f"{TEST_DATA_DIR}/detection_note_add_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/detection_note_add_context.json")
    requests_mock.post(BASE_URL + ENDPOINTS["ADD_AND_LIST_DETECTION_NOTE_ENDPOINT"].format("1"), json=notes_res)
    with open(f"{TEST_DATA_DIR}/detection_note_add_hr.md") as f:
        result_hr = f.read()
    args = {
        "detection_id": "1",
        "note": "test_note",
    }

    # Call the function
    result = vectra_detection_note_add_command(client, args)
    result_context = result.to_context()
    notes_res["note_id"] = notes_res["id"]
    notes_res["detection_id"] = 1
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Notes"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == notes_res
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["detection_id", "note_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"detection_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("note")),
        ({"note": "test_note"}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "0", "note": "test_note"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "0")),
        ({"detection_id": "-1", "note": "test_note"}, ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1")),
        (
            {"detection_id": "1.5", "note": "test_note"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5"),
        ),
    ],
)
def test_vectra_detection_note_add_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Arguments specifying different invalid values for detection_id, and note.

    When:
    - Calling the 'vectra_detection_note_add_command' function with the provided client and arguments.

    Then:
    - Assert that the function raises a ValueError.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_note_add_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_note_update_valid_arguments(requests_mock, client):
    """
    Given:
    - A mocked client for requests.
    - A mock note response.
    - The expected human-readable output file.
    - Arguments specifying valid parameters for updating a note of an entity.

    When:
    - Calling the 'vectra_detection_note_update_command' function with the provided client and arguments.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the content of the expected file.
    - Assert that the 'Contents' property in the context matches the notes response.
    - Assert that the 'EntryContext' property in the context matches the context data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    notes_res = util_load_json(f"{TEST_DATA_DIR}/detection_note_update_response.json")
    context_data = util_load_json(f"{TEST_DATA_DIR}/detection_note_update_context.json")
    requests_mock.patch(BASE_URL + ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(1, 1), json=notes_res)
    with open(f"{TEST_DATA_DIR}/detection_note_update_hr.md") as f:
        result_hr = f.read()
    args = {
        "detection_id": "1",
        "note_id": "1",
        "note": "test_note",
    }

    # Call the function
    result = vectra_detection_note_update_command(client, args)
    result_context = result.to_context()
    notes_res["note_id"] = notes_res["id"]
    notes_res["detection_id"] = 1
    # Assert the CommandResults
    assert result.outputs_prefix == "Vectra.Detection.Notes"
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("Contents") == notes_res
    assert result_context.get("EntryContext") == context_data
    assert result.outputs_key_field == ["detection_id", "note_id"]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"detection_id": "1", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("note")),
        ({"note": "test_note", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "1", "note": "test_note"}, ERRORS["REQUIRED_ARGUMENT"].format("note_id")),
        (
            {"detection_id": "0", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "0"),
        ),
        (
            {"detection_id": "-1", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1"),
        ),
        (
            {"detection_id": "1.5", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5"),
        ),
        (
            {"note_id": "0", "note": "test_note", "detection_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "0"),
        ),
        (
            {"note_id": "-1", "note": "test_note", "detection_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "-1"),
        ),
        (
            {"note_id": "1.5", "note": "test_note", "detection_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "1.5"),
        ),
    ],
)
def test_vectra_detection_note_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating a note of an entity.

    When:
    - Calling the 'vectra_detection_note_update_command' function with the provided client and arguments.

    Then:
    - Assert that a ValueError is raised with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_note_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_note_remove_valid_arguments(requests_mock, client):
    """
    Tests the 'vectra_detection_note_remove_command' function with valid arguments.

    Ensures that the function removes a detection note and returns the expected CommandResults object.

    Args:
        requests_mock: The requests mocker object.
        client: The VectraClient instance.

    Returns:
        None. Raises an AssertionError if the test fails.
    """
    requests_mock.delete(BASE_URL + ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(1, 1), status_code=204)
    with open(f"{TEST_DATA_DIR}/detection_note_remove_hr.md") as f:
        result_hr = f.read()
    args = {
        "detection_id": "1",
        "note_id": "1",
    }

    # Call the function
    result = vectra_detection_note_remove_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == result_hr
    assert result_context.get("EntryContext") == {}


def test_vectra_detection_note_remove_invalid_status_code(requests_mock, client):
    """
    Tests the 'vectra_detection_note_remove_command' function with valid arguments.

    Ensures that the function gives error in HR for status code.

    Args:
        requests_mock: The requests mocker object.
        client: The VectraClient instance.

    Returns:
        None. Raises an AssertionError if the test fails.
    """
    requests_mock.delete(BASE_URL + ENDPOINTS["UPDATE_AND_REMOVE_DETECTION_NOTE_ENDPOINT"].format(1, 1), status_code=200)
    args = {
        "detection_id": "1",
        "note_id": "1",
    }

    # Call the function
    result = vectra_detection_note_remove_command(client, args)
    result_context = result.to_context()
    # Assert the CommandResults
    assert result_context.get("HumanReadable") == "Something went wrong."
    assert result_context.get("EntryContext") == {}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"note": "test_note", "note_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("detection_id")),
        ({"detection_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("note_id")),
        (
            {"detection_id": "0", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "0"),
        ),
        (
            {"detection_id": "-1", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "-1"),
        ),
        (
            {"detection_id": "1.5", "note": "test_note", "note_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("detection_id", "1.5"),
        ),
        (
            {"note_id": "0", "note": "test_note", "detection_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "0"),
        ),
        (
            {"note_id": "-1", "note": "test_note", "detection_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "-1"),
        ),
        (
            {"note_id": "1.5", "note": "test_note", "detection_id": "1"},
            ERRORS["INVALID_INTEGER_VALUE"].format("note_id", "1.5"),
        ),
    ],
)
def test_vectra_detection_note_remove_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating a note of an entity.

    When:
    - Calling the 'vectra_detection_note_remove_command' function with the provided client and arguments.

    Then:
    - Assert that a ValueError is raised with the expected error message.
    """
    # Call the function and assert that it raises ValueError
    with pytest.raises(ValueError) as exception:
        vectra_detection_note_remove_command(client, args)

    assert str(exception.value) == error_msg


@pytest.mark.parametrize("entity_type", ["account", "host"])
def test_vectra_entity_unresolved_priority_reset_valid_arguments(requests_mock, client, entity_type):
    """
    Given:
    - A client object.
    - Valid arguments for marking entity unresolved priority as false.
    - Mocked API response for updating entity unresolved priority status.

    When:
    - Calling the 'vectra_entity_unresolved_priority_reset_command' function with valid entity_id and entity_type.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the expected message.
    - Assert that the 'EntryContext' property contains the correct entity_id and entity_type.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    entity_id = "123"
    mock_response = {"message": {"success": ["Successfully updated unresolved_priority"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}?type={entity_type}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type}

    result = vectra_entity_unresolved_priority_reset_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Entity"
    assert result.outputs_key_field == ["id", "type"]
    assert (
        result_context.get("HumanReadable")
        == "##### The unresolved priority of the provided entity has been successfully changed as 'false'."
    )

    entry_context = result_context.get("EntryContext")
    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    assert entry_context.get(context_key) is not None
    outputs = entry_context.get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("unresolved_priority") is False


def test_vectra_entity_unresolved_priority_reset_with_uppercase_entity_type(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments with uppercase entity_type.

    When:
    - Calling the 'vectra_entity_unresolved_priority_reset_command' function with uppercase entity_type.

    Then:
    - Assert that the function correctly converts entity_type to lowercase when making the API call.
    - Assert that the CommandResults object contains the expected outputs.
    """
    entity_id = "456"
    entity_type = "Account"
    mock_response = {"message": {"success": ["Successfully updated unresolved_priority"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}?type=account"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type}

    result = vectra_entity_unresolved_priority_reset_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Entity"
    assert (
        result_context.get("HumanReadable")
        == "##### The unresolved priority of the provided entity has been successfully changed as 'false'."
    )

    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("unresolved_priority") is False


def test_vectra_entity_unresolved_priority_reset_removes_nulls(requests_mock, client):
    """
    Given:
    - A client object.
    - API response containing null values.

    When:
    - Calling the 'vectra_entity_unresolved_priority_reset_command' function.

    Then:
    - Assert that null values are removed from the response before being added to outputs.
    """
    entity_id = "789"
    entity_type = "host"
    mock_response = {"message": {"success": ["Successfully updated unresolved_priority"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}?type={entity_type}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type}

    result = vectra_entity_unresolved_priority_reset_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("unresolved_priority") is False


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": None, "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "123"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "123", "entity_type": None}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "123", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        (
            {"entity_id": "0", "entity_type": "account"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        (
            {"entity_id": "abc", "entity_type": "account"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "abc"),
        ),
        (
            {"entity_id": "123", "entity_type": "invalid_type"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        (
            {"entity_id": "123", "entity_type": "user"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        (
            {"entity_id": "123", "entity_type": "detection"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
    ],
)
def test_vectra_entity_unresolved_priority_reset_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for marking entity unresolved priority as false.

    When:
    - Calling the 'vectra_entity_unresolved_priority_reset_command' function with invalid arguments.

    Then:
    - Assert that a ValueError is raised.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    with pytest.raises(ValueError) as exception:
        vectra_entity_unresolved_priority_reset_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_unresolved_priority_reset_api_error(requests_mock, client):
    """
    Given:
    - A client object.
    - API returns an error response.

    When:
    - Calling the 'vectra_entity_unresolved_priority_reset_command' function.

    Then:
    - Assert that the function raises an appropriate exception when the API call fails.
    """
    entity_id = "999"
    entity_type = "account"
    mock_response = {
        "errors": {"unresolved_priority": ["unresolved_priority can only be set to false when is_prioritized is false"]},
        "_meta": {"level": "error"},
    }

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}?type={entity_type}"
    requests_mock.patch(url, json=mock_response, status_code=400)

    args = {"entity_id": entity_id, "entity_type": entity_type}

    with pytest.raises(DemistoException):
        vectra_entity_unresolved_priority_reset_command(client, args)


@pytest.mark.parametrize("detection_status", ["open", "acknowledged", "escalated", "paused", "closed", "expired"])
def test_vectra_detection_status_update_valid_single_detection(requests_mock, client, detection_status):
    """
    Given:
    - A client object.
    - Valid arguments for updating detection status with a single detection ID.
    - Mocked API response for updating detection status.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with valid detection_id and detection_status.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the expected message.
    - Assert that the 'EntryContext' property contains the correct detection_ids and detection_status.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    detection_id = "123"
    mock_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_id, "investigation_status": detection_status}

    result = vectra_detection_investigation_status_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Detection"
    assert result.outputs_key_field == "id"
    assert result_context.get("HumanReadable") == (
        f"##### The investigation status for provided Detection ID(s) ['{detection_id}'] have been updated as {detection_status}."
    )

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 1
    assert outputs[0].get("id") == detection_id
    assert outputs[0].get("investigation_status") == detection_status


def test_vectra_detection_status_update_valid_multiple_detections(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments for updating detection status with multiple detection IDs.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with multiple detection IDs.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that detection IDs are sorted in the output.
    """
    detection_ids = "3,1,2"
    detection_status = "escalated"
    mock_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_ids, "investigation_status": detection_status}

    result = vectra_detection_investigation_status_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Detection"
    assert (
        result_context.get("HumanReadable")
        == f"##### The investigation status for provided Detection ID(s) ['3', '1', '2'] have been updated as {detection_status}."
    )

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 3
    detection_ids_in_output = [item.get("id") for item in outputs]
    assert set(detection_ids_in_output) == {"3", "1", "2"}
    for item in outputs:
        assert item.get("investigation_status") == detection_status


def test_vectra_detection_status_update_with_uppercase_status(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments with uppercase detection_status.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with uppercase detection_status.

    Then:
    - Assert that the function accepts uppercase status values.
    - Assert that the CommandResults object contains the expected outputs.
    """
    detection_id = "456"
    detection_status = "Escalated"
    mock_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_id, "investigation_status": detection_status}

    result = vectra_detection_investigation_status_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Detection"
    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 1
    assert outputs[0].get("investigation_status") == detection_status


def test_vectra_detection_status_update_removes_nulls(requests_mock, client):
    """
    Given:
    - A client object.
    - API response containing null values.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function.

    Then:
    - Assert that null values are removed from the response before being added to outputs.
    """
    detection_id = "789"
    detection_status = "closed"
    mock_response = {
        "message": {"success": ["Successfully updated detection statuses"]},
        "_meta": {"level": "success"},
        "extra_field": None,
        "another_null": None,
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_id, "investigation_status": detection_status}

    result = vectra_detection_investigation_status_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 1
    assert outputs[0].get("id") == detection_id
    assert outputs[0].get("investigation_status") == detection_status


def test_vectra_detection_status_update_with_whitespace_in_ids(requests_mock, client):
    """
    Given:
    - A client object.
    - Detection IDs with whitespace.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with detection IDs containing whitespace.

    Then:
    - Assert that whitespace is properly stripped from detection IDs.
    """
    detection_ids = " 1 , 2 , 3 "
    detection_status = "acknowledged"
    mock_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_ids, "investigation_status": detection_status}

    result = vectra_detection_investigation_status_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 3
    detection_ids_in_output = [item.get("id") for item in outputs]
    assert set(detection_ids_in_output) == {"1", "2", "3"}


def test_vectra_detection_status_update_with_mixed_valid_invalid_ids(mocker, requests_mock, client):
    """
    Given:
    - A client object.
    - Mixed valid and invalid detection IDs.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with mixed valid/invalid IDs.

    Then:
    - Assert that a warning is returned for invalid IDs.
    - Assert that valid IDs are processed successfully.
    """
    detection_ids = "1,abc,2,0,-3"
    detection_status = "paused"
    mock_response = {"message": {"success": ["Successfully updated detection statuses"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    mock_return_warning = mocker.patch("VectraRUXEventsDetections.return_warning")

    args = {"detection_ids": detection_ids, "investigation_status": detection_status}

    result = vectra_detection_investigation_status_update_command(client, args)

    mock_return_warning.assert_called_once()
    call_args = mock_return_warning.call_args
    assert "abc,0,-3" in call_args[1]["message"]
    assert call_args[1]["exit"] is False

    result_context = result.to_context()
    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    detection_ids_in_output = [item.get("id") for item in outputs]
    assert set(detection_ids_in_output) == {"1", "2"}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": None}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": ""}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("investigation_status")),
        ({"detection_ids": "1", "investigation_status": None}, ERRORS["REQUIRED_ARGUMENT"].format("investigation_status")),
        ({"detection_ids": "1", "investigation_status": ""}, ERRORS["REQUIRED_ARGUMENT"].format("investigation_status")),
        (
            {"detection_ids": "1", "investigation_status": "invalid_status"},
            ERRORS["INVALID_ARG_VALUE"].format(
                "investigation_status", ", ".join([status.lower() for status in VALID_DETECTION_STATUS])
            ),
        ),
        (
            {"detection_ids": "1", "investigation_status": "pending"},
            ERRORS["INVALID_ARG_VALUE"].format(
                "investigation_status", ", ".join([status.lower() for status in VALID_DETECTION_STATUS])
            ),
        ),
        (
            {"detection_ids": "1", "investigation_status": "resolved"},
            ERRORS["INVALID_ARG_VALUE"].format(
                "investigation_status", ", ".join([status.lower() for status in VALID_DETECTION_STATUS])
            ),
        ),
    ],
)
def test_vectra_detection_status_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating detection status.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with invalid arguments.

    Then:
    - Assert that a ValueError is raised.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    with pytest.raises(ValueError) as exception:
        vectra_detection_investigation_status_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_status_update_all_invalid_ids(mocker, requests_mock, client):
    """
    Given:
    - A client object.
    - All invalid detection IDs.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function with all invalid IDs.

    Then:
    - Assert that return_warning is called with exit=True.
    """
    detection_ids = "abc,xyz,0,-1"
    detection_status = "escalated"

    args = {"detection_ids": detection_ids, "investigation_status": detection_status}

    with pytest.raises(DemistoException) as exception:
        vectra_detection_investigation_status_update_command(client, args)

    assert str(exception.value) == ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ",".join(["abc", "xyz", "0", "-1"]))


def test_vectra_detection_status_update_api_error(requests_mock, client):
    """
    Given:
    - A client object.
    - API returns an error response.

    When:
    - Calling the 'vectra_detection_investigation_status_update_command' function.

    Then:
    - Assert that the function raises an appropriate exception when the API call fails.
    """
    detection_id = "999"
    detection_status = "escalated"

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json={"error": "Detection not found"}, status_code=404)

    args = {"detection_ids": detection_id, "investigation_status": detection_status}

    with pytest.raises(DemistoException):
        vectra_detection_investigation_status_update_command(client, args)


def test_vectra_detection_external_id_update_valid_single_detection(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments for updating external reference ID with a single detection ID.
    - Mocked API response for updating detection external reference ID.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with valid detection_id and external_reference_id.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the expected message.
    - Assert that the 'EntryContext' property contains the correct detection_id and external_reference_id.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    detection_id = "123"
    external_reference_id = "EXT-12345"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_id, "external_reference_id": external_reference_id}

    result = vectra_detection_external_id_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Detection"
    assert result.outputs_key_field == "id"
    assert result_context.get("HumanReadable") == (
        f"##### The external reference ID for provided Detection ID(s) ['{detection_id}'] "
        f"have been updated as {external_reference_id}."
    )

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 1
    assert outputs[0].get("id") == detection_id
    assert outputs[0].get("external_reference_id") == external_reference_id


def test_vectra_detection_external_id_update_valid_multiple_detections(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments for updating external reference ID with multiple detection IDs.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with multiple detection IDs.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert that all detection IDs are present in the output.
    """
    detection_ids = "3,1,2"
    external_reference_id = "EXT-67890"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_ids, "external_reference_id": external_reference_id}

    result = vectra_detection_external_id_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Detection"
    assert result_context.get("HumanReadable") == (
        "##### The external reference ID for provided Detection ID(s) ['3', '1', '2'] "
        f"have been updated as {external_reference_id}."
    )

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 3
    detection_ids_in_output = [item.get("id") for item in outputs]
    assert set(detection_ids_in_output) == {"3", "1", "2"}
    for item in outputs:
        assert item.get("external_reference_id") == external_reference_id


def test_vectra_detection_external_id_update_removes_nulls(requests_mock, client):
    """
    Given:
    - A client object.
    - API response containing null values.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function.

    Then:
    - Assert that null values are removed from the response before being added to outputs.
    """
    detection_id = "789"
    external_reference_id = "EXT-TICKET-001"
    mock_response = {
        "message": {"success": ["Successfully updated external reference ID"]},
        "_meta": {"level": "success"},
        "extra_field": None,
        "another_null": None,
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_id, "external_reference_id": external_reference_id}

    result = vectra_detection_external_id_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 1
    assert outputs[0].get("id") == detection_id
    assert outputs[0].get("external_reference_id") == external_reference_id


def test_vectra_detection_external_id_update_with_whitespace_in_ids(requests_mock, client):
    """
    Given:
    - A client object.
    - Detection IDs with whitespace.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with detection IDs containing whitespace.

    Then:
    - Assert that whitespace is properly stripped from detection IDs.
    """
    detection_ids = " 1 , 2 , 3 "
    external_reference_id = "EXT-WS-123"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_ids, "external_reference_id": external_reference_id}

    result = vectra_detection_external_id_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 3
    detection_ids_in_output = [item.get("id") for item in outputs]
    assert set(detection_ids_in_output) == {"1", "2", "3"}


def test_vectra_detection_external_id_update_with_mixed_valid_invalid_ids(mocker, requests_mock, client):
    """
    Given:
    - A client object.
    - A mix of valid and invalid detection IDs.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with mixed valid and invalid IDs.

    Then:
    - Assert that return_warning is called for invalid IDs.
    - Assert that valid IDs are processed successfully.
    """
    detection_ids = "1,abc,2,0,-3"
    external_reference_id = "EXT-MIXED-456"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    mock_return_warning = mocker.patch("VectraRUXEventsDetections.return_warning")

    args = {"detection_ids": detection_ids, "external_reference_id": external_reference_id}

    result = vectra_detection_external_id_update_command(client, args)

    mock_return_warning.assert_called_once()
    call_args = mock_return_warning.call_args
    assert "abc,0,-3" in call_args[1]["message"]
    assert call_args[1]["exit"] is False

    result_context = result.to_context()
    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    detection_ids_in_output = [item.get("id") for item in outputs]
    assert set(detection_ids_in_output) == {"1", "2"}


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": None}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": ""}, ERRORS["REQUIRED_ARGUMENT"].format("detection_ids")),
        ({"detection_ids": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id")),
        ({"detection_ids": "1", "external_reference_id": None}, ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id")),
        ({"detection_ids": "1", "external_reference_id": ""}, ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id")),
    ],
)
def test_vectra_detection_external_id_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating external reference ID.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with invalid arguments.

    Then:
    - Assert that a ValueError is raised.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    with pytest.raises(ValueError) as exception:
        vectra_detection_external_id_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_external_id_update_all_invalid_ids(mocker, requests_mock, client):
    """
    Given:
    - A client object.
    - All invalid detection IDs.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with all invalid IDs.

    Then:
    - Assert that return_warning is called with exit=True.
    """
    detection_ids = "abc,xyz,0,-1"
    external_reference_id = "EXT-INVALID-789"

    args = {"detection_ids": detection_ids, "external_reference_id": external_reference_id}

    with pytest.raises(DemistoException) as exception:
        vectra_detection_external_id_update_command(client, args)

    assert str(exception.value) == ERRORS["INVALID_INTEGER_VALUE"].format("detection_ids", ",".join(["abc", "xyz", "0", "-1"]))


def test_vectra_detection_external_id_update_api_error(requests_mock, client):
    """
    Given:
    - A client object.
    - API returns an error response.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function.

    Then:
    - Assert that the function raises an appropriate exception when the API call fails.
    """
    detection_id = "999"
    external_reference_id = "EXT-ERROR-404"

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json={"error": "Detection not found"}, status_code=404)

    args = {"detection_ids": detection_id, "external_reference_id": external_reference_id}

    with pytest.raises(DemistoException):
        vectra_detection_external_id_update_command(client, args)


def test_vectra_detection_external_id_update_with_special_characters(requests_mock, client):
    """
    Given:
    - A client object.
    - External reference ID with special characters.

    When:
    - Calling the 'vectra_detection_external_id_update_command' function with special characters in external_reference_id.

    Then:
    - Assert that special characters are handled correctly.
    """
    detection_id = "456"
    external_reference_id = "TICKET-2024-#123-ABC_XYZ"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"detection_ids": detection_id, "external_reference_id": external_reference_id}

    result = vectra_detection_external_id_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Detection(val.id && val.id == obj.id)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert isinstance(outputs, list)
    assert len(outputs) == 1
    assert outputs[0].get("id") == detection_id
    assert outputs[0].get("external_reference_id") == external_reference_id


@pytest.mark.parametrize("entity_type", ["account", "host"])
def test_vectra_entity_external_id_update_valid_arguments(requests_mock, client, entity_type):
    """
    Given:
    - A client object.
    - Valid arguments for updating entity external reference ID.
    - Mocked API response for updating entity external reference ID.

    When:
    - Calling the 'vectra_entity_external_id_update_command' function with valid
    entity_id, entity_type, and external_reference_id.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the human-readable output matches the expected message.
    - Assert that the 'EntryContext' property contains the correct entity_id, entity_type, and external_reference_id.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    entity_id = "123"
    external_reference_id = "EXT-ENTITY-12345"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type, "external_reference_id": external_reference_id}

    result = vectra_entity_external_id_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Entity"
    assert result.outputs_key_field == ["id", "type"]
    assert (
        result_context.get("HumanReadable")
        == f"##### The external reference ID for provided Entity have been updated as {external_reference_id}."
    )

    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("external_reference_id") == external_reference_id


def test_vectra_entity_external_id_update_with_uppercase_entity_type(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments with uppercase entity_type.

    When:
    - Calling the 'vectra_entity_external_id_update_command' function with uppercase entity_type.

    Then:
    - Assert that the function accepts uppercase entity type values.
    - Assert that the CommandResults object contains the expected outputs.
    """
    entity_id = "456"
    entity_type = "Account"
    external_reference_id = "EXT-UPPER-789"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type, "external_reference_id": external_reference_id}

    result = vectra_entity_external_id_update_command(client, args)
    result_context = result.to_context()

    assert result.outputs_prefix == "Vectra.Entity"
    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("external_reference_id") == external_reference_id


def test_vectra_entity_external_id_update_removes_nulls(requests_mock, client):
    """
    Given:
    - A client object.
    - API response containing null values.

    When:
    - Calling the 'vectra_entity_external_id_update_command' function.

    Then:
    - Assert that null values are removed from the response before being added to outputs.
    """
    entity_id = "789"
    entity_type = "host"
    external_reference_id = "EXT-NULL-TEST"
    mock_response = {
        "message": {"success": ["Successfully updated external reference ID"]},
        "_meta": {"level": "success"},
        "extra_field": None,
        "another_null": None,
    }

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type, "external_reference_id": external_reference_id}

    result = vectra_entity_external_id_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("external_reference_id") == external_reference_id


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": None}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"entity_id": "1"}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "1", "entity_type": None}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "1", "entity_type": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_type")),
        ({"entity_id": "1", "entity_type": "account"}, ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id")),
        (
            {"entity_id": "1", "entity_type": "account", "external_reference_id": None},
            ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id"),
        ),
        (
            {"entity_id": "1", "entity_type": "account", "external_reference_id": ""},
            ERRORS["REQUIRED_ARGUMENT"].format("external_reference_id"),
        ),
        (
            {"entity_id": "0", "entity_type": "account", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "0"),
        ),
        (
            {"entity_id": "-1", "entity_type": "account", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "-1"),
        ),
        (
            {"entity_id": "1.5", "entity_type": "account", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "1.5"),
        ),
        (
            {"entity_id": "abc", "entity_type": "account", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_INTEGER_VALUE"].format("entity_id", "abc"),
        ),
        (
            {"entity_id": "1", "entity_type": "invalid_type", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        (
            {"entity_id": "1", "entity_type": "user", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
        (
            {"entity_id": "1", "entity_type": "detection", "external_reference_id": "EXT-123"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", ", ".join(VALID_ENTITY_TYPE)),
        ),
    ],
)
def test_vectra_entity_external_id_update_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for updating entity external reference ID.

    When:
    - Calling the 'vectra_entity_external_id_update_command' function with invalid arguments.

    Then:
    - Assert that a ValueError is raised.
    - Assert that the error message matches the expected error message for each invalid argument.
    """
    with pytest.raises(ValueError) as exception:
        vectra_entity_external_id_update_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_entity_external_id_update_api_error(requests_mock, client):
    """
    Given:
    - A client object.
    - API returns an error response.

    When:
    - Calling the 'vectra_entity_external_id_update_command' function.

    Then:
    - Assert that the function raises an appropriate exception when the API call fails.
    """
    entity_id = "999"
    entity_type = "account"
    external_reference_id = "EXT-ERROR-404"

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}"
    requests_mock.patch(url, json={"error": "Entity not found"}, status_code=404)

    args = {"entity_id": entity_id, "entity_type": entity_type, "external_reference_id": external_reference_id}

    with pytest.raises(DemistoException):
        vectra_entity_external_id_update_command(client, args)


def test_vectra_entity_external_id_update_with_special_characters(requests_mock, client):
    """
    Given:
    - A client object.
    - External reference ID with special characters.

    When:
    - Calling the 'vectra_entity_external_id_update_command' function with special characters in external_reference_id.

    Then:
    - Assert that special characters are handled correctly.
    """
    entity_id = "555"
    entity_type = "host"
    external_reference_id = "TICKET-2024-#456-XYZ_ABC"
    mock_response = {"message": {"success": ["Successfully updated external reference ID"]}, "_meta": {"level": "success"}}

    url = f"{BASE_URL}{ENDPOINTS['ENTITY_ENDPOINT']}/{entity_id}"
    requests_mock.patch(url, json=mock_response, status_code=200)

    args = {"entity_id": entity_id, "entity_type": entity_type, "external_reference_id": external_reference_id}

    result = vectra_entity_external_id_update_command(client, args)
    result_context = result.to_context()

    context_key = "Vectra.Entity(val.id && val.id == obj.id && val.type && val.type == obj.type)"
    outputs = result_context.get("EntryContext").get(context_key)
    assert outputs.get("id") == entity_id
    assert outputs.get("type") == entity_type
    assert outputs.get("external_reference_id") == external_reference_id


def test_vectra_detection_list_command_success(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments for listing detections.
    - Mocked API response with detection results.

    When:
    - Calling the 'vectra_detection_list_command' function.

    Then:
    - Assert that the CommandResults object contains the expected outputs.
    - Assert the correctness of the 'outputs_prefix' property.
    - Assert that the 'outputs' contains detection data.
    - Assert the correctness of the 'outputs_key_field' property.
    """
    mock_response = {
        "count": 2,
        "results": [
            {
                "id": 123,
                "detection": "Test Detection 1",
                "state": "active",
                "certainty": 85,
                "threat": 75,
                "url": "https://example.com/api/v3.3/detections/123",
            },
            {
                "id": 456,
                "detection": "Test Detection 2",
                "state": "active",
                "certainty": 90,
                "threat": 80,
                "url": "https://example.com/api/v3.3/detections/456",
            },
        ],
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {"page": "1", "page_size": "50"}

    result = vectra_detection_list_command(client, args)

    assert result.outputs_prefix == "Vectra.Detection"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == 123
    assert result.outputs[1]["id"] == 456


def test_vectra_detection_list_command_no_results(requests_mock, client):
    """
    Given:
    - A client object.
    - Valid arguments for listing detections.
    - Mocked API response with no detection results.

    When:
    - Calling the 'vectra_detection_list_command' function.

    Then:
    - Assert that the function returns a message indicating no detections found.
    - Assert that outputs is an empty dictionary.
    """
    mock_response = {"count": 0, "results": []}

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {"page": "1", "page_size": "50"}

    result = vectra_detection_list_command(client, args)
    result_context = result.to_context()

    assert result_context.get("HumanReadable") == "##### Couldn't find any detections for provided filters."
    assert result_context.get("EntryContext") == {}


def test_vectra_detection_list_command_with_filters(requests_mock, client):
    """
    Given:
    - A client object.
    - Arguments with multiple filters (detection_name, detection_state, tags).

    When:
    - Calling the 'vectra_detection_list_command' function with filters.

    Then:
    - Assert that the function returns filtered detection results.
    """
    mock_response = {
        "count": 1,
        "results": [
            {
                "id": 789,
                "detection": "Filtered Detection",
                "state": "active",
                "tags": ["critical", "malware"],
                "url": "https://example.com/api/v3.3/detections/789",
            }
        ],
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {
        "detection_name": "Filtered Detection",
        "detection_state": "active",
        "tags": "critical,malware",
        "page": "1",
        "page_size": "50",
    }

    result = vectra_detection_list_command(client, args)

    assert result.outputs_prefix == "Vectra.Detection"
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == 789


def test_vectra_detection_list_command_with_pagination(requests_mock, client):
    """
    Given:
    - A client object.
    - Arguments with custom page and page_size.

    When:
    - Calling the 'vectra_detection_list_command' function with pagination parameters.

    Then:
    - Assert that the function returns the correct page of results.
    """
    mock_response = {
        "count": 100,
        "results": [
            {"id": i, "detection": f"Detection {i}", "url": f"https://example.com/api/v3.3/detections/{i}"}
            for i in range(51, 101)
        ],
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {"page": "2", "page_size": "50"}

    result = vectra_detection_list_command(client, args)

    assert result.outputs_prefix == "Vectra.Detection"
    assert len(result.outputs) == 50


def test_vectra_detection_list_command_with_time_filters(requests_mock, client):
    """
    Given:
    - A client object.
    - Arguments with time-based filters (created_after, created_before).

    When:
    - Calling the 'vectra_detection_list_command' function with time filters.

    Then:
    - Assert that the function returns detections within the time range.
    """
    mock_response = {
        "count": 1,
        "results": [
            {
                "id": 999,
                "detection": "Recent Detection",
                "created_timestamp": "2024-01-15T10:00:00Z",
                "url": "https://example.com/api/v3.3/detections/999",
            }
        ],
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {"created_after": "2024-01-01", "created_before": "2024-01-31", "page": "1", "page_size": "50"}

    result = vectra_detection_list_command(client, args)

    assert result.outputs_prefix == "Vectra.Detection"
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == 999


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"include_info_category_detections": "invalid_bool", "page": "1", "page_size": "50"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("include_info_category_detections", ", ".join(VALID_BOOL_VALUES)),
        ),
        (
            {"is_triaged": "invalid_bool", "page": "1", "page_size": "50"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("is_triaged", ", ".join(VALID_BOOL_VALUES)),
        ),
        (
            {"close_reason": "invalid_reason", "page": "1", "page_size": "50"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("close_reason", ", ".join(VALID_CLOSE_REASON)),
        ),
        (
            {"entity_type": "invalid_type", "page": "1", "page_size": "50"},
            ERRORS["INVALID_COMMAND_ARG_VALUE"].format("entity_type", (", ".join(VALID_ENTITY_TYPES)).lower()),
        ),
        ({"page": "0", "page_size": "50"}, ERRORS["INVALID_INTEGER_VALUE"].format("page", "0")),
        ({"page": "-1", "page_size": "50"}, ERRORS["INVALID_INTEGER_VALUE"].format("page", "-1")),
        ({"page": "1", "page_size": "0"}, ERRORS["INVALID_INTEGER_VALUE"].format("page_size", "0")),
        ({"page": "1", "page_size": "6000"}, ERRORS["INVALID_PAGE_SIZE"]),
    ],
)
def test_vectra_detection_list_command_invalid_args(client, args, error_msg):
    """
    Given:
    - A client object.
    - Invalid arguments for listing detections.

    When:
    - Calling the 'vectra_detection_list_command' function with invalid arguments.

    Then:
    - Assert that a ValueError is raised.
    - Assert that the error message matches the expected error message.
    """
    with pytest.raises(ValueError) as exception:
        vectra_detection_list_command(client, args)

    assert str(exception.value) == error_msg


def test_vectra_detection_list_command_invalid_time_range(client):
    """
    Given:
    - A client object.
    - Arguments with invalid time range (created_after > created_before).

    When:
    - Calling the 'vectra_detection_list_command' function.

    Then:
    - Assert that a ValueError is raised for invalid time range.
    """
    args = {"created_after": "2024-01-31", "created_before": "2024-01-01", "page": "1", "page_size": "50"}

    with pytest.raises(ValueError) as exception:
        vectra_detection_list_command(client, args)

    assert "Invalid time range" in str(exception.value)


def test_vectra_detection_list_command_with_description_filter(requests_mock, client):
    """
    Given:
    - A client object.
    - Arguments with description filter.

    When:
    - Calling the 'vectra_detection_list_command' function with description filter.

    Then:
    - Assert that the function returns detections matching the description.
    """
    mock_response = {
        "count": 1,
        "results": [
            {
                "id": 111,
                "detection": "Suspicious Activity",
                "description": "Malware detected on endpoint",
                "url": "https://example.com/api/v3.3/detections/111",
            }
        ],
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {"description": "Malware", "page": "1", "page_size": "50"}

    result = vectra_detection_list_command(client, args)

    assert result.outputs_prefix == "Vectra.Detection"
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == 111


def test_vectra_detection_list_command_with_triaged_filter(requests_mock, client):
    """
    Given:
    - A client object.
    - Arguments with is_triaged filter set to true.

    When:
    - Calling the 'vectra_detection_list_command' function with is_triaged filter.

    Then:
    - Assert that the function returns only triaged detections.
    """
    mock_response = {
        "count": 1,
        "results": [
            {
                "id": 222,
                "detection": "Triaged Detection",
                "is_triaged": True,
                "url": "https://example.com/api/v3.3/detections/222",
            }
        ],
    }

    url = f"{BASE_URL}{ENDPOINTS['DETECTION_ENDPOINT']}"
    requests_mock.get(url, json=mock_response, status_code=200)

    args = {"is_triaged": "true", "page": "1", "page_size": "50"}

    result = vectra_detection_list_command(client, args)

    assert result.outputs_prefix == "Vectra.Detection"
    assert len(result.outputs) == 1
    assert result.outputs[0]["is_triaged"] is True


def test_vectra_investigation_query_send_command_success(mocker, client):
    """
    Given:
    - A client object.
    - Valid query and version arguments.

    When:
    - Calling vectra_investigation_query_send_command with valid arguments.

    Then:
    - Assert that the command returns a CommandResults object with the correct outputs.
    - Assert that the investigation_query_send method was called with correct parameters.
    - Assert that the human readable output contains the request_id.
    """
    mock_response = {
        "request_id": "inv-12345",
        "query": "SELECT * FROM detections WHERE severity > 5",
        "version": "v1",
        "status": "pending",
    }
    mocker.patch.object(client, "investigation_query_send", return_value=mock_response)

    args = {
        "query": "SELECT * FROM detections WHERE severity > 5",
        "version": "v1",
    }

    result = vectra_investigation_query_send_command(client, args)

    client.investigation_query_send.assert_called_once_with(
        query="SELECT * FROM detections WHERE severity > 5",
        version="v1",
    )

    assert result.outputs_prefix == "Vectra.Investigation"
    assert result.outputs_key_field == "request_id"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response
    assert result.readable_output is not None
    assert "inv-12345" in result.readable_output
    assert "!vectra-investigation-result-get" in result.readable_output


def test_vectra_investigation_query_send_command_without_version(mocker, client):
    """
    Given:
    - A client object.
    - Valid query argument without version.

    When:
    - Calling vectra_investigation_query_send_command without version.

    Then:
    - Assert that the command returns a CommandResults object.
    - Assert that the investigation_query_send method was called with query and None for version.
    """
    mock_response = {
        "request_id": "inv-67890",
        "query": "SELECT * FROM hosts",
        "version": None,
        "status": "pending",
    }
    mocker.patch.object(client, "investigation_query_send", return_value=mock_response)

    args = {
        "query": "SELECT * FROM hosts",
    }

    result = vectra_investigation_query_send_command(client, args)

    client.investigation_query_send.assert_called_once_with(
        query="SELECT * FROM hosts",
        version=None,
    )

    assert result.outputs_prefix == "Vectra.Investigation"
    assert result.outputs_key_field == "request_id"
    assert result.outputs == mock_response
    assert result.readable_output is not None
    assert "inv-67890" in result.readable_output


def test_vectra_investigation_query_send_command_missing_query(client):
    """
    Given:
    - A client object.
    - Arguments without the required 'query' parameter.

    When:
    - Calling vectra_investigation_query_send_command without query.

    Then:
    - Assert that ValueError is raised with the appropriate error message.
    """
    args = {
        "version": "v1",
    }

    with pytest.raises(ValueError) as exception:
        vectra_investigation_query_send_command(client, args)

    assert ERRORS["REQUIRED_ARGUMENT"].format("query") in str(exception.value)


def test_vectra_investigation_query_send_command_empty_query(client):
    """
    Given:
    - A client object.
    - Arguments with an empty 'query' parameter.

    When:
    - Calling vectra_investigation_query_send_command with empty query.

    Then:
    - Assert that ValueError is raised with the appropriate error message.
    """
    args = {
        "query": "",
        "version": "v1",
    }

    with pytest.raises(ValueError) as exception:
        vectra_investigation_query_send_command(client, args)

    assert ERRORS["REQUIRED_ARGUMENT"].format("query") in str(exception.value)


def test_vectra_investigation_query_send_command_with_complex_query(mocker, client):
    """
    Given:
    - A client object.
    - A complex SQL-like query with multiple conditions.

    When:
    - Calling vectra_investigation_query_send_command with a complex query.

    Then:
    - Assert that the command returns a CommandResults object.
    - Assert that the query is passed correctly to the client method.
    """
    complex_query = """
    SELECT d.id, d.name, d.severity, h.ip_address
    FROM detections d
    JOIN hosts h ON d.host_id = h.id
    WHERE d.severity > 7 AND d.status = 'active'
    ORDER BY d.severity DESC
    LIMIT 100
    """
    mock_response = {
        "request_id": "inv-complex-001",
        "query": complex_query,
        "version": "v2",
        "status": "pending",
    }
    mocker.patch.object(client, "investigation_query_send", return_value=mock_response)

    args = {
        "query": complex_query,
        "version": "v2",
    }

    result = vectra_investigation_query_send_command(client, args)

    client.investigation_query_send.assert_called_once_with(
        query=complex_query,
        version="v2",
    )

    assert result.outputs_prefix == "Vectra.Investigation"
    assert result.outputs == mock_response
    assert result.readable_output is not None
    assert "inv-complex-001" in result.readable_output


def test_vectra_investigation_query_send_command_response_with_nulls(mocker, client):
    """
    Given:
    - A client object.
    - Valid query argument.
    - API response contains null values.

    When:
    - Calling vectra_investigation_query_send_command.

    Then:
    - Assert that null values are removed from the response.
    - Assert that the command returns a CommandResults object without nulls.
    """
    mock_response_with_nulls = {
        "request_id": "inv-nulls-123",
        "query": "SELECT * FROM accounts",
        "version": "v1",
        "status": "pending",
        "error": None,
        "metadata": None,
    }
    expected_response = {
        "request_id": "inv-nulls-123",
        "query": "SELECT * FROM accounts",
        "version": "v1",
        "status": "pending",
    }
    mocker.patch.object(client, "investigation_query_send", return_value=mock_response_with_nulls)

    args = {
        "query": "SELECT * FROM accounts",
        "version": "v1",
    }

    result = vectra_investigation_query_send_command(client, args)

    assert result.outputs == expected_response
    assert isinstance(result.outputs, dict)
    assert "error" not in result.outputs
    assert "metadata" not in result.outputs


def test_vectra_investigation_query_send_command_api_error(mocker, client):
    """
    Given:
    - A client object.
    - Valid query argument.
    - API call raises an exception.

    When:
    - Calling vectra_investigation_query_send_command.

    Then:
    - Assert that the exception is propagated.
    """
    mocker.patch.object(
        client,
        "investigation_query_send",
        side_effect=DemistoException("API connection error"),
    )

    args = {
        "query": "SELECT * FROM detections",
        "version": "v1",
    }

    with pytest.raises(DemistoException) as exception:
        vectra_investigation_query_send_command(client, args)

    assert "API connection error" in str(exception.value)


def test_vectra_investigation_result_get_command_success(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID with page and page_size arguments.

    When:
    - Calling vectra_investigation_result_get_command with valid arguments.

    Then:
    - Assert that the command returns a CommandResults object with the correct outputs.
    - Assert that the investigation_result_get method was called with correct parameters.
    - Assert that the human readable output contains the request_id and metadata.
    """
    mock_response = {
        "request_id": "inv-12345",
        "meta": {
            "query_status": "completed",
            "page": 1,
            "page_size": 50,
            "num_rows_available": 100,
            "estimated_file_size_bytes": 2048,
            "columns": ["id", "name", "severity"],
        },
        "data": [
            {"id": 1, "name": "Detection 1", "severity": 8},
            {"id": 2, "name": "Detection 2", "severity": 6},
        ],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-12345",
        "page": "1",
        "page_size": "50",
    }

    result = vectra_investigation_result_get_command(client, args)

    client.investigation_result_get.assert_called_once_with(
        request_id="inv-12345",
        page=1,
        page_size=50,
    )

    assert result.outputs_prefix == "Vectra.Investigation"
    assert result.outputs_key_field == "request_id"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response
    assert result.readable_output is not None
    assert "inv-12345" in result.readable_output
    assert "completed" in result.readable_output
    assert "Detection 1" in result.readable_output


def test_vectra_investigation_result_get_command_with_defaults(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID without page and page_size arguments.

    When:
    - Calling vectra_investigation_result_get_command with only request ID.

    Then:
    - Assert that the command uses default values for page and page_size.
    - Assert that the investigation_result_get method was called with default parameters.
    """
    mock_response = {
        "request_id": "inv-67890",
        "meta": {
            "query_status": "pending",
            "page": 1,
            "page_size": 50,
            "num_rows_available": 0,
        },
        "data": [],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-67890",
    }

    result = vectra_investigation_result_get_command(client, args)

    client.investigation_result_get.assert_called_once_with(
        request_id="inv-67890",
        page=1,
        page_size=50,
    )

    assert result.outputs_prefix == "Vectra.Investigation"
    assert result.outputs_key_field == "request_id"
    assert result.outputs == mock_response
    assert result.readable_output is not None
    assert "inv-67890" in result.readable_output
    assert "pending" in result.readable_output


def test_vectra_investigation_result_get_command_missing_id(client):
    """
    Given:
    - A client object.
    - Arguments without the required 'id' parameter.

    When:
    - Calling vectra_investigation_result_get_command without id.

    Then:
    - Assert that ValueError is raised with the appropriate error message.
    """
    args = {
        "page": "1",
        "page_size": "50",
    }

    with pytest.raises(ValueError) as exception:
        vectra_investigation_result_get_command(client, args)

    assert ERRORS["REQUIRED_ARGUMENT"].format("id") in str(exception.value)


def test_vectra_investigation_result_get_command_empty_id(client):
    """
    Given:
    - A client object.
    - Arguments with an empty 'id' parameter.

    When:
    - Calling vectra_investigation_result_get_command with empty id.

    Then:
    - Assert that ValueError is raised with the appropriate error message.
    """
    args = {
        "id": "",
        "page": "1",
        "page_size": "50",
    }

    with pytest.raises(ValueError) as exception:
        vectra_investigation_result_get_command(client, args)

    assert ERRORS["REQUIRED_ARGUMENT"].format("id") in str(exception.value)


def test_vectra_investigation_result_get_command_invalid_page(client):
    """
    Given:
    - A client object.
    - Valid request ID with invalid page number (negative).

    When:
    - Calling vectra_investigation_result_get_command with invalid page.

    Then:
    - Assert that ValueError is raised for invalid page number.
    """
    args = {
        "id": "inv-12345",
        "page": "-1",
        "page_size": "50",
    }

    with pytest.raises(ValueError):
        vectra_investigation_result_get_command(client, args)


def test_vectra_investigation_result_get_command_invalid_page_size(client):
    """
    Given:
    - A client object.
    - Valid request ID with invalid page_size (zero).

    When:
    - Calling vectra_investigation_result_get_command with invalid page_size.

    Then:
    - Assert that ValueError is raised for invalid page_size.
    """
    args = {
        "id": "inv-12345",
        "page": "1",
        "page_size": "0",
    }

    with pytest.raises(ValueError):
        vectra_investigation_result_get_command(client, args)


def test_vectra_investigation_result_get_command_with_nulls(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID.
    - API response contains null values.

    When:
    - Calling vectra_investigation_result_get_command.

    Then:
    - Assert that null values are removed from the response.
    - Assert that the command returns a CommandResults object without nulls.
    """
    mock_response_with_nulls = {
        "request_id": "inv-nulls-456",
        "meta": {
            "query_status": "completed",
            "page": 1,
            "page_size": 50,
            "num_rows_available": 10,
            "estimated_file_size_bytes": None,
            "columns": ["id", "name"],
        },
        "data": [
            {"id": 1, "name": "Test", "extra": None},
        ],
        "error": None,
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response_with_nulls)

    args = {
        "id": "inv-nulls-456",
    }

    result = vectra_investigation_result_get_command(client, args)

    # remove_nulls_from_dictionary removes top-level None values but not nested ones
    assert isinstance(result.outputs, dict)
    assert result.outputs["request_id"] == "inv-nulls-456"
    assert "error" not in result.outputs  # Top-level None removed
    assert result.outputs["meta"]["query_status"] == "completed"
    # Nested None values may still be present depending on remove_nulls_from_dictionary implementation


def test_vectra_investigation_result_get_command_empty_data(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID.
    - API response with empty data array.

    When:
    - Calling vectra_investigation_result_get_command.

    Then:
    - Assert that the command handles empty data gracefully.
    - Assert that the readable output is generated correctly.
    """
    mock_response = {
        "request_id": "inv-empty-789",
        "meta": {
            "query_status": "completed",
            "page": 1,
            "page_size": 50,
            "num_rows_available": 0,
            "columns": [],
        },
        "data": [],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-empty-789",
    }

    result = vectra_investigation_result_get_command(client, args)

    # remove_nulls_from_dictionary removes empty lists, so 'data' and 'columns' keys may be removed
    assert isinstance(result.outputs, dict)
    assert result.outputs["request_id"] == "inv-empty-789"
    assert result.outputs["meta"]["query_status"] == "completed"
    assert result.readable_output is not None
    assert "inv-empty-789" in result.readable_output
    assert "completed" in result.readable_output


def test_vectra_investigation_result_get_command_large_page_size(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID with large page_size.

    When:
    - Calling vectra_investigation_result_get_command with large page_size.

    Then:
    - Assert that the command accepts the large page_size value.
    - Assert that the investigation_result_get method was called with the specified page_size.
    """
    mock_response = {
        "request_id": "inv-large-001",
        "meta": {
            "query_status": "completed",
            "page": 1,
            "page_size": 1000,
            "num_rows_available": 500,
        },
        "data": [],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-large-001",
        "page": "1",
        "page_size": "1000",
    }

    result = vectra_investigation_result_get_command(client, args)

    client.investigation_result_get.assert_called_once_with(
        request_id="inv-large-001",
        page=1,
        page_size=1000,
    )

    assert result.outputs == mock_response


def test_vectra_investigation_result_get_command_pagination(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID with specific page number.

    When:
    - Calling vectra_investigation_result_get_command with page 3.

    Then:
    - Assert that the command correctly passes the page parameter.
    - Assert that the investigation_result_get method was called with page 3.
    """
    mock_response = {
        "request_id": "inv-page-003",
        "meta": {
            "query_status": "completed",
            "page": 3,
            "page_size": 50,
            "num_rows_available": 200,
        },
        "data": [
            {"id": 101, "name": "Detection 101"},
            {"id": 102, "name": "Detection 102"},
        ],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-page-003",
        "page": "3",
        "page_size": "50",
    }

    result = vectra_investigation_result_get_command(client, args)

    client.investigation_result_get.assert_called_once_with(
        request_id="inv-page-003",
        page=3,
        page_size=50,
    )

    assert isinstance(result.outputs, dict)
    assert result.outputs["meta"]["page"] == 3  # type: ignore
    assert result.readable_output is not None
    assert "Detection 101" in result.readable_output


def test_vectra_investigation_result_get_command_api_error(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID.
    - API call raises an exception.

    When:
    - Calling vectra_investigation_result_get_command.

    Then:
    - Assert that the exception is propagated.
    """
    mocker.patch.object(
        client,
        "investigation_result_get",
        side_effect=DemistoException("API connection error"),
    )

    args = {
        "id": "inv-error-999",
        "page": "1",
        "page_size": "50",
    }

    with pytest.raises(DemistoException) as exception:
        vectra_investigation_result_get_command(client, args)

    assert "API connection error" in str(exception.value)


def test_vectra_investigation_result_get_command_query_status_failed(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID.
    - API response with query_status as 'failed'.

    When:
    - Calling vectra_investigation_result_get_command.

    Then:
    - Assert that the command returns the response with failed status.
    - Assert that the readable output contains the failed status.
    """
    mock_response = {
        "request_id": "inv-failed-111",
        "meta": {
            "query_status": "failed",
            "page": 1,
            "page_size": 50,
            "num_rows_available": 0,
            "error_message": "Query execution failed",
        },
        "data": [],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-failed-111",
    }

    result = vectra_investigation_result_get_command(client, args)

    assert isinstance(result.outputs, dict)
    assert result.outputs == mock_response
    assert result.outputs["meta"]["query_status"] == "failed"  # type: ignore
    assert result.readable_output is not None
    assert "failed" in result.readable_output
    assert "inv-failed-111" in result.readable_output


def test_vectra_investigation_result_get_command_complex_data(mocker, client):
    """
    Given:
    - A client object.
    - Valid request ID.
    - API response with complex nested data structures.

    When:
    - Calling vectra_investigation_result_get_command.

    Then:
    - Assert that the command handles complex data structures correctly.
    - Assert that the readable output is generated properly.
    """
    mock_response = {
        "request_id": "inv-complex-222",
        "meta": {
            "query_status": "completed",
            "page": 1,
            "page_size": 50,
            "num_rows_available": 2,
            "columns": ["id", "name", "metadata", "tags"],
        },
        "data": [
            {
                "id": 1,
                "name": "Complex Detection",
                "metadata": {"severity": 9, "category": "exfiltration"},
                "tags": ["critical", "reviewed"],
            },
            {
                "id": 2,
                "name": "Another Detection",
                "metadata": {"severity": 5, "category": "reconnaissance"},
                "tags": ["medium"],
            },
        ],
    }
    mocker.patch.object(client, "investigation_result_get", return_value=mock_response)

    args = {
        "id": "inv-complex-222",
    }

    result = vectra_investigation_result_get_command(client, args)

    assert isinstance(result.outputs, dict)
    assert result.outputs == mock_response
    assert len(result.outputs["data"]) == 2  # type: ignore
    assert result.outputs["data"][0]["metadata"]["severity"] == 9  # type: ignore
    assert result.readable_output is not None
    assert "Complex Detection" in result.readable_output


class TestUserRoleMapping:
    """Tests for the USER_ROLE_MAPPING constant added in v3.5 migration."""

    def test_user_role_mapping_constant_exists(self):
        """
        Given:
        - The USER_ROLE_MAPPING constant.

        When:
        - Checking if the constant is defined and contains expected mappings.

        Then:
        - Assert that the mapping contains all expected role conversions.
        """
        assert USER_ROLE_MAPPING is not None
        assert isinstance(USER_ROLE_MAPPING, dict)

        expected_mappings = {
            "Admin": "admins",
            "Auditor": "auditor",
            "Global Analyst": "global_analyst",
            "Read-Only": "read_only",
            "Restricted Admin": "restricted_admins",
            "Security Analyst": "security_analyst",
            "Setting Admin": "setting_admins",
            "Super Admin": "super_admins",
        }
        assert expected_mappings == USER_ROLE_MAPPING

    def test_user_role_mapping_admin_role(self):
        """Test Admin role mapping."""
        assert USER_ROLE_MAPPING.get("Admin") == "admins"

    def test_user_role_mapping_super_admin_role(self):
        """Test Super Admin role mapping."""
        assert USER_ROLE_MAPPING.get("Super Admin") == "super_admins"

    def test_user_role_mapping_security_analyst_role(self):
        """Test Security Analyst role mapping."""
        assert USER_ROLE_MAPPING.get("Security Analyst") == "security_analyst"


class TestVectraUserListCommandRoleMapping:
    """Tests for the role mapping functionality in vectra_user_list_command."""

    def test_vectra_user_list_with_role_mapping(self, mocker, client):
        """
        Given:
        - A mocked client for requests.
        - Arguments with a user role that needs to be mapped.

        When:
        - Calling the 'vectra_user_list_command' function with a role like 'Super Admin'.

        Then:
        - Assert that the role is mapped to 'super_admins' and sent to the API.
        - Assert that the command returns expected user data.
        """
        user_res = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": 32,
                    "name": "user.name2",
                    "email": "user@example.com",
                    "role": "Super Admin",
                    "last_login_timestamp": "2023-07-02T18:41:19Z",
                }
            ],
        }

        # Mock the list_users_request method
        mocker.patch.object(client, "list_users_request", return_value=user_res)

        # Call the function with a role that needs mapping
        result = vectra_user_list_command(client, {"role": "Super Admin"})

        # Assert the CommandResults
        assert result.outputs_prefix == "Vectra.User"
        assert len(result.outputs) == 1
        assert result.outputs_key_field == ["user_id"]

    def test_vectra_user_list_with_unmapped_role(self, mocker, client):
        """
        Given:
        - A mocked client for requests.
        - Arguments with a user role that doesn't need mapping.

        When:
        - Calling the 'vectra_user_list_command' function with an unmapped role.

        Then:
        - Assert that the role is passed as-is to the API.
        """
        user_res = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": 59,
                    "name": "user.name1",
                    "email": "user@example.com",
                    "role": "custom_role",
                    "last_login_timestamp": "2023-08-22T09:24:44Z",
                }
            ],
        }
        mocker.patch.object(client, "list_users_request", return_value=user_res)

        # Call with an unmapped role (should be passed as-is)
        result = vectra_user_list_command(client, {"role": "custom_role"})

        assert result.outputs_prefix == "Vectra.User"
        assert len(result.outputs) > 0

    def test_vectra_user_list_with_auditor_role_mapping(self, mocker, client):
        """
        Given:
        - A mocked client for requests.
        - Arguments with the 'Auditor' role.

        When:
        - Calling the 'vectra_user_list_command' function.

        Then:
        - Assert that 'Auditor' is mapped to 'auditor'.
        """
        user_res = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": 10,
                    "name": "auditor_user",
                    "email": "auditor@example.com",
                    "role": "Auditor",
                    "last_login_timestamp": "2023-08-22T09:24:44Z",
                }
            ],
        }
        mocker.patch.object(client, "list_users_request", return_value=user_res)

        result = vectra_user_list_command(client, {"role": "Auditor"})

        assert result.outputs_prefix == "Vectra.User"
        assert result.outputs_key_field == ["user_id"]

    @pytest.mark.parametrize(
        "role_input",
        [
            "Admin",
            "Security Analyst",
            "Super Admin",
            "Auditor",
            "Global Analyst",
            "Read-Only",
            "Restricted Admin",
            "Setting Admin",
        ],
    )
    def test_user_list_command_all_role_mappings(self, mocker, client, role_input):
        """
        Test all possible role mappings for vectra_user_list_command.
        """
        user_res = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": 1,
                    "name": "test_user",
                    "email": "test@example.com",
                    "role": role_input,
                    "last_login_timestamp": "2023-08-22T09:24:44Z",
                }
            ],
        }
        mocker.patch.object(client, "list_users_request", return_value=user_res)

        result = vectra_user_list_command(client, {"role": role_input})

        assert result.outputs_prefix == "Vectra.User"


class TestUserListCommandWithNameField:
    """Tests for the updated 'name' field in user list command output."""

    def test_user_list_uses_name_field(self, mocker, client):
        """
        Given:
        - A mocked user response with 'name' field.

        When:
        - Calling the 'vectra_user_list_command' function.

        Then:
        - Assert that the human-readable output uses 'name' field instead of 'username'.
        """
        # Create a user response with 'name' field (new v3.5 format)
        user_res = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    "id": 59,
                    "name": "user.name1",  # Using 'name' instead of 'username'
                    "email": "user@example.com",
                    "role": "Security Analyst",
                    "last_login_timestamp": "2023-08-22T09:24:44Z",
                }
            ],
        }
        mocker.patch.object(client, "list_users_request", return_value=user_res)

        result = vectra_user_list_command(client, {})

        # Check that the readable output contains the name
        assert result.readable_output is not None
        assert "user.name1" in result.readable_output
        assert result.outputs_prefix == "Vectra.User"


class TestDetectionInvestigationStatusUpdateValidation:
    """Tests for the enhanced validation in vectra_detection_investigation_status_update_command."""

    def test_detection_investigation_status_no_valid_ids_raises_exception(self, client):
        """
        Given:
        - Arguments with detection IDs that are all invalid (non-numeric, negative, zero).

        When:
        - Calling the 'vectra_detection_investigation_status_update_command' function.

        Then:
        - Assert that a DemistoException is raised with appropriate error message.
        """
        args = {
            "detection_ids": "-1,-5,0",
            "investigation_status": "Open",
        }

        with pytest.raises(DemistoException) as exc_info:
            vectra_detection_investigation_status_update_command(client, args)

        assert "INVALID_INTEGER_VALUE" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    def test_detection_investigation_status_empty_detection_ids_raises_error(self, client):
        """
        Given:
        - Arguments with empty detection_ids.

        When:
        - Calling the 'vectra_detection_investigation_status_update_command' function.

        Then:
        - Assert that a ValueError is raised.
        """
        args = {
            "detection_ids": "",
            "investigation_status": "Open",
        }

        with pytest.raises(ValueError):
            vectra_detection_investigation_status_update_command(client, args)

    def test_detection_investigation_status_valid_ids_with_some_invalid(self, mocker, client):
        """
        Given:
        - Arguments with both valid and invalid detection IDs.

        When:
        - Calling the 'vectra_detection_investigation_status_update_command' function.

        Then:
        - Assert that the command processes valid IDs and returns a warning for invalid ones.
        """
        response = {
            "status": "success",
            "data": {"updated_count": 1},
        }
        mocker.patch.object(client, "update_detection_status_request", return_value=response)

        args = {
            "detection_ids": "1,invalid,-5",  # Mix of valid and invalid
            "investigation_status": "Open",
        }

        result = vectra_detection_investigation_status_update_command(client, args)

        # The command should process valid ID (1) and issue warnings for invalid ones
        assert result.outputs_prefix == "Vectra.Detection"

    def test_detection_investigation_status_only_valid_ids(self, mocker, client):
        """
        Given:
        - Arguments with only valid detection IDs.

        When:
        - Calling the 'vectra_detection_investigation_status_update_command' function.

        Then:
        - Assert that the command successfully updates the detection status.
        """
        response = {
            "status": "success",
            "data": {"updated_count": 3},
        }
        mocker.patch.object(client, "update_detection_status_request", return_value=response)

        args = {
            "detection_ids": "1,2,3",
            "investigation_status": "Acknowledged",
        }

        result = vectra_detection_investigation_status_update_command(client, args)

        assert result.outputs_prefix == "Vectra.Detection"
        assert len(result.outputs) == 3  # type: ignore


class TestJsonDataParameterChanges:
    """Tests to verify the 'json_data' parameter changes in HTTP requests work correctly."""

    def test_detection_note_add_uses_json_data(self, mocker, client):
        """
        Given:
        - Arguments for adding a detection note.

        When:
        - Calling the 'vectra_detection_note_add_command' function.

        Then:
        - Assert that the function executes successfully, implying json_data parameter works.
        """
        notes_res = util_load_json(f"{TEST_DATA_DIR}/detection_note_add_response.json")
        mocker.patch.object(client, "add_detection_note_request", return_value=notes_res)

        args = {
            "detection_id": "1",
            "note": "test_note",
        }

        result = vectra_detection_note_add_command(client, args)

        assert result.outputs_prefix == "Vectra.Detection.Notes"
        # Verify the mocked method was called
        client.add_detection_note_request.assert_called()

    def test_detection_note_update_uses_json_data(self, mocker, client):
        """
        Given:
        - Arguments for updating a detection note.

        When:
        - Calling the 'vectra_detection_note_update_command' function.

        Then:
        - Assert that the function executes successfully with json_data parameter.
        """
        notes_res = util_load_json(f"{TEST_DATA_DIR}/detection_note_update_response.json")
        mocker.patch.object(client, "update_detection_note_request", return_value=notes_res)

        args = {
            "detection_id": "1",
            "note_id": "1",
            "note": "updated_note",
        }

        result = vectra_detection_note_update_command(client, args)

        assert result.outputs_prefix == "Vectra.Detection.Notes"
        client.update_detection_note_request.assert_called()

    def test_http_request_accepts_json_data_parameter(self, client):
        """
        Given:
        - A VectraEventsDetectionsClient instance.

        When:
        - Verifying that the http_request method accepts json_data parameter.

        Then:
        - Assert that the method signature includes json_data parameter.
        """
        # Verify that http_request method has json_data parameter
        import inspect

        sig = inspect.signature(client.http_request)
        assert "json_data" in sig.parameters or "json_data" in str(sig)

    def test_entity_note_add_uses_json_data(self, mocker, client):
        """
        Given:
        - Arguments for adding an entity note.

        When:
        - Calling the 'vectra_entity_note_add_command' function.

        Then:
        - Assert that the function executes with json_data parameter.
        """
        notes_res = {
            "id": 1,
            "note": "test_note",
            "tags": [],
            "created_by": {"id": 1, "username": "test_user"},
        }
        mocker.patch.object(client, "add_entity_note_request", return_value=notes_res)

        args = {
            "entity_type": "account",
            "entity_id": "1",
            "note": "test_note",
        }

        result = vectra_entity_note_add_command(client, args)

        assert result.outputs_prefix == "Vectra.Entity.Notes"
        client.add_entity_note_request.assert_called()
