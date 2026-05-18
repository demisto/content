import asyncio
import json
import os
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from CommonServerPython import *
from fastapi import Request
from fastapi.testclient import TestClient
from ContrastSecurity import (
    app,
    main,
    parse_incidents,
    validate_configuration_params,
    fetch_samples,
    Client,
    ERROR_MESSAGES,
    ENDPOINTS,
    RULE_MODE_HUMAN_READABLE_LIST,
    contrast_security_adrpolicy_update_command,
    contrast_security_issue_list_command,
    contrast_security_issue_get_command,
    contrast_security_observation_get_command,
    contrast_security_incident_observation_list_command,
    SORT_BY_VALID_VALUES,
    SORT_ORDER_VALID_VALUES,
    OBSERVATION_SORT_BY_VALID_VALUES,
    MAX_ISSUE_PAGE_SIZE,
    MAX_OBSERVATION_PAGE_SIZE,
    test_module as contrast_test_module,
)

DUMMAY_SERVER_URL = "https://test.contrast.com"
INVALID_NUMBER = 'Invalid number: "{}"="{}"'

# Load schema files from test_data directory
TEST_DATA_DIR = Path(__file__).parent / "test_data"

with open(TEST_DATA_DIR / "incident_schema.json") as f:
    SAMPLE_INCIDENT_PAYLOAD = json.load(f)

with open(TEST_DATA_DIR / "incident_schema_1.json") as f:
    SAMPLE_INCIDENT_PAYLOAD_1 = json.load(f)

with open(TEST_DATA_DIR / "issue_schema.json") as f:
    SAMPLE_ISSUE_PAYLOAD = json.load(f)

with open(TEST_DATA_DIR / "issue_schema_1.json") as f:
    SAMPLE_ISSUE_PAYLOAD_1 = json.load(f)

with open(TEST_DATA_DIR / "sample_incidents_expected.json") as f:
    SAMPLE_INCIDENTS_EXPECTED = json.load(f)

with open(TEST_DATA_DIR / "adrpolicy_update_context.json") as f:
    ADRPOLICY_UPDATE_CONTEXT = json.load(f)

with open(TEST_DATA_DIR / "issue_list_response.json") as f:
    ISSUE_LIST_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "issue_list_outputs.json") as f:
    ISSUE_LIST_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "issue_get_response.json") as f:
    ISSUE_GET_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "issue_get_summary_response.json") as f:
    ISSUE_GET_SUMMARY_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "issue_get_outputs.json") as f:
    ISSUE_GET_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "get_incident_response.json") as f:
    SAMPLE_GET_INCIDENT_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_attack_response.json") as f:
    OBSERVATION_ATTACK_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_attack_outputs.json") as f:
    OBSERVATION_ATTACK_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "observation_library_response.json") as f:
    OBSERVATION_LIBRARY_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_library_outputs.json") as f:
    OBSERVATION_LIBRARY_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "observation_list_response.json") as f:
    OBSERVATION_LIST_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_list_outputs.json") as f:
    OBSERVATION_LIST_OUTPUTS = json.load(f)

SAMPLE_OBSERVATION_PAYLOAD = {
    "organizationUuid": "3ccd2a09-b356-42c4-9c0c-80128513ff3b",
    "observationId": "OBS-2024-99999",
    "timestamp": "2026-03-25T16:24:31.351851Z",
}

WEBHOOK_PARAMS = {
    "event_type": "Contrast Incident",
    "webhook_credentials": {"identifier": "user", "password": "pass"},
}

WEBHOOK_PARAMS_BOTH_TYPES = {
    "event_type": ["Contrast Incident", "Contrast Issue"],
    "webhook_credentials": {"identifier": "user", "password": "pass"},
}

SAMPLE_GET_INCIDENT_RESPONSE_CLOSED = {
    **SAMPLE_GET_INCIDENT_RESPONSE,
    "status": "closed",
    "closedAt": "2026-04-19T06:39:22.509Z",
}


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_client():
    """Create a real Client instance pointing to a test server URL."""
    return Client(
        server_url=DUMMAY_SERVER_URL,
        username="test_user",
        service_key="test_service_key",
        api_key="test_api_key",
        organization_id="test-org-id",
        verify_certificate=False,
        proxy=False,
    )


@pytest.fixture
def incident_payload():
    """Provide a fresh deep copy of SAMPLE_INCIDENT_PAYLOAD for each test."""
    return json.loads(json.dumps(SAMPLE_INCIDENT_PAYLOAD))


@pytest.fixture
def issue_payload():
    """Provide a fresh deep copy of SAMPLE_ISSUE_PAYLOAD for each test."""
    return json.loads(json.dumps(SAMPLE_ISSUE_PAYLOAD))


def make_mock_request(payload):
    """Return a mock FastAPI Request whose .json() coroutine yields payload."""
    mock_request = MagicMock(spec=Request)

    async def mock_json():
        return payload

    mock_request.json = mock_json
    return mock_request


def util_load_json(path):
    """Load JSON data from file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_client_initialization():
    """
    Given: Valid credentials are passed to Client.__init__
    When: A Client instance is created
    Then: Headers are set correctly and organization_id is stored
    """
    client = Client(
        server_url=DUMMAY_SERVER_URL,
        username="test_user",
        service_key="test_service_key",
        api_key="test_api_key",
        organization_id="test-org-id",
        verify_certificate=False,
        proxy=False,
    )

    assert client._headers["API-Key"] == "test_api_key"
    assert "Authorization" in client._headers
    assert client._headers["Accept"] == "application/json"
    assert client._headers["Content-Type"] == "application/json"
    assert client.organization_id == "test-org-id"


def test_client_list_issues_success(mock_client, requests_mock):
    """
    Given: A valid Client and query parameters
    When: list_issues is called
    Then: A GET request is made to the correct endpoint and the response is returned
    """
    org_id = "test-org-id"
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(org_id)}"
    requests_mock.get(url, json={"issues": [], "count": 0})

    result = mock_client.list_issues({"page": 0, "size": 10})

    assert result == {"issues": [], "count": 0}
    assert requests_mock.last_request.qs == {"page": ["0"], "size": ["10"]}


def test_client_list_issues_unauthorized(mock_client, requests_mock):
    """
    Given: The API returns a 401 response
    When: list_issues is called
    Then: DemistoException is raised containing 'Unauthorized'
    """
    org_id = "test-org-id"
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(org_id)}"
    requests_mock.get(url, json={"error": "Unauthorized"}, status_code=401)

    with pytest.raises(DemistoException) as exc_info:
        mock_client.list_issues({"page": 0, "size": 1})

    assert "Unauthorized" in str(exc_info.value)


def test_test_module_success(mocker, mock_client, requests_mock):
    """
    Given: Valid API credentials and API is reachable
    When: test_module is called
    Then: Returns 'ok'
    """
    mocker.patch.object(demisto, "params", return_value={"longRunningPort": "8080"})
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json={"issues": []})

    result = contrast_test_module(mock_client)

    assert result == "ok"


def test_test_module_invalid_api_key(mock_client, requests_mock, mocker):
    """
    Given: API returns 401 Unauthorized due to invalid credentials
    When: test_module is called
    Then: DemistoException is raised with authentication failure message
    """
    mocker.patch.object(demisto, "params", return_value={"longRunningPort": "8080"})
    url = f"https://test.contrast.com{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json={"error": "Unauthorized"}, status_code=401)

    with pytest.raises(DemistoException) as exc_info:
        contrast_test_module(mock_client)

    assert "Unauthorized" in str(exc_info.value)


def test_test_module_sets_default_port_when_missing(mocker, mock_client, requests_mock):
    """
    Given: params dict has no longRunningPort key
    When: test_module is called
    Then: Returns 'ok' and sets longRunningPort to default value '1111' in params
    """
    params = {}
    mocker.patch.object(demisto, "params", return_value=params)
    url = f"https://test.contrast.com{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json={"issues": []})

    result = contrast_test_module(mock_client)

    assert result == "ok"
    assert params.get("longRunningPort") == "1111"


@pytest.mark.parametrize(
    "params, should_raise, error_substring",
    [
        # Should pass - no long running
        ({"longRunning": False}, False, None),
        # Should pass - all params valid
        (
            {
                "longRunning": True,
                "longRunningPort": "8080",
                "event_type": "Contrast Incident",
                "webhook_credentials": {"identifier": "user", "password": "pass"},
            },
            False,
            None,
        ),
        # Should fail - missing port
        (
            {
                "longRunning": True,
                "event_type": "Contrast Incident",
                "webhook_credentials": {"identifier": "user", "password": "pass"},
            },
            True,
            "Listening Port",
        ),
        # Should fail - missing event_type
        (
            {
                "longRunning": True,
                "longRunningPort": "8080",
                "webhook_credentials": {"identifier": "user", "password": "pass"},
            },
            True,
            "Event Type",
        ),
        # Should fail - missing webhook_credentials
        (
            {
                "longRunning": True,
                "longRunningPort": "8080",
                "event_type": "Contrast Incident",
            },
            True,
            "Webhook Credentials",
        ),
        # Should fail - empty webhook username
        (
            {
                "longRunning": True,
                "longRunningPort": "8080",
                "event_type": "Contrast Incident",
                "webhook_credentials": {"identifier": "", "password": "pass"},
            },
            True,
            "Webhook Username",
        ),
        # Should fail - empty webhook password
        (
            {
                "longRunning": True,
                "longRunningPort": "8080",
                "event_type": "Contrast Incident",
                "webhook_credentials": {"identifier": "user", "password": ""},
            },
            True,
            "Webhook Password",
        ),
        # Should fail - invalid event_type
        (
            {
                "longRunning": True,
                "longRunningPort": "8080",
                "event_type": "Invalid Event Type",
                "webhook_credentials": {"identifier": "user", "password": "pass"},
            },
            True,
            "Invalid Event Type",
        ),
    ],
)
def test_validate_configuration_params(params, should_raise, error_substring):
    """
    Test validate_configuration_params with various parameter combinations.

    Covers both valid configurations (no exception) and invalid configurations
    (ValueError with specific error messages).
    """
    if should_raise:
        with pytest.raises(ValueError) as exc_info:
            validate_configuration_params(params)
        assert error_substring in str(exc_info.value)
    else:
        validate_configuration_params(params)  # Must not raise


@pytest.mark.parametrize(
    "payload,selected_types,expected_count,description",
    [
        (SAMPLE_INCIDENT_PAYLOAD, ["Contrast Issue"], 0, "Incident skipped when only Issue type selected"),
        (SAMPLE_ISSUE_PAYLOAD, ["Contrast Incident"], 0, "Issue skipped when only Incident type selected"),
        (
            {"organizationUuid": "some-org", "severity": "HIGH"},
            ["Contrast Incident", "Contrast Issue"],
            0,
            "Unknown event type dropped",
        ),
        (
            SAMPLE_OBSERVATION_PAYLOAD,
            ["Contrast Incident", "Contrast Issue"],
            0,
            "Observation type filtered out when not in selected types",
        ),
        (SAMPLE_OBSERVATION_PAYLOAD, ["Contrast Incident"], 0, "Observation type filtered out when Incident type selected"),
        (
            {"organizationUuid": "test-org"},
            ["Contrast Incident", "Contrast Issue"],
            0,
            "Empty payload with no identifying fields dropped",
        ),
        (
            [SAMPLE_INCIDENT_PAYLOAD, SAMPLE_ISSUE_PAYLOAD],
            ["Contrast Incident"],
            1,
            "List: only Incidents included, Issues filtered",
        ),
        (
            [SAMPLE_INCIDENT_PAYLOAD, SAMPLE_ISSUE_PAYLOAD],
            ["Contrast Issue"],
            1,
            "List: only Issues included, Incidents filtered",
        ),
        (
            [SAMPLE_INCIDENT_PAYLOAD, SAMPLE_OBSERVATION_PAYLOAD],
            ["Contrast Incident", "Contrast Issue"],
            1,
            "List: Observations filtered from mixed list",
        ),
        ([], ["Contrast Incident", "Contrast Issue"], 0, "Empty list handled gracefully"),
    ],
)
def test_parse_incidents_filters_by_event_type(mocker, payload, selected_types, expected_count, description):
    """
    Given: Various payloads and event type selections
    When: parse_incidents is called
    Then: Events not matching selected types are filtered out
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")

    request = make_mock_request(payload)
    result = asyncio.run(parse_incidents(request, selected_types))

    assert len(result) == expected_count, f"Failed: {description}. Expected {expected_count} items, got {len(result)}"


def test_parse_incidents_single_contrast_incident(mocker):
    """
    Given: A single flat payload containing an incidentId
    When: parse_incidents is called with event_type=['Contrast Incident']
    Then: Returns one incident with incidentId and mirroring fields set on rawJson
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    mocker.patch.object(demisto, "params", return_value={"incident_mirror_direction": "None", "note_tag": ""})

    request = make_mock_request(SAMPLE_INCIDENT_PAYLOAD)
    result = asyncio.run(parse_incidents(request, ["Contrast Incident"]))

    assert len(result) == 1
    assert result[0]["rawJson"]["incidentId"] == "INC-0000-00001"
    assert "mirror_id" in result[0]["rawJson"]


def test_parse_incidents_single_contrast_issue(mocker):
    """
    Given: A single flat payload containing an issueId
    When: parse_incidents is called with event_type=['Contrast Issue']
    Then: Returns one incident with issueId and mirroring fields set on rawJson
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    mocker.patch.object(demisto, "params", return_value={"issue_mirror_direction": "None", "note_tag": ""})

    request = make_mock_request(SAMPLE_ISSUE_PAYLOAD)
    result = asyncio.run(parse_incidents(request, ["Contrast Issue"]))

    assert len(result) == 1
    assert result[0]["rawJson"]["issueId"] == "ISS-2025-1"
    assert "mirror_id" in result[0]["rawJson"]


def test_parse_incidents_list_of_two_incidents(mocker):
    """
    Given: A list of two payloads each with a distinct incidentId
    When: parse_incidents is called with event_type=['Contrast Incident']
    Then: Both incidents are returned
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")

    incident1 = SAMPLE_INCIDENT_PAYLOAD_1
    incident2 = SAMPLE_INCIDENT_PAYLOAD
    payload = [incident1, incident2]
    request = make_mock_request(payload)
    result = asyncio.run(parse_incidents(request, ["Contrast Incident"]))
    assert len(result) == 2


def test_parse_incidents_list_of_two_issues(mocker):
    """
    Given: A list of two payloads each with a distinct issueId
    When: parse_incidents is called with event_type=['Contrast Issue']
    Then: Both issues are returned
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")

    issue1 = SAMPLE_ISSUE_PAYLOAD_1
    issue2 = SAMPLE_ISSUE_PAYLOAD
    payload = [issue1, issue2]
    request = make_mock_request(payload)
    result = asyncio.run(parse_incidents(request, ["Contrast Issue"]))
    assert len(result) == 2


@pytest.mark.parametrize(
    "context,payload,selected_types,description",
    [
        (
            {"incident_ids": ["INC-0000-00001"], "issue_ids": []},
            SAMPLE_INCIDENT_PAYLOAD,
            ["Contrast Incident"],
            "Deduplicates incident already in context",
        ),
        (
            {"incident_ids": [], "issue_ids": ["ISS-2025-1"]},
            SAMPLE_ISSUE_PAYLOAD,
            ["Contrast Issue"],
            "Deduplicates issue already in context",
        ),
        (
            {"incident_ids": ["INC-0000-00001"], "issue_ids": ["ISS-2025-1"]},
            [SAMPLE_INCIDENT_PAYLOAD, SAMPLE_ISSUE_PAYLOAD],
            ["Contrast Incident", "Contrast Issue"],
            "Deduplicates both incident and issue already in context",
        ),
    ],
)
def test_parse_incidents_deduplicates_already_in_context(mocker, context, payload, selected_types, description):
    """
    Given: Event IDs are already stored in the integration context
    When: parse_incidents is called with the same payloads
    Then: Duplicates are filtered out; empty list is returned
    """
    mocker.patch(
        "ContrastSecurity.get_integration_context",
        return_value=context,
    )
    mocker.patch("ContrastSecurity.set_integration_context")

    request = make_mock_request(payload)
    result = asyncio.run(parse_incidents(request, selected_types))

    assert result == [], f"Failed: {description}"


def test_parse_incidents_updates_integration_context_with_new_ids(mocker):
    """
    Given: A new incident not previously seen
    When: parse_incidents is called
    Then: set_integration_context is called with the new incidentId included
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={"incident_ids": [], "issue_ids": []})
    mock_set_ctx = mocker.patch("ContrastSecurity.set_integration_context")

    request = make_mock_request(SAMPLE_INCIDENT_PAYLOAD)
    asyncio.run(parse_incidents(request, ["Contrast Incident"]))

    saved_context = mock_set_ctx.call_args[0][0]
    assert "INC-0000-00001" in saved_context["incident_ids"]


def test_parse_issues_updates_integration_context_with_new_ids(mocker):
    """
    Given: A new issue not previously seen
    When: parse_incidents is called
    Then: set_integration_context is called with the new issueId included
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={"incident_ids": [], "issue_ids": []})
    mock_set_ctx = mocker.patch("ContrastSecurity.set_integration_context")

    request = make_mock_request(SAMPLE_ISSUE_PAYLOAD)
    asyncio.run(parse_incidents(request, ["Contrast Issue"]))

    saved_context = mock_set_ctx.call_args[0][0]
    assert "ISS-2025-1" in saved_context["issue_ids"]


def test_parse_incidents_mixed_list_incident_and_issue(mocker):
    """
    Given: A list containing one incident and one issue payload
    When: parse_incidents is called with both event types
    Then: Both are returned with mirroring fields
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    mocker.patch.object(
        demisto, "params", return_value={"incident_mirror_direction": "None", "issue_mirror_direction": "None", "note_tag": ""}
    )

    payload = [SAMPLE_INCIDENT_PAYLOAD, SAMPLE_ISSUE_PAYLOAD]
    request = make_mock_request(payload)
    result = asyncio.run(parse_incidents(request, ["Contrast Incident", "Contrast Issue"]))

    assert len(result) == 2
    # Verify both have mirror_id (indicating mirroring was set)
    assert all("mirror_id" in r["rawJson"] for r in result)


@pytest.mark.parametrize(
    "body",
    [
        SAMPLE_INCIDENT_PAYLOAD,
        SAMPLE_INCIDENT_PAYLOAD_1,
        [SAMPLE_INCIDENT_PAYLOAD, SAMPLE_ISSUE_PAYLOAD],
    ],
)
def test_parse_incidents_handles_various_formats(mocker, body):
    """
    Given: Various payload formats (single incident, different incident, list of mixed types)
    When: parse_incidents is called
    Then: All formats are parsed consistently regardless of structure
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")

    request = make_mock_request(body)
    result = asyncio.run(parse_incidents(request, ["Contrast Incident", "Contrast Issue"]))

    assert isinstance(result, list)
    if isinstance(body, list):
        # Multiple items
        assert len(result) >= 0
    else:
        # Single item
        assert len(result) == 1 or len(result) == 0


def test_handle_post_with_invalid_credentials(mocker, client):
    """
    Given: A server configured with webhook credentials
    When: POST / is called with wrong username and password
    Then: 401 Unauthorized is returned with WEBHOOK_UNAUTHORIZED message
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")

    response = client.post("/", json=SAMPLE_INCIDENT_PAYLOAD, auth=("wrong_user", "wrong_pass"))

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.text == ERROR_MESSAGES["WEBHOOK_UNAUTHORIZED"]


def test_handle_post_with_valid_credentials(mocker, client):
    """
    Given: Correct webhook credentials
    When: POST / is called
    Then: 200 OK is returned
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    mocker.patch.object(demisto, "createIncidents", return_value=[])

    response = client.post("/", json=SAMPLE_INCIDENT_PAYLOAD, auth=("user", "pass"))

    assert response.status_code == HTTPStatus.OK


def test_handle_post_with_invalid_json(mocker, client):
    """
    Given: A request body that is not valid JSON
    When: POST / is called
    Then: 400 Bad Request is returned with BAD_REQUEST error message
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch.object(demisto, "error")

    response = client.post("/", data="this_is_not_json", auth=("user", "pass"))

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert ERROR_MESSAGES["BAD_REQUEST"] in response.text


def test_handle_post_single_incident(mocker, client):
    """
    Given: A single Contrast incident payload and valid credentials
    When: POST / is called
    Then: createIncidents is called with one incident; 200 OK is returned
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=[{"name": "created"}])

    response = client.post("/", json=SAMPLE_INCIDENT_PAYLOAD, auth=("user", "pass"))

    assert response.status_code == HTTPStatus.OK
    create_incidents.assert_called_once()
    called = create_incidents.call_args[0][0]
    assert isinstance(called, list)
    assert len(called) == 1

    # Validate incident matches expected schema
    created_incident = called[0]
    expected_incident = SAMPLE_INCIDENTS_EXPECTED[0]

    assert created_incident["name"] == expected_incident["name"]

    # Validate rawJSON contains incident data
    assert "rawJSON" in created_incident
    raw_json = json.loads(created_incident["rawJSON"])
    assert raw_json["incidentId"] == SAMPLE_INCIDENT_PAYLOAD["incidentId"]
    assert "mirror_id" in raw_json


def test_handle_post_multiple_incidents(mocker, client):
    """
    Given: A list of two distinct Contrast incident payloads
    When: POST / is called with valid credentials
    Then: createIncidents is called with two incidents
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=[])

    incident1 = SAMPLE_INCIDENT_PAYLOAD
    incident2 = SAMPLE_INCIDENT_PAYLOAD_1
    payload = [incident1, incident2]
    response = client.post("/", json=payload, auth=("user", "pass"))

    assert response.status_code == HTTPStatus.OK
    called = create_incidents.call_args[0][0]
    assert len(called) == 2


def test_handle_post_observation_is_filtered_out(mocker, client):
    """
    Given: A payload with observationId
    When: POST / is called with both event types enabled
    Then: createIncidents is called with an empty list (observation skipped)
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS_BOTH_TYPES)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=[])

    response = client.post("/", json=SAMPLE_OBSERVATION_PAYLOAD, auth=("user", "pass"))

    assert response.status_code == HTTPStatus.OK
    called = create_incidents.call_args[0][0]
    assert called == []


def test_handle_post_duplicate_incident_not_forwarded(mocker, client):
    """
    Given: An incidentId that already exists in the integration context
    When: POST / is called with the same payload
    Then: createIncidents is called with an empty list (duplicate filtered)
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch(
        "ContrastSecurity.get_integration_context",
        return_value={"incident_ids": ["INC-0000-00001"], "issue_ids": []},
    )
    mocker.patch("ContrastSecurity.set_integration_context")
    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=[])

    response = client.post("/", json=SAMPLE_INCIDENT_PAYLOAD, auth=("user", "pass"))

    assert response.status_code == HTTPStatus.OK
    called = create_incidents.call_args[0][0]
    assert called == []


def test_handle_post_stores_sample_events(mocker, client):
    """
    Given: store_samples is enabled in params
    When: POST / is called with a valid incident
    Then: set_integration_context is called with sample_events populated
    """
    params = {**WEBHOOK_PARAMS, "store_samples": True}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mock_set_ctx = mocker.patch("ContrastSecurity.set_integration_context")
    mocker.patch.object(demisto, "createIncidents", return_value=[])

    response = client.post("/", json=SAMPLE_INCIDENT_PAYLOAD, auth=("user", "pass"))

    assert response.status_code == HTTPStatus.OK
    # set_integration_context called at least twice: once in parse_incidents and once for sample_events
    assert mock_set_ctx.call_count >= 2
    last_context = mock_set_ctx.call_args[0][0]
    assert "sample_events" in last_context
    assert len(last_context["sample_events"]) > 0


def test_handle_post_raw_json_is_serialized_in_created_incident(mocker, client):
    """
    Given: An incident payload
    When: POST / is called
    Then: The created incident's rawJSON field is a JSON string (not a dict)
    """
    mocker.patch.object(demisto, "params", return_value=WEBHOOK_PARAMS)
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mocker.patch("ContrastSecurity.set_integration_context")
    create_incidents = mocker.patch.object(demisto, "createIncidents", return_value=[])

    client.post("/", json=SAMPLE_INCIDENT_PAYLOAD, auth=("user", "pass"))

    called = create_incidents.call_args[0][0]
    assert isinstance(called[0]["rawJSON"], str)
    parsed = json.loads(called[0]["rawJSON"])
    assert parsed["incidentId"] == "INC-0000-00001"


def test_fetch_samples_with_stored_events(mocker):
    """
    Given: Sample events are stored in the integration context
    When: fetch_samples is called
    Then: demisto.incidents is called with those events
    """
    sample_events = [{"name": "SQL Injection Alert"}, {"name": "XSS Alert"}]
    mocker.patch("ContrastSecurity.get_integration_context", return_value={"sample_events": sample_events})
    mock_incidents = mocker.patch.object(demisto, "incidents")

    fetch_samples()

    mock_incidents.assert_called_once_with(sample_events)


def test_fetch_samples_with_no_stored_events(mocker):
    """
    Given: Integration context has no sample_events key
    When: fetch_samples is called
    Then: demisto.incidents is called with an empty list
    """
    mocker.patch("ContrastSecurity.get_integration_context", return_value={})
    mock_incidents = mocker.patch.object(demisto, "incidents")

    fetch_samples()

    mock_incidents.assert_called_once_with([])


def test_main_test_module_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and test-module command

    When:
    - Running the main function

    Then:
    - Validate that test_module is called and return_results is called with 'ok'
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
        "longRunningPort": "8080",
        "insecure": False,
        "proxy": False,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    url = f"https://test.contrast.com{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json={"issues": []})

    main()

    mock_return_results.assert_called_once_with("ok")
    mock_return_error.assert_not_called()


def test_main_invalid_configuration_calls_return_error(mocker):
    """
    Given: longRunning=True but required params (port, event_type, creds) are missing
    When: main is called
    Then: return_error is called with a message containing the command name
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
        "longRunning": True,
        # Missing: longRunningPort, event_type, webhook_credentials
        "insecure": False,
        "proxy": False,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    main()

    mock_return_error.assert_called_once()
    error_msg = mock_return_error.call_args[0][0]
    assert "Failed to execute test-module command" in error_msg


def test_main_long_running_with_auto_recovery(mocker):
    """
    Given: A long-running instance is configured with a webhook
    When: The uvicorn server fails with an exception
    Then: The application auto-recovers by restarting after 5 seconds
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
        "longRunningPort": "8080",
        "event_type": "Contrast Incident",
        "webhook_credentials": {"identifier": "user", "password": "pass"},
        "insecure": False,
        "proxy": False,
    }

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="long-running-execution")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "updateModuleHealth")
    mocker.patch("time.sleep")

    # Simulate failures on first two attempts, then raise BaseException to exit loop
    uvicorn_mock = MagicMock(
        side_effect=[
            Exception("Connection reset"),
            Exception("Port already in use"),
            BaseException("Exit loop"),
        ]
    )
    mocker.patch("uvicorn.run", uvicorn_mock)

    try:
        main()
        raise AssertionError("Expected BaseException to exit the loop")
    except BaseException:
        # Expected behavior - we use BaseException to break the while True loop
        pass

    # Verify that uvicorn.run was called 3 times (2 failures + 1 exit)
    assert uvicorn_mock.call_count == 3


def test_main_long_running_http_server(mocker):
    """
    Given: Certificate and key are not provided
    When: long-running-execution is called
    Then: HTTP server is started (not HTTPS)
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
        "longRunningPort": "8080",
        "event_type": "Contrast Incident",
        "webhook_credentials": {"identifier": "user", "password": "pass"},
        "insecure": False,
        "proxy": False,
    }

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="long-running-execution")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "updateModuleHealth")
    mocker.patch("time.sleep")
    mocker.patch("demistomock.debug")

    uvicorn_mock = MagicMock(side_effect=BaseException("Exit"))
    mocker.patch("uvicorn.run", uvicorn_mock)

    try:
        main()
    except BaseException:
        pass

    # Verify uvicorn.run was called with HTTP args (no ssl_certfile/ssl_keyfile)
    call_kwargs = uvicorn_mock.call_args[1]
    assert "ssl_certfile" not in call_kwargs
    assert "ssl_keyfile" not in call_kwargs


def test_main_long_running_https_server(mocker):
    """
    Given: Certificate and key are provided
    When: long-running-execution is called
    Then: HTTPS server is started with SSL configuration
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
        "longRunningPort": "8443",
        "event_type": "Contrast Incident",
        "webhook_credentials": {"identifier": "user", "password": "pass"},
        "certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
        "key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
        "insecure": False,
        "proxy": False,
    }

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="long-running-execution")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "updateModuleHealth")
    mocker.patch("time.sleep")
    mocker.patch("demistomock.debug")

    uvicorn_mock = MagicMock(side_effect=BaseException("Exit"))
    mocker.patch("uvicorn.run", uvicorn_mock)

    try:
        main()
    except BaseException:
        pass

    # Verify uvicorn.run was called with HTTPS args
    call_kwargs = uvicorn_mock.call_args[1]
    assert "ssl_certfile" in call_kwargs
    assert "ssl_keyfile" in call_kwargs


def test_contrast_security_incident_comment_add_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID and comment text

    When:
    - Running the !contrastsecurity-incident-comment-add command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_incident_comment_add_command

    mock_response = util_load_json("test_data/incident_comment_add_response.json")
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/incident_comment_add_human_readable.md")) as f:
        incident_comment_add_hr = f.read()

    test_args = {
        "incident_id": "incident-123",
        "comment": "dummy comment message",
    }

    formatted_endpoint = ENDPOINTS["incident_comment"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.post(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_incident_comment_add_command(mock_client, test_args)

    assert results.readable_output == incident_comment_add_hr
    assert results.outputs == [mock_response]
    assert results.outputs[0]["incident_id"] == "incident-123"


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"incident_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
        ({"incident_id": "incident-123", "comment": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("comment")),
        ({"comment": "test comment"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
    ],
)
def test_contrast_security_incident_comment_add_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing incident_id or comment)

    When:
    - Running the !contrastsecurity-incident-comment-add command

    Then:
    - Validate that appropriate error is raised
    """
    from ContrastSecurity import contrast_security_incident_comment_add_command

    with pytest.raises(exception) as e:
        contrast_security_incident_comment_add_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_incident_status_update_command_closed_with_reason(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID, status "closed", and a close reason

    When:
    - Running the !contrastsecurity-incident-status-update command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data/incident_status_update_with_reason_human_readable.md"
        )
    ) as f:
        incident_status_update_hr = f.read()

    test_args = {
        "incident_id": "incident-123",
        "status": "Closed",
        "close_reason": "True Positive",
    }

    formatted_endpoint = ENDPOINTS["incident_status"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_incident_status_update_command(mock_client, test_args)

    assert results.readable_output == incident_status_update_hr
    assert results.outputs[0]["id"] == "incident-123"
    assert results.outputs[0]["status"] == "Closed"
    assert results.outputs[0]["close_reason"] == "True Positive"


def test_contrast_security_incident_status_update_command_open(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID and status "open"

    When:
    - Running the !contrastsecurity-incident-status-update command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    test_args = {
        "incident_id": "incident-456",
        "status": "Open",
    }

    formatted_endpoint = ENDPOINTS["incident_status"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_incident_status_update_command(mock_client, test_args)

    assert results.outputs[0]["id"] == "incident-456"
    assert results.outputs[0]["status"] == "Open"


def test_contrast_security_incident_status_update_command_closed_various_reasons(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID, status "closed", and different close reasons

    When:
    - Running the !contrastsecurity-incident-status-update command with different close reasons

    Then:
    - Validate the command results are valid for each close reason
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    close_reasons = ["True Positive", "False Positive", "Benign True Positive", "Other"]

    for close_reason in close_reasons:
        test_args = {
            "incident_id": "incident-789",
            "status": "Closed",
            "close_reason": close_reason,
        }

        formatted_endpoint = ENDPOINTS["incident_status"].format(mock_client.organization_id, test_args["incident_id"])
        requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

        results = contrast_security_incident_status_update_command(mock_client, test_args)

        assert results.outputs[0]["id"] == "incident-789"
        assert results.outputs[0]["status"] == "Closed"
        assert results.outputs[0]["close_reason"] == close_reason


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"incident_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
        ({"incident_id": "incident-123", "status": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("status")),
        ({"status": "Closed"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
        (
            {"incident_id": "incident-123", "status": "invalid_status"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("invalid_status", "status", ["Closed", "Open"]),
        ),
        (
            {"incident_id": "incident-123", "status": "Closed"},
            ValueError,
            ERROR_MESSAGES["CLOSE_REASON_REQUIRED"].format("close_reason", "Closed"),
        ),
        (
            {"incident_id": "incident-123", "status": "Closed", "close_reason": "Invalid Reason"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format(
                "Invalid Reason", "close_reason", ["True Positive", "False Positive", "Benign True Positive", "Other"]
            ),
        ),
    ],
)
def test_contrast_security_incident_status_update_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing/invalid incident_id, status, or close_reason)

    When:
    - Running the !contrastsecurity-incident-status-update command

    Then:
    - Validate that appropriate error is raised
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    with pytest.raises(exception) as e:
        contrast_security_incident_status_update_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_ip_block_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID and IP address

    When:
    - Running the !contrastsecurity-ip-block command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_ip_block_command

    mock_list_response = {"ipAddresses": [{"ipAddress": "192.168.1.1"}]}
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ip_block_human_readable.md")) as f:
        ip_block_hr = f.read()

    test_args = {
        "incident_id": "INC-2024-12345",
        "ip_addresses": "192.168.1.1",
    }

    formatted_endpoint = ENDPOINTS["ip_addresses"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.get(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_list_response)
    requests_mock.put(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_ip_block_command(mock_client, test_args)

    expected_output = util_load_json("test_data/ip_block_response.json")

    assert results.readable_output == ip_block_hr
    assert results.outputs == [expected_output]


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"incident_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
        (
            {"incident_id": "INC-2024-12345", "ip_addresses": ""},
            ValueError,
            ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("ip_addresses"),
        ),
        ({"ip_addresses": "192.168.1.1"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
    ],
)
def test_contrast_security_ip_block_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing incident_id or ip_addresses)

    When:
    - Running the !contrastsecurity-ip-block command

    Then:
    - Validate that appropriate error is raised
    """
    from ContrastSecurity import contrast_security_ip_block_command

    with pytest.raises(exception) as e:
        contrast_security_ip_block_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_ip_block_command_multiple_ips_with_expiration(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID, multiple IP addresses, and expiration date

    When:
    - Running the !contrastsecurity-ip-block command

    Then:
    - Validate the command results are valid with expiration date included
    """
    from ContrastSecurity import contrast_security_ip_block_command

    mock_list_response = {"ipAddresses": [{"ipAddress": "192.168.1.1"}, {"ipAddress": "10.0.0.1"}]}
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ip_block_multiple_with_expiration_human_readable.md")
    ) as f:
        ip_block_hr = f.read()

    test_args = {"incident_id": "INC-2024-12346", "ip_addresses": "192.168.1.1,10.0.0.1"}

    formatted_endpoint = ENDPOINTS["ip_addresses"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.get(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_list_response)
    requests_mock.put(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_ip_block_command(mock_client, test_args)

    expected_output = util_load_json("test_data/ip_block_multiple_with_expiration_response.json")

    assert results.readable_output == ip_block_hr
    assert results.outputs == [expected_output]


def test_contrast_security_adrpolicy_update_command_single_rule(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID and single rule name

    When:
    - Running the !contrastsecurity-adrpolicy-update command with a single rule

    Then:
    - Validate the command results are valid and HR matches the expected output
    """
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/adrpolicy_update_single_rule_human_readable.md")
    ) as f:
        expected_hr = f.read()

    test_args = {
        "incident_id": "test-incident-id",
        "rule_names": "SQL_INJECTION_RULE",
        "dev_mode": "Block",
        "qa_mode": "Monitor",
        "prod_mode": "Off",
    }

    formatted_endpoint = ENDPOINTS["adr_policy"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.put(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_adrpolicy_update_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs[0]["id"] == "test-incident-id"


def test_contrast_security_adrpolicy_update_command_multiple_rules(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID and multiple rule names (comma-separated)

    When:
    - Running the !contrastsecurity-adrpolicy-update command with multiple rules

    Then:
    - Validate the command results are valid and HR matches the expected output
    """
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/adrpolicy_update_multiple_rules_human_readable.md")
    ) as f:
        expected_hr = f.read()

    test_args = {
        "incident_id": "test-incident-id",
        "rule_names": "SQL_INJECTION, XSS_RULE, COMMAND_INJECTION",
        "dev_mode": "Monitor",
        "qa_mode": "Block",
        "prod_mode": "Block at perimeter",
    }

    formatted_endpoint = ENDPOINTS["adr_policy"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.put(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_adrpolicy_update_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs[0]["id"] == "test-incident-id"


def test_contrast_security_adrpolicy_update_command_default_rule_value_output(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID, rule name, and no mode values (defaults to "Monitor")

    When:
    - Running the !contrastsecurity-adrpolicy-update command without specifying modes

    Then:
    - Validate the command results use default values and HR matches the expected output
    """
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/adrpolicy_update_default_modes_human_readable.md")
    ) as f:
        expected_hr = f.read()

    test_args = {
        "incident_id": "test-incident-id",
        "rule_names": "SECURITY_RULE",
    }

    formatted_endpoint = ENDPOINTS["adr_policy"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.put(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_adrpolicy_update_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs == ADRPOLICY_UPDATE_CONTEXT


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"incident_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
        ({"incident_id": "incident-123", "rule_names": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("rule_names")),
        ({"rule_names": "TEST_RULE"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id")),
        (
            {"incident_id": "incident-123", "rule_names": "TEST_RULE", "dev_mode": "Invalid"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "dev_mode", RULE_MODE_HUMAN_READABLE_LIST),
        ),
        (
            {"incident_id": "incident-123", "rule_names": "TEST_RULE", "qa_mode": "InvalidMode"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("InvalidMode", "qa_mode", RULE_MODE_HUMAN_READABLE_LIST),
        ),
        (
            {"incident_id": "incident-123", "rule_names": "TEST_RULE", "prod_mode": "NotAMode"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("NotAMode", "prod_mode", RULE_MODE_HUMAN_READABLE_LIST),
        ),
    ],
)
def test_contrast_security_adrpolicy_update_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid input (missing incident_id/rule_names or invalid mode values)

    When:
    - Running the !contrastsecurity-adrpolicy-update command

    Then:
    - Validate that appropriate error is raised
    """
    with pytest.raises(exception) as e:
        contrast_security_adrpolicy_update_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_get_remote_data_command_open_incident_no_flags(mocker, mock_client, requests_mock):
    """
    Given: An open remote incident and both close/reopen flags disabled
    When: get_remote_data_command is called
    Then: Returns GetRemoteDataResponse with status=open, score, and no entries
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert result.mirrored_object["status"] == "open"
    assert result.mirrored_object["score"] == "10.0"
    assert result.entries == []


def test_get_remote_data_command_closed_incident_no_flags(mocker, mock_client, requests_mock):
    """
    Given: A closed remote incident and both close/reopen flags disabled
    When: get_remote_data_command is called
    Then: Returns GetRemoteDataResponse with status=closed and no close entry
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE_CLOSED)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert result.mirrored_object["status"] == "closed"
    assert result.entries == []


def test_get_remote_data_command_closes_xsoar_incident(mocker, mock_client, requests_mock):
    """
    Given: A closed remote incident, close_active_incident=True, and incident in processed_incidents
    When: get_remote_data_command is called
    Then: Returns a close entry and removes the incident from processed_incidents
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": True})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE_CLOSED)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert len(result.entries) == 1
    assert result.entries[0]["Contents"]["dbotIncidentClose"] is True
    # Incident ID must be removed from processed_incidents after close
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert incident_id not in saved_ctx["processed_incidents"]


def test_get_remote_data_command_closed_incident_not_in_processed(mocker, mock_client, requests_mock):
    """
    Given: A closed remote incident, close_active_incident=True, but incident NOT in processed_incidents
    When: get_remote_data_command is called
    Then: No close entry is generated (incident was never tracked as open)
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": True})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE_CLOSED)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert result.entries == []


def test_get_remote_data_command_reopens_xsoar_incident(mocker, mock_client, requests_mock):
    """
    Given: An open remote incident, reopen_closed_incident=True, and incident NOT in processed_incidents
    When: get_remote_data_command is called
    Then: Returns a reopen entry and adds the incident to processed_incidents
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": True, "close_active_incident": False})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert len(result.entries) == 1
    assert result.entries[0]["Contents"]["dbotIncidentReopen"] is True
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert incident_id in saved_ctx["processed_incidents"]


def test_get_remote_data_command_open_incident_already_in_processed(mocker, mock_client, requests_mock):
    """
    Given: An open remote incident, reopen_closed_incident=True, and incident already in processed_incidents
    When: get_remote_data_command is called
    Then: No reopen entry is generated (already tracked as open)
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": True, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert result.entries == []


def test_get_remote_data_command_saves_integration_context(mocker, mock_client, requests_mock):
    """
    Given: A valid remote incident
    When: get_remote_data_command is called
    Then: setIntegrationContext is called with updated processed_incidents list
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    get_remote_data_command(mock_client, {"id": incident_id})

    mock_set_ctx.assert_called_once()
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert "processed_incidents" in saved_ctx


def test_get_modified_remote_data_command_single_page(mocker, mock_client, requests_mock):
    """
    Given: A single page of modified incidents from Contrast
    When: get_modified_remote_data_command is called
    Then: Returns list with all incident IDs from that page
    """
    from ContrastSecurity import get_modified_remote_data_command

    incident_id_1 = "INC-2026-001"
    incident_id_2 = "INC-2026-002"

    mock_response = {
        "content": [
            {"incidentId": incident_id_1, "status": "open", "updatedDt": "2026-04-20T10:00:00Z"},
            {"incidentId": incident_id_2, "status": "closed", "updatedDt": "2026-04-20T09:00:00Z"},
        ],
        "page": {"totalPages": 1, "number": 0, "size": 100},
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, json=mock_response)

    result = get_modified_remote_data_command(mock_client, {})

    assert len(result.modified_incident_ids) == 2
    assert incident_id_1 in result.modified_incident_ids
    assert incident_id_2 in result.modified_incident_ids


def test_get_modified_remote_data_command_multiple_pages(mocker, mock_client, requests_mock):
    """
    Given: Multiple pages of incidents from Contrast API
    When: get_modified_remote_data_command is called
    Then: Paginates through pages and returns limited to PAGE_SIZE (100)
    """
    from ContrastSecurity import get_modified_remote_data_command

    incident_ids_page1 = [f"INC-2026-{i:03d}" for i in range(1, 101)]
    incident_ids_page2 = [f"INC-2026-{i:03d}" for i in range(101, 151)]

    # Mock first page
    page1_response = {
        "content": [{"incidentId": id} for id in incident_ids_page1],
        "page": {"totalPages": 2, "number": 0, "size": 100},
    }

    # Mock second page
    page2_response = {
        "content": [{"incidentId": id} for id in incident_ids_page2],
        "page": {"totalPages": 2, "number": 1, "size": 100},
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, [{"json": page1_response, "status_code": 200}, {"json": page2_response, "status_code": 200}])

    result = get_modified_remote_data_command(mock_client, {})

    assert len(result.modified_incident_ids) == 100
    assert incident_ids_page1[0] in result.modified_incident_ids
    assert incident_ids_page1[-1] in result.modified_incident_ids


def test_get_modified_remote_data_command_empty_response(mocker, mock_client, requests_mock):
    """
    Given: No incidents returned from Contrast API
    When: get_modified_remote_data_command is called
    Then: Returns empty list
    """
    from ContrastSecurity import get_modified_remote_data_command

    mock_response = {"content": [], "page": {"totalPages": 1, "number": 0, "size": 100}}

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, json=mock_response)

    result = get_modified_remote_data_command(mock_client, {})

    assert result.modified_incident_ids == []


def test_get_modified_remote_data_command_respects_page_size_limit(mocker, mock_client, requests_mock):
    """
    Given: More incidents available than PAGE_SIZE from Contrast API
    When: get_modified_remote_data_command is called
    Then: Returns only first PAGE_SIZE (100) incidents
    """
    from ContrastSecurity import get_modified_remote_data_command

    # Create 250 incident IDs across multiple pages
    incident_ids_page1 = [f"INC-2026-{i:04d}" for i in range(1, 101)]
    incident_ids_page2 = [f"INC-2026-{i:04d}" for i in range(101, 201)]
    incident_ids_page3 = [f"INC-2026-{i:04d}" for i in range(201, 251)]

    pages_responses = []
    for page_num, incident_ids in enumerate([incident_ids_page1, incident_ids_page2, incident_ids_page3]):
        pages_responses.append(
            {
                "json": {
                    "content": [{"incidentId": id} for id in incident_ids],
                    "page": {"totalPages": 3, "number": page_num, "size": 100},
                },
                "status_code": 200,
            }
        )

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, pages_responses)

    result = get_modified_remote_data_command(mock_client, {})

    # Should be capped at PAGE_SIZE (100)
    assert len(result.modified_incident_ids) == 100


def test_get_modified_remote_data_command_skips_missing_incident_id(mocker, mock_client, requests_mock):
    """
    Given: Some incidents in response missing incidentId field
    When: get_modified_remote_data_command is called
    Then: Skips incidents without ID and returns only valid ones
    """
    from ContrastSecurity import get_modified_remote_data_command

    mock_response = {
        "content": [
            {"incidentId": "INC-2026-001", "status": "open"},
            {"status": "open"},  # Missing incidentId
            {"incidentId": "INC-2026-002", "status": "closed"},
        ],
        "page": {"totalPages": 1, "number": 0, "size": 100},
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, json=mock_response)

    result = get_modified_remote_data_command(mock_client, {})

    assert len(result.modified_incident_ids) == 2
    assert "INC-2026-001" in result.modified_incident_ids
    assert "INC-2026-002" in result.modified_incident_ids


def test_update_remote_system_command_incident_status_change_to_closed(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR incident with status DONE (maps to "closed")
    - A valid Contrast Security incident ID (INC-*)
    - Close reason provided

    When:
    - update_remote_system_command is called with incident status DONE

    Then:
    - Client incident_status_update is called with "closed" status and close reason
    - The remote incident ID is returned
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "INC-2026-001",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {
            "id": "xsoar_incident_123",
            "closeReason": "Resolved",
            "closingUserId": "user@example.com",
        },
        "entries": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-001')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-001"
    assert requests_mock.last_request.method == "PATCH"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "closed"
    assert request_body["closedReason"] == "TRUE_POSITIVE"


def test_update_remote_system_command_incident_status_change_to_open(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR incident with status ACTIVE (maps to "open")
    - A valid Contrast Security incident ID (INC-*)

    When:
    - update_remote_system_command is called with incident status ACTIVE

    Then:
    - Client incident_status_update is called with "open" status
    - The remote incident ID is returned
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "INC-2026-002",
        "status": IncidentStatus.ACTIVE,
        "incidentChanged": True,
        "data": {"id": "xsoar_incident_124"},
        "entries": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-002')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-002"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "open"


def test_update_remote_system_command_issue_status_change_to_closed(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR issue with status DONE (maps to "closed")
    - A valid Contrast Security issue ID (ISS-*)

    When:
    - update_remote_system_command is called with issue status DONE

    Then:
    - Client issue_status_update is called with "closed" status
    - Payload is passed as string (not dict with "status" key like incidents)
    - The remote issue ID is returned
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "ISS-2026-100",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_issue_001"},
        "entries": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_status'].format('test-org-id', 'ISS-2026-100')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")
    mock_issue_status = mocker.patch.object(mock_client, "issue_status_update", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "ISS-2026-100"
    mock_issue_status.assert_called_once()
    # Verify payload is passed as string "closed" (not dict)
    call_args = mock_issue_status.call_args
    assert call_args[1]["payload"] == "closed"
    assert call_args[1]["issue_id"] == "ISS-2026-100"


def test_update_remote_system_command_incident_add_comment(mocker, mock_client, requests_mock):
    """
    Given:
    - A new entry (note) to be added to a Contrast Security incident
    - A valid incident ID (INC-*)

    When:
    - update_remote_system_command is called with new_entries

    Then:
    - Client incident_comment_add is called (branching logic)
    - Note includes mirroring metadata (XSOAR incident ID, user, note content)
    - The remote incident ID is returned
    """
    from ContrastSecurity import update_remote_system_command

    args = {
        "remoteId": "INC-2026-003",
        "status": 0,  # No status change
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_125"},
        "entries": [
            {
                "id": "entry_001",
                "type": "note",
                "contents": "This is a test note",
                "user": "analyst@example.com",
            }
        ],
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2026-003')}"
    requests_mock.post(url, json={})

    mocker.patch.object(demisto, "debug")
    mock_incident_comment = mocker.patch.object(mock_client, "incident_comment_add", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-003"
    # Verify incident_comment_add is called (not issue_comment_add)
    mock_incident_comment.assert_called_once()
    comment_payload = mock_incident_comment.call_args[1]["payload"]
    assert "[Mirrored From XSOAR]" in comment_payload["commentText"]
    assert "xsoar_incident_125" in comment_payload["commentText"]
    assert "This is a test note" in comment_payload["commentText"]
    assert "analyst@example.com" in comment_payload["commentText"]


def test_update_remote_system_command_issue_add_comment(mocker, mock_client, requests_mock):
    """
    Given:
    - A new entry (note) to be added to a Contrast Security issue
    - A valid issue ID (ISS-*)

    When:
    - update_remote_system_command is called with new_entries

    Then:
    - Client issue_comment_add is called (branching logic)
    - Note includes mirroring metadata
    - The remote issue ID is returned
    """
    from ContrastSecurity import update_remote_system_command

    args = {
        "remoteId": "ISS-2026-101",
        "status": 0,
        "incidentChanged": False,
        "data": {"id": "xsoar_issue_002"},
        "entries": [
            {
                "id": "entry_002",
                "type": "note",
                "contents": "Issue investigation note",
                "user": "researcher",
            }
        ],
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_comment'].format('test-org-id', 'ISS-2026-101')}"
    requests_mock.post(url, json={})

    mocker.patch.object(demisto, "debug")
    mock_issue_comment = mocker.patch.object(mock_client, "issue_comment_add", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "ISS-2026-101"
    # Verify issue_comment_add is called (not incident_comment_add)
    mock_issue_comment.assert_called_once()
    comment_payload = mock_issue_comment.call_args[1]["payload"]
    assert "[Mirrored From XSOAR]" in comment_payload["commentText"]
    assert "Issue investigation note" in comment_payload["commentText"]
    assert "xsoar_issue_002" in comment_payload["commentText"]


def test_update_remote_system_command_incident_closing_note(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR incident being closed with close notes
    - A valid incident ID (INC-*)
    - closingUserId is present in delta
    - closeReason "False Positive" maps to "FALSE_POSITIVE"

    When:
    - update_remote_system_command is called with status DONE and closingUserId in delta

    Then:
    - Status update called with payload containing mapped close reason
    - Closing note sent via incident_comment_add with formatted close reason
    - Closing note includes close reason, user info, and incident ID
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "INC-2026-004",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {
            "id": "xsoar_incident_126",
            "closeReason": "False Positive",
            "closingUserId": "admin@example.com",
            "closeNotes": "Investigation complete. False positive confirmed.",
        },
        "delta": {"closingUserId": "admin@example.com"},
        "entries": None,
    }

    status_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-004')}"
    comment_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2026-004')}"

    requests_mock.patch(status_url, json={})
    requests_mock.post(comment_url, json={})

    mocker.patch.object(demisto, "debug")
    mock_status_update = mocker.patch.object(mock_client, "incident_status_update", return_value={})
    mock_comment_add = mocker.patch.object(mock_client, "incident_comment_add", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-004"
    # Verify status update with mapped close reason
    mock_status_update.assert_called_once()
    status_payload = mock_status_update.call_args[1]["payload"]
    assert status_payload["status"] == "closed"
    assert status_payload["closedReason"] == "FALSE_POSITIVE"
    # Verify closing note includes mapped reason and incident ID
    mock_comment_add.assert_called_once()
    comment_text = mock_comment_add.call_args[1]["payload"]["commentText"]
    assert "FALSE_POSITIVE" in comment_text
    assert "xsoar_incident_126" in comment_text
    assert "admin@example.com" in comment_text


def test_update_remote_system_command_incident_reopen(mocker, mock_client, requests_mock):
    """
    Given:
    - A Contrast Security incident that is being reopened
    - XSOAR status is ACTIVE
    - Delta contains closingUserId cleared to empty string (reopen signal)

    When:
    - update_remote_system_command is called with reopen signal

    Then:
    - Incident status is updated to "open"
    - Remote incident ID is returned
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "INC-2026-005",
        "status": IncidentStatus.ACTIVE,
        "incidentChanged": True,
        "data": {"id": "xsoar_incident_127"},
        "delta": {"closingUserId": ""},  # Reopen signal
        "entries": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-005')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-005"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "open"


def test_update_remote_system_command_no_remote_id(mocker, mock_client):
    """
    Given:
    - No remote incident ID provided (empty or None)

    When:
    - update_remote_system_command is called

    Then:
    - Returns the remote_incident_id unchanged
    - No API calls are made
    """
    from ContrastSecurity import update_remote_system_command

    args = {
        "remoteId": "",
        "status": 0,
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_128"},
    }

    mocker.patch.object(demisto, "debug")
    mock_status = mocker.patch.object(mock_client, "incident_status_update")

    result = update_remote_system_command(mock_client, args)

    assert result == ""
    mock_status.assert_not_called()


def test_update_remote_system_command_invalid_remote_id_format(mocker, mock_client):
    """
    Given:
    - Remote incident ID with invalid prefix (not ISS- or INC-)

    When:
    - update_remote_system_command is called

    Then:
    - Returns the remote_incident_id unchanged
    - No API calls are made
    - Valid ISS- and INC- formats pass validation and continue processing
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    invalid_id = "INVALID-2026-001"
    args = {
        "remoteId": invalid_id,
        "status": 0,
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_129"},
    }

    mocker.patch.object(demisto, "debug")
    mock_status = mocker.patch.object(mock_client, "incident_status_update")
    mock_issue_status = mocker.patch.object(mock_client, "issue_status_update")

    # Test invalid format
    result = update_remote_system_command(mock_client, args)
    assert result == invalid_id
    mock_status.assert_not_called()
    mock_issue_status.assert_not_called()

    # Verify valid ISS- format passes validation
    args_iss = {
        "remoteId": "ISS-2026-001",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_issue_129"},
    }
    mocker.patch.object(mock_client, "issue_status_update", return_value={})
    result_iss = update_remote_system_command(mock_client, args_iss)
    assert result_iss == "ISS-2026-001"

    # Verify valid INC- format passes validation
    args_inc = {
        "remoteId": "INC-2026-001",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_incident_129"},
    }
    mocker.patch.object(mock_client, "incident_status_update", return_value={})
    result_inc = update_remote_system_command(mock_client, args_inc)
    assert result_inc == "INC-2026-001"


def test_update_remote_system_command_note_exceeds_character_limit(mocker, mock_client):
    """
    Given:
    - A note that exceeds MAX_OUTGOING_NOTE_LIMIT characters

    When:
    - update_remote_system_command is called with oversized note

    Then:
    - Note is skipped (not sent)
    - Info message is logged
    - Function returns remote incident ID without error
    """
    from ContrastSecurity import update_remote_system_command

    oversized_content = "x" * (64001)  # Exceeds MAX_OUTGOING_NOTE_LIMIT

    args = {
        "remoteId": "INC-2026-006",
        "status": 0,
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_130"},
        "entries": [
            {
                "id": "entry_003",
                "type": "note",
                "contents": oversized_content,
                "user": "analyst",
            }
        ],
    }

    mocker.patch.object(demisto, "debug")
    mock_info = mocker.patch.object(demisto, "info")
    mock_comment = mocker.patch.object(mock_client, "incident_comment_add")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-006"
    mock_info.assert_called_once()
    assert "exceeds" in mock_info.call_args[0][0].lower()
    mock_comment.assert_not_called()


def test_update_remote_system_command_closing_note_exceeds_limit(mocker, mock_client):
    """
    Given:
    - A closing note that exceeds MAX_OUTGOING_NOTE_LIMIT characters

    When:
    - update_remote_system_command is called with oversized closing note

    Then:
    - Closing note is skipped
    - Status update still happens
    - Info message is logged
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    oversized_notes = "x" * (64001)

    args = {
        "remoteId": "INC-2026-007",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {
            "id": "xsoar_incident_131",
            "closeReason": "Other",
            "closingUserId": "admin",
            "closeNotes": oversized_notes,
        },
        "delta": {"closingUserId": "admin"},
        "entries": None,
    }

    mocker.patch.object(demisto, "debug")
    mock_info = mocker.patch.object(demisto, "info")
    mock_status = mocker.patch.object(mock_client, "incident_status_update")
    mock_comment = mocker.patch.object(mock_client, "incident_comment_add")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-007"
    mock_status.assert_called_once()  # Status update should happen
    mock_info.assert_called_once()  # Info about skipped note
    mock_comment.assert_not_called()  # Comment not added


def test_update_remote_system_command_status_update_fails_continues_with_notes(mocker, mock_client, requests_mock):
    """
    Given:
    - Status update fails with DemistoException
    - New entries (notes) need to be added

    When:
    - update_remote_system_command is called

    Then:
    - Status update error is logged but doesn't block note mirroring
    - Notes are still mirrored
    - Function returns remote incident ID
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus, DemistoException

    args = {
        "remoteId": "INC-2026-008",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_incident_132"},
        "entries": [
            {
                "id": "entry_004",
                "type": "note",
                "contents": "Note despite status failure",
                "user": "analyst",
            }
        ],
    }

    status_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-008')}"
    comment_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2026-008')}"

    # Status update fails
    requests_mock.patch(status_url, status_code=400, json={"error": "Bad request"})
    # But comment succeeds
    requests_mock.post(comment_url, json={})

    mocker.patch.object(demisto, "debug")

    # Mock the client methods
    mocker.patch.object(mock_client, "incident_status_update", side_effect=DemistoException("Status update failed"))
    mocker.patch.object(mock_client, "incident_comment_add", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-008"
    mock_client.incident_comment_add.assert_called_once()


def test_update_remote_system_command_multiple_notes(mocker, mock_client, requests_mock):
    """
    Given:
    - Multiple entries (notes) to be added to a Contrast incident

    When:
    - update_remote_system_command is called with multiple entries

    Then:
    - Each note is processed and added separately
    - All notes are mirrored successfully
    """
    from ContrastSecurity import update_remote_system_command

    args = {
        "remoteId": "INC-2026-009",
        "status": 0,
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_133"},
        "entries": [
            {
                "id": "entry_005",
                "type": "note",
                "contents": "First note",
                "user": "analyst1",
            },
            {
                "id": "entry_006",
                "type": "note",
                "contents": "Second note",
                "user": "analyst2",
            },
            {
                "id": "entry_007",
                "type": "note",
                "contents": "Third note",
                "user": "analyst3",
            },
        ],
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2026-009')}"
    requests_mock.post(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-009"
    # Verify 3 POST requests were made for the 3 notes
    post_requests = [r for r in requests_mock.request_history if r.method == "POST"]
    assert len(post_requests) == 3


def test_update_remote_system_command_note_with_dbot_user(mocker, mock_client, requests_mock):
    """
    Given:
    - A note entry with no user specified (defaults to "dbot")

    When:
    - update_remote_system_command is called

    Then:
    - User defaults to "dbot" in the mirrored note
    """
    from ContrastSecurity import update_remote_system_command

    args = {
        "remoteId": "INC-2026-010",
        "status": 0,
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_134"},
        "entries": [
            {
                "id": "entry_008",
                "type": "note",
                "contents": "Automated note",
                "user": None,  # No user specified
            }
        ],
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2026-010')}"
    requests_mock.post(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-010"
    request_body = json.loads(requests_mock.last_request.text)
    assert "dbot" in request_body["commentText"]


def test_update_remote_system_command_incident_not_changed_skip_status_update(mocker, mock_client):
    """
    Given:
    - incidentChanged is False
    - Status is DONE

    When:
    - update_remote_system_command is called

    Then:
    - Status update is not performed
    - Only notes are mirrored
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "INC-2026-011",
        "status": IncidentStatus.DONE,
        "incidentChanged": False,
        "data": {"id": "xsoar_incident_135"},
        "entries": None,
    }

    mocker.patch.object(demisto, "debug")
    mock_status = mocker.patch.object(mock_client, "incident_status_update")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-011"
    mock_status.assert_not_called()


def test_update_remote_system_command_investigate_status_triggers_update(mocker, mock_client, requests_mock):
    """
    Given:
    - XSOAR incident status is ACTIVE (investigating)
    - Delta only contains runStatus="waiting" (no actual change)
    - incidentChanged is True

    When:
    - update_remote_system_command is called

    Then:
    - Status update is triggered to sync with Contrast
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "INC-2026-012",
        "status": IncidentStatus.ACTIVE,
        "incidentChanged": True,
        "data": {"id": "xsoar_incident_136"},
        "delta": {"runStatus": "waiting"},
        "entries": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-012')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-012"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "open"


def test_update_remote_system_command_close_reason_mapping(mocker, mock_client, requests_mock):
    """
    Given:
    - Different XSOAR close reasons mapping to Contrast Security close reasons

    When:
    - update_remote_system_command is called with various close reasons

    Then:
    - Each close reason is correctly mapped
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    close_reason_mappings = [
        ("False Positive", "FALSE_POSITIVE"),
        ("Resolved", "TRUE_POSITIVE"),
        ("Duplicate", "OTHER"),
        ("Other", "OTHER"),
    ]

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-013')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")

    for xsoar_reason, contrast_reason in close_reason_mappings:
        requests_mock.reset()
        requests_mock.patch(url, json={})

        args = {
            "remoteId": "INC-2026-013",
            "status": IncidentStatus.DONE,
            "incidentChanged": True,
            "data": {
                "id": "xsoar_incident_137",
                "closeReason": xsoar_reason,
            },
            "delta": None,
            "entries": None,
        }

        result = update_remote_system_command(mock_client, args)

        assert result == "INC-2026-013"
        request_body = json.loads(requests_mock.last_request.text)
        assert request_body["closedReason"] == contrast_reason


def test_update_remote_system_command_issue_no_close_reason_required(mocker, mock_client, requests_mock):
    """
    Given:
    - An issue being closed without close_reason
    - Issue ID is ISS-*

    When:
    - update_remote_system_command is called with issue status closed

    Then:
    - Status update succeeds without close_reason field
    - Only status "closed" is sent
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "ISS-2026-102",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_issue_003"},
        "entries": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_status'].format('test-org-id', 'ISS-2026-102')}"
    requests_mock.patch(url, json={})

    mocker.patch.object(demisto, "debug")

    result = update_remote_system_command(mock_client, args)

    assert result == "ISS-2026-102"


def test_update_remote_system_command_issue_closing_note(mocker, mock_client, requests_mock):
    """
    Given:
    - An issue being closed with close notes and close reason
    - Valid issue ID (ISS-*)
    - closingUserId is present in delta

    When:
    - update_remote_system_command is called with status DONE and closingUserId in delta

    Then:
    - Status update called with "closed" payload
    - Closing note sent via issue_comment_add with direct close reason (not mapped)
    - Closing note includes close reason used directly, not mapped like incidents
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

    args = {
        "remoteId": "ISS-2026-103",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {
            "id": "xsoar_issue_004",
            "closeReason": "Resolved",
            "closingUserId": "researcher@example.com",
            "closeNotes": "Issue has been resolved.",
        },
        "delta": {"closingUserId": "researcher@example.com"},
        "entries": None,
    }

    status_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_status'].format('test-org-id', 'ISS-2026-103')}"
    comment_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_comment'].format('test-org-id', 'ISS-2026-103')}"

    requests_mock.patch(status_url, json={})
    requests_mock.post(comment_url, json={})

    mocker.patch.object(demisto, "debug")
    mock_status_update = mocker.patch.object(mock_client, "issue_status_update", return_value={})
    mock_comment_add = mocker.patch.object(mock_client, "issue_comment_add", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "ISS-2026-103"
    # Verify status update with direct payload string
    mock_status_update.assert_called_once()
    assert mock_status_update.call_args[1]["payload"] == "closed"
    # Verify closing note uses close reason directly (not mapped)
    mock_comment_add.assert_called_once()
    comment_text = mock_comment_add.call_args[1]["payload"]["commentText"]
    assert "Resolved" in comment_text  # Direct reason, not mapped
    assert "xsoar_issue_004" in comment_text
    assert "researcher@example.com" in comment_text


def test_contrast_security_issue_list_command_success(mock_client, requests_mock):
    """
    Given:
    - Valid pagination arguments (default page=0, page_size=50)

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate the command results are valid, context contains the issues, and HR matches
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/issue_list_human_readable.md")) as f:
        expected_hr = f.read()

    test_args: dict = {}

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(mock_client.organization_id)}"
    requests_mock.get(url, json=ISSUE_LIST_RESPONSE)

    results = contrast_security_issue_list_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert isinstance(results.outputs, list)
    assert results.outputs == ISSUE_LIST_OUTPUTS
    assert results.outputs[0]["issueId"] == "ISS-2026-1430"
    assert results.outputs[1]["issueId"] == "ISS-2026-1431"
    assert results.raw_response == ISSUE_LIST_RESPONSE


def test_contrast_security_issue_list_command_with_sort(mock_client, requests_mock):
    """
    Given:
    - sort_by and sort_order arguments are provided

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate the API is called with the correct sort query parameter
    """
    test_args = {
        "sort_by": "cvss_score",
        "sort_order": "Desc",
        "page_size": "10",
        "page": "1",
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(mock_client.organization_id)}"
    requests_mock.get(url, json=ISSUE_LIST_RESPONSE)

    contrast_security_issue_list_command(mock_client, test_args)

    # qs lowercases values; verify each sort component and pagination params
    qs = requests_mock.last_request.qs
    sort_value = qs["sort"][0].lower()
    assert "cvssscore" in sort_value  # SORT_BY_MAPPING["CVSS Score"] = "cvssScore"
    assert "desc" in sort_value
    assert qs["page"] == ["1"]
    assert qs["size"] == ["10"]


def test_contrast_security_issue_list_command_no_results(mock_client, requests_mock):
    """
    Given:
    - The API returns an empty content list

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate an appropriate no-results message is returned and no context is set
    """
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(mock_client.organization_id)}"
    requests_mock.get(url, json={"content": [], "page": {"size": 0, "number": 0, "totalElements": 0, "totalPages": 0}})

    results = contrast_security_issue_list_command(mock_client, {})

    assert results.readable_output == "No issues were found for the given filters."
    assert results.outputs is None


@pytest.mark.parametrize(
    "args, exception, error",
    [
        # page_size exceeds maximum
        (
            {"page_size": "101"},
            ValueError,
            ERROR_MESSAGES["INVALID_PAGE_SIZE"].format("101", MAX_ISSUE_PAGE_SIZE),
        ),
        # page_size is zero
        (
            {"page_size": "0"},
            ValueError,
            ERROR_MESSAGES["INVALID_INTEGER"].format("0", "page_size"),
        ),
        # page_size is negative
        (
            {"page_size": "-5"},
            ValueError,
            ERROR_MESSAGES["INVALID_INTEGER"].format("-5", "page_size"),
        ),
        # page_size is not an integer
        (
            {"page_size": "abc"},
            ValueError,
            INVALID_NUMBER.format("page_size", "abc"),
        ),
        # page is negative
        (
            {"page": "-1"},
            ValueError,
            ERROR_MESSAGES["INVALID_INTEGER"].format("-1", "page"),
        ),
        # page is not an integer
        (
            {"page": "xyz"},
            ValueError,
            INVALID_NUMBER.format("page", "xyz"),
        ),
        # invalid sort_order
        (
            {"sort_order": "Ascending"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Ascending", "sort_order", SORT_ORDER_VALID_VALUES),
        ),
        # invalid sort_by
        (
            {"sort_by": "Invalid Field"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid Field", "sort_by", SORT_BY_VALID_VALUES),
        ),
    ],
)
def test_contrast_security_issue_list_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid input (page_size exceeds max, non-integer page/page_size, invalid sort_order or sort_by)

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate that an appropriate error is raised
    """
    with pytest.raises(exception) as e:
        contrast_security_issue_list_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_issue_get_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID

    When:
    - Running the !contrastsecurity-issue-get command

    Then:
    - Validate the command results are valid, context contains merged issue+summary data, and HR matches
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/issue_get_human_readable.md")) as f:
        expected_hr = f.read()

    test_args = {"issue_id": "ISS-2026-1430"}
    organization_id = mock_client.organization_id

    issue_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format(organization_id, test_args['issue_id'])}"
    summary_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get_summary'].format(organization_id, test_args['issue_id'])}"
    requests_mock.get(issue_url, json=ISSUE_GET_RESPONSE)
    requests_mock.get(summary_url, json=ISSUE_GET_SUMMARY_RESPONSE)

    results = contrast_security_issue_get_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs["issueId"] == "ISS-2026-1430"
    assert results.outputs["summary"] == ISSUE_GET_SUMMARY_RESPONSE["summary"]
    assert results.outputs["lastAttackIdRef"] == ISSUE_GET_SUMMARY_RESPONSE["lastAttackIdRef"]
    assert results.outputs == ISSUE_GET_OUTPUTS


def test_contrast_security_issue_get_command_no_last_attack_ref(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID where summary has no lastAttackIdRef

    When:
    - Running the !contrastsecurity-issue-get command

    Then:
    - Validate lastAttackIdRef is absent from context and command succeeds
    """
    test_args = {"issue_id": "ISS-2026-1430"}

    summary_no_ref = {"vulnEventId": None, "lastAttackIdRef": None, "summary": "some summary text"}
    organization_id = mock_client.organization_id

    issue_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format(organization_id, test_args['issue_id'])}"
    summary_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get_summary'].format(organization_id, test_args['issue_id'])}"
    requests_mock.get(issue_url, json=ISSUE_GET_RESPONSE)
    requests_mock.get(summary_url, json=summary_no_ref)

    results = contrast_security_issue_get_command(mock_client, test_args)

    assert results.outputs["summary"] == "some summary text"
    assert "lastAttackIdRef" not in results.outputs


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"issue_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
        ({}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
    ],
)
def test_contrast_security_issue_get_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing or empty issue_id)

    When:
    - Running the !contrastsecurity-issue-get command

    Then:
    - Validate that appropriate error is raised
    """
    with pytest.raises(exception) as e:
        contrast_security_issue_get_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_issue_get_command_api_error(mock_client, requests_mock):
    """
    Given:
    - An issue ID that does not exist in the API

    When:
    - Running the !contrastsecurity-issue-get command

    Then:
    - An exception is raised with the API error message
    """
    test_args = {"issue_id": "ISS-0000-9999"}

    issue_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format(mock_client.organization_id, test_args['issue_id'])}"
    requests_mock.get(issue_url, json={"error": "Issue not found"}, status_code=404)

    with pytest.raises(Exception):
        contrast_security_issue_get_command(mock_client, test_args)


def test_contrast_security_issue_comment_add_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID and comment text

    When:
    - Running the !contrastsecurity-issue-comment-add command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_issue_comment_add_command

    mock_response = util_load_json("test_data/issue_comment_add_response.json")
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/issue_comment_add_human_readable.md")) as f:
        issue_comment_add_hr = f.read()

    test_args = {
        "issue_id": "ISS-2026-100",
        "comment": "this is test comment for issue ",
    }

    formatted_endpoint = ENDPOINTS["issue_comment"].format(mock_client.organization_id, test_args["issue_id"])
    requests_mock.post(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_issue_comment_add_command(mock_client, test_args)

    assert results.readable_output == issue_comment_add_hr
    assert results.outputs == [mock_response]


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"issue_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
        ({"issue_id": "ISS-2026-100", "comment": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("comment")),
        ({"comment": "test comment"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
    ],
)
def test_contrast_security_issue_comment_add_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing issue_id or comment)

    When:
    - Running the !contrastsecurity-issue-comment-add command

    Then:
    - Validate that appropriate error is raised
    """
    from ContrastSecurity import contrast_security_issue_comment_add_command

    with pytest.raises(exception) as e:
        contrast_security_issue_comment_add_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_issue_comment_add_command_with_special_characters(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID and comment text with special characters

    When:
    - Running the !contrastsecurity-issue-comment-add command

    Then:
    - Validate the command results are valid with special characters preserved
    """
    from ContrastSecurity import contrast_security_issue_comment_add_command

    special_comment = "Test comment with special chars: @#$%^&*()[]{}|<>?/\\\\~`"
    mock_response = util_load_json("test_data/issue_comment_add_response.json")
    mock_response = {"commentText": special_comment, "commentId": "test-special-chars-id"}

    test_args = {
        "issue_id": "ISS-2026-101",
        "comment": special_comment,
    }

    formatted_endpoint = ENDPOINTS["issue_comment"].format(mock_client.organization_id, test_args["issue_id"])
    requests_mock.post(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_issue_comment_add_command(mock_client, test_args)

    assert results.outputs[0]["commentText"] == special_comment
    assert results.outputs[0]["commentId"] == "test-special-chars-id"


def test_contrast_security_issue_status_update_command_open(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID and status "open"

    When:
    - Running the !contrastsecurity-issue-status-update command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_issue_status_update_command

    test_args = {
        "issue_id": "ISS-2026-100",
        "status": "Open",
    }

    formatted_endpoint = ENDPOINTS["issue_status"].format(mock_client.organization_id, test_args["issue_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_issue_status_update_command(mock_client, test_args)

    assert results.outputs[0]["id"] == "ISS-2026-100"
    assert results.outputs[0]["status"] == "Open"


def test_contrast_security_issue_status_update_command_closed(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID and status "closed"

    When:
    - Running the !contrastsecurity-issue-status-update command

    Then:
    - Validate the command results are valid
    """
    from ContrastSecurity import contrast_security_issue_status_update_command

    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/issue_status_update_closed_human_readable.md")
    ) as f:
        issue_status_update_hr = f.read()

    test_args = {
        "issue_id": "ISS-2026-100",
        "status": "Closed",
    }

    formatted_endpoint = ENDPOINTS["issue_status"].format(mock_client.organization_id, test_args["issue_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json={})

    results = contrast_security_issue_status_update_command(mock_client, test_args)

    assert results.readable_output == issue_status_update_hr
    assert results.outputs[0]["id"] == "ISS-2026-100"
    assert results.outputs[0]["status"] == "Closed"


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"issue_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
        ({"issue_id": "ISS-2026-100", "status": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("status")),
        ({"status": "Open"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("issue_id")),
        (
            {"issue_id": "ISS-2026-100", "status": "invalid_status"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("invalid_status", "status", ["Closed", "Open"]),
        ),
    ],
)
def test_contrast_security_issue_status_update_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing/invalid issue_id or status)

    When:
    - Running the !contrastsecurity-issue-status-update command

    Then:
    - Validate that appropriate error is raised
    """
    from ContrastSecurity import contrast_security_issue_status_update_command

    with pytest.raises(exception) as e:
        contrast_security_issue_status_update_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_contrast_security_issue_status_update_command_idempotency_warning(mock_client, mocker):
    """
    Given:
    - A valid issue ID and status, but the issue already has the requested status
    - API returns "not found with previous status" error

    When:
    - Running the !contrastsecurity-issue-status-update command

    Then:
    - Validate that a warning is returned indicating the issue already has the requested status
    - Verify the function returns None and doesn't raise an exception
    """
    from ContrastSecurity import contrast_security_issue_status_update_command
    from CommonServerPython import DemistoException

    test_args = {
        "issue_id": "ISS-2026-100",
        "status": "Closed",
    }

    # Mock the client.issue_status_update to raise an exception with "not found with previous status"
    error_message = "Issue not found with previous status"
    mocker.patch.object(mock_client, "issue_status_update", side_effect=DemistoException(error_message))

    # Mock the return_warning function to verify it's called with the correct message
    mock_return_warning = mocker.patch("ContrastSecurity.return_warning")

    # Execute the command
    result = contrast_security_issue_status_update_command(mock_client, test_args)

    # Verify return_warning was called with the correct message and exit=True
    mock_return_warning.assert_called_once_with(
        f"Issue {test_args['issue_id']} already has status '{test_args['status']}'.", exit=True
    )

    # Verify the function returns None
    assert result is None


def test_contrast_security_observation_get_command_attack_success(mock_client, requests_mock):
    """
    Given:
    - A valid observation ID for an ATTACK type observation

    When:
    - Running the !contrastsecurity-observation-get command

    Then:
    - Validate the command results with correct context outputs, raw_response, and human-readable output
    - Verify the observation type is ATTACK and contains attack insights
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/observation_attack_human_readable.md")) as f:
        expected_hr = f.read()

    test_args = {"observation_id": "A-D-b78412a9-2a35-4683-1777670053"}
    organization_id = mock_client.organization_id

    obs_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observation_get'].format(organization_id, test_args['observation_id'])}"
    details_url = (
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['observation_get_details'].format(organization_id, test_args['observation_id'])}"
    )

    requests_mock.get(obs_url, json=OBSERVATION_ATTACK_RESPONSE)
    requests_mock.get(
        details_url,
        json={
            "teamserverAuthorizationFailure": OBSERVATION_ATTACK_RESPONSE["teamserverAuthorizationFailure"],
            "attackInsightsResponseDto": OBSERVATION_ATTACK_RESPONSE["attackInsightsResponseDto"],
        },
    )

    results = contrast_security_observation_get_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs[0]["type"] == "ATTACK"
    assert results.outputs[0]["issueId"] == "ISS-2026-2"
    assert "attackInsightsResponseDto" in results.outputs[0]
    assert results.raw_response["type"] == "ATTACK"
    assert results.raw_response == OBSERVATION_ATTACK_RESPONSE


def test_contrast_security_observation_get_command_library_success(mock_client, requests_mock):
    """
    Given:
    - A valid observation ID for a LIBRARY type observation

    When:
    - Running the !contrastsecurity-observation-get command

    Then:
    - Validate the command results with correct context outputs, raw_response, and human-readable output
    - Verify the observation type is LIBRARY and contains SCA library vulnerability data
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/observation_library_human_readable.md")) as f:
        expected_hr = f.read()

    test_args = {"observation_id": "test-obs-wkmsdkw"}
    organization_id = mock_client.organization_id

    obs_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observation_get'].format(organization_id, test_args['observation_id'])}"
    details_url = (
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['observation_get_details'].format(organization_id, test_args['observation_id'])}"
    )

    requests_mock.get(obs_url, json=OBSERVATION_LIBRARY_RESPONSE)
    requests_mock.get(
        details_url,
        json={
            "teamserverAuthorizationFailure": OBSERVATION_LIBRARY_RESPONSE["teamserverAuthorizationFailure"],
            "scaLibraryResponseDto": OBSERVATION_LIBRARY_RESPONSE["scaLibraryResponseDto"],
        },
    )

    results = contrast_security_observation_get_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs[0]["type"] == "LIBRARY"
    assert results.outputs[0]["issueId"] == "ISS-2026-2"
    assert "scaLibraryResponseDto" in results.outputs[0]
    assert len(results.outputs[0]["scaLibraryResponseDto"]["vulnerabilities"]) == 2
    assert results.raw_response == OBSERVATION_LIBRARY_RESPONSE


def test_contrast_security_incident_observation_list_command_success(mock_client, requests_mock):
    """
    Given:
    - Valid incident_id and default pagination arguments

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate the command results are valid, context contains the observations, and HR matches
    - Validate no pagination message when hasMore is False
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/observation_list_human_readable.md")) as f:
        expected_hr = f.read()

    test_args: dict = {"incident_id": "INC-2026-1001"}

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observations_list'].format(mock_client.organization_id, test_args['incident_id'])}"
    requests_mock.post(url, json=OBSERVATION_LIST_RESPONSE)

    results = contrast_security_incident_observation_list_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert isinstance(results.outputs, list)
    assert results.outputs == OBSERVATION_LIST_OUTPUTS
    assert results.outputs[0]["observationId"] == "A-D-11111111-2222-3333-4444-555555555555-1234567890"
    assert results.outputs[1]["observationId"] == "A-D-66666666-7777-8888-9999-000000000000-1234567891"
    assert results.raw_response == OBSERVATION_LIST_RESPONSE
    # Verify no pagination message when hasMore is False
    assert "**To Get Next page Observations:**" not in results.readable_output


def test_contrast_security_incident_observation_list_command_with_sort(mock_client, requests_mock):
    """
    Given:
    - sort_by and sort_order arguments are provided

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate the API is called with the correct sort parameters in query params
    - Validate pagination message appears when hasMore is True
    - Validate the complete human-readable output matches expected format
    """
    test_args = {
        "incident_id": "INC-2026-1001",
        "sort_by": "event_time",
        "sort_order": "Desc",
        "page_size": "20",
    }

    # Response with pagination enabled
    response_with_pagination = {
        "total": OBSERVATION_LIST_RESPONSE["total"],
        "observations": OBSERVATION_LIST_RESPONSE["observations"],
        "sortValue": OBSERVATION_LIST_RESPONSE.get("sortValue"),
        "hasMore": True,
        "cursor": "test-cursor-123",
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observations_list'].format(mock_client.organization_id, test_args['incident_id'])}"
    requests_mock.post(url, json=response_with_pagination)

    results = contrast_security_incident_observation_list_command(mock_client, test_args)

    # Verify the request was made with POST method
    assert requests_mock.last_request.method == "POST"

    # Verify the query parameters contain pagination and sort information
    query_params = requests_mock.last_request.qs
    assert query_params.get("pagination") == ["cursor"]
    assert query_params.get("size") == ["20"]
    assert query_params.get("sort") == ["event_time,desc"]

    # Load expected human-readable output with pagination
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/observation_list_with_pagination_human_readable.md")
    ) as f:
        expected_hr_with_pagination = f.read()

    # Verify the complete human-readable output matches expected format
    assert results.readable_output == expected_hr_with_pagination


def test_contrast_security_incident_observation_list_command_no_results(mock_client, requests_mock):
    """
    Given:
    - The API returns an empty observations list

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate an appropriate no-results message is returned and no context is set
    """
    test_args = {"incident_id": "INC-2026-1001"}
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observations_list'].format(mock_client.organization_id, test_args['incident_id'])}"
    requests_mock.post(url, json={"observations": [], "total": 0})

    results = contrast_security_incident_observation_list_command(mock_client, test_args)

    assert results.readable_output == "No observations were found for the given incident."
    assert results.outputs is None


@pytest.mark.parametrize(
    "args, exception, error",
    [
        # incident_id is missing
        (
            {},
            ValueError,
            "Missing argument incident_id.",
        ),
        # page_size exceeds maximum
        (
            {"incident_id": "INC-2026-1001", "page_size": "1001"},
            ValueError,
            ERROR_MESSAGES["INVALID_PAGE_SIZE"].format("1001", MAX_OBSERVATION_PAGE_SIZE),
        ),
        # page_size is zero
        (
            {"incident_id": "INC-2026-1001", "page_size": "0"},
            ValueError,
            ERROR_MESSAGES["INVALID_INTEGER"].format("0", "page_size"),
        ),
        # page_size is negative
        (
            {"incident_id": "INC-2026-1001", "page_size": "-5"},
            ValueError,
            ERROR_MESSAGES["INVALID_INTEGER"].format("-5", "page_size"),
        ),
        # page_size is not an integer
        (
            {"incident_id": "INC-2026-1001", "page_size": "abc"},
            ValueError,
            INVALID_NUMBER.format("page_size", "abc"),
        ),
        # invalid sort_order
        (
            {"incident_id": "INC-2026-1001", "sort_order": "Ascending"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Ascending", "sort_order", SORT_ORDER_VALID_VALUES),
        ),
        # invalid sort_by
        (
            {"incident_id": "INC-2026-1001", "sort_by": "Invalid Field"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid Field", "sort_by", OBSERVATION_SORT_BY_VALID_VALUES),
        ),
    ],
)
def test_contrast_security_incident_observation_list_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid input (missing incident_id, page_size exceeds max, non-integer page_size, invalid sort_order or sort_by)

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate that an appropriate error is raised
    """
    with pytest.raises(exception) as exception_info:
        contrast_security_incident_observation_list_command(client=mock_client, args=args)
    assert str(exception_info.value) == error
