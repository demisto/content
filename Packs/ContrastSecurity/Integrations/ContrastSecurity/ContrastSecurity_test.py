import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import pytest
from freezegun import freeze_time
from CommonServerPython import *
from ContrastSecurity import (
    Client,
    ERROR_MESSAGES,
    ENDPOINTS,
    EVENT_TYPES,
    MAX_FETCH_LIMIT,
    RULE_MODE_HUMAN_READABLE_LIST,
    fetch_incidents,
    contrast_security_adr_rule_update_command,
    contrast_security_issue_list_command,
    contrast_security_issue_get_command,
    contrast_security_observation_get_command,
    contrast_security_incident_observation_list_command,
    SORT_BY_VALID_VALUES,
    SORT_ORDER_VALID_VALUES,
    STATUS_HUMAN_READABLE_LIST,
    SEVERITY_HUMAN_READABLE_LIST,
    MAX_ISSUE_PAGE_SIZE,
    MAX_OBSERVATION_PAGE_SIZE,
    main,
    test_module as contrast_test_module,
)

DUMMAY_SERVER_URL = "https://test.contrast.com"
INVALID_NUMBER = 'Invalid number: "{}"="{}"'

# Load schema files from test_data directory
TEST_DATA_DIR = Path(__file__).parent / "test_data"


with open(TEST_DATA_DIR / "issue_list_response.json") as f:
    ISSUE_LIST_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "issue_list_outputs.json") as f:
    ISSUE_LIST_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "issue_get_response.json") as f:
    ISSUE_GET_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "issue_get_outputs.json") as f:
    ISSUE_GET_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "get_incident_response.json") as f:
    SAMPLE_GET_INCIDENT_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_attack_response.json") as f:
    OBSERVATION_ATTACK_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_attack_outputs.json") as f:
    OBSERVATION_ATTACK_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "observation_behavior_response.json") as f:
    OBSERVATION_BEHAVIOR_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_behavior_outputs.json") as f:
    OBSERVATION_BEHAVIOR_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "observation_vulnerability_response.json") as f:
    OBSERVATION_VULNERABILITY_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_vulnerability_outputs.json") as f:
    OBSERVATION_VULNERABILITY_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "observation_attack_partial_response.json") as f:
    OBSERVATION_ATTACK_PARTIAL_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_attack_partial_outputs.json") as f:
    OBSERVATION_ATTACK_PARTIAL_OUTPUTS = json.load(f)

with open(TEST_DATA_DIR / "observation_list_response.json") as f:
    OBSERVATION_LIST_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "observation_list_outputs.json") as f:
    OBSERVATION_LIST_OUTPUTS = json.load(f)


with open(TEST_DATA_DIR / "fetch_incidents_list_response.json") as f:
    FETCH_INCIDENTS_LIST_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "fetch_incidents_details_response.json") as f:
    FETCH_INCIDENTS_DETAILS_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "fetch_incidents_outputs.json") as f:
    FETCH_INCIDENTS_OUTPUTS = json.load(f)

FETCH_INCIDENTS_PARAMS = {
    "event_type": "Contrast Incident",
    "max_fetch": "4",
    "first_fetch": "3 days",
    "incident_statuses": "Open,Closed",
    "incident_severities": "Critical,High,Medium",
    "issue_statuses": "Invalid",
    "incident_mirror_direction": "Incoming And Outgoing",
    "note_tag": "note",
}

with open(TEST_DATA_DIR / "fetch_issues_list_response.json") as f:
    FETCH_ISSUES_LIST_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "fetch_issues_details_response.json") as f:
    FETCH_ISSUES_DETAILS_RESPONSE = json.load(f)

with open(TEST_DATA_DIR / "fetch_issues_outputs.json") as f:
    FETCH_ISSUES_OUTPUTS = json.load(f)

FETCH_ISSUES_PARAMS = {
    "event_type": "Contrast Issue",
    "max_fetch": "4",
    "first_fetch": "3 days",
    "issue_statuses": "Open,Closed",
    "issue_severities": "Critical,High,Medium",
    # Filters of the other event type are not validated or sent
    "incident_statuses": "Invalid",
    "issue_mirror_direction": "Outgoing",
    "note_tag": "note",
}


SAMPLE_GET_INCIDENT_RESPONSE_CLOSED = {
    **SAMPLE_GET_INCIDENT_RESPONSE,
    "status": "CLOSED",
    "closedReason": "TRUE_POSITIVE_BENIGN",
    "closedTime": "2026-10-21T06:39:22.509Z",
}


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


@freeze_time("2026-10-04T00:00:00Z")
def test_fetch_contrast_incidents_first_run(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Incident and an empty last run (first run)

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the incidents created after the first fetch time are fetched and the cursor moves to the next page
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_INCIDENTS_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}", json=FETCH_INCIDENTS_LIST_RESPONSE
    )
    for incident_details in FETCH_INCIDENTS_DETAILS_RESPONSE:
        incident_id = incident_details.get("incidentId")
        requests_mock.get(
            f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}", json=incident_details
        )

    next_run, incidents = fetch_incidents(mock_client, FETCH_INCIDENTS_PARAMS, {})

    assert parse_qs(urlparse(requests_mock.request_history[0].url).query) == {
        "createdAfter": ["2026-10-01T00:00:00Z"],
        "statuses": ["OPEN", "CLOSED"],
        "severities": ["CRITICAL", "HIGH", "MEDIUM"],
        "sort": ["createdTime,asc"],
        "size": ["4"],
    }
    assert incidents == FETCH_INCIDENTS_OUTPUTS
    assert next_run == {
        "incident": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-1",
            "ingested_ids": ["INC-2026-1001", "INC-2026-1002", "INC-2026-1003", "INC-2026-1004"],
        }
    }


def test_fetch_contrast_incidents_next_run(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Incident and a last run with a cursor and ingested IDs (next run)

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the stored cursor is sent, the new IDs are added to the ingested IDs and the cursor moves to the next page
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_INCIDENTS_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}",
        json={**FETCH_INCIDENTS_LIST_RESPONSE, "cursor": "dummy-cursor-2"},
    )
    for incident_details in FETCH_INCIDENTS_DETAILS_RESPONSE:
        incident_id = incident_details.get("incidentId")
        requests_mock.get(
            f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}", json=incident_details
        )

    last_run = {
        "incident": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-1", "ingested_ids": ["INC-2026-0001"]}
    }

    next_run, incidents = fetch_incidents(mock_client, FETCH_INCIDENTS_PARAMS, last_run)

    assert parse_qs(urlparse(requests_mock.request_history[0].url).query).get("cursor") == ["dummy-cursor-1"]
    assert incidents == FETCH_INCIDENTS_OUTPUTS
    assert next_run == {
        "incident": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-2",
            "ingested_ids": ["INC-2026-0001", "INC-2026-1001", "INC-2026-1002", "INC-2026-1003", "INC-2026-1004"],
        }
    }


def test_fetch_contrast_incidents_with_duplicates(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Incident and a last run with already ingested incident IDs

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the already ingested incidents are skipped without the details call
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_INCIDENTS_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}",
        json={**FETCH_INCIDENTS_LIST_RESPONSE, "cursor": "dummy-cursor-2"},
    )
    for incident_details in FETCH_INCIDENTS_DETAILS_RESPONSE:
        incident_id = incident_details.get("incidentId")
        requests_mock.get(
            f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}", json=incident_details
        )

    last_run = {
        "incident": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-1",
            "ingested_ids": ["INC-2026-1001", "INC-2026-1002"],
        }
    }

    next_run, incidents = fetch_incidents(mock_client, FETCH_INCIDENTS_PARAMS, last_run)

    # 1 list call and 2 details calls, the already ingested incidents are skipped without the details call
    assert requests_mock.call_count == 3
    assert incidents == FETCH_INCIDENTS_OUTPUTS[2:]
    assert next_run == {
        "incident": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-2",
            "ingested_ids": ["INC-2026-1001", "INC-2026-1002", "INC-2026-1003", "INC-2026-1004"],
        }
    }


def test_fetch_contrast_incidents_when_time_limit_reached(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Incident and the fetch time limit reached after the first incident

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the fetch stops, keeps the current cursor and stores the ingested incident ID
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_INCIDENTS_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    # Run start, first incident within the time limit, second incident after the time limit
    mocker.patch("ContrastSecurity.time").time.side_effect = [0, 0, 241]
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}",
        json={**FETCH_INCIDENTS_LIST_RESPONSE, "cursor": "dummy-cursor-2"},
    )
    for incident_details in FETCH_INCIDENTS_DETAILS_RESPONSE:
        incident_id = incident_details.get("incidentId")
        requests_mock.get(
            f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}", json=incident_details
        )

    last_run = {"incident": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-1", "ingested_ids": []}}

    next_run, incidents = fetch_incidents(mock_client, FETCH_INCIDENTS_PARAMS, last_run)

    assert incidents == FETCH_INCIDENTS_OUTPUTS[:1]
    assert next_run == {
        "incident": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-1", "ingested_ids": ["INC-2026-1001"]}
    }


def test_fetch_contrast_incidents_with_last_page(mocker, mock_client, requests_mock):
    """
    Given:
    - Default fetch parameters (event type, max fetch and first fetch time not set, no statuses or severities)
      and the last page of incidents

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the default event type and max fetch are used, no statuses or severities are sent,
      the next run starts from the latest created time and the cursor is cleared
    """
    params = {"incident_mirror_direction": "Incoming And Outgoing", "note_tag": "note"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}",
        json={**FETCH_INCIDENTS_LIST_RESPONSE, "hasMore": False, "cursor": None},
    )
    for incident_details in FETCH_INCIDENTS_DETAILS_RESPONSE:
        incident_id = incident_details.get("incidentId")
        requests_mock.get(
            f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}", json=incident_details
        )

    last_run = {"incident": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-2", "ingested_ids": []}}

    next_run, incidents = fetch_incidents(mock_client, params, last_run)

    assert parse_qs(urlparse(requests_mock.request_history[0].url).query) == {
        "createdAfter": ["2026-10-01T00:00:00Z"],
        "sort": ["createdTime,asc"],
        "size": ["25"],
        "cursor": ["dummy-cursor-2"],
    }
    assert incidents == FETCH_INCIDENTS_OUTPUTS
    assert next_run == {
        "incident": {
            "created_after": "2026-10-14T09:30:12.512Z",
            "cursor": None,
            "ingested_ids": ["INC-2026-1001", "INC-2026-1002", "INC-2026-1003", "INC-2026-1004"],
        }
    }


def test_fetch_contrast_incidents_with_empty_response(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Incident and no new incidents

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that no incidents are created, no details call is made and the next run is not changed
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_INCIDENTS_PARAMS)
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}",
        json={"content": [], "hasMore": False, "cursor": None},
    )
    last_run = {"incident": {"created_after": "2026-10-14T09:30:12.512Z", "cursor": None, "ingested_ids": ["INC-2026-1004"]}}

    next_run, incidents = fetch_incidents(mock_client, FETCH_INCIDENTS_PARAMS, last_run)

    assert incidents == []
    assert requests_mock.call_count == 1
    assert next_run == last_run


@pytest.mark.parametrize(
    "params, error",
    [
        ({"max_fetch": "0"}, ERROR_MESSAGES["INVALID_MAX_FETCH"].format(0, MAX_FETCH_LIMIT)),
        ({"max_fetch": "-1"}, ERROR_MESSAGES["INVALID_MAX_FETCH"].format(-1, MAX_FETCH_LIMIT)),
        ({"max_fetch": "201"}, ERROR_MESSAGES["INVALID_MAX_FETCH"].format(201, MAX_FETCH_LIMIT)),
        ({"max_fetch": "invalid"}, INVALID_NUMBER.format("Max Fetch", "invalid")),
        ({"first_fetch": "invalid"}, 'Invalid date: "First Fetch Time"="invalid"'),
        ({"event_type": "Invalid"}, ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "Event Type", EVENT_TYPES)),
        (
            {"incident_statuses": "Open,Invalid"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "Incident Statuses", STATUS_HUMAN_READABLE_LIST),
        ),
        (
            {"incident_severities": "Critical,Invalid"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "Incident Severity Levels", SEVERITY_HUMAN_READABLE_LIST),
        ),
    ],
)
def test_fetch_contrast_incidents_invalid_params(mock_client, params, error):
    """
    Given:
    - Invalid fetch parameters (max fetch, first fetch time, event type, incident statuses or severities)

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that a ValueError with the appropriate error message is raised
    """
    with pytest.raises(ValueError) as exc_info:
        fetch_incidents(mock_client, {**FETCH_INCIDENTS_PARAMS, **params}, {})

    assert str(exc_info.value) == error


@freeze_time("2026-10-04T00:00:00Z")
def test_main_fetch_incidents(mocker, requests_mock):
    """
    Given:
    - Valid parameters with event type set to Contrast Incident and the fetch-incidents command

    When:
    - Running the main function

    Then:
    - Validate that the XSOAR incidents are created and the next run is stored
    """
    params = {
        **FETCH_INCIDENTS_PARAMS,
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    mock_incidents = mocker.patch.object(demisto, "incidents")
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}",
        json={**FETCH_INCIDENTS_LIST_RESPONSE, "hasMore": False, "cursor": None},
    )
    for incident_details in FETCH_INCIDENTS_DETAILS_RESPONSE:
        incident_id = incident_details.get("incidentId")
        requests_mock.get(
            f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}", json=incident_details
        )

    main()

    mock_incidents.assert_called_once_with(FETCH_INCIDENTS_OUTPUTS)
    mock_set_last_run.assert_called_once_with(
        {
            "incident": {
                "created_after": "2026-10-14T09:30:12.512Z",
                "cursor": None,
                "ingested_ids": ["INC-2026-1001", "INC-2026-1002", "INC-2026-1003", "INC-2026-1004"],
            }
        }
    )
    mock_return_error.assert_not_called()


@freeze_time("2026-10-04T00:00:00Z")
def test_fetch_contrast_issues_first_run(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Issue and an empty last run (first run)

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the issues created after the first fetch time are fetched and the cursor moves to the next page
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_ISSUES_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}", json=FETCH_ISSUES_LIST_RESPONSE)
    for issue_details in FETCH_ISSUES_DETAILS_RESPONSE:
        issue_id = issue_details.get("issueId")
        requests_mock.get(f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format('test-org-id', issue_id)}", json=issue_details)

    next_run, incidents = fetch_incidents(mock_client, FETCH_ISSUES_PARAMS, {})

    assert parse_qs(urlparse(requests_mock.request_history[0].url).query) == {
        "createdAfter": ["2026-10-01T00:00:00Z"],
        "statuses": ["OPEN", "CLOSED"],
        "severities": ["CRITICAL", "HIGH", "MEDIUM"],
        "sort": ["createdTime,asc"],
        "size": ["4"],
    }
    assert incidents == FETCH_ISSUES_OUTPUTS
    assert next_run == {
        "issue": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-1",
            "ingested_ids": ["ISS-2026-1001", "ISS-2026-1002", "ISS-2026-1003", "ISS-2026-1004"],
        }
    }


def test_fetch_contrast_issues_next_run(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Issue and a last run with a cursor and ingested IDs (next run),
      along with the state of the Contrast Incident event type

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the stored cursor is sent, the new IDs are added to the ingested IDs, the cursor moves to the next page
      and the state of the Contrast Incident event type is kept
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_ISSUES_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}",
        json={**FETCH_ISSUES_LIST_RESPONSE, "cursor": "dummy-cursor-2"},
    )
    for issue_details in FETCH_ISSUES_DETAILS_RESPONSE:
        issue_id = issue_details.get("issueId")
        requests_mock.get(f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format('test-org-id', issue_id)}", json=issue_details)

    incident_last_run = {"created_after": "2026-10-01T00:00:00Z", "cursor": None, "ingested_ids": ["INC-2026-0001"]}
    last_run = {
        "incident": incident_last_run,
        "issue": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-1", "ingested_ids": ["ISS-2026-0001"]},
    }

    next_run, incidents = fetch_incidents(mock_client, FETCH_ISSUES_PARAMS, last_run)

    assert parse_qs(urlparse(requests_mock.request_history[0].url).query).get("cursor") == ["dummy-cursor-1"]
    assert incidents == FETCH_ISSUES_OUTPUTS
    assert next_run == {
        "incident": incident_last_run,
        "issue": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-2",
            "ingested_ids": ["ISS-2026-0001", "ISS-2026-1001", "ISS-2026-1002", "ISS-2026-1003", "ISS-2026-1004"],
        },
    }


def test_fetch_contrast_issues_with_duplicates(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Issue and a last run with already ingested issue IDs

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the already ingested issues are skipped without the details call
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_ISSUES_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}",
        json={**FETCH_ISSUES_LIST_RESPONSE, "cursor": "dummy-cursor-2"},
    )
    for issue_details in FETCH_ISSUES_DETAILS_RESPONSE:
        issue_id = issue_details.get("issueId")
        requests_mock.get(f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format('test-org-id', issue_id)}", json=issue_details)

    last_run = {
        "issue": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-1",
            "ingested_ids": ["ISS-2026-1001", "ISS-2026-1002"],
        }
    }

    next_run, incidents = fetch_incidents(mock_client, FETCH_ISSUES_PARAMS, last_run)

    # 1 list call and 2 details calls, the already ingested issues are skipped without the details call
    assert requests_mock.call_count == 3
    assert incidents == FETCH_ISSUES_OUTPUTS[2:]
    assert next_run == {
        "issue": {
            "created_after": "2026-10-01T00:00:00Z",
            "cursor": "dummy-cursor-2",
            "ingested_ids": ["ISS-2026-1001", "ISS-2026-1002", "ISS-2026-1003", "ISS-2026-1004"],
        }
    }


def test_fetch_contrast_issues_when_time_limit_reached(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Issue and the fetch time limit reached after the first issue

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the fetch stops, keeps the current cursor and stores the ingested issue ID
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_ISSUES_PARAMS)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    # Run start, first issue within the time limit, second issue after the time limit
    mocker.patch("ContrastSecurity.time").time.side_effect = [0, 0, 241]
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}",
        json={**FETCH_ISSUES_LIST_RESPONSE, "cursor": "dummy-cursor-2"},
    )
    for issue_details in FETCH_ISSUES_DETAILS_RESPONSE:
        issue_id = issue_details.get("issueId")
        requests_mock.get(f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format('test-org-id', issue_id)}", json=issue_details)

    last_run = {"issue": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-1", "ingested_ids": []}}

    next_run, incidents = fetch_incidents(mock_client, FETCH_ISSUES_PARAMS, last_run)

    assert incidents == FETCH_ISSUES_OUTPUTS[:1]
    assert next_run == {
        "issue": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-1", "ingested_ids": ["ISS-2026-1001"]}
    }


def test_fetch_contrast_issues_with_last_page(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Issue without the issue mirroring direction and the last page of issues

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that the mirroring direction is not added, the next run starts from the latest created time
      and the cursor is cleared
    """
    params = {key: value for key, value in FETCH_ISSUES_PARAMS.items() if key != "issue_mirror_direction"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "integrationInstance", return_value="dummy-instance")
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}",
        json={**FETCH_ISSUES_LIST_RESPONSE, "hasMore": False, "cursor": None},
    )
    for issue_details in FETCH_ISSUES_DETAILS_RESPONSE:
        issue_id = issue_details.get("issueId")
        requests_mock.get(f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format('test-org-id', issue_id)}", json=issue_details)

    last_run = {"issue": {"created_after": "2026-10-01T00:00:00Z", "cursor": "dummy-cursor-2", "ingested_ids": []}}

    next_run, incidents = fetch_incidents(mock_client, params, last_run)

    expected_incidents = [
        {
            **incident,
            "rawJSON": json.dumps(
                {key: value for key, value in json.loads(incident["rawJSON"]).items() if key != "mirror_direction"}
            ),
        }
        for incident in FETCH_ISSUES_OUTPUTS
    ]
    assert incidents == expected_incidents
    assert next_run == {
        "issue": {
            "created_after": "2026-10-14T09:30:12.512Z",
            "cursor": None,
            "ingested_ids": ["ISS-2026-1001", "ISS-2026-1002", "ISS-2026-1003", "ISS-2026-1004"],
        }
    }


def test_fetch_contrast_issues_with_empty_response(mocker, mock_client, requests_mock):
    """
    Given:
    - Event type set to Contrast Issue and no new issues

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that no incidents are created, no details call is made and the next run is not changed
    """
    mocker.patch.object(demisto, "params", return_value=FETCH_ISSUES_PARAMS)
    requests_mock.get(
        f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}",
        json={"content": [], "hasMore": False, "cursor": None},
    )
    last_run = {"issue": {"created_after": "2026-10-14T09:30:12.512Z", "cursor": None, "ingested_ids": ["ISS-2026-1004"]}}

    next_run, incidents = fetch_incidents(mock_client, FETCH_ISSUES_PARAMS, last_run)

    assert incidents == []
    assert requests_mock.call_count == 1
    assert next_run == last_run


@pytest.mark.parametrize(
    "params, error",
    [
        (
            {"issue_statuses": "Open,Invalid"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "Issue Statuses", STATUS_HUMAN_READABLE_LIST),
        ),
        (
            {"issue_severities": "Critical,Invalid"},
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "Issue Severity Levels", SEVERITY_HUMAN_READABLE_LIST),
        ),
    ],
)
def test_fetch_contrast_issues_invalid_params(mock_client, params, error):
    """
    Given:
    - Event type set to Contrast Issue and invalid issue statuses or severities

    When:
    - Running the fetch-incidents command

    Then:
    - Validate that a ValueError with the appropriate error message is raised
    """
    with pytest.raises(ValueError) as exc_info:
        fetch_incidents(mock_client, {**FETCH_ISSUES_PARAMS, **params}, {})

    assert str(exc_info.value) == error


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


def test_client_http_request_returns_response_object_by_default(mock_client, requests_mock):
    """
    Given: A valid Client
    When: http_request is called without response_type
    Then: The raw response object is returned instead of the parsed JSON
    """
    org_id = "test-org-id"
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(org_id)}"
    requests_mock.get(url, json={"issues": [], "count": 0})

    raw_response = mock_client.http_request(method="GET", url_suffix=ENDPOINTS["issue_list"].format(org_id))

    assert raw_response.json() == {"issues": [], "count": 0}


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


@pytest.mark.parametrize(
    "response_kwargs, error",
    [
        (
            {"status_code": 401, "json": {"error": "Unauthorized"}},
            ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "Unauthorized"),
        ),
        (
            {"status_code": 401, "text": "Unauthorized"},
            ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "<Response [401]>"),
        ),
        (
            {"status_code": 200, "text": "invalid json"},
            ERROR_MESSAGES["INVALID_OBJECT"].format("json", b"invalid json"),
        ),
    ],
)
def test_client_http_request_when_invalid_response(mock_client, requests_mock, response_kwargs, error):
    """
    Given:
    - An unauthorized or non-JSON response from the Contrast Security API

    When:
    - Calling Client.http_request

    Then:
    - Validate that DemistoException is raised with the appropriate error message
    """
    requests_mock.get(f"{DUMMAY_SERVER_URL}/test", **response_kwargs)

    with pytest.raises(DemistoException) as e:
        mock_client.http_request(method="GET", url_suffix="/test", response_type="json")

    assert str(e.value) == error


@pytest.mark.parametrize(
    "status_code, response_json",
    [
        (400, {"status": 400, "title": "Bad Request", "detail": "Invalid id: INC-0000-0, expected INC-YYYY-..."}),
        (403, {"status": 403, "title": "Forbidden", "detail": "Access Denied"}),
        (404, {"status": 404, "title": "Not Found", "detail": "Incident not found"}),
    ],
)
def test_client_http_request_when_error_status_code(mock_client, requests_mock, status_code, response_json):
    """
    Given:
    - An error status code other than 401 from the Contrast Security API

    When:
    - Calling Client.http_request

    Then:
    - Validate that DemistoException is raised with the status code and the API error detail
    """
    requests_mock.get(f"{DUMMAY_SERVER_URL}/test", status_code=status_code, json=response_json)

    with pytest.raises(DemistoException) as e:
        mock_client.http_request(method="GET", url_suffix="/test", response_type="json")

    assert f"[{status_code}]" in str(e.value)
    assert response_json["detail"] in str(e.value)


@pytest.mark.parametrize(
    "params, endpoint, response",
    [
        ({}, "issue_list", {"content": [], "hasMore": False}),
        # Fetch parameters are not validated when fetch incidents is disabled
        ({"isFetch": False, "max_fetch": "0"}, "issue_list", {"content": [], "hasMore": False}),
        # Fetch incidents enabled: only the list request of the configured event type is made
        ({**FETCH_INCIDENTS_PARAMS, "isFetch": True}, "incidents_list", FETCH_INCIDENTS_LIST_RESPONSE),
        ({**FETCH_ISSUES_PARAMS, "isFetch": True}, "issue_list", FETCH_ISSUES_LIST_RESPONSE),
    ],
)
def test_test_module_success(mocker, mock_client, requests_mock, params, endpoint, response):
    """
    Given: Valid API credentials, API is reachable and fetch incidents disabled or enabled with valid fetch parameters
    When: test_module is called
    Then: Returns 'ok' with a single list request and no details request
    """
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS[endpoint].format('test-org-id')}"
    requests_mock.get(url, json=response)

    result = contrast_test_module(mock_client, params)

    assert result == "ok"
    assert requests_mock.call_count == 1


def test_test_module_with_invalid_fetch_params(mock_client):
    """
    Given: Fetch incidents enabled with an invalid max fetch
    When: test_module is called
    Then: ValueError is raised with the invalid max fetch message
    """
    with pytest.raises(ValueError) as exc_info:
        contrast_test_module(mock_client, {**FETCH_INCIDENTS_PARAMS, "isFetch": True, "max_fetch": "0"})

    assert str(exc_info.value) == ERROR_MESSAGES["INVALID_MAX_FETCH"].format(0, MAX_FETCH_LIMIT)


def test_test_module_invalid_api_key(mock_client, requests_mock, mocker):
    """
    Given: API returns 401 Unauthorized due to invalid credentials
    When: test_module is called
    Then: DemistoException is raised with authentication failure message
    """
    url = f"https://test.contrast.com{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json={"error": "Unauthorized"}, status_code=401)

    with pytest.raises(DemistoException) as exc_info:
        contrast_test_module(mock_client, {})

    assert "Unauthorized" in str(exc_info.value)


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
        "insecure": False,
        "proxy": False,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    url = f"https://test.contrast.com{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json={"content": [], "hasMore": False})

    main()

    mock_return_results.assert_called_once_with("ok")
    mock_return_error.assert_not_called()


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
    assert results.outputs == [remove_empty_elements(mock_response)]
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


def test_main_incident_comment_add_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-incident-comment-add command with padded arguments

    When:
    - Running the main function

    Then:
    - Validate that the trimmed arguments are sent and the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-incident-comment-add")
    mocker.patch.object(demisto, "args", return_value={"incident_id": " incident-123 ", "comment": " dummy comment message "})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    mock_response = util_load_json("test_data/incident_comment_add_response.json")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'incident-123')}"
    requests_mock.post(url, json=mock_response, status_code=201)

    main()

    mock_return_error.assert_not_called()
    assert requests_mock.last_request.json() == {"commentText": "dummy comment message"}
    results = mock_return_results.call_args[0][0]
    assert results.outputs_prefix == "ContrastSecurity.IncidentComment"
    assert results.outputs == [remove_empty_elements(mock_response)]


def test_main_incident_comment_add_command_when_incident_not_found(mocker, requests_mock):
    """
    Given:
    - An incident ID that does not exist in Contrast Security

    When:
    - Running the main function with the contrastsecurity-incident-comment-add command

    Then:
    - Validate that return_error is called with the command name and the 404 status code
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-incident-comment-add")
    mocker.patch.object(demisto, "args", return_value={"incident_id": "INC-2099-999999", "comment": "dummy comment message"})
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2099-999999')}"
    requests_mock.post(url, status_code=404, json={"status": 404, "title": "Not Found"})

    main()

    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "Failed to execute contrastsecurity-incident-comment-add command." in error_message
    assert "[404]" in error_message


def test_contrast_security_incident_status_update_command_closed_with_reason(mock_client, requests_mock):
    """
    Given:
    - A valid incident ID, status "Closed", and a close reason

    When:
    - Running the !contrastsecurity-incident-status-update command

    Then:
    - Validate that the uppercase status and mapped close reason are sent
    - Validate the command results are built from the API response
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    mock_response = util_load_json("test_data/incident_status_update_response.json")
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data/incident_status_update_with_reason_human_readable.md"
        )
    ) as f:
        incident_status_update_hr = f.read()

    test_args = {
        "incident_id": "INC-2026-001",
        "status": "Closed",
        "close_reason": "True Positive",
    }

    formatted_endpoint = ENDPOINTS["incident_status"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_incident_status_update_command(mock_client, test_args)

    assert requests_mock.last_request.json() == {"status": "CLOSED", "closedReason": "TRUE_POSITIVE"}
    assert results.readable_output == incident_status_update_hr
    assert results.outputs_prefix == "ContrastSecurity.Incident"
    assert results.outputs_key_field == "incidentId"
    assert results.outputs == [remove_empty_elements(mock_response)]
    assert results.raw_response == mock_response


@pytest.mark.parametrize("status", ["Open", "open", "OPEN"])
def test_contrast_security_incident_status_update_command_open(mock_client, requests_mock, status):
    """
    Given:
    - A valid incident ID and status "Open" in different casings

    When:
    - Running the !contrastsecurity-incident-status-update command

    Then:
    - Validate that only the uppercase status is sent
    - Validate the command results are built from the API response
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    mock_response = util_load_json("test_data/incident_status_update_response.json")
    mock_response.update({"status": "OPEN", "closedTime": None, "closedReason": None})
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/incident_status_update_human_readable.md")
    ) as f:
        incident_status_update_hr = f.read()

    test_args = {
        "incident_id": "INC-2026-001",
        "status": status,
        "close_reason": "True Positive",
    }

    formatted_endpoint = ENDPOINTS["incident_status"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_incident_status_update_command(mock_client, test_args)

    assert requests_mock.last_request.json() == {"status": "OPEN"}
    assert results.readable_output == incident_status_update_hr
    assert results.outputs == [remove_empty_elements(mock_response)]


@pytest.mark.parametrize(
    "status, close_reason, closed_reason",
    [
        ("Closed", "True Positive", "TRUE_POSITIVE"),
        ("closed", "False Positive", "FALSE_POSITIVE"),
        ("CLOSED", "Benign True Positive", "TRUE_POSITIVE_BENIGN"),
        ("Closed", "Other", "OTHER"),
    ],
)
def test_contrast_security_incident_status_update_command_closed_various_reasons(
    mock_client, requests_mock, status, close_reason, closed_reason
):
    """
    Given:
    - A valid incident ID, status "Closed" in different casings, and different close reasons

    When:
    - Running the !contrastsecurity-incident-status-update command

    Then:
    - Validate that each close reason is mapped to the Contrast Security closedReason value
    - Validate that the human-readable output shows the close reason as provided in the argument
    """
    from ContrastSecurity import contrast_security_incident_status_update_command

    mock_response = util_load_json("test_data/incident_status_update_response.json")
    mock_response["closedReason"] = closed_reason

    test_args = {
        "incident_id": "INC-2026-001",
        "status": status,
        "close_reason": close_reason,
    }

    formatted_endpoint = ENDPOINTS["incident_status"].format(mock_client.organization_id, test_args["incident_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_incident_status_update_command(mock_client, test_args)

    assert requests_mock.last_request.json() == {"status": "CLOSED", "closedReason": closed_reason}
    assert results.outputs[0]["closedReason"] == closed_reason
    assert f"| {close_reason} |" in results.readable_output


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


def test_main_incident_status_update_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-incident-status-update command

    When:
    - Running the main function

    Then:
    - Validate that the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-incident-status-update")
    mocker.patch.object(
        demisto, "args", return_value={"incident_id": "INC-2026-001", "status": "Closed", "close_reason": "True Positive"}
    )
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    mock_response = util_load_json("test_data/incident_status_update_response.json")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-001')}"
    requests_mock.patch(url, json=mock_response)

    main()

    mock_return_error.assert_not_called()
    results = mock_return_results.call_args[0][0]
    assert results.outputs_prefix == "ContrastSecurity.Incident"
    assert results.outputs == [remove_empty_elements(mock_response)]


@freeze_time("2026-10-23T00:00:00Z")
@pytest.mark.parametrize(
    "expiration_date, expiration_time",
    [
        ("2099-04-08T16:47:00Z", "2099-04-08T16:47:00Z"),
        ("2099-04-08", "2099-04-08T00:00:00Z"),
        ("2 days", "2026-10-25T00:00:00Z"),
    ],
)
def test_contrast_security_ip_block_command_success(mock_client, requests_mock, expiration_date, expiration_time):
    """
    Given:
    - A valid IP address, policy name prefix and expiration date as an ISO, date-only or relative value

    When:
    - Running the !contrastsecurity-ip-block command

    Then:
    - Validate that an IP policy is created with the name "<policy_name_prefix> - <ip_address>" and expiration time
    - Validate the command results are built from the API response
    """
    from ContrastSecurity import contrast_security_ip_block_command

    mock_response = util_load_json("test_data/ip_block_response.json")
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ip_block_human_readable.md")) as f:
        ip_block_hr = f.read()

    test_args = {
        "ip_address": "192.168.1.1",
        "policy_name_prefix": "INC-2026-80",
        "expiration_date": expiration_date,
    }

    formatted_endpoint = ENDPOINTS["ip_policies"].format(mock_client.organization_id)
    requests_mock.post(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response, status_code=201)

    results = contrast_security_ip_block_command(mock_client, test_args)

    assert requests_mock.last_request.json() == {
        "ip": "192.168.1.1",
        "name": "INC-2026-80 - 192.168.1.1",
        "trusted": False,
        "environments": {"development": True, "qa": True, "production": True},
        "expirationTime": expiration_time,
    }
    assert results.readable_output == ip_block_hr
    assert results.outputs_prefix == "ContrastSecurity.IPPolicy"
    assert results.outputs_key_field == "uuid"
    assert results.outputs == [remove_empty_elements(mock_response)]
    assert results.raw_response == mock_response


def test_contrast_security_ip_block_command_when_no_policy_name_prefix_and_expiration_date(mock_client, requests_mock):
    """
    Given:
    - A valid IPv6 address without a policy name prefix and expiration date

    When:
    - Running the !contrastsecurity-ip-block command

    Then:
    - Validate that the IP policy is created with the default XSOAR prefix and without an expiration time
    - Validate that the human-readable output shows the IP address is blocked forever
    """
    from ContrastSecurity import contrast_security_ip_block_command

    mock_response = util_load_json("test_data/ip_block_permanent_response.json")
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/ip_block_permanent_human_readable.md")) as f:
        ip_block_hr = f.read()

    formatted_endpoint = ENDPOINTS["ip_policies"].format(mock_client.organization_id)
    requests_mock.post(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response, status_code=201)

    results = contrast_security_ip_block_command(mock_client, {"ip_address": "2001:db8::1"})

    assert requests_mock.last_request.json() == {
        "ip": "2001:db8::1",
        "name": "XSOAR - 2001:db8::1",
        "trusted": False,
        "environments": {"development": True, "qa": True, "production": True},
    }
    assert results.readable_output == ip_block_hr
    assert results.outputs == [remove_empty_elements(mock_response)]
    assert "expirationTime" not in results.outputs[0]


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"ip_address": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("ip_address")),
        ({"policy_name_prefix": "INC-2026-80"}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("ip_address")),
        ({"ip_address": "999.1.1.1"}, ValueError, ERROR_MESSAGES["INVALID_IP"].format("999.1.1.1", "ip_address")),
        (
            {"ip_address": "192.168.1.1", "expiration_date": "2020-01-01T00:00:00Z"},
            ValueError,
            ERROR_MESSAGES["INVALID_TIMESTAMP"].format("expiration_date", "2020-01-01T00:00:00Z"),
        ),
    ],
)
def test_contrast_security_ip_block_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input (missing or invalid ip_address, or past expiration_date)

    When:
    - Running the !contrastsecurity-ip-block command

    Then:
    - Validate that appropriate error is raised
    """
    from ContrastSecurity import contrast_security_ip_block_command

    with pytest.raises(exception) as e:
        contrast_security_ip_block_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_main_ip_block_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-ip-block command with padded arguments

    When:
    - Running the main function

    Then:
    - Validate that the trimmed arguments are sent and the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-ip-block")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "ip_address": " 192.168.1.1 ",
            "policy_name_prefix": " INC-2026-80 ",
            "expiration_date": " 2099-04-08T16:47:00Z ",
        },
    )
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    mock_response = util_load_json("test_data/ip_block_response.json")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['ip_policies'].format('test-org-id')}"
    requests_mock.post(url, json=mock_response, status_code=201)

    main()

    mock_return_error.assert_not_called()
    assert requests_mock.last_request.json() == {
        "ip": "192.168.1.1",
        "name": "INC-2026-80 - 192.168.1.1",
        "trusted": False,
        "environments": {"development": True, "qa": True, "production": True},
        "expirationTime": "2099-04-08T16:47:00Z",
    }
    results = mock_return_results.call_args[0][0]
    assert results.outputs_prefix == "ContrastSecurity.IPPolicy"
    assert results.outputs == [remove_empty_elements(mock_response)]


@pytest.mark.parametrize(
    "modes, expected_payload, get_called",
    [
        (
            {"dev_mode": "Monitor at perimeter", "qa_mode": "Off", "prod_mode": "Block at perimeter"},
            {"devMode": "MONITOR_AT_PERIMETER", "qaMode": "OFF", "prodMode": "BLOCK_AT_PERIMETER"},
            False,
        ),
        ({"qa_mode": "Block"}, {"devMode": "MONITOR", "qaMode": "BLOCK", "prodMode": "MONITOR"}, True),
    ],
)
def test_contrast_security_adr_rule_update_command_success(mock_client, requests_mock, modes, expected_payload, get_called):
    """
    Given:
    - A valid application ID and rule ID, with all or some of the mode values

    When:
    - Running the !contrastsecurity-adr-rule-update command

    Then:
    - Validate that the current modes of the rule are retrieved only when a mode is not provided
    - Validate that all three modes are sent in the request body, using the current mode for the modes not provided
    - Validate the command results are built from the API response with the application ID
    """
    mock_response = util_load_json("test_data/adr_rule_update_response.json")
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/adr_rule_update_human_readable.md")) as f:
        expected_hr = f.read()

    test_args = {
        "application_id": "12345678-1234-1234-1234-123456789012",
        "rule_id": "dummy-rule",
        **modes,
    }

    formatted_endpoint = ENDPOINTS["adr_rule"].format(
        mock_client.organization_id, "12345678-1234-1234-1234-123456789012", "dummy-rule"
    )
    get_mock = requests_mock.get(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)
    requests_mock.put(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_adr_rule_update_command(mock_client, test_args)

    assert get_mock.called == get_called
    assert requests_mock.last_request.json() == expected_payload
    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ContrastSecurity.AdrRule"
    assert results.outputs_key_field == ["applicationId", "ruleId"]
    assert results.outputs == {**mock_response, "applicationId": "12345678-1234-1234-1234-123456789012"}
    assert results.raw_response == mock_response


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"application_id": ""}, ValueError, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("application_id")),
        (
            {"application_id": "12345678-1234-1234-1234-123456789012", "rule_id": ""},
            ValueError,
            ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("rule_id"),
        ),
        (
            {"rule_id": "dummy-rule"},
            ValueError,
            ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("application_id"),
        ),
        (
            {
                "application_id": "12345678-1234-1234-1234-123456789012",
                "rule_id": "dummy-rule",
                "dev_mode": "Invalid",
            },
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Invalid", "dev_mode", RULE_MODE_HUMAN_READABLE_LIST),
        ),
        (
            {
                "application_id": "12345678-1234-1234-1234-123456789012",
                "rule_id": "dummy-rule",
                "qa_mode": "InvalidMode",
            },
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("InvalidMode", "qa_mode", RULE_MODE_HUMAN_READABLE_LIST),
        ),
        (
            {
                "application_id": "12345678-1234-1234-1234-123456789012",
                "rule_id": "dummy-rule",
                "prod_mode": "NotAMode",
            },
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("NotAMode", "prod_mode", RULE_MODE_HUMAN_READABLE_LIST),
        ),
        (
            {"application_id": "12345678-1234-1234-1234-123456789012", "rule_id": "dummy-rule"},
            ValueError,
            ERROR_MESSAGES["ADR_RULE_MODE_REQUIRED"],
        ),
    ],
)
def test_contrast_security_adr_rule_update_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid input (missing application_id/rule_id, no or invalid mode values)

    When:
    - Running the !contrastsecurity-adr-rule-update command

    Then:
    - Validate that appropriate error is raised
    """
    with pytest.raises(exception) as e:
        contrast_security_adr_rule_update_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_get_remote_data_command_open_incident_no_flags(mocker, mock_client, requests_mock):
    """
    Given: An open remote incident and both close/reopen flags disabled
    When: get_remote_data_command is called
    Then: Returns the full incident without empty values as the mirrored object, and no entries
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    expected_mirrored_object = {**SAMPLE_GET_INCIDENT_RESPONSE, "organizationUuid": "test-org-id"}
    remove_nulls_from_dictionary(expected_mirrored_object)
    assert result.mirrored_object == expected_mirrored_object
    assert result.mirrored_object["status"] == "OPEN"
    assert "closedReason" not in result.mirrored_object
    assert result.entries == []


def test_get_remote_data_command_closed_incident_no_flags(mocker, mock_client, requests_mock):
    """
    Given: A closed remote incident and both close/reopen flags disabled
    When: get_remote_data_command is called
    Then: Returns GetRemoteDataResponse with status=CLOSED and no close entry
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE_CLOSED)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert result.mirrored_object["status"] == "CLOSED"
    assert result.entries == []


@pytest.mark.parametrize(
    "closed_reason, expected_close_reason",
    [
        ("TRUE_POSITIVE", "Resolved"),
        ("TRUE_POSITIVE_BENIGN", "Resolved"),
        ("FALSE_POSITIVE", "False Positive"),
        ("OTHER", "Other"),
        (None, "Other"),
    ],
)
def test_get_remote_data_command_closes_xsoar_incident(mocker, mock_client, requests_mock, closed_reason, expected_close_reason):
    """
    Given: A closed remote incident, close_active_incident=True, and incident in processed_incidents
    When: get_remote_data_command is called
    Then: Returns a close entry with the mapped XSOAR close reason and removes the incident from processed_incidents
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": True})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json={**SAMPLE_GET_INCIDENT_RESPONSE_CLOSED, "closedReason": closed_reason})

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert len(result.entries) == 1
    assert result.entries[0]["Contents"]["dbotIncidentClose"] is True
    assert result.entries[0]["Contents"]["closeReason"] == expected_close_reason
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


def test_get_remote_data_command_incoming_direction_closes_when_not_in_processed(mocker, mock_client, requests_mock):
    """
    Given:
    - A closed remote incident, close_active_incident=True
    - The incident is NOT in processed_incidents
    - incident_mirror_direction is configured as "Incoming"

    When: get_remote_data_command is called

    Then:
    - The "Incoming" override bypasses the processed_incidents guard so the close
      entry is still produced (one-way incoming mirror has no outgoing race to dedupe)
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "reopen_closed_incident": False,
            "close_active_incident": True,
            "incident_mirror_direction": "Incoming",
        },
    )
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE_CLOSED)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert len(result.entries) == 1
    assert result.entries[0]["Contents"]["dbotIncidentClose"] is True


def test_get_remote_data_command_incoming_direction_reopens_when_already_in_processed(mocker, mock_client, requests_mock):
    """
    Given:
    - An open remote incident, reopen_closed_incident=True
    - The incident is already in processed_incidents
    - incident_mirror_direction is configured as "Incoming"

    When: get_remote_data_command is called

    Then:
    - The "Incoming" override bypasses the processed_incidents guard so the reopen
      entry is still produced (one-way incoming mirror has no outgoing race to dedupe)
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "reopen_closed_incident": True,
            "close_active_incident": False,
            "incident_mirror_direction": "Incoming",
        },
    )
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})
    mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert len(result.entries) == 1
    assert result.entries[0]["Contents"]["dbotIncidentReopen"] is True


def test_get_remote_data_command_skips_integration_context_write(mocker, mock_client, requests_mock):
    """
    Given: A valid remote incident and both close/reopen flags disabled
    When: get_remote_data_command is called
    Then: setIntegrationContext is not called, as processed_incidents is not changed
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-252"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": False})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    get_remote_data_command(mock_client, {"id": incident_id})

    mock_set_ctx.assert_not_called()


def test_get_remote_data_command_no_remote_id(mocker, mock_client):
    """
    Given: No remote incident ID in the arguments
    When: get_remote_data_command is called
    Then: Returns the not found message without calling the API
    """
    from ContrastSecurity import get_remote_data_command

    mock_get_incident = mocker.patch.object(mock_client, "get_incident")

    assert get_remote_data_command(mock_client, {}) == "Contrast Security Remote Incident was not found."
    mock_get_incident.assert_not_called()


def test_get_modified_remote_data_command_single_page(mocker, mock_client, requests_mock):
    """
    Given: A single page of modified incidents from Contrast, one of them without incidentId
    When: get_modified_remote_data_command is called with the last update time
    Then: Lists incidents modified after the last update and returns the incident IDs, skipping the missing one
    """
    from ContrastSecurity import get_modified_remote_data_command

    incident_id_1 = "INC-2026-001"
    incident_id_2 = "INC-2026-002"

    mock_response = {
        "content": [
            {"incidentId": incident_id_1, "status": "OPEN", "updatedTime": "2026-10-30T10:05:00Z"},
            {"status": "OPEN"},  # Missing incidentId
            {"incidentId": incident_id_2, "status": "CLOSED", "updatedTime": "2026-10-30T10:02:00Z"},
        ],
        "hasMore": False,
        "cursor": None,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, json=mock_response)

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2026-10-30T15:30:00.123+05:30"})

    assert result.modified_incident_ids == [incident_id_1, incident_id_2]
    query = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert query == {"modifiedAfter": ["2026-10-30T10:00:00Z"], "size": ["200"]}


def test_get_modified_remote_data_command_multiple_pages(mocker, mock_client, requests_mock):
    """
    Given: Multiple pages of modified incidents from Contrast API
    When: get_modified_remote_data_command is called
    Then: Pages through the results with the cursor until hasMore is false and returns all incident IDs
    """
    from ContrastSecurity import get_modified_remote_data_command

    incident_ids_page1 = [f"INC-2026-{i:03d}" for i in range(1, 201)]
    incident_ids_page2 = [f"INC-2026-{i:03d}" for i in range(201, 251)]

    page1_response = {"content": [{"incidentId": id} for id in incident_ids_page1], "hasMore": True, "cursor": "dummy-cursor"}
    page2_response = {"content": [{"incidentId": id} for id in incident_ids_page2], "hasMore": False, "cursor": None}

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, [{"json": page1_response, "status_code": 200}, {"json": page2_response, "status_code": 200}])

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2026-10-30T10:00:00Z"})

    assert result.modified_incident_ids == incident_ids_page1 + incident_ids_page2
    assert requests_mock.call_count == 2
    second_query = parse_qs(urlparse(requests_mock.request_history[1].url).query)
    assert second_query == {"modifiedAfter": ["2026-10-30T10:00:00Z"], "size": ["200"], "cursor": ["dummy-cursor"]}


def test_get_modified_remote_data_command_respects_mirroring_limit(mocker, mock_client, requests_mock):
    """
    Given: More modified incidents available than the mirroring limit (3 for this test)
    When: get_modified_remote_data_command is called
    Then: Stops paging once the mirroring limit is reached and returns only the first 3 incident IDs
    """
    from ContrastSecurity import get_modified_remote_data_command

    mocker.patch("ContrastSecurity.MAX_INCIDENTS_MIRRORING_LIMIT", 3)
    page1_response = {
        "content": [{"incidentId": "INC-2026-001"}, {"incidentId": "INC-2026-002"}],
        "hasMore": True,
        "cursor": "c1",
    }
    page2_response = {
        "content": [{"incidentId": "INC-2026-003"}, {"incidentId": "INC-2026-004"}],
        "hasMore": True,
        "cursor": "c2",
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, [{"json": page1_response, "status_code": 200}, {"json": page2_response, "status_code": 200}])

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2026-10-30T10:00:00Z"})

    # The third page is not listed, as 4 IDs are collected after the second page
    assert requests_mock.call_count == 2
    assert result.modified_incident_ids == ["INC-2026-001", "INC-2026-002", "INC-2026-003"]


def test_update_remote_system_command_incident_status_change_to_closed(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR incident with status DONE (maps to "closed")
    - A valid Contrast Security incident ID (INC-*) already tracked in processed_incidents
    - Close reason provided

    When:
    - update_remote_system_command is called with incident status DONE

    Then:
    - Client incident_status_update is called with "closed" status and close reason
    - The remote incident ID is returned
    - The remote incident ID is removed from processed_incidents to prevent the race
      condition where the incoming mirror would re-close it
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
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-001", "INC-2026-999"]})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-001"
    assert requests_mock.last_request.method == "PATCH"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "CLOSED"
    assert request_body["closedReason"] == "TRUE_POSITIVE"
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert "INC-2026-001" not in saved_ctx["processed_incidents"]
    assert "INC-2026-999" in saved_ctx["processed_incidents"]


def test_update_remote_system_command_incident_status_change_to_open(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR incident with status ACTIVE (maps to "open")
    - A valid Contrast Security incident ID (INC-*) not yet tracked in processed_incidents

    When:
    - update_remote_system_command is called with incident status ACTIVE

    Then:
    - Client incident_status_update is called with "open" status
    - The remote incident ID is returned
    - The remote incident ID is appended to processed_incidents to prevent the race
      condition where the incoming mirror would re-open it
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
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-002"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "OPEN"
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert "INC-2026-002" in saved_ctx["processed_incidents"]


def test_update_remote_system_command_issue_status_change_to_closed(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR issue with status DONE (maps to "closed")
    - A valid Contrast Security issue ID (ISS-*)
    - processed_incidents tracking exists for some other incident

    When:
    - update_remote_system_command is called with issue status DONE

    Then:
    - Client issue_status_update is called with "CLOSED" status
    - Payload is passed as a dict with the uppercase "status" key
    - The remote issue ID is returned
    - Issues are NOT added to or removed from processed_incidents tracking
      (only incidents participate in the race-condition guard)
    - setIntegrationContext is NOT called for issue updates, to avoid
      spurious context writes that could conflict with concurrent incident mirroring
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
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-999"]})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")
    mock_issue_status = mocker.patch.object(mock_client, "issue_status_update", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "ISS-2026-100"
    mock_issue_status.assert_called_once()
    # Verify payload is passed as a dict with the uppercase status
    call_args = mock_issue_status.call_args
    assert call_args[1]["payload"] == {"status": "CLOSED"}
    assert call_args[1]["issue_id"] == "ISS-2026-100"
    # Integration context must not be written for issue updates
    mock_set_ctx.assert_not_called()


@pytest.mark.parametrize(
    "inc_status, delta, expected_payloads",
    [
        (IncidentStatus.DONE, {"closingUserId": "admin"}, [{"status": "CLOSED"}]),
        (IncidentStatus.ACTIVE, {"closingUserId": ""}, [{"status": "OPEN"}]),
        (IncidentStatus.PENDING, {"closingUserId": ""}, []),
    ],
)
def test_update_remote_system_command_issue_status_payload(mocker, mock_client, inc_status, delta, expected_payloads):
    """
    Given:
    - An XSOAR issue being closed, reopened, or reopened with a status that has no Contrast Security mapping

    When:
    - update_remote_system_command is called

    Then:
    - Client issue_status_update is called with the matching OPEN/CLOSED payload
    - Client issue_status_update is not called when the status has no mapping
    """
    from ContrastSecurity import update_remote_system_command

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(mock_client, "issue_comment_add")
    mock_issue_status = mocker.patch.object(mock_client, "issue_status_update", return_value={})
    args = {
        "remoteId": "ISS-2026-100",
        "status": inc_status,
        "incidentChanged": True,
        "data": {"id": "xsoar_issue_001"},
        "entries": None,
        "delta": delta,
    }

    update_remote_system_command(mock_client, args)

    assert [call_args[1]["payload"] for call_args in mock_issue_status.call_args_list] == expected_payloads


def test_update_remote_system_command_issue_status_update_failure_logged(mocker, mock_client):
    """
    Given:
    - Issue status update fails with DemistoException

    When:
    - update_remote_system_command is called

    Then:
    - Error is logged via demisto.error and the remote ID is still returned
    """
    from ContrastSecurity import update_remote_system_command

    mocker.patch.object(demisto, "debug")
    mock_error = mocker.patch.object(demisto, "error")
    mocker.patch.object(mock_client, "issue_status_update", side_effect=DemistoException("403 Forbidden"))
    args = {
        "remoteId": "ISS-2026-100",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_issue_001"},
        "entries": None,
    }

    assert update_remote_system_command(mock_client, args) == "ISS-2026-100"
    mock_error.assert_called_once()
    assert "Continuing without status update" in mock_error.call_args[0][0]


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
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-004"]})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")
    mock_status_update = mocker.patch.object(mock_client, "incident_status_update", return_value={})
    mock_comment_add = mocker.patch.object(mock_client, "incident_comment_add", return_value={})

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-004"
    # Verify status update with mapped close reason
    mock_status_update.assert_called_once()
    status_payload = mock_status_update.call_args[1]["payload"]
    assert status_payload["status"] == "CLOSED"
    assert status_payload["closedReason"] == "FALSE_POSITIVE"
    # Verify closing note includes mapped reason and incident ID
    mock_comment_add.assert_called_once()
    comment_text = mock_comment_add.call_args[1]["payload"]["commentText"]
    assert "FALSE_POSITIVE" in comment_text
    assert "xsoar_incident_126" in comment_text
    assert "admin@example.com" in comment_text
    # Verify the closed incident was removed from processed_incidents
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert "INC-2026-004" not in saved_ctx["processed_incidents"]


def test_update_remote_system_command_incident_reopen(mocker, mock_client, requests_mock):
    """
    Given:
    - A Contrast Security incident that is being reopened
    - XSOAR status is ACTIVE
    - Delta contains closingUserId cleared to empty string (reopen signal)
    - Incident is not currently in processed_incidents

    When:
    - update_remote_system_command is called with reopen signal

    Then:
    - Incident status is updated to "open"
    - Remote incident ID is returned
    - The reopened incident is appended to processed_incidents to prevent the
      incoming mirror from re-reopening it
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
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": []})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-005"
    request_body = json.loads(requests_mock.last_request.text)
    assert request_body["status"] == "OPEN"
    saved_ctx = mock_set_ctx.call_args[0][0]
    assert "INC-2026-005" in saved_ctx["processed_incidents"]


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
    - Status update error (HTTP 400) is logged but doesn't block note mirroring
    - processed_incidents is not updated, as the status is not updated in Contrast Security
    - Notes are still mirrored
    - Function returns remote incident ID
    """
    from ContrastSecurity import update_remote_system_command
    from CommonServerPython import IncidentStatus

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
    mock_error = mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-008"]})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    result = update_remote_system_command(mock_client, args)

    assert result == "INC-2026-008"
    mock_error.assert_called_once()
    assert "Continuing without status update" in mock_error.call_args[0][0]
    mock_set_ctx.assert_not_called()
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.url == comment_url
    assert "Note despite status failure" in json.loads(requests_mock.last_request.text)["commentText"]


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


@pytest.mark.parametrize(
    "status, incident_changed",
    [
        (IncidentStatus.DONE, False),
        (IncidentStatus.ACTIVE, True),
    ],
)
def test_update_remote_system_command_incident_not_changed_skip_status_update(mocker, mock_client, status, incident_changed):
    """
    Given:
    - incidentChanged is False and status is DONE, or
    - status is ACTIVE with an empty delta and the incident is already in processed_incidents

    When:
    - update_remote_system_command is called

    Then:
    - Status update is not performed
    - Only notes are mirrored
    """
    from ContrastSecurity import update_remote_system_command

    args = {
        "remoteId": "INC-2026-011",
        "status": status,
        "incidentChanged": incident_changed,
        "data": {"id": "xsoar_incident_135"},
        "entries": None,
    }

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-011"]})
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
    assert request_body["status"] == "OPEN"


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
    # Verify status update with the uppercase status payload
    mock_status_update.assert_called_once()
    assert mock_status_update.call_args[1]["payload"] == {"status": "CLOSED"}
    # Verify closing note uses close reason directly (not mapped)
    mock_comment_add.assert_called_once()
    comment_text = mock_comment_add.call_args[1]["payload"]["commentText"]
    assert "Resolved" in comment_text  # Direct reason, not mapped
    assert "xsoar_issue_004" in comment_text
    assert "researcher@example.com" in comment_text


@pytest.mark.parametrize(
    "processed_incidents, is_active, expected",
    [
        (["INC-2026-001"], True, ["INC-2026-001", "INC-2026-252"]),  # add active incident
        (["INC-2026-252"], True, ["INC-2026-252"]),  # already added, no duplicate
        (["INC-2026-001", "INC-2026-252"], False, ["INC-2026-001"]),  # remove closed incident
        (["INC-2026-001"], False, ["INC-2026-001"]),  # already removed
        (["INC-2026-001", "INC-2026-002", "INC-2026-003"], True, ["INC-2026-002", "INC-2026-003", "INC-2026-252"]),  # trim
    ],
)
def test_update_processed_incidents(mocker, processed_incidents, is_active, expected):
    """
    Given:
    - An integration context with processed incidents

    When:
    - update_processed_incidents is called for an active or closed incident

    Then:
    - The incident ID is added when active and removed when closed, without duplicates
    - The list is trimmed to the mirroring limit, keeping the latest IDs
    """
    from ContrastSecurity import update_processed_incidents

    mocker.patch("ContrastSecurity.MAX_INCIDENTS_MIRRORING_LIMIT", 3)
    integration_context = {"processed_incidents": processed_incidents}

    assert update_processed_incidents(integration_context, "INC-2026-252", is_active) == expected
    assert integration_context["processed_incidents"] == expected


def test_update_integration_context_with_retries_success_after_conflict(mocker):
    """
    Given:
    - The integration context is changed by another process once, between the read and the write

    When:
    - update_integration_context_with_retries is called to add an incident ID

    Then:
    - The context is read again, the update is retried and saved with the latest version
    """
    from ContrastSecurity import update_integration_context_with_retries, update_processed_incidents

    mocker.patch(
        "ContrastSecurity.get_integration_context_with_version",
        side_effect=lambda: ({"processed_incidents": ["INC-2026-001"]}, 5),
    )
    mock_set_ctx = mocker.patch("ContrastSecurity.set_integration_context", side_effect=[ValueError("DB version mismatch"), None])
    mocker.patch("ContrastSecurity.time.sleep")

    result = update_integration_context_with_retries(update_processed_incidents, "INC-2026-252", True)

    assert result == ["INC-2026-001", "INC-2026-252"]
    assert mock_set_ctx.call_count == 2
    mock_set_ctx.assert_called_with({"processed_incidents": ["INC-2026-001", "INC-2026-252"]}, version=5)


def test_update_integration_context_with_retries_max_retries_exceeded(mocker):
    """
    Given:
    - The integration context is changed by another process on every attempt

    When:
    - update_integration_context_with_retries is called to add an incident ID

    Then:
    - DemistoException is raised after the max retry attempts
    """
    from ContrastSecurity import MAX_CONTEXT_UPDATE_RETRIES, update_integration_context_with_retries, update_processed_incidents

    mocker.patch("ContrastSecurity.get_integration_context_with_version", side_effect=lambda: ({}, 5))
    mock_set_ctx = mocker.patch("ContrastSecurity.set_integration_context", side_effect=ValueError("DB version mismatch"))
    mocker.patch("ContrastSecurity.time.sleep")

    with pytest.raises(DemistoException, match="Failed updating integration context. Max retry attempts exceeded."):
        update_integration_context_with_retries(update_processed_incidents, "INC-2026-252", True)

    assert mock_set_ctx.call_count == MAX_CONTEXT_UPDATE_RETRIES


def test_get_remote_data_command_processed_incidents_update_failure_logged(mocker, mock_client, requests_mock):
    """
    Given:
    - A closed remote incident, close_active_incident=True, and incident in processed_incidents
    - The integration context update fails after the max retry attempts

    When:
    - get_remote_data_command is called

    Then:
    - The error is logged and the close entry is still returned
    """
    from ContrastSecurity import get_remote_data_command

    incident_id = "INC-2026-327"
    mocker.patch.object(demisto, "params", return_value={"reopen_closed_incident": False, "close_active_incident": True})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})
    mocker.patch(
        "ContrastSecurity.update_integration_context_with_retries",
        side_effect=DemistoException("Failed updating integration context. Max retry attempts exceeded."),
    )
    mock_error = mocker.patch.object(demisto, "error")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', incident_id)}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE_CLOSED)

    result = get_remote_data_command(mock_client, {"id": incident_id})

    assert result.entries[0]["Contents"]["dbotIncidentClose"] is True
    assert mock_error.call_args[0][0] == (
        f"Failed to update {incident_id} in processed incidents: "
        "Failed updating integration context. Max retry attempts exceeded."
    )


def test_update_remote_system_command_processed_incidents_update_failure_logged(mocker, mock_client, requests_mock):
    """
    Given:
    - An XSOAR incident closed with a new note, and the incident in processed_incidents
    - The integration context update fails after the max retry attempts

    When:
    - update_remote_system_command is called

    Then:
    - The status is updated, the error is logged and the note is still mirrored
    """
    from ContrastSecurity import update_remote_system_command

    incident_id = "INC-2026-008"
    args = {
        "remoteId": incident_id,
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "data": {"id": "xsoar_incident_132", "closeReason": "Resolved"},
        "entries": [{"id": "entry_004", "type": "note", "contents": "Dummy note", "user": "analyst"}],
    }
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": [incident_id]})
    mocker.patch(
        "ContrastSecurity.update_integration_context_with_retries",
        side_effect=DemistoException("Failed updating integration context. Max retry attempts exceeded."),
    )
    mock_error = mocker.patch.object(demisto, "error")
    status_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', incident_id)}"
    comment_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', incident_id)}"
    requests_mock.patch(status_url, json={})
    requests_mock.post(comment_url, json={})

    assert update_remote_system_command(mock_client, args) == incident_id

    assert [request.method for request in requests_mock.request_history] == ["PATCH", "POST"]
    assert mock_error.call_args[0][0] == (
        f"Failed to update {incident_id} in processed incidents: "
        "Failed updating integration context. Max retry attempts exceeded."
    )


MIRRORING_PARAMS = {
    "server_url": DUMMAY_SERVER_URL,
    "credentials": {"identifier": "user", "password": "svc_key"},
    "api_credentials": {"password": "api_key"},
    "organization_id": "test-org-id",
    "incident_mirror_direction": "Incoming And Outgoing",
    "close_active_incident": True,
    "reopen_closed_incident": True,
}


def test_main_get_remote_data_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the get-remote-data command for an open incident

    When:
    - Running the main function

    Then:
    - Validate that the incident data is returned as the mirrored object
    """
    mocker.patch.object(demisto, "params", return_value=MIRRORING_PARAMS)
    mocker.patch.object(demisto, "command", return_value="get-remote-data")
    mocker.patch.object(demisto, "args", return_value={"id": "INC-2026-252", "lastUpdate": "2026-10-30T10:00:00Z"})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-252"]})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_get'].format('test-org-id', 'INC-2026-252')}"
    requests_mock.get(url, json=SAMPLE_GET_INCIDENT_RESPONSE)

    main()

    mock_return_error.assert_not_called()
    result = mock_return_results.call_args[0][0]
    assert result.mirrored_object["incidentId"] == "INC-2026-252"
    assert result.entries == []


def test_main_get_modified_remote_data_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the get-modified-remote-data command

    When:
    - Running the main function

    Then:
    - Validate that the modified incident IDs are returned
    """
    mocker.patch.object(demisto, "params", return_value=MIRRORING_PARAMS)
    mocker.patch.object(demisto, "command", return_value="get-modified-remote-data")
    mocker.patch.object(demisto, "args", return_value={"lastUpdate": "2026-10-30T10:00:00Z"})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incidents_list'].format('test-org-id')}"
    requests_mock.get(url, json={"content": [{"incidentId": "INC-2026-252"}], "hasMore": False, "cursor": None})

    main()

    mock_return_error.assert_not_called()
    assert mock_return_results.call_args[0][0].modified_incident_ids == ["INC-2026-252"]


def test_main_update_remote_system_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the update-remote-system command for an incident closed in XSOAR

    When:
    - Running the main function

    Then:
    - Validate that the incident is closed and the closing note is added in Contrast Security
    - Validate that the remote incident ID is returned
    """
    args = {
        "remoteId": "INC-2026-252",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "delta": {"closingUserId": "admin"},
        "data": {"id": "xsoar_incident_123", "closeReason": "Resolved", "closingUserId": "admin"},
        "entries": [],
    }
    mocker.patch.object(demisto, "params", return_value=MIRRORING_PARAMS)
    mocker.patch.object(demisto, "command", return_value="update-remote-system")
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_incidents": ["INC-2026-252"]})
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")
    status_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_status'].format('test-org-id', 'INC-2026-252')}"
    comment_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['incident_comment'].format('test-org-id', 'INC-2026-252')}"
    requests_mock.patch(status_url, json={})
    requests_mock.post(comment_url, json={})

    main()

    mock_return_error.assert_not_called()
    mock_return_results.assert_called_once_with("INC-2026-252")
    assert [request.method for request in requests_mock.request_history] == ["PATCH", "POST"]


def test_contrast_security_issue_list_command_success(mock_client, requests_mock):
    """
    Given:
    - No arguments (default page_size=50)

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate the issues and the next page cursor are set in context, and HR matches
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/issue_list_human_readable.md")) as f:
        expected_hr = f.read()

    test_args: dict = {}

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(mock_client.organization_id)}"
    requests_mock.get(url, json=ISSUE_LIST_RESPONSE)

    results = contrast_security_issue_list_command(mock_client, test_args)

    issues_context = results.outputs["ContrastSecurity.Issue(val.issueId == obj.issueId)"]
    assert requests_mock.last_request.qs == {"size": ["50"]}
    assert results.readable_output == expected_hr
    assert results.outputs == ISSUE_LIST_OUTPUTS
    assert [issue["issueId"] for issue in issues_context] == ["ISS-2026-001", "ISS-2026-002"]
    assert [issue["issueLink"] for issue in results.raw_response["content"]] == [issue["issueLink"] for issue in issues_context]
    assert [
        {k: v for k, v in issue.items() if k != "issueLink"} for issue in results.raw_response["content"]
    ] == ISSUE_LIST_RESPONSE["content"]


@pytest.mark.parametrize(
    "args, endpoint, expected_query, has_more",
    [
        # Filters, sort and cursor are sent to the issues API; more pages are available
        (
            {
                "statuses": "open,Closed",
                "severities": "high, Medium",
                "application_ids": "app-1,app-2",
                "repository_ids": "repo-1",
                "created_after": "2 days",
                "created_before": "2026-01-31",
                "modified_after": "2026-01-15T10:20:30Z",
                "modified_before": "2026-01-15T15:50:30+05:30",
                "sort_by": "updated_at",
                "sort_order": "Desc",
                "page_size": "10",
                "next_page_cursor": "test-next-page-cursor",
            },
            ENDPOINTS["issue_list"].format("test-org-id"),
            {
                "size": ["10"],
                "cursor": ["test-next-page-cursor"],
                "statuses": ["OPEN,CLOSED"],
                "severities": ["HIGH,MEDIUM"],
                "applicationIds": ["app-1,app-2"],
                "repositoryIds": ["repo-1"],
                "createdAfter": ["2026-01-08T12:00:00Z"],
                "createdBefore": ["2026-01-31T00:00:00Z"],
                "modifiedAfter": ["2026-01-15T10:20:30Z"],
                "modifiedBefore": ["2026-01-15T10:20:30Z"],
                "sort": ["updatedTime,desc"],
            },
            True,
        ),
        # The incident issues API gets only size and cursor; ignored args are not validated
        (
            {
                "incident_id": "INC-2026-001",
                "statuses": "invalid",
                "severities": "invalid",
                "created_after": "invalid",
                "sort_by": "invalid",
                "sort_order": "invalid",
                "page_size": "10",
                "next_page_cursor": "test-next-page-cursor",
            },
            ENDPOINTS["incident_issues_list"].format("test-org-id", "INC-2026-001"),
            {"size": ["10"], "cursor": ["test-next-page-cursor"]},
            False,
        ),
    ],
)
@freeze_time("2026-01-10T12:00:00Z")
def test_contrast_security_issue_list_command_with_args(mock_client, requests_mock, args, endpoint, expected_query, has_more):
    """
    Given:
    - Filter, sort and pagination arguments, with and without incident_id
    - A response with or without a next page

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate the expected endpoint is called with the expected query parameters
    - Validate the next page cursor is shown and set in context only when more pages are available
    """
    requests_mock.get(f"{DUMMAY_SERVER_URL}{endpoint}", json={**ISSUE_LIST_RESPONSE, "hasMore": has_more})
    cursor = ISSUE_LIST_RESPONSE["cursor"] if has_more else ""

    results = contrast_security_issue_list_command(mock_client, args)

    # requests_mock qs lowercases values, so parse the raw URL to check the casing sent to the API
    assert parse_qs(urlparse(requests_mock.last_request.url).query) == expected_query
    assert results.outputs["ContrastSecurity.PageToken.Issue(val.name == obj.name)"] == remove_empty_elements(
        {"next_page_cursor": cursor, "name": "contrastsecurity-issue-list", "has_next_page": has_more}
    )
    assert ("**next_page_cursor**" in results.readable_output) == has_more


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
    requests_mock.get(url, json={"content": [], "hasMore": False, "cursor": None})

    results = contrast_security_issue_list_command(mock_client, {})

    assert results.readable_output == "No issues were found for the given filters."
    assert results.outputs is None


def test_contrast_security_issue_list_command_without_application_id(mock_client, requests_mock):
    """
    Given:
    - The API returns issues without an applicationId and without an applicationName

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate no application link is built in human readable or context for either issue
    - Validate the application ID is still shown in the Application ID column
    """
    issue = {"issueId": "ISS-2026-003", "applicationName": "sample-app"}
    issue_without_name = {"issueId": "ISS-2026-004", "applicationId": "app-id-4"}
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format(mock_client.organization_id)}"
    requests_mock.get(url, json={"content": [issue, issue_without_name], "hasMore": False, "cursor": None})

    results = contrast_security_issue_list_command(mock_client, {})

    issues_context = results.outputs["ContrastSecurity.Issue(val.issueId == obj.issueId)"]
    assert "applicationLink" not in issues_context[0]
    assert "| sample-app |" in results.readable_output
    assert "applicationLink" not in issues_context[1]
    assert "| app-id-4 |" in results.readable_output
    assert "[](" not in results.readable_output


@pytest.mark.parametrize(
    "args, exception, error",
    [
        # page_size exceeds maximum
        (
            {"page_size": "201"},
            ValueError,
            ERROR_MESSAGES["INVALID_PAGE_SIZE"].format("201", MAX_ISSUE_PAGE_SIZE),
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
        # invalid statuses
        (
            {"statuses": "Open,Pending"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Pending", "statuses", STATUS_HUMAN_READABLE_LIST),
        ),
        # invalid severities
        (
            {"severities": "High,Urgent"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("Urgent", "severities", SEVERITY_HUMAN_READABLE_LIST),
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
        # invalid created_after
        (
            {"created_after": "invalid"},
            ValueError,
            'Invalid date: "created_after"="invalid"',
        ),
        # invalid modified_after
        (
            {"modified_after": "invalid"},
            ValueError,
            'Invalid date: "modified_after"="invalid"',
        ),
        # created_after is later than created_before
        (
            {"created_after": "2026-01-02T00:00:00Z", "created_before": "2026-01-01T00:00:00Z"},
            ValueError,
            ERROR_MESSAGES["INVALID_TIME_RANGE"].format("created_after", "created_before"),
        ),
        # modified_after is later than modified_before
        (
            {"modified_after": "2026-01-02T00:00:00Z", "modified_before": "2026-01-01T00:00:00Z"},
            ValueError,
            ERROR_MESSAGES["INVALID_TIME_RANGE"].format("modified_after", "modified_before"),
        ),
    ],
)
def test_contrast_security_issue_list_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid input (page_size exceeds max or is not a positive integer, invalid statuses, severities, sort_order, sort_by
      or time filters, inverted time ranges)

    When:
    - Running the !contrastsecurity-issue-list command

    Then:
    - Validate that an appropriate error is raised
    """
    with pytest.raises(exception) as e:
        contrast_security_issue_list_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_main_issue_list_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-issue-list command

    When:
    - Running the main function

    Then:
    - Validate that the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-issue-list")
    mocker.patch.object(demisto, "args", return_value={"page_size": "2"})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_list'].format('test-org-id')}"
    requests_mock.get(url, json=ISSUE_LIST_RESPONSE)

    main()

    mock_return_error.assert_not_called()
    assert requests_mock.last_request.qs == {"size": ["2"]}
    results = mock_return_results.call_args[0][0]
    assert results.outputs == ISSUE_LIST_OUTPUTS


def test_contrast_security_issue_get_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid issue ID

    When:
    - Running the !contrastsecurity-issue-get command

    Then:
    - Validate the issue with its issue link is set in context, HR matches, and the raw response is unchanged
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/issue_get_human_readable.md")) as f:
        expected_hr = f.read()

    test_args = {"issue_id": "ISS-2026-001"}

    issue_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format(mock_client.organization_id, test_args['issue_id'])}"
    requests_mock.get(issue_url, json=ISSUE_GET_RESPONSE)

    results = contrast_security_issue_get_command(mock_client, test_args)

    assert results.readable_output == expected_hr
    assert results.outputs == ISSUE_GET_OUTPUTS
    assert results.outputs_key_field == "issueId"
    assert results.raw_response == ISSUE_GET_RESPONSE


def test_contrast_security_issue_get_command_without_application_id(mock_client, requests_mock):
    """
    Given:
    - The API returns an issue without an applicationId

    When:
    - Running the !contrastsecurity-issue-get command

    Then:
    - Validate the application name is displayed without a link and no applicationLink is set in context
    """
    test_args = {"issue_id": "ISS-2026-003"}

    issue_url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format(mock_client.organization_id, test_args['issue_id'])}"
    requests_mock.get(issue_url, json={"issueId": "ISS-2026-003", "applicationName": "sample-app"})

    results = contrast_security_issue_get_command(mock_client, test_args)

    assert "applicationLink" not in results.outputs
    assert "| sample-app |" in results.readable_output


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


def test_main_issue_get_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-issue-get command

    When:
    - Running the main function

    Then:
    - Validate that the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-issue-get")
    mocker.patch.object(demisto, "args", return_value={"issue_id": "ISS-2026-001"})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_get'].format('test-org-id', 'ISS-2026-001')}"
    requests_mock.get(url, json=ISSUE_GET_RESPONSE)

    main()

    mock_return_error.assert_not_called()
    results = mock_return_results.call_args[0][0]
    assert results.outputs == ISSUE_GET_OUTPUTS


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
    assert results.outputs == [remove_empty_elements(mock_response)]


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


def test_main_issue_comment_add_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-issue-comment-add command

    When:
    - Running the main function

    Then:
    - Validate that the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-issue-comment-add")
    mocker.patch.object(demisto, "args", return_value={"issue_id": "ISS-2026-100", "comment": "this is test comment for issue"})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    mock_response = util_load_json("test_data/issue_comment_add_response.json")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_comment'].format('test-org-id', 'ISS-2026-100')}"
    requests_mock.post(url, json=mock_response, status_code=201)

    main()

    mock_return_error.assert_not_called()
    assert requests_mock.last_request.json() == {"commentText": "this is test comment for issue"}
    results = mock_return_results.call_args[0][0]
    assert results.outputs_prefix == "ContrastSecurity.IssueComment"
    assert results.outputs == [remove_empty_elements(mock_response)]


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


@pytest.mark.parametrize(
    "status, response_update, hr_file",
    [
        ("Closed", {}, "test_data/issue_status_update_closed_human_readable.md"),
        ("Open", {"status": "OPEN", "closedTime": None}, "test_data/issue_status_update_human_readable.md"),
    ],
)
def test_contrast_security_issue_status_update_command_success(mock_client, requests_mock, status, response_update, hr_file):
    """
    Given:
    - A valid issue ID and status "Closed" or "Open"

    When:
    - Running the !contrastsecurity-issue-status-update command

    Then:
    - Validate that the uppercase status is sent
    - Validate the command results are built from the API response
    """
    from ContrastSecurity import contrast_security_issue_status_update_command

    mock_response = util_load_json("test_data/issue_status_update_response.json")
    mock_response.update(response_update)
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), hr_file)) as f:
        issue_status_update_hr = f.read()

    test_args = {
        "issue_id": "ISS-2026-001",
        "status": status,
    }

    formatted_endpoint = ENDPOINTS["issue_status"].format(mock_client.organization_id, test_args["issue_id"])
    requests_mock.patch(f"{DUMMAY_SERVER_URL}{formatted_endpoint}", json=mock_response)

    results = contrast_security_issue_status_update_command(mock_client, test_args)

    assert requests_mock.last_request.json() == {"status": status.upper()}
    assert results.readable_output == issue_status_update_hr
    assert results.outputs_prefix == "ContrastSecurity.Issue"
    assert results.outputs_key_field == "issueId"
    assert results.outputs == [remove_empty_elements(mock_response)]
    assert results.raw_response == mock_response


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


def test_main_issue_status_update_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-issue-status-update command

    When:
    - Running the main function

    Then:
    - Validate that the command results are returned
    """
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-issue-status-update")
    mocker.patch.object(demisto, "args", return_value={"issue_id": "ISS-2026-001", "status": "Closed"})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    mock_response = util_load_json("test_data/issue_status_update_response.json")
    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['issue_status'].format('test-org-id', 'ISS-2026-001')}"
    requests_mock.patch(url, json=mock_response)

    main()

    mock_return_error.assert_not_called()
    results = mock_return_results.call_args[0][0]
    assert results.outputs_prefix == "ContrastSecurity.Issue"
    assert results.outputs == [remove_empty_elements(mock_response)]


@pytest.mark.parametrize(
    "observation_id, response, outputs, hr_file",
    [
        (
            "A-D-11111111-2222-3333-4444-555555555555-1234567890",
            OBSERVATION_ATTACK_RESPONSE,
            OBSERVATION_ATTACK_OUTPUTS,
            "observation_attack_human_readable.md",
        ),
        (
            "C-11111111-2222-3333-4444-555555555555",
            OBSERVATION_BEHAVIOR_RESPONSE,
            OBSERVATION_BEHAVIOR_OUTPUTS,
            "observation_behavior_human_readable.md",
        ),
        (
            "S-11111111-2222-3333-4444-555555555555",
            OBSERVATION_VULNERABILITY_RESPONSE,
            OBSERVATION_VULNERABILITY_OUTPUTS,
            "observation_vulnerability_human_readable.md",
        ),
        (
            "A-D-22222222-3333-4444-5555-666666666666-1234567890",
            OBSERVATION_ATTACK_PARTIAL_RESPONSE,
            OBSERVATION_ATTACK_PARTIAL_OUTPUTS,
            "observation_attack_partial_human_readable.md",
        ),
    ],
)
def test_contrast_security_observation_get_command_success(
    observation_id, response, outputs, hr_file, mock_client, requests_mock
):
    """
    Given:
    - A valid observation ID for an ATTACK, BEHAVIOR or VULNERABILITY type observation
    - An ATTACK observation without the UI URL, issue ID and application ID, with a query string and no request body

    When:
    - Running the !contrastsecurity-observation-get command

    Then:
    - Validate the observation with its links is set in context, HR matches, and the raw response is unchanged
    """
    with open(TEST_DATA_DIR / hr_file) as f:
        expected_hr = f.read()

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observation_get'].format(mock_client.organization_id, observation_id)}"
    requests_mock.get(url, json=response)

    results = contrast_security_observation_get_command(mock_client, {"observation_id": observation_id})

    assert results.readable_output == expected_hr
    assert results.outputs == outputs
    assert results.outputs_key_field == "observationId"
    assert results.raw_response == response


def test_main_observation_get_command_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and the contrastsecurity-observation-get command
    - The API returns an ATTACK observation without request details

    When:
    - Running the main function

    Then:
    - Validate that the command results are returned without the request details
    """
    observation_id = "A-D-11111111-2222-3333-4444-555555555555-1234567890"
    params = {
        "server_url": DUMMAY_SERVER_URL,
        "credentials": {"identifier": "user", "password": "svc_key"},
        "api_credentials": {"password": "api_key"},
        "organization_id": "test-org-id",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="contrastsecurity-observation-get")
    mocker.patch.object(demisto, "args", return_value={"observation_id": observation_id})
    mock_return_results = mocker.patch("ContrastSecurity.return_results")
    mock_return_error = mocker.patch("ContrastSecurity.return_error")

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observation_get'].format('test-org-id', observation_id)}"
    requests_mock.get(url, json={**OBSERVATION_ATTACK_RESPONSE, "request": None})

    main()

    mock_return_error.assert_not_called()
    results = mock_return_results.call_args[0][0]
    assert results.outputs_prefix == "ContrastSecurity.Observation"
    expected_outputs = OBSERVATION_ATTACK_OUTPUTS.copy()
    expected_outputs.pop("request")
    assert results.outputs == expected_outputs
    assert "Request Details" not in results.readable_output


def test_contrast_security_incident_observation_list_command_success(mock_client, requests_mock):
    """
    Given:
    - Valid incident_id and default pagination arguments

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate the observations and the page token are set in context, and HR matches
    """
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/observation_list_human_readable.md")) as f:
        expected_hr = f.read()

    test_args: dict = {"incident_id": "INC-2026-1001"}

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observations_list'].format(mock_client.organization_id, test_args['incident_id'])}"
    requests_mock.get(url, json=OBSERVATION_LIST_RESPONSE)

    results = contrast_security_incident_observation_list_command(mock_client, test_args)

    assert requests_mock.last_request.qs == {"size": ["10"]}
    assert results.readable_output == expected_hr
    assert results.outputs == OBSERVATION_LIST_OUTPUTS
    assert results.raw_response == OBSERVATION_LIST_RESPONSE


@freeze_time("2026-10-27T10:00:00Z")
@pytest.mark.parametrize(
    "created_after, created_before, expected_created_after, expected_created_before",
    [
        ("2026-10-01T00:00:00Z", "2026-10-31", "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"),
        # relative time resolves against UTC now, and an equal time range is accepted
        ("2 days", "2026-10-25T10:00:00Z", "2026-10-25T10:00:00Z", "2026-10-25T10:00:00Z"),
    ],
)
def test_contrast_security_incident_observation_list_command_with_args(
    mock_client, requests_mock, created_after, created_before, expected_created_after, expected_created_before
):
    """
    Given:
    - Pagination and time range (absolute, relative or equal) arguments are provided
    - A response with a next page

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate the API is called with the expected query parameters
    - Validate the next page cursor is set in context
    - Validate the complete human-readable output matches expected format
    """
    test_args = {
        "incident_id": "INC-2026-1001",
        "page_size": "20",
        "next_page_cursor": "test-next-page-cursor",
        "created_after": created_after,
        "created_before": created_before,
    }

    url = f"{DUMMAY_SERVER_URL}{ENDPOINTS['observations_list'].format(mock_client.organization_id, test_args['incident_id'])}"
    requests_mock.get(url, json={**OBSERVATION_LIST_RESPONSE, "hasMore": True, "cursor": "test-cursor-123"})

    results = contrast_security_incident_observation_list_command(mock_client, test_args)

    # requests_mock qs lowercases values, so parse the raw URL to check the casing sent to the API
    assert parse_qs(urlparse(requests_mock.last_request.url).query) == {
        "size": ["20"],
        "cursor": ["test-next-page-cursor"],
        "createdAfter": [expected_created_after],
        "createdBefore": [expected_created_before],
    }
    assert results.outputs == {
        **OBSERVATION_LIST_OUTPUTS,
        "ContrastSecurity.PageToken.Observation(val.name == obj.name)": {
            "next_page_cursor": "test-cursor-123",
            "name": "contrastsecurity-incident-observation-list",
            "has_next_page": True,
        },
    }

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
    requests_mock.get(url, json={"content": [], "hasMore": False, "cursor": None})

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
            {"incident_id": "INC-2026-1001", "page_size": "201"},
            ValueError,
            ERROR_MESSAGES["INVALID_PAGE_SIZE"].format("201", MAX_OBSERVATION_PAGE_SIZE),
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
        # invalid created_after
        (
            {"incident_id": "INC-2026-1001", "created_after": "not a date"},
            ValueError,
            'Invalid date: "created_after"="not a date"',
        ),
        # created_after is later than created_before
        (
            {"incident_id": "INC-2026-1001", "created_after": "2026-10-31", "created_before": "2026-10-01"},
            ValueError,
            ERROR_MESSAGES["INVALID_TIME_RANGE"].format("created_after", "created_before"),
        ),
    ],
)
def test_contrast_security_incident_observation_list_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - Invalid input (missing incident_id, page_size exceeds max or is not a positive integer, invalid dates,
      created_after later than created_before)

    When:
    - Running the !contrastsecurity-incident-observation-list command

    Then:
    - Validate that an appropriate error is raised
    """
    with pytest.raises(exception) as exception_info:
        contrast_security_incident_observation_list_command(client=mock_client, args=args)
    assert str(exception_info.value) == error
