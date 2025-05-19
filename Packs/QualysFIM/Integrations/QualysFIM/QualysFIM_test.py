import json
from urllib.parse import urljoin
import pytest
from QualysFIM import Client

BASE_URL = "https://gateway.qg2.apps.qualys.eu/"
USERNAME = "Foo"
PASSWORD = "Bar"


def util_load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as file:
        return json.loads(file.read())


@pytest.fixture
def authenticated_client(requests_mock) -> Client:
    """Fixture to create a QualysFIM.Client instance."""
    auth_url = urljoin(BASE_URL, "/auth")
    requests_mock.post(auth_url, json={})
    return Client(base_url=BASE_URL, verify=False, proxy=False, auth=(USERNAME, PASSWORD))


def test_get_token_and_set_headers(mocker, authenticated_client: Client) -> None:
    """
    Given:
        - QualysFIM.Client and access credentials

    When:
        - Client.get_token_and_set_headers is called

    Assert:
        - Correct authentication request URL and JSON body
    """
    # Set
    auth_request = mocker.patch.object(Client, "_http_request")

    # Arrange
    authenticated_client.get_token_and_set_headers((USERNAME, PASSWORD))
    auth_request_kwargs: dict = auth_request.call_args.kwargs

    # Assert
    assert auth_request.call_count == 1
    assert auth_request_kwargs["url_suffix"] == "/auth"
    assert auth_request_kwargs["data"] == {"username": USERNAME, "password": PASSWORD, "token": True}


def test_list_events_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: List events.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_events_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import list_events_command

    # Set
    mock_response = util_load_json("test_data/list_events.json")
    requests_mock.post(f"{BASE_URL}fim/v2/events/search", json=mock_response)

    # Arrange
    result = list_events_command(authenticated_client, {"sort": "most_recent"})

    # Assert
    assert result.outputs_prefix == "QualysFIM.Event"
    assert result.outputs_key_field == "id"

    assert result.raw_response == mock_response
    assert result.outputs == [incident["data"] for incident in mock_response]


def test_get_event_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: List events.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - get_event_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import get_event_command

    # Set
    mock_response = util_load_json("test_data/get_event.json")
    requests_mock.get(f"{BASE_URL}fim/v2/events/123456", json=mock_response)

    # Arrange
    result = get_event_command(authenticated_client, {"event_id": "123456"})

    # Assert
    assert result.outputs_prefix == "QualysFIM.Event"
    assert result.outputs_key_field == "id"

    assert result.raw_response == mock_response
    assert result.outputs == mock_response


def test_list_incidents_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: List incidents
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_incidents_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import list_incidents_command

    # Set
    mock_response = util_load_json("test_data/list_incidents.json")
    requests_mock.post(f"{BASE_URL}fim/v3/incidents/search", json=mock_response)

    # Arrange
    result = list_incidents_command(authenticated_client, {"sort": "most_recent"})

    # Assert
    assert result.outputs_prefix == "QualysFIM.Incident"
    assert result.outputs_key_field == "id"

    assert len(result.raw_response) == len(mock_response)
    assert result.raw_response == mock_response

    assert result.outputs[0]["id"] == mock_response[0]["data"]["id"]
    assert result.outputs[1]["id"] == mock_response[1]["data"]["id"]
    assert result.outputs == [incident["data"] for incident in mock_response]


def test_get_incident_events_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: List incident's events
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_incidents_events_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import list_incident_events_command

    # Set
    limit = 10
    mock_response = util_load_json("test_data/get_incident_events.json")
    requests_mock.post(f"{BASE_URL}fim/v2/incidents/None/events/search", json=mock_response)

    # Arrange
    result = list_incident_events_command(authenticated_client, {"limit": str(limit)})

    # Assert
    assert result.outputs_prefix == "QualysFIM.Event"
    assert result.outputs_key_field == "id"

    assert len(result.raw_response) == limit
    assert result.raw_response == mock_response
    assert result.outputs == [event["data"] for event in mock_response]


def test_create_incident_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: Create Incident.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - create_incident_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import create_incident_command

    # Set
    create_incident_mock_response = util_load_json("test_data/create_incident.json")
    requests_mock.post(f"{BASE_URL}fim/v3/incidents/create", json=create_incident_mock_response)
    search_incidents_mock_response = util_load_json("test_data/list_incidents.json")
    requests_mock.post(f"{BASE_URL}fim/v3/incidents/search", json=search_incidents_mock_response)
    first_search_result = search_incidents_mock_response[0]["data"]

    # Arrange
    result = create_incident_command(authenticated_client, {"name": "test"})

    # Assert
    assert result.outputs_prefix == "QualysFIM.Incident"
    assert result.outputs_key_field == "id"

    assert result.raw_response == first_search_result
    assert result.outputs == first_search_result


def test_approve_incident_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: Approve Incident.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - approve_incident_command is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import approve_incident_command

    # Set
    mock_response = util_load_json("test_data/approve_incident.json")
    requests_mock.post(f"{BASE_URL}fim/v3/incidents/None/approve", json=mock_response)
    args = {"approval_status": "test", "change_type": "test", "comment": "test", "disposition_category": "test"}

    # Arrange
    result = approve_incident_command(authenticated_client, args)

    # Assert
    assert result.outputs_prefix == "QualysFIM.Incident"
    assert result.outputs_key_field == "id"
    assert result.raw_response == mock_response
    assert result.outputs == mock_response


def test_list_assets_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: List Assets.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - list_assets_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure outputs key fields is correct.
    """
    from QualysFIM import list_assets_command

    mock_response = util_load_json("test_data/list_assets.json")
    requests_mock.post(f"{BASE_URL}fim/v3/assets/search", json=mock_response)

    result = list_assets_command(authenticated_client, {})

    assert result.outputs_prefix == "QualysFIM.Asset"
    assert result.outputs_key_field == "id"

    assert len(result.outputs) == 2
    assert result.raw_response == mock_response


def test_fetch_incidents_command(requests_mock, authenticated_client: Client) -> None:
    """
    Scenario: Fetch Incidents.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - fetch_incidents is called.
    Then:
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure occurred time is correct.
    """
    from QualysFIM import fetch_incidents

    mock_response = util_load_json("test_data/fetch_incidents.json")
    requests_mock.post(f"{BASE_URL}fim/v3/incidents/search", json=mock_response)

    _, incidents = fetch_incidents(
        client=authenticated_client, last_run={}, fetch_filter="", first_fetch_time="3 days", max_fetch="2"
    )
    raw_json = json.loads(incidents[0]["rawJSON"])

    assert raw_json["id"] == "75539bfc-c0e7-4bcb-b55a-48065ef89ebe"
    assert raw_json["createdBy"]["date"] == 1613378492427


def test_create_event_or_incident_output() -> None:
    """
    Given:
        - A list of table headers and a QualysFIM API event
    When:
        - create_event_or_incident_output is called
    Then:
        - Assert correct output dictionary and no empty values
    """
    from QualysFIM import create_event_or_incident_output

    # Set
    table_headers = ["id", "severity", "dateTime", "agentId", "fullPath"]
    raw_event: dict = util_load_json("test_data/get_event.json")

    # Arrange
    event_output = create_event_or_incident_output(raw_event, table_headers)

    # Assert
    assert "customerId" not in event_output
    assert event_output == {
        "id": raw_event["id"],
        "severity": raw_event["severity"],
        "dateTime": raw_event["dateTime"],
        "agentId": raw_event["asset"]["agentId"],
        "fullPath": raw_event["fullPath"],
    }
    # function calls remove_empty_elements
    assert all(value not in ({}, []) for value in event_output.values()), "One or more event values are empty"
