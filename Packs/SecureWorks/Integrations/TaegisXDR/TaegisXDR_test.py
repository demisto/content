import pytest

from CommonServerPython import DemistoException

from TaegisXDR import (
    Client,
    execute_playbook_command,
    fetch_alerts_command,
    fetch_incidents,
    fetch_investigation_command,
    fetch_investigation_alerts_command,
    fetch_playbook_execution_command,
    create_investigation_command,
    update_investigation_command,
)

from test_data.data import (
    TAEGIS_ENVIRONMENT,
    TAEGIS_ALERT,
    TAEGIS_INVESTIGATION,
    TAEGIS_PLAYBOOK_EXECUTION,
    TAEGIS_PLAYBOOK_EXECUTION_ID,
    TAEGIS_PLAYBOOK_INSTANCE_ID,
    EXECUTE_PLAYBOOK_RESPONSE,
    EXECUTE_PLAYBOOK_BAD_RESPONSE,
    FETCH_ALERTS_RESPONSE,
    FETCH_ALERTS_BY_ID_RESPONSE,
    FETCH_INCIDENTS_RESPONSE,
    FETCH_INCIDENTS_BAD_RESPONSE,
    FETCH_INVESTIGATION_RESPONSE,
    FETCH_INVESTIGATIONS,
    FETCH_INVESTIGATION_ALERTS_RESPONSE,
    FETCH_PLAYBOOK_EXECUTION_RESPONSE,
    FETCH_PLAYBOOK_EXECUTION_BAD_RESPONSE,
    CREATE_INVESTIGATION_RESPONSE,
    UPDATE_INVESTIGATION_RESPONSE,
)


''' UTILITY FUNCTIONS '''


def mock_client(requests_mock, mock_response):
    base_url = "https://api.ctpx.secureworks.com"

    requests_mock.post(f"{base_url}/graphql", json=mock_response)
    client = Client(
        client_id="TestID",
        client_secret="TestSecret",
        base_url=base_url,
    )
    return client


''' TESTS '''


def test_execute_playbook(requests_mock):
    """Tests taegis-execute-playbook command function
    """
    client = mock_client(requests_mock, EXECUTE_PLAYBOOK_RESPONSE)
    args = {
        "id": TAEGIS_PLAYBOOK_INSTANCE_ID,
        "inputs": {
            "MyInput": "MyValue",
        }
    }

    response = execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == TAEGIS_PLAYBOOK_EXECUTION_ID

    with pytest.raises(ValueError, match="Cannot execute playbook, missing playbook_id"):
        assert execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    client = mock_client(requests_mock, EXECUTE_PLAYBOOK_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to execute playbook: must be defined"):
        assert execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_fetch_alerts(requests_mock):
    client = mock_client(requests_mock, FETCH_ALERTS_RESPONSE)
    args = {
        "limit": 1,
        "offset": 0,
        "cql_query": "from alert severity >= 0.6 and status='OPEN'",
    }

    # Test with no IDs set
    response = fetch_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


def test_fetch_alerts_by_id(requests_mock):
    """Tests taegis-fetch-alert command function
    """
    client = mock_client(requests_mock, FETCH_ALERTS_BY_ID_RESPONSE)
    args = {
        "ids": ["c4f33b53-eaba-47ac-8272-199af0f7935b"]
    }

    # Test with IDs set
    response = fetch_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


def test_fetch_incidents(requests_mock):
    """Tests taegis-fetch-incidents command function
    """
    client = mock_client(requests_mock, FETCH_INCIDENTS_RESPONSE)
    response = fetch_incidents(client=client)
    assert response[0]['name'] == FETCH_INCIDENTS_RESPONSE["data"]["allInvestigations"][0]['description']

    with pytest.raises(ValueError, match="Max Fetch must be between 1 and 200"):
        assert fetch_incidents(client=client, max_fetch=0)

    with pytest.raises(ValueError, match="Max Fetch must be between 1 and 200"):
        assert fetch_incidents(client=client, max_fetch=201)

    # Failure from Taegis API
    client = mock_client(requests_mock, FETCH_INCIDENTS_BAD_RESPONSE)
    error = f"Error when fetching investigations: {FETCH_INCIDENTS_BAD_RESPONSE['errors'][0]['message']}"
    with pytest.raises(DemistoException, match=error):
        assert fetch_incidents(client=client, max_fetch=200)

    # Ignore incidents that have been archived
    FETCH_INCIDENTS_RESPONSE["data"]["allInvestigations"][0]["archived_at"] = "2022-02-03T13:53:35Z"
    client = mock_client(requests_mock, FETCH_INCIDENTS_RESPONSE)
    response = fetch_incidents(client=client)
    assert len(response) == 0


def test_fetch_investigaton(requests_mock):
    """Tests taegis-fetch-investigation command function

    Test fetching of a single incident
    """
    client = mock_client(requests_mock, FETCH_INVESTIGATION_RESPONSE)
    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
        "page": 0,
        "page_sie": 1,
    }

    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_INVESTIGATION

    # Investigation not found
    client = mock_client(requests_mock, {})
    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert len(response.outputs) == 0


def test_fetch_investigatons(requests_mock):
    """Tests taegis-fetch-investigations command function

    Test fetching of all incidents
    """

    client = mock_client(requests_mock, FETCH_INVESTIGATIONS)
    args = {
        "page": 0,
        "page_sie": 1,
    }

    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == [TAEGIS_INVESTIGATION]


def test_fetch_investigation_alerts(requests_mock):
    """Tests taegis-fetch-investigation-alerts command function
    """
    client = mock_client(requests_mock, FETCH_INVESTIGATION_ALERTS_RESPONSE)
    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    }

    response = fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])

    # No alerts returned
    client = mock_client(requests_mock, {})
    response = fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert len(response.outputs) == 0

    # Investigation ID not provided
    with pytest.raises(ValueError, match="Cannot fetch investigation, missing investigation_id"):
        assert fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args={})


def test_fetch_playbook_execution(requests_mock):
    """Tests taegis-fetch-playbook-execution command function
    """
    client = mock_client(requests_mock, FETCH_PLAYBOOK_EXECUTION_RESPONSE)
    args = {
        "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
    }

    response = fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == TAEGIS_PLAYBOOK_EXECUTION

    client = mock_client(requests_mock, FETCH_PLAYBOOK_EXECUTION_RESPONSE)
    with pytest.raises(ValueError, match="Cannot fetch playbook execution, missing execution id"):
        assert fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    client = mock_client(requests_mock, FETCH_PLAYBOOK_EXECUTION_BAD_RESPONSE)
    response = fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.readable_output == f"""## Results
* Could not locate execution '{args['id']}': {FETCH_PLAYBOOK_EXECUTION_BAD_RESPONSE['errors'][0]['message']}"""


def test_create_investigation(requests_mock):
    """Tests taegis-create-investigation command function
    """
    client = mock_client(requests_mock, CREATE_INVESTIGATION_RESPONSE)
    args = {
        "description": "Test Investigation",
        "priority": 3,
    }

    response = create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs["id"] == CREATE_INVESTIGATION_RESPONSE["data"]["createInvestigation"]["id"]


def test_update_investigation(requests_mock):
    """Tests taegis-update-investigation command function
    """
    client = mock_client(requests_mock, UPDATE_INVESTIGATION_RESPONSE)
    args = {
        "id": UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigation"]["id"],
        "description": "Test Investigation Updated",
        "priority": 2,
    }
    response = update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs["id"] == args["id"]

    with pytest.raises(ValueError, match="Cannot fetch investigation without investigation_id defined"):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    args["status"] = "BadStatus"
    bad_status = r"The provided status, BadStatus, is not valid for updating an investigation. Supported Status Values:.*"
    with pytest.raises(ValueError, match=bad_status):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args = {"id": UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigation"]["id"]}
    invalid_fields = r"No valid investigation fields provided. Supported Update Fields:.*"
    with pytest.raises(ValueError, match=invalid_fields):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
