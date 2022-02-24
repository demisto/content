from TaegisXDR import (
    Client,
    execute_playbook_command,
    fetch_alerts_command,
    fetch_investigation_command,
    fetch_investigation_alerts_command,
    fetch_playbook_execution_command,
    create_investigation_command,
    update_investigation_command,
)

TAEGIS_ENVIRONMENT = "us1"

TAEGIS_ALERT = {
    "id": "c4f33b53-eaba-47ac-8272-199af0f7935b",
    "description": "Test Alert",
    "message": "This is a test alert",
    "severity": 0.5,
}

TAEGIS_INVESTIGATION = {
    "description": "Test Investigation",
    "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    "key_findings": "",
    "priority": 2,
    "service_desk_id": "",
    "service_desk_type": "",
    "status": "Open"
}

TAEGIS_PLAYBOOK_EXECUTION = {
    "createdAt": "2022-02-10T13:51:24Z",
    "executionTime": 1442,
    "id": "UGxheWJvb2tFeGVjdXRpb246ZjkxNWYzMjMtZDFlNS00MWQ2LTg4NzktYzE4ZTBhMmYzZmNh",
    "inputs": {
        "PagerDuty": {
            "dedup_key": "25f16f6c-dbc1-4efe-85a7-385e73f94efc"
        },
        "alert": {
            "description": "Please, verify the login was authorized.",
            "message": "Test Alert: Successful Login for User",
            "severity": 0.9,
            "uuid": "25f16f6c-dbc1-4efe-85a7-385e73f94efc"
        },
        "event": "create"
    },
    "instance": {
        "name": "My Playbook Instance",
        "playbook": {
            "name": "My Playbook Name"
        }
    },
    "outputs": "25f16f6c-dbc1-4efe-85a7-385e73f94efc",
    "state": "Completed",
    "updatedAt": "2022-02-10T13:51:31Z"
}

TAEGIS_PLAYBOOK_EXECUTION_ID = "UGxheWJvb2tFeGVjdXRpb246M2NiM2FmYWItYTZiNy00ZWNmLTk1NDUtY2JlNjg1OTdhODY1"

TAEGIS_PLAYBOOK_INSTANCE_ID = "UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg="


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

    mock_response = {
        "data": {
            "executePlaybookInstance": {
                "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
            }
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "id": TAEGIS_PLAYBOOK_INSTANCE_ID,
        "inputs": {
            "MyInput": "MyValue",
        }
    }
    response = execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs["id"] == TAEGIS_PLAYBOOK_EXECUTION_ID


def test_fetch_alerts(requests_mock):
    """Tests taegis-fetch-alert command function
    """

    mock_response = {
        "data": {
            "alerts": [TAEGIS_ALERT]
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "ids": ["c4f33b53-eaba-47ac-8272-199af0f7935b"]
    }

    response = fetch_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


def test_fetch_investigaton(requests_mock):
    """Tests taegis-fetch-investigation command function

    Test fetching of a single incident
    """

    mock_response = {
        "data": {
            "investigation": TAEGIS_INVESTIGATION
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
        "page": 0,
        "page_sie": 1,
    }

    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs[0] == TAEGIS_INVESTIGATION


def test_fetch_investigatons(requests_mock):
    """Tests taegis-fetch-investigations command function

    Test fetching of all incidents
    """

    mock_response = {
        "data": {
            "allInvestigations": [TAEGIS_INVESTIGATION]
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "page": 0,
        "page_sie": 1,
    }

    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs == [TAEGIS_INVESTIGATION]


def test_fetch_investigation_alerts(requests_mock):
    """Tests taegis-fetch-investigation-alerts command function
    """

    mock_response = {
        "data": {
            "investigationAlerts": {
                "alerts": [TAEGIS_ALERT]
            }
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    }

    response = fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


def test_fetch_playbook_execution(requests_mock):
    """Tests taegis-fetch-playbook-execution command function

    Test fetching a playbook's execution
    """

    mock_response = {
        "data": {
            "playbookExecution": TAEGIS_PLAYBOOK_EXECUTION
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
    }

    response = fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs == TAEGIS_PLAYBOOK_EXECUTION


def test_create_investigation(requests_mock):
    """Tests taegis-create-investigation command function
    """

    mock_response = {
        "data": {
            "createInvestigation": {
                "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
            }
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "description": "Test Investigation",
        "priority": 3,
    }

    response = create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs["id"] == mock_response["data"]["createInvestigation"]["id"]


def test_update_investigation(requests_mock):
    """Tests taegis-update-investigation command function
    """

    mock_response = {
        "data": {
            "updateInvestigation": {
                "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
            }
        }
    }

    client = mock_client(requests_mock, mock_response)

    args = {
        "id": mock_response["data"]["updateInvestigation"]["id"],
        "description": "Test Investigation Updated",
        "priority": 2,
    }

    response = update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs["id"] == args["id"]
