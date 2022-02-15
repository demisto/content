from TaegisXDR import (
    Client,
    fetch_alerts_command,
    fetch_investigation_command,
    fetch_investigation_alerts_command,
    create_investigation_command,
    update_investigation_command,
)

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

    response = fetch_alerts_command(client, args)

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

    response = fetch_investigation_command(client, args)

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

    response = fetch_investigation_command(client, args)

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

    response = fetch_investigation_alerts_command(client, args)

    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


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

    response = create_investigation_command(client, args)

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

    response = update_investigation_command(client, args)

    assert response.outputs["id"] == args["id"]
