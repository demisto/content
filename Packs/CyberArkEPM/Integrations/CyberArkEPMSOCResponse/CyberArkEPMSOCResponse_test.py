import pytest
from CyberArkEPMSOCResponse import Client


@pytest.fixture()
def client(mocker):
    """Returns a mocked Client instance for testing.

    This fixture provides a default client that can be used by any test.
    The client is mocked to prevent actual HTTP requests.
    """
    client_instance = Client(
        base_tenant_url="https://base-tenant.cyberark.cloud",
        identity_url="https://identity.cyberark.cloud/OAuth2/Token/test-web-app-id",
        client_id="test-client-id",
        client_secret="test-client-secret",
        web_app_id="test-web-app-id",
        verify=True,
        proxy=False,
    )

    # Mock the methods that make HTTP requests to prevent actual network calls
    mocker.patch.object(client_instance, "_get_access_token", return_value="mock_access_token")
    mocker.patch.object(client_instance, "_get_tenant_url", return_value="https://mock-tenant.cyberark.cloud")
    mocker.patch("CyberArkEPMSOCResponse.get_sets", return_value=[{"Id": "id1", "Name": "set_name1"}])

    return client_instance


def test_activate_risk_plan_command(client, mocker):
    """
    Given:
        - A CyberArkEPMSOCResponse client, a risk plan, an endpoint name, and a logged-in user.

    When:
        - activate_risk_plan_command function is running.

    Then:
        - Validates that the function works as expected.
    """
    from CyberArkEPMSOCResponse import change_risk_plan_command

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context", return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}}
    )

    mock_response_search_endpoints = {
        "endpoints": [
            {"id": "endpoint_id1", "logged_in_user": "tester", "connectionStatus": "Connected"},
        ]
    }

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            mock_response_search_endpoints,  # search_endpoints call
            [{"id": "group_id1"}],  # search_endpoint_group_id call
            {},  # add_endpoint_to_group call
        ],
    )

    args = {"risk_plan": "risk_plan1", "action": "add", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    result = change_risk_plan_command(client, args)
    expected_outputs = {"EndpointIDs": "endpoint_id1", "RiskPlan": "risk_plan1", "Action": "add"}
    assert result.outputs == expected_outputs


def test_activate_multiple_endpoint_risk_plan_command(client, mocker):
    """
    Given:
        - A CyberArkEPMSOCResponse client, a risk plan, an endpoint name, and a logged-in user.

    When:
        - activate_risk_plan_command function is running.

    Then:
        - Validates that the function works as expected.
    """
    from CyberArkEPMSOCResponse import change_risk_plan_command

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context", return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}}
    )

    mock_response_search_endpoints = {
        "endpoints": [
            {"id": "endpoint_id2", "logged_in_user": "tester2", "connectionStatus": "Connected"},
            {"id": "endpoint_id2", "logged_in_user": "tester2", "connectionStatus": "Disconnected"},
        ]
    }

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            mock_response_search_endpoints,  # search_endpoints call
            [{"id": "group_id1"}],  # search_endpoint_group_id call
            {},  # add_endpoint_to_group call
        ],
    )

    args = {
        "risk_plan": "risk_plan1",
        "action": "add",
        "endpoint_name": "endpoint2",
        "logged_in_user": "tester2",
    }

    result = change_risk_plan_command(client, args)
    expected_outputs = {"EndpointIDs": "endpoint_id2,endpoint_id2", "RiskPlan": "risk_plan1", "Action": "add"}

    assert result.outputs == expected_outputs


def test_deactivate_risk_plan_command(client, mocker):
    """
    Given:
        - A CyberArkEPMSOCResponse client, a risk plan, an endpoint name, and an external IP.

    When:
        - activate_risk_plan_command function is running.

    Then:
        - Validates that the function works as expected.
    """
    from CyberArkEPMSOCResponse import change_risk_plan_command

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context", return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}}
    )

    mock_response_search_endpoints = {
        "endpoints": [
            {"id": "endpoint_id1", "logged_in_user": "tester", "connectionStatus": "Connected"},
        ]
    }

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            mock_response_search_endpoints,  # search_endpoints call
            [{"id": "group_id1"}],  # search_endpoint_group_id call
            {},  # remove_endpoint_from_group call
        ],
    )

    args = {"risk_plan": "risk_plan1", "action": "remove", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    result = change_risk_plan_command(client, args)
    expected_outputs = {"EndpointIDs": "endpoint_id1", "RiskPlan": "risk_plan1", "Action": "remove"}
    assert result.outputs == expected_outputs


def test_change_risk_plan_no_endpoints_found(client, mocker):
    """Tests error when no endpoints are found."""
    from CyberArkEPMSOCResponse import change_risk_plan_command
    from CommonServerPython import DemistoException

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context",
        return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}},
    )

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": []},  # search_endpoints call
        ],
    )

    args = {"risk_plan": "risk_plan1", "action": "add", "endpoint_name": "nonexistent", "logged_in_user": "tester9"}

    with pytest.raises(DemistoException, match=r"(?i)no endpoints found"):
        change_risk_plan_command(client, args)


def test_change_risk_plan_no_group_found(client, mocker):
    """Tests error when no endpoint group is found."""
    from CyberArkEPMSOCResponse import change_risk_plan_command
    from CommonServerPython import DemistoException

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context",
        return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}},
    )

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "endpoint_id1"}]},  # search_endpoints
            [],  # search_endpoint_group_id returns empty
        ],
    )

    args = {"risk_plan": "nonexistent_plan", "action": "add", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    with pytest.raises(DemistoException, match=r"(?i)no endpoint group found"):
        change_risk_plan_command(client, args)


def test_change_risk_plan_invalid_action(client, mocker):
    """Tests error when invalid action is provided."""
    from CyberArkEPMSOCResponse import change_risk_plan_command
    from CommonServerPython import DemistoException

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context",
        return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}},
    )

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "endpoint_id1"}]},
            [{"id": "group_id1"}],
        ],
    )

    args = {"risk_plan": "risk_plan1", "action": "invalid_action", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    with pytest.raises(DemistoException, match=r"(?i)invalid action"):
        change_risk_plan_command(client, args)


def test_search_endpoints_without_logged_in_user(client, mocker):
    """Tests search_endpoints works without logged_in_user parameter."""
    from CyberArkEPMSOCResponse import search_endpoints

    mocker.patch(
        "CyberArkEPMSOCResponse.get_integration_context",
        return_value={"CyberArkEPMSOCResponse_Context": {"set_id": "id1"}},
    )

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "endpoint_id1"}]},  # search_endpoints call
        ],
    )

    result = search_endpoints("endpoint1", "", client)
    assert result == ["endpoint_id1"]
