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
    expected_outputs = [
        {"SetID": "id1", "EndpointIDs": "endpoint_id1", "RiskPlan": "risk_plan1", "Action": "add", "GroupActionPerformed": True}
    ]
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
    expected_outputs = [
        {
            "SetID": "id1",
            "EndpointIDs": "endpoint_id2,endpoint_id2",
            "RiskPlan": "risk_plan1",
            "Action": "add",
            "GroupActionPerformed": True,
        }
    ]

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
    expected_outputs = [
        {
            "SetID": "id1",
            "EndpointIDs": "endpoint_id1",
            "RiskPlan": "risk_plan1",
            "Action": "remove",
            "GroupActionPerformed": True,
        }
    ]
    assert result.outputs == expected_outputs


def test_change_risk_plan_no_endpoints_found(client, mocker):
    """Tests error when no endpoints are found."""
    from CyberArkEPMSOCResponse import change_risk_plan_command
    from CommonServerPython import DemistoException

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
    """Tests that when no endpoint group is found the command still succeeds with GroupActionPerformed=False."""
    from CyberArkEPMSOCResponse import change_risk_plan_command

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "endpoint_id1"}]},  # search_endpoints
            [],  # search_endpoint_group_id returns empty
        ],
    )

    args = {"risk_plan": "nonexistent_plan", "action": "add", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    result = change_risk_plan_command(client, args)
    expected_outputs = [
        {
            "SetID": "id1",
            "EndpointIDs": "endpoint_id1",
            "RiskPlan": "nonexistent_plan",
            "Action": "add",
            "GroupActionPerformed": False,
        }
    ]
    assert result.outputs == expected_outputs


def test_change_risk_plan_invalid_action(client, mocker):
    """Tests error when invalid action is provided."""
    from CyberArkEPMSOCResponse import change_risk_plan_command
    from CommonServerPython import DemistoException

    args = {"risk_plan": "risk_plan1", "action": "invalid_action", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    with pytest.raises(DemistoException, match=r"(?i)invalid action"):
        change_risk_plan_command(client, args)


def test_search_endpoints_without_logged_in_user(client, mocker):
    """Tests search_endpoints works without logged_in_user parameter."""
    from CyberArkEPMSOCResponse import search_endpoints

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "endpoint_id1"}]},  # search_endpoints call
        ],
    )

    result = search_endpoints("endpoint1", "", "id1", client)
    assert result == ["endpoint_id1"]


def test_change_risk_plan_endpoints_in_multiple_sets(client, mocker):
    """
    Given:
        - Endpoints matching in two different sets, each set has a matching group.

    When:
        - change_risk_plan_command function is running with action 'add'.

    Then:
        - Both sets are processed and results contain one row per set with GroupActionPerformed=True.
    """
    from CyberArkEPMSOCResponse import change_risk_plan_command

    mocker.patch(
        "CyberArkEPMSOCResponse.get_sets",
        return_value=[{"Id": "set_id1", "Name": "set1"}, {"Id": "set_id2", "Name": "set2"}],
    )

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "ep1"}]},  # search_endpoints: set_id1
            [{"id": "group_id1"}],  # search_endpoint_group_id: set_id1
            {},  # add_endpoint_to_group: set_id1
            {"endpoints": [{"id": "ep2"}]},  # search_endpoints: set_id2
            [{"id": "group_id2"}],  # search_endpoint_group_id: set_id2
            {},  # add_endpoint_to_group: set_id2
        ],
    )

    args = {"risk_plan": "risk_plan1", "action": "add", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    result = change_risk_plan_command(client, args)
    expected_outputs = [
        {"SetID": "set_id1", "EndpointIDs": "ep1", "RiskPlan": "risk_plan1", "Action": "add", "GroupActionPerformed": True},
        {"SetID": "set_id2", "EndpointIDs": "ep2", "RiskPlan": "risk_plan1", "Action": "add", "GroupActionPerformed": True},
    ]
    assert result.outputs == expected_outputs


def test_change_risk_plan_no_group_in_some_sets(client, mocker):
    """
    Given:
        - Endpoints matching in two sets, but a matching group only exists in the first set.

    When:
        - change_risk_plan_command function is running with action 'add'.

    Then:
        - First set has GroupActionPerformed=True; second set has GroupActionPerformed=False.
        - No exception is raised.
    """
    from CyberArkEPMSOCResponse import change_risk_plan_command

    mocker.patch(
        "CyberArkEPMSOCResponse.get_sets",
        return_value=[{"Id": "set_id1", "Name": "set1"}, {"Id": "set_id2", "Name": "set2"}],
    )

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"endpoints": [{"id": "ep1"}]},  # search_endpoints: set_id1
            [{"id": "group_id1"}],  # search_endpoint_group_id: set_id1 -> found
            {},  # add_endpoint_to_group: set_id1
            {"endpoints": [{"id": "ep2"}]},  # search_endpoints: set_id2
            [],  # search_endpoint_group_id: set_id2 -> not found
        ],
    )

    args = {"risk_plan": "risk_plan1", "action": "add", "endpoint_name": "endpoint1", "logged_in_user": "tester"}

    result = change_risk_plan_command(client, args)
    expected_outputs = [
        {"SetID": "set_id1", "EndpointIDs": "ep1", "RiskPlan": "risk_plan1", "Action": "add", "GroupActionPerformed": True},
        {"SetID": "set_id2", "EndpointIDs": "ep2", "RiskPlan": "risk_plan1", "Action": "add", "GroupActionPerformed": False},
    ]
    assert result.outputs == expected_outputs
