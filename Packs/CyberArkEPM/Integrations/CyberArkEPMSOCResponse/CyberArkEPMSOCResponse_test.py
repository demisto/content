def mocked_client(requests_mock, mock_response_search_endpoints=None):
    from CyberArkEPMSOCResponse import Client

    mock_response_sets = {"Sets": [{"Id": "id1", "Name": "set_name1"}]}

    if not mock_response_search_endpoints:
        mock_response_search_endpoints = {
            "endpoints": [
                {"id": "endpoint_id1", "external_ip": "1.1.1.1", "connectionStatus": "Connected"},
            ]
        }
    mock_response_search_endpoint_group_id = [{"id": "group_id1"}]

    requests_mock.post(
        "https://url.com/EPM/API/Auth/EPM/Logon", json={"ManagerURL": "https://mock.com", "EPMAuthenticationResult": "123"}
    )
    requests_mock.get("https://mock.com/EPM/API/Sets", json=mock_response_sets)
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Search", json=mock_response_search_endpoints)
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Groups/Search", json=mock_response_search_endpoint_group_id)
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Groups/group_id1/Members/ids", json={})
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Groups/group_id1/Members/ids/remove", json={})

    return Client("https://url.com", "test", "123456", "1", "set_name")


def test_activate_risk_plan_command(requests_mock, mocker):
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
            {"id": "endpoint_id1", "external_ip": "1.1.1.1", "connectionStatus": "Connected"},
        ]
    }

    client = mocked_client(requests_mock, mock_response_search_endpoints)
    args = {"risk_plan": "risk_plan1", "action": "add", "endpoint_name": "endpoint1", "external_ip": "1.1.1.1"}

    result = change_risk_plan_command(client, args)
    expected_outputs = {"Endpoint_IDs": "endpoint_id1", "Risk_Plan": "risk_plan1", "Action": "add"}
    assert result.outputs == expected_outputs


def test_activate_multiple_endpoint_risk_plan_command(requests_mock, mocker):
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
            {"id": "endpoint_id2", "external_ip": "2.2.2.2", "connectionStatus": "Connected"},
            {"id": "endpoint_id2", "external_ip": "2.2.2.2", "connectionStatus": "Disconnected"},
        ]
    }

    client = mocked_client(requests_mock, mock_response_search_endpoints)
    args = {
        "risk_plan": "risk_plan1",
        "action": "add",
        "endpoint_name": "endpoint2",
        "external_ip": "2.2.2.2",
    }

    result = change_risk_plan_command(client, args)
    expected_outputs = {"Endpoint_IDs": "endpoint_id2,endpoint_id2", "Risk_Plan": "risk_plan1", "Action": "add"}

    assert result.outputs == expected_outputs


def test_deactivate_risk_plan_command(requests_mock, mocker):
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
    client = mocked_client(requests_mock)
    args = {"risk_plan": "risk_plan1", "action": "remove", "endpoint_name": "endpoint1", "external_ip": "1.1.1.1"}

    result = change_risk_plan_command(client, args)
    expected_outputs = {"Endpoint_IDs": "endpoint_id1", "Risk_Plan": "risk_plan1", "Action": "remove"}
    assert result.outputs == expected_outputs
