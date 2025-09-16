
def mocked_client(requests_mock):
    from CyberArkEPMARR import Client

    mock_response_sets = {"Sets": [{"Id": "id1", "Name": "set_name1"}]}
    mock_response_search_endpoints = {"endpoints": [{"id": "endpoint_id1"}]}
    mock_response_search_endpoint_group_id = [{"id": "group_id1"}]

    requests_mock.post("https://url.com/EPM/API/Auth/EPM/Logon", json={"ManagerURL": "https://mock.com", "EPMAuthenticationResult": "123"})
    requests_mock.get("https://mock.com/EPM/API/Sets", json=mock_response_sets)
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Search", json=mock_response_search_endpoints)
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Groups/Search", json=mock_response_search_endpoint_group_id)
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Groups/group_id1/Members/ids", json={})
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Endpoints/Groups/group_id1/Members/ids/remove", json={})

    return Client("https://url.com", "test", "123456", "1")


def test_activate_risk_plan_command(requests_mock, mocker):
    """
    Given:
        - A CyberArkEPMARR client, a risk plan, an endpoint name, and an external IP.

    When:
        - activate_risk_plan_command function is running.

    Then:
        - Validates that the function works as expected.
    """
    from CyberArkEPMARR import change_risk_plan_command

    mocker.patch("CyberArkEPMARR.get_integration_context", return_value={"CyberArkEPMARR_Context": {"set_id": "id1"}})
    client = mocked_client(requests_mock)
    args = {
        "risk_plan": "risk_plan1",
        "action": "add",
        "endpoint_name": "endpoint1",
        "external_ip": "1.1.1.1"
    }

    result = change_risk_plan_command(client, args)
    print(result)

    assert result.readable_output == "### Risk Plan changed successfully\n|Endpoint IDs|Risk Plan|Action|\n|---|---|---|\n| endpoint_id1 | risk_plan1 | add |\n"

def test_deactivate_risk_plan_command(requests_mock, mocker):
    """
        Given:
            - A CyberArkEPMARR client, a risk plan, an endpoint name, and an external IP.

        When:
            - activate_risk_plan_command function is running.

        Then:
            - Validates that the function works as expected.
        """
    from CyberArkEPMARR import change_risk_plan_command

    mocker.patch("CyberArkEPMARR.get_integration_context", return_value={"CyberArkEPMARR_Context": {"set_id": "id1"}})
    client = mocked_client(requests_mock)
    args = {
        "risk_plan": "risk_plan1",
        "action": "remove",
        "endpoint_name": "endpoint1",
        "external_ip": "1.1.1.1"
    }

    result = change_risk_plan_command(client, args)
    print(result)

    assert result.readable_output == "### Risk Plan changed successfully\n|Endpoint IDs|Risk Plan|Action|\n|---|---|---|\n| endpoint_id1 | risk_plan1 | remove |\n"

