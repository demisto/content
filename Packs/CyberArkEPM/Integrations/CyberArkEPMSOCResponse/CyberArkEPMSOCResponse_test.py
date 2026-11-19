import pytest
from CommonServerPython import DemistoException
from CyberArkEPMSOCResponse import Client, build_adoption_event, get_adoption_url


@pytest.fixture(autouse=True)
def _block_network(mocker):
    """Fail any test that would send a real HTTP request (e.g. a real Feature Adoption event).

    Every test must mock ``Client._http_request`` (or a higher-level method). Anything that reaches
    the underlying ``requests`` session is blocked, and the teardown assertion fails the test even if
    production code swallowed the raised error (``report_adoption_event`` catches all exceptions).
    """
    session_request = mocker.patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("Unmocked network call attempted in a unit test"),
    )
    yield session_request
    assert session_request.call_count == 0, f"Unmocked network call(s) attempted: {session_request.call_args_list}"


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


def test_build_adoption_event():
    """The event matches the Feature Adoption authenticated-user schema (no user_id)."""
    event = build_adoption_event()
    assert event == {
        "metric_key": "IDIINT.cortex_epm_soc_response.integration_executed",
        "number_of_events": 1,
        "triggered_by": "BE",
        "tags": {
            "vendor_name": "Palo Alto Networks",
            "integration_version": "1.0",
            "idira_service": "Idira EPM",
        },
    }
    assert "user_id" not in event


@pytest.mark.parametrize(
    "identity_url, expect_url",
    [
        ("https://abc1234.id.cyberark.cloud", True),
        ("https://abc1234.id.integration-cyberark.cloud/", True),
        ("https://custom-vanity-host.example.com", False),
        ("identity_url", False),
        ("", False),
        (None, False),
    ],
)
def test_get_adoption_url(identity_url, expect_url):
    """The root domain comes from the <tenant>.id.<root domain> host; anything else yields no URL."""
    url = get_adoption_url(identity_url)
    assert bool(url) is expect_url
    if expect_url:
        assert url.endswith("/api/feature-adoption")
        assert "abc1234" not in url


def test_report_adoption_event_uses_platform_token_not_epm_token(mocker):
    """The event is POSTed once with the bearer token; the tenant sub-domain is not part of the target host."""
    adoption_client = Client(
        base_tenant_url="https://base-tenant.cyberark.cloud",
        identity_url="https://abc1234.id.cyberark.cloud",
        client_id="id",
        client_secret="secret",
        web_app_id="app",
    )
    epm_token = mocker.patch.object(adoption_client, "_get_access_token", return_value="epm_web_app_token")
    http = mocker.patch.object(
        Client,
        "_http_request",
        side_effect=[{"access_token": "platform_token"}, mocker.Mock(status_code=202)],
    )
    adoption_client.report_adoption_event()

    assert http.call_count == 2
    token_call, event_call = http.call_args_list
    assert token_call.kwargs["full_url"] == "https://abc1234.id.cyberark.cloud/oauth2/platformtoken"
    assert token_call.kwargs["data"]["grant_type"] == "client_credentials"
    assert event_call.kwargs["method"] == "POST"
    assert event_call.kwargs["json_data"] == build_adoption_event()
    assert event_call.kwargs["full_url"] == get_adoption_url("https://abc1234.id.cyberark.cloud")
    # The adoption service rejects the EPM web-app token: it must get the platform token.
    assert event_call.kwargs["headers"]["Authorization"] == "Bearer platform_token"
    epm_token.assert_not_called()


def test_report_adoption_event_swallows_errors(client, mocker):
    client.identity_url = "https://abc1234.id.cyberark.cloud"
    mocker.patch.object(Client, "_http_request", side_effect=DemistoException("400 invalid metric"))
    client.report_adoption_event()  # must not raise


def test_report_adoption_event_skipped_without_derivable_url(client, mocker):
    """The fixture's identity URL has no '.id.' host, so nothing is sent."""
    http = mocker.patch.object(Client, "_http_request")
    client.report_adoption_event()
    http.assert_not_called()


def test_http_request_does_not_send_telemetry_header(client, mocker):
    """Regular API calls no longer carry the legacy x-cybr-telemetry header."""

    class _Resp:
        status_code = 200
        headers: dict = {}
        text = "{}"

        def json(self):
            return {}

    http = mocker.patch.object(Client, "_http_request", return_value=_Resp())
    client.http_request("GET", "Sets")
    headers = http.call_args.kwargs["headers"]
    assert "x-cybr-telemetry" not in headers
    assert headers["authorization"] == "Bearer mock_access_token"


@pytest.mark.parametrize("command", ["cyberarkepm-activate-risk-plan", "test-module"])
def test_main_reports_adoption_only_for_successful_real_commands(command, mocker):
    """main() reports after a successful action command and never for test-module."""
    import CyberArkEPMSOCResponse as module

    params = {
        "url": "https://base-tenant.cyberark.cloud",
        "identity_url": "https://abc1234.id.cyberark.cloud",
        "web_app_id": "app",
        "client_id": "id",
        "credentials": {"password": "secret"},
    }
    args = {"risk_plan": "plan", "endpoint_name": "endpoint1"}
    mocker.patch.object(module.demisto, "params", return_value=params)
    mocker.patch.object(module.demisto, "args", return_value=args)
    mocker.patch.object(module.demisto, "command", return_value=command)
    mocker.patch.object(module, "change_risk_plan_command", return_value="result")
    mocker.patch.object(module, "test_module", return_value="ok")
    mocker.patch.object(module, "return_results")
    report = mocker.patch.object(Client, "report_adoption_event")
    module.main()
    assert report.call_count == (0 if command == "test-module" else 1)


def test_main_does_not_report_adoption_when_command_fails(mocker):
    import CyberArkEPMSOCResponse as module

    params = {
        "url": "https://base-tenant.cyberark.cloud",
        "identity_url": "https://abc1234.id.cyberark.cloud",
        "web_app_id": "app",
        "client_id": "id",
        "credentials": {"password": "secret"},
    }
    mocker.patch.object(module.demisto, "params", return_value=params)
    mocker.patch.object(module.demisto, "args", return_value={})
    mocker.patch.object(module.demisto, "command", return_value="cyberarkepm-activate-risk-plan")
    mocker.patch.object(module, "change_risk_plan_command", side_effect=DemistoException("boom"))
    mocker.patch.object(module, "return_error")
    report = mocker.patch.object(Client, "report_adoption_event")
    module.main()
    report.assert_not_called()


def test_report_adoption_event_swallows_platform_token_errors(client, mocker):
    """A failing platform-token request must not break the command either."""
    client.identity_url = "https://abc1234.id.cyberark.cloud"
    http = mocker.patch.object(Client, "_http_request", side_effect=DemistoException("401 Unauthorized"))
    client.report_adoption_event()  # must not raise
    assert http.call_count == 1  # the event POST is never attempted without a token


def test_report_adoption_event_skipped_when_usage_reporting_disabled(mocker):
    """With the opt-out checked, nothing is sent: no platform token request and no event POST."""
    opted_out_client = Client(
        base_tenant_url="https://base-tenant.cyberark.cloud",
        identity_url="https://abc1234.id.cyberark.cloud",
        client_id="id",
        client_secret="secret",
        web_app_id="app",
        usage_reporting_enabled=False,
    )
    http = mocker.patch.object(Client, "_http_request")
    opted_out_client.report_adoption_event()
    http.assert_not_called()


@pytest.mark.parametrize(
    "disable_param, expected_enabled",
    [
        (None, True),  # parameter absent: instances created before the setting existed keep reporting
        (False, True),
        ("false", True),
        (True, False),
        ("true", False),
    ],
)
def test_main_passes_usage_reporting_setting_to_client(disable_param, expected_enabled, mocker):
    import CyberArkEPMSOCResponse as module

    params = {
        "url": "https://base-tenant.cyberark.cloud",
        "identity_url": "https://abc1234.id.cyberark.cloud",
        "web_app_id": "app",
        "client_id": "id",
        "credentials": {"password": "secret"},
    }
    if disable_param is not None:
        params["disable_usage_reporting"] = disable_param
    mocker.patch.object(module.demisto, "params", return_value=params)
    mocker.patch.object(module.demisto, "args", return_value={})
    mocker.patch.object(module.demisto, "command", return_value="cyberarkepm-activate-risk-plan")
    mocker.patch.object(module, "change_risk_plan_command", return_value="result")
    mocker.patch.object(module, "return_results")
    seen: list[bool] = []
    mocker.patch.object(
        Client, "report_adoption_event", autospec=True, side_effect=lambda c: seen.append(c.usage_reporting_enabled)
    )
    module.main()
    assert seen == [expected_enabled]
