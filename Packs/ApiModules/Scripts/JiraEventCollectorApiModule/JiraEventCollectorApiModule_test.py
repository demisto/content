import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import CommonServerPython
import demistomock as demisto
import JiraEventCollectorApiModule
import pytest
import requests_mock
from CommonServerPython import DemistoException
from freezegun import freeze_time
from requests.auth import HTTPBasicAuth

DEMISTO_PARAMS = {
    "method": "GET",
    "url": "https://your.domain.atlassian.net",
    "max_fetch": 100,
    "first_fetch": "3 days",
    "credentials": {
        "identifier": "admin@your.domain",
        "password": "123456",
    },
}
URL = "https://your.domain.atlassian.net/rest/api/3/auditing/record"
FIRST_REQUESTS_PARAMS = "from=2022-04-11T00%3A00%3A00.000Z&limit=1000&offset=0"
SECOND_REQUESTS_PARAMS = "from=2022-04-11T00%3A00%3A00.000Z&limit=1000&offset=1000"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def calculate_next_run(time):
    last_datetime_str = time.removesuffix("+0000").removesuffix("Z")
    try:
        last_datetime = datetime.strptime(last_datetime_str, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        last_datetime = datetime.strptime(last_datetime_str, "%Y-%m-%dT%H:%M:%S")
    last_datetime_with_delta = last_datetime + timedelta(seconds=1)
    return datetime.strftime(last_datetime_with_delta, "%Y-%m-%dT%H:%M:%S")


@freeze_time("2022-04-14T00:00:00Z")
def test_fetch_incidents_few_incidents(mocker):
    """
    Given
        - 3 events was created in Jira side in the last 3 days.
    When
        - fetch-events is running (with max_fetch set to 100).
    Then
        - Verify that all 3 events were created in XSIAM.
        - Verify last_run was set as expected.
    """

    mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-get-events")
    last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
    results = mocker.patch.object(demisto, "results")
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        # First call returns events, second call returns empty to stop pagination
        m.get(
            URL,
            [
                {"json": util_load_json("test_data/events.json"), "headers": {"Content-Type": "application/json"}},
                {"json": {"records": []}, "headers": {"Content-Type": "application/json"}},
            ],
        )

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    events = results.call_args[0][0]["Contents"]
    assert last_run.return_value.get("from") == calculate_next_run(events[0]["created"])
    assert not last_run.return_value.get("next_time")
    assert last_run.return_value.get("offset") == 0
    assert len(events) == 3


@freeze_time("2022-04-14T00:00:00Z")
def test_fetch_events_no_incidents(mocker):
    """
    Given
        - No events was created in Jira side in the last 3 days.
    When
        - fetch-events is running.
    Then
        - Make sure no events was created in XSIAM.
        - Make sure last_run was set as expected.
    """

    mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-get-events")
    last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
    incidents = mocker.patch.object(demisto, "incidents")
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.get(URL, json={}, headers={"Content-Type": "application/json"})

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    assert not last_run.return_value.get("from")
    assert last_run.return_value.get("offset") == 0
    assert not incidents.call_args


@freeze_time("2022-04-14T00:00:00Z")
def test_fetch_events_max_fetch_set_to_one(mocker):
    """
    Given
        - 3 events was created in Jira side in the last 3 days.
    When
        - fetch-events is running (with max_fetch set to 1).
    Then
        - Verify that only 1 event were created in XSIAM.
        - Verify last_run was set as expected.
    """

    params = DEMISTO_PARAMS.copy()
    params["max_fetch"] = 1

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-get-events")
    last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
    results = mocker.patch.object(demisto, "results")
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.get(URL, json=util_load_json("test_data/events.json"), headers={"Content-Type": "application/json"})

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    events = results.call_args[0][0]["Contents"]
    assert not last_run.return_value.get("from")
    assert last_run.return_value.get("next_time") == calculate_next_run(events[0]["created"])
    assert last_run.return_value.get("offset") == 1
    assert len(events) == 1


@freeze_time("2022-04-14T00:00:00Z")
def test_oauth_start_command(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured
    When
        - jira-oauth-start command is executed
    Then
        - Verify authorization URL is returned
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["cloud_id"] = "test-cloud-id"
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-start")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("AtlassianApiModule.get_integration_context", return_value={})
    mocker.patch("AtlassianApiModule.set_integration_context")
    results = mocker.patch("JiraEventCollectorApiModule.return_results")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    # Verify command results were returned
    assert results.called
    result = results.call_args[0][0]
    assert "Authorization Instructions" in result.readable_output


@freeze_time("2022-04-14T00:00:00Z")
def test_oauth_complete_command(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured
        - Authorization code is provided
    When
        - jira-oauth-complete command is executed
    Then
        - Verify tokens are saved to integration context
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["cloud_id"] = "test-cloud-id"
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={"code": "test-auth-code"})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-complete")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("AtlassianApiModule.get_integration_context", return_value={})
    set_context = mocker.patch("AtlassianApiModule.set_integration_context")
    results = mocker.patch("JiraEventCollectorApiModule.return_results")

    with requests_mock.Mocker() as m:
        m.post(
            "https://auth.atlassian.com/oauth/token",
            json={
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "expires_in": 3600,
                "scope": "read:audit-log:jira",
            },
        )

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    # Verify tokens were saved
    assert set_context.called
    context = set_context.call_args[0][0]
    assert context["token"] == "test-access-token"
    assert context["refresh_token"] == "test-refresh-token"

    # Verify success message
    assert results.called
    result = results.call_args[0][0]
    assert "Successfully authenticated" in result.readable_output


@freeze_time("2022-04-14T00:00:00Z")
def test_oauth_test_command(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured
        - Valid tokens exist in integration context
    When
        - jira-oauth-test command is executed
    Then
        - Verify authentication is successful
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["cloud_id"] = "test-cloud-id"
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-test")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch(
        "AtlassianApiModule.get_integration_context",
        return_value={
            "token": "valid-token",
            "valid_until": 9999999999,  # Far future
            "refresh_token": "refresh-token",
        },
    )
    results = mocker.patch("JiraEventCollectorApiModule.return_results")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    # Verify success message
    assert results.called
    result = results.call_args[0][0]
    assert "Authentication successful" in result.readable_output


@freeze_time("2022-04-14T00:00:00Z")
def test_fetch_events_with_oauth(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured
        - Valid tokens exist in integration context
    When
        - fetch-events is running
    Then
        - Verify events are fetched using OAuth Bearer token
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["cloud_id"] = "test-cloud-id"
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch(
        "AtlassianApiModule.get_integration_context",
        return_value={"token": "valid-oauth-token", "valid_until": 9999999999, "refresh_token": "refresh-token"},
    )
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")
    set_last_run = mocker.patch.object(demisto, "setLastRun")

    oauth_url = "https://api.atlassian.com/ex/jira/test-cloud-id/rest/api/3/auditing/record"

    with requests_mock.Mocker() as m:
        m.get(oauth_url, json=util_load_json("test_data/events.json"), headers={"Content-Type": "application/json"})

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    # Verify last run was set
    assert set_last_run.called

    # Verify OAuth token was used (check request history)
    assert len(m.request_history) > 0
    first_request = m.request_history[0]
    assert "Authorization" in first_request.headers
    assert first_request.headers["Authorization"] == "Bearer valid-oauth-token"


@freeze_time("2022-04-14T00:00:00Z")
def test_oauth_start_command_onprem(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured for On-Prem
    When
        - jira-oauth-start command is executed
    Then
        - Verify authorization URL is returned with PKCE parameters
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["url"] = "https://jira.company.com"
    oauth_params["cloud_id"] = ""  # Empty for on-prem
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-start")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("AtlassianApiModule.get_integration_context", return_value={})
    set_context = mocker.patch("AtlassianApiModule.set_integration_context")
    results = mocker.patch("JiraEventCollectorApiModule.return_results")

    with requests_mock.Mocker() as m:
        m.get(
            "https://jira.company.com/rest/oauth2/latest/authorize",
            status_code=302,
            headers={"Location": "https://jira.company.com/rest/oauth2/latest/authorize?client_id=test"},
        )

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    # Verify code_verifier was stored for PKCE
    assert set_context.called
    context = set_context.call_args[0][0]
    assert "code_verifier" in context

    # Verify command results were returned
    assert results.called


@freeze_time("2022-04-14T00:00:00Z")
def test_fetch_events_with_oauth_onprem(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured for On-Prem
        - Valid tokens exist in integration context
    When
        - fetch-events is running
    Then
        - Verify events are fetched using OAuth Bearer token from On-Prem server
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["url"] = "https://jira.company.com"
    oauth_params["cloud_id"] = ""  # Empty for on-prem
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch(
        "AtlassianApiModule.get_integration_context",
        return_value={"token": "valid-onprem-oauth-token", "valid_until": 9999999999, "refresh_token": "refresh-token"},
    )
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")
    set_last_run = mocker.patch.object(demisto, "setLastRun")

    onprem_url = "https://jira.company.com/rest/auditing/1.0/events"

    with requests_mock.Mocker() as m:
        m.get(onprem_url, json=util_load_json("test_data/events.json"), headers={"Content-Type": "application/json"})

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    # Verify last run was set
    assert set_last_run.called

    # Verify OAuth token was used
    assert len(m.request_history) > 0
    first_request = m.request_history[0]
    assert "Authorization" in first_request.headers
    assert first_request.headers["Authorization"] == "Bearer valid-onprem-oauth-token"


@freeze_time("2022-04-14T00:00:00Z")
def test_basic_auth_missing_credentials(mocker):
    """
    Given
        - Basic authentication is configured but credentials are missing
    When
        - main() is called
    Then
        - Verify a DemistoException is raised with a clear error message
    """
    params = DEMISTO_PARAMS.copy()
    params["credentials"] = {"identifier": "", "password": ""}

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    return_error_mock = mocker.patch("JiraEventCollectorApiModule.return_error")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    assert return_error_mock.called
    error_msg = return_error_mock.call_args[0][0]
    assert "Username and API token are required" in error_msg


@freeze_time("2022-04-14T00:00:00Z")
def test_basic_auth_missing_password(mocker):
    """
    Given
        - Basic authentication is configured but API token is missing
    When
        - main() is called
    Then
        - Verify a DemistoException is raised
    """
    params = DEMISTO_PARAMS.copy()
    params["credentials"] = {"identifier": "admin@example.com", "password": ""}

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    return_error_mock = mocker.patch("JiraEventCollectorApiModule.return_error")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    assert return_error_mock.called
    error_msg = return_error_mock.call_args[0][0]
    assert "Username and API token are required" in error_msg


@freeze_time("2022-04-14T00:00:00Z")
def test_test_module_basic_auth(mocker):
    """
    Given
        - Basic authentication is configured with valid credentials
    When
        - test-module command is executed
    Then
        - Verify 'ok' is returned
    """
    mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    results = mocker.patch.object(demisto, "results")
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.get(
            URL,
            [
                {"json": {"records": []}, "headers": {"Content-Type": "application/json"}},
            ],
        )

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    results.assert_called_once_with("ok")


@freeze_time("2022-04-14T00:00:00Z")
def test_test_module_oauth(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured with valid tokens
    When
        - test-module command is executed
    Then
        - Verify 'ok' is returned
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["cloud_id"] = "test-cloud-id"
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch(
        "AtlassianApiModule.get_integration_context",
        return_value={"token": "valid-token", "valid_until": 9999999999, "refresh_token": "refresh-token"},
    )
    results = mocker.patch.object(demisto, "results")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    results.assert_called_once_with("ok")


@freeze_time("2022-04-14T00:00:00Z")
def test_oauth_command_without_oauth_config(mocker):
    """
    Given
        - Basic authentication is configured (not OAuth)
    When
        - jira-oauth-start command is executed
    Then
        - Verify an error is raised
    """
    mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-start")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    return_error_mock = mocker.patch("JiraEventCollectorApiModule.return_error")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    assert return_error_mock.called
    error_msg = return_error_mock.call_args[0][0]
    assert "OAuth commands are only available" in error_msg


@freeze_time("2022-04-14T00:00:00Z")
def test_oauth_complete_missing_code(mocker):
    """
    Given
        - OAuth 2.0 authentication is configured
        - No authorization code is provided
    When
        - jira-oauth-complete command is executed
    Then
        - Verify an error is raised
    """
    oauth_params = DEMISTO_PARAMS.copy()
    oauth_params["auth_method"] = "OAuth 2.0"
    oauth_params["cloud_id"] = "test-cloud-id"
    oauth_params["callback_url"] = "https://localhost/callback"
    oauth_params["client_credentials"] = {"identifier": "test-client-id", "password": "test-client-secret"}

    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-complete")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    return_error_mock = mocker.patch("JiraEventCollectorApiModule.return_error")

    from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

    main()

    assert return_error_mock.called
    error_msg = return_error_mock.call_args[0][0]
    assert "Authorization code is required" in error_msg


@freeze_time("2022-04-14T00:00:00Z")
def test_set_next_run_with_milliseconds():
    """
    Given
        - An event with a timestamp containing milliseconds
    When
        - set_next_run is called
    Then
        - Verify the timestamp is parsed correctly
    """
    from JiraEventCollectorApiModule import GetEvents

    log = {"created": "2022-04-12T18:45:42.967+0000"}
    result = GetEvents.set_next_run(log)
    assert result.get("from") == "2022-04-12T18:45:43"


@freeze_time("2022-04-14T00:00:00Z")
def test_set_next_run_without_milliseconds():
    """
    Given
        - An event with a timestamp without milliseconds
    When
        - set_next_run is called
    Then
        - Verify the timestamp is parsed correctly
    """
    from JiraEventCollectorApiModule import GetEvents

    log = {"timestamp": "2022-04-12T18:45:42"}
    result = GetEvents.set_next_run(log)
    assert result.get("from") == "2022-04-12T18:45:43"


@freeze_time("2022-04-14T00:00:00Z")
def test_set_next_run_no_timestamp():
    """
    Given
        - An event with no timestamp field
    When
        - set_next_run is called
    Then
        - Verify last_run is returned unchanged
    """
    from JiraEventCollectorApiModule import GetEvents

    log = {"summary": "some event"}
    result = GetEvents.set_next_run(log)
    assert "from" not in result


@freeze_time("2022-04-14T00:00:00Z")
def test_set_next_run_invalid_timestamp():
    """
    Given
        - An event with an unparseable timestamp
    When
        - set_next_run is called
    Then
        - Verify last_run is returned unchanged
    """
    from JiraEventCollectorApiModule import GetEvents

    log = {"created": "not-a-valid-timestamp"}
    result = GetEvents.set_next_run(log)
    assert "from" not in result


@freeze_time("2022-04-14T00:00:00Z")
def test_redirect_detection(mocker):
    """
    Given
        - A request that gets redirected (e.g., to a login page)
    When
        - fetch-events is running
    Then
        - Verify a DemistoException is raised about redirect
    """
    mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")
    return_error_mock = mocker.patch("JiraEventCollectorApiModule.return_error")

    with requests_mock.Mocker() as m:
        m.get(URL, status_code=302, headers={"Location": "https://login.example.com"})

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    assert return_error_mock.called
    error_msg = return_error_mock.call_args[0][0]
    assert "redirected" in error_msg.lower() or "redirect" in error_msg.lower()


@freeze_time("2022-04-14T00:00:00Z")
def test_non_json_response(mocker):
    """
    Given
        - A response with non-JSON content type
    When
        - fetch-events is running
    Then
        - Verify a DemistoException is raised about unexpected content type
    """
    mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollectorApiModule.send_events_to_xsiam")
    return_error_mock = mocker.patch("JiraEventCollectorApiModule.return_error")

    with requests_mock.Mocker() as m:
        m.get(URL, text="<html>Login Page</html>", headers={"Content-Type": "text/html"})

        from JiraEventCollectorApiModule import run_jira_event_collector_integration as main

        main()

    assert return_error_mock.called
    error_msg = return_error_mock.call_args[0][0]
    assert "Content-Type" in error_msg or "content type" in error_msg.lower()


""" UCP (Atlassian Standard Connector) """

UCP_METHOD_ID = "jira-collector-method"
UCP_CREDENTIALS = {
    "plain": {"type": "plain", "plain": {"username": "me@acme.com", "password": "api-token"}},
    "api_key": {"type": "api_key", "api_key": {"key": "dc-pat"}},
    "oauth2_authorization_code": {
        "type": "oauth2_authorization_code",
        "oauth2": {"access_token": "oauth-token", "token_type": "Bearer"},
    },
}
EXPECTED_UCP_AUTHORIZATION = {
    "plain": "Basic " + __import__("base64").b64encode(b"me@acme.com:api-token").decode(),
    "api_key": "Bearer dc-pat",
    "oauth2_authorization_code": "Bearer oauth-token",
}
SITE_URL = "https://acme.atlassian.net"
SITE_AUDIT_URL = f"{SITE_URL}/rest/api/3/auditing/record"
DC_URL = "https://jira.acme.local"
DC_AUDIT_URL = f"{DC_URL}/rest/auditing/1.0/events"
GATEWAY_AUDIT_URL = "https://api.atlassian.com/ex/jira/cid/rest/api/3/auditing/record"
JSON_HEADERS = {"Content-Type": "application/json"}


@pytest.fixture
def ucp_profile(monkeypatch):
    """
    Activate UCP with a single connection profile of the given type, through the
    real CommonServerPython / AtlassianApiModule UCP helpers.
    """

    def configure(profile_type: str) -> None:
        monkeypatch.setattr(CommonServerPython, "_ucp_creds_cache", {})
        monkeypatch.setattr(
            demisto,
            "unifiedConnectorMetadata",
            lambda: {
                "connectionProfiles": [{"method_unique_id": UCP_METHOD_ID, "type": profile_type, "capability": "log-collection"}]
            },
        )
        monkeypatch.setattr(demisto, "getUCPCredentials", lambda *a, **k: UCP_CREDENTIALS[profile_type])

    return configure


@pytest.fixture
def last_run(monkeypatch):
    """
    Record the demisto last-run interactions.
    """
    set_last_run = MagicMock(spec=demisto.setLastRun)
    monkeypatch.setattr(demisto, "getLastRun", dict)
    monkeypatch.setattr(demisto, "setLastRun", set_last_run)
    return set_last_run


@pytest.fixture
def run_command(monkeypatch, last_run):
    """
    Run the integration entry point for a command, capturing every result / error.
    """

    def run(command: str, params: dict, args: dict | None = None) -> list:
        outputs: list = []
        monkeypatch.setattr(demisto, "params", lambda: params)
        monkeypatch.setattr(demisto, "args", lambda: args or {})
        monkeypatch.setattr(demisto, "command", lambda: command)
        monkeypatch.setattr(demisto, "results", outputs.append)
        monkeypatch.setattr(JiraEventCollectorApiModule, "return_results", outputs.append)
        monkeypatch.setattr(JiraEventCollectorApiModule, "return_error", lambda message: outputs.append(("error", message)))
        JiraEventCollectorApiModule.run_jira_event_collector_integration()
        return outputs

    return run


def connector_params(url: str | None, cloud_id: str | None = None) -> dict:
    """
    Instance params as the connector delivers them: unbound fields are None.
    """
    return {
        "url": url,
        "cloud_id": cloud_id,
        "auth_method": None,
        "credentials": None,
        "client_credentials": None,
        "callback_url": None,
        "first_fetch": None,
        "max_fetch": None,
        "insecure": False,
        "proxy": False,
    }


class TestApplyUcpAuthToRequest:
    @pytest.mark.parametrize("profile_type", ["api_key", "oauth2_authorization_code"])
    def test_bearer_profiles_replace_legacy_auth_with_header(self, ucp_profile, profile_type):
        ucp_profile(profile_type)
        request_dict = {"headers": {"Accept": "application/json"}, "auth": HTTPBasicAuth("legacy", "legacy")}

        JiraEventCollectorApiModule.apply_ucp_auth_to_request(request_dict)

        assert request_dict == {
            "headers": {"Accept": "application/json", "Authorization": EXPECTED_UCP_AUTHORIZATION[profile_type]}
        }

    def test_plain_profile_sets_basic_auth_and_drops_legacy_header(self, ucp_profile):
        ucp_profile("plain")
        request_dict = {"headers": {"Authorization": "Bearer legacy"}, "auth": None}

        JiraEventCollectorApiModule.apply_ucp_auth_to_request(request_dict)

        assert request_dict == {"headers": {}, "auth": ("me@acme.com", "api-token")}


class TestBuildAuditUrl:
    @pytest.mark.parametrize(
        ("base_url", "cloud_id", "auth_type", "expected"),
        [
            pytest.param(SITE_URL, "cid", "oauth2", GATEWAY_AUDIT_URL, id="oauth2 always uses the gateway"),
            pytest.param(f"{SITE_URL}/", "", "plain", SITE_AUDIT_URL, id="plain on a Cloud site"),
            pytest.param(DC_URL, "", "plain", DC_AUDIT_URL, id="plain on Data Center"),
            pytest.param(DC_URL, "", "api_key", DC_AUDIT_URL, id="PAT on Data Center"),
            pytest.param(
                "https://api.atlassian.com/ex/jira", "cid", "plain", GATEWAY_AUDIT_URL, id="plain on the gateway default"
            ),
        ],
    )
    def test_returns_expected_audit_url(self, base_url, cloud_id, auth_type, expected):
        assert JiraEventCollectorApiModule.build_audit_url(base_url, cloud_id, auth_type) == expected

    @pytest.mark.parametrize("base_url", [SITE_URL, "https://api.atlassian.com/ex/jira"])
    def test_gateway_without_cloud_id_raises(self, base_url):
        with pytest.raises(DemistoException, match="The Cloud ID is required"):
            JiraEventCollectorApiModule.build_audit_url(base_url, "", "oauth2")


class TestClientCall:
    @pytest.fixture
    def client(self):
        request = JiraEventCollectorApiModule.Request.model_validate(  # type: ignore[attr-defined]
            {
                "url": SITE_AUDIT_URL,
                "params": JiraEventCollectorApiModule.ReqParams.model_validate({}),  # type: ignore[attr-defined]
                "verify": True,
                "proxies": False,
            }
        )
        return JiraEventCollectorApiModule.Client(request)

    @pytest.mark.parametrize("profile_type", ["plain", "api_key", "oauth2_authorization_code"])
    def test_ucp_sends_profile_credential(self, ucp_profile, requests_mock, client, profile_type):
        ucp_profile(profile_type)
        requests_mock.get(SITE_AUDIT_URL, json={"records": []}, headers=JSON_HEADERS)

        client.call()

        assert requests_mock.last_request.headers["Authorization"] == EXPECTED_UCP_AUTHORIZATION[profile_type]

    def test_ucp_401_invalidates_cached_credential_and_raises(self, ucp_profile, requests_mock, client, monkeypatch):
        ucp_profile("oauth2_authorization_code")
        invalidate = MagicMock(spec=CommonServerPython.invalidate_ucp_credentials)
        monkeypatch.setattr(JiraEventCollectorApiModule, "invalidate_ucp_credentials", invalidate)
        requests_mock.get(SITE_AUDIT_URL, status_code=401, json={}, headers=JSON_HEADERS)

        with pytest.raises(DemistoException, match="401"):
            client.call()

        assert invalidate.call_count == 1
        assert invalidate.call_args.args == (UCP_METHOD_ID,)

    def test_legacy_401_does_not_invalidate(self, requests_mock, client, monkeypatch):
        invalidate = MagicMock(spec=CommonServerPython.invalidate_ucp_credentials)
        monkeypatch.setattr(JiraEventCollectorApiModule, "invalidate_ucp_credentials", invalidate)
        requests_mock.get(SITE_AUDIT_URL, status_code=401, json={}, headers=JSON_HEADERS)

        with pytest.raises(DemistoException):
            client.call()

        assert invalidate.call_count == 0


class TestGetEventsRun:
    def test_without_last_run_update_does_not_store_offset(self, last_run):
        client = MagicMock(spec=JiraEventCollectorApiModule.Client)
        client.request = MagicMock(spec=JiraEventCollectorApiModule.Request)
        client.request.params = JiraEventCollectorApiModule.ReqParams.model_validate({})  # type: ignore[attr-defined]
        get_events = JiraEventCollectorApiModule.GetEvents(client)
        get_events.call = MagicMock(side_effect=[[{"id": 1}, {"id": 2}], []])

        events = get_events.run(max_fetch=1, update_last_run=False)

        assert events == [{"id": 1}]
        assert last_run.call_count == 0


class TestRunJiraEventCollectorIntegration:
    @pytest.mark.parametrize(
        ("profile_type", "url", "cloud_id", "expected_url"),
        [
            ("plain", SITE_URL, None, SITE_AUDIT_URL),
            ("plain", DC_URL, None, DC_AUDIT_URL),
            ("api_key", DC_URL, None, DC_AUDIT_URL),
            ("oauth2_authorization_code", "https://api.atlassian.com/ex/jira", "cid", GATEWAY_AUDIT_URL),
            ("oauth2_authorization_code", SITE_URL, "cid", GATEWAY_AUDIT_URL),
        ],
    )
    def test_ucp_test_module_returns_ok_without_moving_last_run(
        self, ucp_profile, requests_mock, run_command, last_run, profile_type, url, cloud_id, expected_url
    ):
        ucp_profile(profile_type)
        requests_mock.get(expected_url, json=util_load_json("test_data/events.json"), headers=JSON_HEADERS)

        outputs = run_command("test-module", connector_params(url, cloud_id))

        assert outputs == ["ok"]
        assert requests_mock.last_request.headers["Authorization"] == EXPECTED_UCP_AUTHORIZATION[profile_type]
        assert last_run.call_count == 0

    def test_ucp_oauth2_without_cloud_id_returns_error(self, ucp_profile, run_command):
        ucp_profile("oauth2_authorization_code")

        outputs = run_command("test-module", connector_params(SITE_URL))

        assert len(outputs) == 1
        assert outputs[0][0] == "error"
        assert "The Cloud ID is required" in outputs[0][1]

    @pytest.mark.parametrize("command", ["jira-oauth-start", "jira-oauth-complete"])
    def test_ucp_oauth_flow_commands_return_not_needed_error(self, ucp_profile, run_command, command):
        ucp_profile("oauth2_authorization_code")

        outputs = run_command(command, connector_params(SITE_URL, "cid"), args={"code": "x"})

        assert len(outputs) == 1
        assert outputs[0][0] == "error"
        assert f"`!{command}` is not needed in the Atlassian Standard Connector" in outputs[0][1]

    def test_ucp_oauth_test_runs_connectivity_check(self, ucp_profile, requests_mock, run_command, last_run):
        ucp_profile("oauth2_authorization_code")
        requests_mock.get(GATEWAY_AUDIT_URL, json={"records": []}, headers=JSON_HEADERS)

        outputs = run_command("jira-oauth-test", connector_params(SITE_URL, "cid"))

        assert len(outputs) == 1
        assert outputs[0].readable_output == "✓ Authentication successful"
        assert requests_mock.call_count == 1
        assert last_run.call_count == 0

    def test_ucp_ignores_oauth_auth_method_param(self, ucp_profile, requests_mock, run_command, monkeypatch):
        ucp_profile("plain")
        create_oauth_client = MagicMock(spec=JiraEventCollectorApiModule.create_atlassian_oauth_client)
        monkeypatch.setattr(JiraEventCollectorApiModule, "create_atlassian_oauth_client", create_oauth_client)
        requests_mock.get(SITE_AUDIT_URL, json={"records": []}, headers=JSON_HEADERS)
        params = connector_params(SITE_URL) | {"auth_method": "OAuth 2.0"}

        assert run_command("test-module", params) == ["ok"]
        assert create_oauth_client.call_count == 0

    def test_ucp_fetch_events_sends_events(self, ucp_profile, requests_mock, run_command, monkeypatch, last_run):
        ucp_profile("api_key")
        send_events = MagicMock(spec=JiraEventCollectorApiModule.send_events_to_xsiam)
        monkeypatch.setattr(JiraEventCollectorApiModule, "send_events_to_xsiam", send_events)
        requests_mock.get(
            DC_AUDIT_URL,
            [
                {"json": util_load_json("test_data/events.json"), "headers": JSON_HEADERS},
                {"json": {"records": []}, "headers": JSON_HEADERS},
            ],
        )

        assert run_command("fetch-events", connector_params(DC_URL)) == []

        assert send_events.call_count == 1
        assert len(send_events.call_args.args[0]) == 3
        assert send_events.call_args.kwargs == {"vendor": "atlassian", "product": "jira"}
        assert last_run.call_count == 2

    def test_legacy_missing_credentials_still_returns_error(self, run_command):
        outputs = run_command("test-module", connector_params(SITE_URL))

        assert outputs == [
            (
                "error",
                "Username and API token are required for Basic authentication. "
                "Please provide valid credentials or switch to OAuth 2.0.",
            )
        ]
