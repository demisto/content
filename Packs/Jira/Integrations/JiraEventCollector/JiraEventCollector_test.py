import json
from datetime import datetime, timedelta

import demistomock as demisto
import requests_mock
from freezegun import freeze_time

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
FIRST_REQUESTS_PARAMS = "from=2022-04-11T00:00:00.000000&limit=1000&offset=0"
SECOND_REQUESTS_PARAMS = "from=2022-04-11T00:00:00.000000&limit=1000&offset=1000"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def calculate_next_run(time):
    last_datetime = datetime.strptime(time.removesuffix("+0000"), DATETIME_FORMAT) + timedelta(milliseconds=1)
    return datetime.strftime(last_datetime, DATETIME_FORMAT)


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
    mocker.patch("JiraEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.get(f"{URL}?{FIRST_REQUESTS_PARAMS}", json=util_load_json("test_data/events.json"))
        m.get(f"{URL}?{SECOND_REQUESTS_PARAMS}", json={})

        from JiraEventCollector import main

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
    mocker.patch("JiraEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.get(f"{URL}?{FIRST_REQUESTS_PARAMS}", json={})

        from JiraEventCollector import main

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

    params = DEMISTO_PARAMS
    params["max_fetch"] = 1

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-get-events")
    last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
    results = mocker.patch.object(demisto, "results")
    mocker.patch("JiraEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.get(f"{URL}?{FIRST_REQUESTS_PARAMS}", json=util_load_json("test_data/events.json"))
        m.get(f"{URL}?{SECOND_REQUESTS_PARAMS}", json={})

        from JiraEventCollector import main

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
    oauth_params["client_credentials"] = {
        "identifier": "test-client-id",
        "password": "test-client-secret"
    }
    
    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-start")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    results = mocker.patch("JiraEventCollector.return_results")
    
    with requests_mock.Mocker() as m:
        m.get(
            "https://auth.atlassian.com/authorize",
            status_code=302,
            headers={"Location": "https://auth.atlassian.com/authorize?client_id=test"}
        )
        
        from JiraEventCollector import main
        
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
    oauth_params["client_credentials"] = {
        "identifier": "test-client-id",
        "password": "test-client-secret"
    }
    
    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={"code": "test-auth-code"})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-complete")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollector.get_integration_context", return_value={})
    set_context = mocker.patch("JiraEventCollector.set_integration_context")
    results = mocker.patch("JiraEventCollector.return_results")
    
    with requests_mock.Mocker() as m:
        m.post(
            "https://auth.atlassian.com/oauth/token",
            json={
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "expires_in": 3600,
                "scope": "read:audit-log:jira"
            }
        )
        
        from JiraEventCollector import main
        
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
    oauth_params["client_credentials"] = {
        "identifier": "test-client-id",
        "password": "test-client-secret"
    }
    
    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-test")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollector.get_integration_context", return_value={
        "token": "valid-token",
        "valid_until": 9999999999,  # Far future
        "refresh_token": "refresh-token"
    })
    results = mocker.patch("JiraEventCollector.return_results")
    
    from JiraEventCollector import main
    
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
    oauth_params["client_credentials"] = {
        "identifier": "test-client-id",
        "password": "test-client-secret"
    }
    
    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollector.get_integration_context", return_value={
        "token": "valid-oauth-token",
        "valid_until": 9999999999,
        "refresh_token": "refresh-token"
    })
    mocker.patch("JiraEventCollector.send_events_to_xsiam")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    
    oauth_url = "https://api.atlassian.com/ex/jira/test-cloud-id/rest/api/3/auditing/record"
    
    with requests_mock.Mocker() as m:
        m.get(
            f"{oauth_url}?{FIRST_REQUESTS_PARAMS}",
            json=util_load_json("test_data/events.json")
        )
        m.get(f"{oauth_url}?{SECOND_REQUESTS_PARAMS}", json={})
        
        from JiraEventCollector import main
        
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
    oauth_params["client_credentials"] = {
        "identifier": "test-client-id",
        "password": "test-client-secret"
    }
    
    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="jira-oauth-start")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollector.get_integration_context", return_value={})
    set_context = mocker.patch("JiraEventCollector.set_integration_context")
    results = mocker.patch("JiraEventCollector.return_results")
    
    with requests_mock.Mocker() as m:
        m.get(
            "https://jira.company.com/rest/oauth2/latest/authorize",
            status_code=302,
            headers={"Location": "https://jira.company.com/rest/oauth2/latest/authorize?client_id=test"}
        )
        
        from JiraEventCollector import main
        
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
    oauth_params["client_credentials"] = {
        "identifier": "test-client-id",
        "password": "test-client-secret"
    }
    
    mocker.patch.object(demisto, "params", return_value=oauth_params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("JiraEventCollector.get_integration_context", return_value={
        "token": "valid-onprem-oauth-token",
        "valid_until": 9999999999,
        "refresh_token": "refresh-token"
    })
    mocker.patch("JiraEventCollector.send_events_to_xsiam")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    
    onprem_url = "https://jira.company.com/rest/api/3/auditing/record"
    
    with requests_mock.Mocker() as m:
        m.get(
            f"{onprem_url}?{FIRST_REQUESTS_PARAMS}",
            json=util_load_json("test_data/events.json")
        )
        m.get(f"{onprem_url}?{SECOND_REQUESTS_PARAMS}", json={})
        
        from JiraEventCollector import main
        
        main()
    
    # Verify last run was set
    assert set_last_run.called
    
    # Verify OAuth token was used
    assert len(m.request_history) > 0
    first_request = m.request_history[0]
    assert "Authorization" in first_request.headers
    assert first_request.headers["Authorization"] == "Bearer valid-onprem-oauth-token"
