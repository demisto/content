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

def test_jira_oauth_start(mocker):
    """
    Given
        - Client ID and redirect URI.
    When
        - jira-oauth-start is running.
    Then
        - Verify that the authorization URL is generated correctly.
    """
    from JiraEventCollector import jira_oauth_start, AUTH_URL
    
    client_id = "test_client_id"
    redirect_uri = "https://test.com/callback"
    
    mocker.patch("secrets.token_hex", return_value="test_state")
    
    result = jira_oauth_start(client_id, redirect_uri)
    
    assert result.raw_response.startswith(AUTH_URL)
    assert "client_id=test_client_id" in result.raw_response
    assert "redirect_uri=https%3A%2F%2Ftest.com%2Fcallback" in result.raw_response
    assert "state=test_state" in result.raw_response


def test_jira_oauth_complete(mocker):
    """
    Given
        - Authorization code and state.
    When
        - jira-oauth-complete is running.
    Then
        - Verify that the token exchange request is sent correctly.
        - Verify that the integration context is updated with the token.
    """
    from JiraEventCollector import jira_oauth_complete
    
    client_id = "test_client_id"
    client_secret = "test_client_secret"
    code = "test_code"
    state = "test_state"
    redirect_uri = "https://test.com/callback"
    
    mock_response = {
        "access_token": "test_access_token",
        "refresh_token": "test_refresh_token",
        "expires_in": 3600
    }
    
    mocker.patch("requests.post", return_value=mocker.Mock(json=lambda: mock_response, status_code=200))
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    set_context = mocker.patch.object(demisto, "setIntegrationContext")
    
    jira_oauth_complete(client_id, client_secret, code, state, redirect_uri)
    
    assert set_context.call_count == 1
    context = set_context.call_args[0][0]
    assert context["access_token"] == "test_access_token"
    assert context["refresh_token"] == "test_refresh_token"
    assert "valid_until" in context


def test_get_access_token_refresh(mocker):
    """
    Given
        - Expired access token and valid refresh token in context.
    When
        - get_access_token is called.
    Then
        - Verify that the token refresh request is sent.
        - Verify that the new token is returned and context updated.
    """
    from JiraEventCollector import get_access_token
    
    client_id = "test_client_id"
    client_secret = "test_client_secret"
    redirect_uri = "https://test.com/callback"
    
    expired_time = (datetime.now() - timedelta(hours=1)).timestamp()
    context = {
        "access_token": "expired_token",
        "refresh_token": "valid_refresh_token",
        "valid_until": expired_time
    }
    
    mock_response = {
        "access_token": "new_access_token",
        "refresh_token": "new_refresh_token",
        "expires_in": 3600
    }
    
    mocker.patch.object(demisto, "getIntegrationContext", return_value=context)
    set_context = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("requests.post", return_value=mocker.Mock(json=lambda: mock_response, status_code=200))
    
    token = get_access_token(client_id, client_secret, redirect_uri)
    
    assert token == "new_access_token"
    assert set_context.call_count == 1
    new_context = set_context.call_args[0][0]
    assert new_context["access_token"] == "new_access_token"
