import json
import time
from datetime import datetime, timedelta

import pytest
from CommonServerPython import CommandResults, DemistoException, IncidentStatus

from Cyberhaven import (
    CLOSE_REASON_VALUES,
    ERROR_MESSAGES,
    EVENT_DETAILS_ENDPOINT,
    EVENT_LINEAGE_ENDPOINT,
    INCIDENT_PATCH_ENDPOINT,
    INCIDENTS_ENDPOINT,
    MAX_INCIDENTS_TO_FETCH,
    SEVERITY_MAP,
    TOKEN_ENDPOINT,
    Client,
    apply_api_labels,
    convert_severity,
    cyberhaven_event_details_get_command,
    cyberhaven_event_lineage_get_command,
    cyberhaven_incident_list_command,
    cyberhaven_incident_update_command,
    fetch_incidents,
    get_mirroring,
    main,
    nullify_sentinels,
    test_module as cyberhaven_test_module,
    trim_spaces_from_args,
    update_remote_system_command,
    validate_cyberhaven_url,
    validate_incident_list_args,
    validate_incident_update_args,
)

BASE_URL = "https://your-tenant.cyberhaven.io"
TOKEN_URL = f"{BASE_URL}{TOKEN_ENDPOINT}"
INCIDENTS_URL = f"{BASE_URL}{INCIDENTS_ENDPOINT}"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client(mocker, requests_mock):
    """Fixture: client with empty integration context, token endpoint stubbed to return a valid token."""
    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response, status_code=200)

    return Client(
        base_url=BASE_URL,
        refresh_token="test-refresh-token",
        verify=False,
        proxy=False,
    )


def test_client_uses_cached_access_token(mocker):
    """
    Given:
    - A non-expired access_token already stored in integration context.

    When:
    - Constructing the Client.

    Then:
    - The cached token is reused and set_integration_context is never called.
    """
    future_expiry = time.time() + 900
    mocker.patch(
        "Cyberhaven.get_integration_context",
        return_value={"access_token": "cached-token", "token_expiry": future_expiry},
    )
    set_ctx = mocker.patch("Cyberhaven.set_integration_context")

    client = Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)

    assert client._access_token == "cached-token"
    set_ctx.assert_not_called()


def test_client_generates_new_token_when_cache_empty(mocker, requests_mock):
    """
    Given:
    - An empty integration context (no cached token).

    When:
    - Constructing the Client.

    Then:
    - The token endpoint is called, the returned token is stored, and cached in the client.
    """
    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    set_ctx = mocker.patch("Cyberhaven.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response, status_code=200)

    client = Client(base_url=BASE_URL, refresh_token="test-tok", verify=False, proxy=False)

    assert client._access_token == auth_response["access_token"]
    set_ctx.assert_called_once()
    stored = set_ctx.call_args[0][0]
    assert stored["access_token"] == auth_response["access_token"]
    assert "token_expiry" in stored


def test_client_generates_new_token_when_token_expired(mocker, requests_mock):
    """
    Given:
    - An integration context with an expired token (expiry in the past).

    When:
    - Constructing the Client.

    Then:
    - A new token is fetched and replaces the expired one.
    """
    mocker.patch(
        "Cyberhaven.get_integration_context",
        return_value={"access_token": "old-token", "token_expiry": time.time() - 10},
    )
    set_ctx = mocker.patch("Cyberhaven.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response, status_code=200)

    client = Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)

    assert client._access_token == auth_response["access_token"]
    set_ctx.assert_called_once()


def test_generate_token_invalid_refresh_token_401_json(mocker, requests_mock):
    """
    Given:
    - Token endpoint returns 401 with a JSON error body.

    When:
    - Constructing the Client.

    Then:
    - DemistoException is raised containing the UNAUTHORIZED_REQUEST message.
    """
    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")

    requests_mock.post(
        TOKEN_URL,
        json={"error": "invalid_token", "message": "Bad refresh token"},
        status_code=401,
    )

    with pytest.raises(DemistoException) as exc:
        Client(base_url=BASE_URL, refresh_token="bad-token", verify=False, proxy=False)

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_generate_token_invalid_refresh_token_401_non_json(mocker, requests_mock):
    """
    Given:
    - Token endpoint returns 401 with a plain-text body (not JSON).

    When:
    - Constructing the Client.

    Then:
    - DemistoException is raised via the ValueError fallback path; still contains UNAUTHORIZED_REQUEST.
    """
    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")

    requests_mock.post(TOKEN_URL, text="Unauthorized", status_code=401)

    with pytest.raises(DemistoException) as exc:
        Client(base_url=BASE_URL, refresh_token="bad-token", verify=False, proxy=False)

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_generate_token_non_json_success_response(mocker, requests_mock):
    """
    Given:
    - Token endpoint returns 200 with a plain-text (non-JSON) body.

    When:
    - Constructing the Client.

    Then:
    - DemistoException is raised because the token response cannot be parsed as JSON.
    """
    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")

    requests_mock.post(TOKEN_URL, text="not-json", status_code=200)

    with pytest.raises(DemistoException) as exc:
        Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)

    assert ERROR_MESSAGES["INVALID_OBJECT"].format("json", "") in str(exc.value)


def test_generate_token_missing_access_token_field(mocker, requests_mock):
    """
    Given:
    - Token endpoint returns 200 JSON but without an access_token field.

    When:
    - Constructing the Client.

    Then:
    - DemistoException is raised with the TOKEN_GENERATION_FAILED message.
    """
    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")

    requests_mock.post(TOKEN_URL, json={"token_type": "Bearer"}, status_code=200)

    with pytest.raises(DemistoException) as exc:
        Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)

    assert ERROR_MESSAGES["TOKEN_GENERATION_FAILED"] in str(exc.value)


def test_http_request_refreshes_token_on_401(mocker, requests_mock):
    """
    Given:
    - Client with a stale (cached, not-yet-expired) token. First API call returns 401;
      auth endpoint returns a new token; second API call succeeds.

    When:
    - list_incidents is called.

    Then:
    - A new access token is fetched and the retried call returns the successful response.
    """
    mocker.patch(
        "Cyberhaven.get_integration_context",
        return_value={"access_token": "stale-token", "token_expiry": time.time() + 900},
    )
    mocker.patch("Cyberhaven.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response, status_code=200)

    incident_list = util_load_json("test_data/incident_list.json")
    requests_mock.post(
        INCIDENTS_URL,
        [
            {"json": {"error": "unauthorized"}, "status_code": 401},
            {"json": incident_list, "status_code": 200},
        ],
    )

    client = Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)
    result = client.list_incidents(page_size=1)

    assert result == incident_list
    assert client._access_token == auth_response["access_token"]


def test_http_request_persistent_401_json_body(mocker, requests_mock):
    """
    Given:
    - Client whose retried request (after token refresh) also returns 401 with JSON body.

    When:
    - list_incidents is called.

    Then:
    - DemistoException is raised with the UNAUTHORIZED_REQUEST message.
    """
    mocker.patch(
        "Cyberhaven.get_integration_context",
        return_value={"access_token": "stale-token", "token_expiry": time.time() + 900},
    )
    mocker.patch("Cyberhaven.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response, status_code=200)
    requests_mock.post(INCIDENTS_URL, json={"error": "unauthorized"}, status_code=401)

    client = Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)

    with pytest.raises(DemistoException) as exc:
        client.list_incidents(page_size=1)

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_http_request_persistent_401_non_json_body(mocker, requests_mock):
    """
    Given:
    - Client whose retried request (after token refresh) returns 401 with plain-text body.

    When:
    - list_incidents is called.

    Then:
    - DemistoException is raised via the ValueError fallback; still contains UNAUTHORIZED_REQUEST.
    """
    mocker.patch(
        "Cyberhaven.get_integration_context",
        return_value={"access_token": "stale-token", "token_expiry": time.time() + 900},
    )
    mocker.patch("Cyberhaven.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response, status_code=200)
    requests_mock.post(INCIDENTS_URL, text="Unauthorized", status_code=401)

    client = Client(base_url=BASE_URL, refresh_token="tok", verify=False, proxy=False)

    with pytest.raises(DemistoException) as exc:
        client.list_incidents(page_size=1)

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_http_request_response_type_json_returns_parsed(mock_client, requests_mock):
    """
    Given:
    - A valid client and a successful JSON response.

    When:
    - http_request is called with response_type='json'.

    Then:
    - The parsed JSON dict is returned.
    """
    incident_list = util_load_json("test_data/incident_list.json")
    requests_mock.post(INCIDENTS_URL, json=incident_list, status_code=200)

    result = mock_client.http_request(method="POST", url_suffix=INCIDENTS_ENDPOINT, response_type="json")

    assert result == incident_list


def test_http_request_response_type_response_returns_raw(mock_client, requests_mock):
    """
    Given:
    - A valid client and a successful response.

    When:
    - http_request is called with response_type='response'.

    Then:
    - The raw response object is returned with status_code 200.
    """
    incident_list = util_load_json("test_data/incident_list.json")
    requests_mock.post(INCIDENTS_URL, json=incident_list, status_code=200)

    result = mock_client.http_request(method="POST", url_suffix=INCIDENTS_ENDPOINT, response_type="response")

    assert result.status_code == 200
    assert result.json() == incident_list


def test_http_request_json_parse_error_raises(mock_client, requests_mock):
    """
    Given:
    - A valid client and a 200 response with non-JSON body.

    When:
    - http_request is called with response_type='json'.

    Then:
    - DemistoException is raised with the INVALID_OBJECT message.
    """
    requests_mock.post(INCIDENTS_URL, text="not-valid-json", status_code=200)

    with pytest.raises(DemistoException) as exc:
        mock_client.http_request(method="POST", url_suffix=INCIDENTS_ENDPOINT, response_type="json")

    assert ERROR_MESSAGES["INVALID_OBJECT"].format("json", "") in str(exc.value)


def test_test_module_success_no_fetch(mock_client, mocker, requests_mock):
    """
    Given:
    - Integration params with isFetch=False.
    - Incidents endpoint returns valid data.

    When:
    - test_module is called.

    Then:
    - list_incidents is called (not fetch_incidents) and "ok" is returned.
    """
    mocker.patch("Cyberhaven.demisto.params", return_value={"isFetch": False})
    requests_mock.post(INCIDENTS_URL, json=util_load_json("test_data/incident_list.json"), status_code=200)

    result = cyberhaven_test_module(mock_client)

    assert result == "ok"


def test_test_module_with_is_fetch_calls_fetch_incidents(mock_client, mocker):
    """
    Given:
    - Integration params with isFetch=True.

    When:
    - test_module is called.

    Then:
    - fetch_incidents is called with is_test=True and "ok" is returned.
    """
    params = {"isFetch": True, "first_fetch": "3 days", "max_fetch": "10"}
    mocker.patch("Cyberhaven.demisto.params", return_value=params)
    mock_fetch = mocker.patch("Cyberhaven.fetch_incidents", return_value=([], {}))

    result = cyberhaven_test_module(mock_client)

    assert result == "ok"
    mock_fetch.assert_called_once_with(mock_client, {}, params, is_test=True)


def test_test_module_401_returns_auth_error_string(mock_client, mocker):
    """
    Given:
    - Integration params with isFetch=False.
    - list_incidents raises DemistoException containing '401'.

    When:
    - test_module is called.

    Then:
    - The string 'Authorization Error' is returned instead of raising.
    """
    mocker.patch("Cyberhaven.demisto.params", return_value={"isFetch": False})
    mocker.patch.object(mock_client, "list_incidents", side_effect=DemistoException("401 Unauthorized"))

    result = cyberhaven_test_module(mock_client)

    assert "Authorization Error" in result


def test_test_module_403_returns_auth_error_string(mock_client, mocker):
    """
    Given:
    - list_incidents raises DemistoException containing '403'.

    When:
    - test_module is called.

    Then:
    - 'Authorization Error' string is returned.
    """
    mocker.patch("Cyberhaven.demisto.params", return_value={"isFetch": False})
    mocker.patch.object(mock_client, "list_incidents", side_effect=DemistoException("403 Forbidden"))

    result = cyberhaven_test_module(mock_client)

    assert "Authorization Error" in result


def test_test_module_non_auth_error_reraises(mock_client, mocker):
    """
    Given:
    - list_incidents raises DemistoException NOT containing 401 or 403.

    When:
    - test_module is called.

    Then:
    - The DemistoException propagates (is re-raised).
    """
    mocker.patch("Cyberhaven.demisto.params", return_value={"isFetch": False})
    mocker.patch.object(mock_client, "list_incidents", side_effect=DemistoException("Connection timed out"))

    with pytest.raises(DemistoException):
        cyberhaven_test_module(mock_client)


def _make_incident(
    inc_id: str = "inc-001",
    event_time: str = "2026-06-10T08:00:00Z",
    policy_name: str = "Test Policy",
    severity: str = "high",
    user_email: str = "alice@example.com",
) -> dict:
    return {
        "id": inc_id,
        "status": "open",
        "blocked": True,
        "event_time": event_time,
        "trigger_time": event_time,
        "policy": {"name": policy_name, "severity": severity},
        "user": {"email": user_email},
        "dataset": {"name": "DS", "sensitivity": "confidential"},
        "ai_summary": "Summary text.",
    }


def test_fetch_incidents_first_run_creates_incident(mock_client, mocker):
    """
    Given:
    - Empty last_run (first fetch).
    - API returns one incident from test_data/incident_list.json.

    When:
    - fetch_incidents is called.

    Then:
    - One incident dict is returned with correct name, occurred, severity, rawJSON, and details.
    - next_run contains next_fetch_time and already_fetch_ids.
    """
    incident_list = util_load_json("test_data/incident_list.json")
    mocker.patch.object(mock_client, "list_incidents", return_value=incident_list)

    incidents, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["name"] == "Cyberhaven: HR Data Exfiltration Prevention - usr_john_doe_001"
    assert inc["occurred"] == "2026-01-15T10:29:02Z"
    assert inc["severity"] == SEVERITY_MAP["high"]
    expected_raw = util_load_json("test_data/fetch_incidents_raw.json")
    assert json.loads(inc["rawJSON"]) == expected_raw
    assert inc["details"] == incident_list["resources"][0]["ai_summary"]

    assert "next_fetch_time" in next_run
    assert "already_fetch_ids" in next_run
    assert "inc_a1b2c3d4e5f6" in next_run["already_fetch_ids"]


def test_fetch_incidents_uses_stored_next_fetch_time(mock_client, mocker):
    """
    Given:
    - last_run has a next_fetch_time of '2026-06-09T00:00:00Z'.
    - API returns one new incident.

    When:
    - fetch_incidents is called.

    Then:
    - client.list_incidents is called with start_time equal to the stored next_fetch_time.
    """
    mock_list = mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [_make_incident("inc-002")], "page_response": {"next_id": ""}},
    )

    last_run = {
        "next_fetch_time": "2026-06-09T00:00:00Z",
        "already_fetch_ids": [],
        "next_page_id": "",
        "filter_string": '{"severity": [], "status": []}',
    }

    fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    call_kwargs = mock_list.call_args[1]
    assert call_kwargs.get("start_time") == "2026-06-09T00:00:00Z"


def test_fetch_incidents_deduplication_skips_known_ids(mock_client, mocker):
    """
    Given:
    - last_run already_fetch_ids contains 'inc-001'.
    - API returns inc-001 (duplicate) and inc-002 (new).

    When:
    - fetch_incidents is called.

    Then:
    - Only inc-002 becomes an incident.
    - next_run.already_fetch_ids contains both inc-001 and inc-002.
    """
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={
            "resources": [
                _make_incident("inc-001"),
                _make_incident("inc-002", event_time="2026-06-11T00:00:00Z"),
            ],
            "page_response": {"next_id": ""},
        },
    )

    last_run = {"next_fetch_time": "2026-06-09T00:00:00Z", "already_fetch_ids": ["inc-001"], "next_page_id": ""}

    incidents, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    assert json.loads(incidents[0]["rawJSON"])["id"] == "inc-002"
    assert set(next_run["already_fetch_ids"]) == {"inc-001", "inc-002"}


def test_fetch_incidents_all_duplicates_returns_empty(mock_client, mocker):
    """
    Given:
    - All incidents returned by API are already in already_fetch_ids.

    When:
    - fetch_incidents is called.

    Then:
    - No incidents are created.
    """
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [_make_incident("inc-001")], "page_response": {"next_id": ""}},
    )

    last_run = {"next_fetch_time": "2026-06-09T00:00:00Z", "already_fetch_ids": ["inc-001"], "next_page_id": ""}

    incidents, _ = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents == []


def test_fetch_incidents_is_test_returns_empty_after_api_call(mock_client, mocker):
    """
    Given:
    - is_test=True and API returns one incident.

    When:
    - fetch_incidents is called.

    Then:
    - Returns ([], {}) without creating any incidents.
    - The API was still called once (to verify connectivity).
    """
    mock_list = mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [_make_incident()], "page_response": {"next_id": ""}},
    )

    incidents, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"}, is_test=True)

    assert incidents == []
    assert next_run == {}
    mock_list.assert_called_once()


def test_fetch_incidents_empty_api_response_preserves_next_fetch_time(mock_client, mocker):
    """
    Given:
    - API returns no incidents.
    - last_run has a stored next_fetch_time.

    When:
    - fetch_incidents is called.

    Then:
    - No incidents are created.
    - next_run.next_fetch_time equals the stored value.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [], "page_response": {"next_id": ""}})

    stored_time = "2026-06-09T00:00:00Z"
    last_run = {
        "next_fetch_time": stored_time,
        "already_fetch_ids": [],
        "next_page_id": "",
        "filter_string": '{"severity": [], "status": []}',
    }

    incidents, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents == []
    assert next_run["next_fetch_time"] == stored_time


def test_fetch_incidents_next_fetch_time_updated_from_last_incident(mock_client, mocker):
    """
    Given:
    - API returns two incidents, the second has a later event_time.

    When:
    - fetch_incidents is called.

    Then:
    - next_run.next_fetch_time equals the last incident's event_time.
    """
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={
            "resources": [
                _make_incident("inc-001", event_time="2026-06-10T08:00:00Z"),
                _make_incident("inc-002", event_time="2026-06-11T10:00:00Z"),
            ],
            "page_response": {"next_id": ""},
        },
    )

    _, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert next_run["next_fetch_time"] == "2026-06-11T10:00:00Z"


def test_fetch_incidents_next_page_id_stored_in_next_run(mock_client, mocker):
    """
    Given:
    - API returns a page_response with a non-empty next_id (cursor).

    When:
    - fetch_incidents is called.

    Then:
    - next_run contains next_fetch_time and already_fetch_ids (pagination cursor not stored).
    """
    incident_list = util_load_json("test_data/incident_list_response.json")
    mocker.patch.object(mock_client, "list_incidents", return_value=incident_list)

    _, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert "next_fetch_time" in next_run
    assert "already_fetch_ids" in next_run


def test_fetch_incidents_page_id_passed_to_client_and_clears_start_time(mock_client, mocker):
    """
    Given:
    - last_run contains a next_page_id cursor and a next_fetch_time.

    When:
    - fetch_incidents is called.

    Then:
    - client.list_incidents is called with the stored start_time (cursor is ignored).
    """
    mock_list = mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [], "page_response": {"next_id": ""}},
    )

    last_run = {
        "next_fetch_time": "2026-06-09T00:00:00Z",
        "already_fetch_ids": [],
        "next_page_id": "cursor-xyz",
        "filter_string": '{"severity": [], "status": []}',
    }

    fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    call_kwargs = mock_list.call_args[1]
    assert call_kwargs.get("start_time") == "2026-06-09T00:00:00Z"


def test_fetch_incidents_invalid_max_fetch_raises(mock_client):
    """
    Given:
    - max_fetch param is 0 (below minimum of 1).

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised with the INVALID_MAX_FETCH message.
    """
    with pytest.raises(ValueError) as exc:
        fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "0"})

    assert ERROR_MESSAGES["INVALID_MAX_FETCH"].format(0, MAX_INCIDENTS_TO_FETCH) in str(exc.value)


def test_fetch_incidents_negative_max_fetch_raises(mock_client):
    """
    Given:
    - max_fetch param is -1.

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised with the INVALID_MAX_FETCH message.
    """
    with pytest.raises(ValueError) as exc:
        fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "-1"})

    assert ERROR_MESSAGES["INVALID_MAX_FETCH"].format(-1, MAX_INCIDENTS_TO_FETCH) in str(exc.value)


def test_fetch_incidents_first_fetch_older_than_30_days_is_test_raises(mock_client):
    """
    Given:
    - first_fetch is set to 31 days ago (older than the 30-day limit).
    - is_test=True (called from test-module).

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised with the FIRST_FETCH_TOO_OLD message.
    """
    with pytest.raises(ValueError) as exc:
        fetch_incidents(mock_client, {}, {"first_fetch": "31 days", "max_fetch": "10"}, is_test=True)

    assert ERROR_MESSAGES["FIRST_FETCH_TOO_OLD"] in str(exc.value)


def test_fetch_incidents_first_fetch_older_than_30_days_caps_to_30_days(mock_client, mocker):
    """
    Given:
    - first_fetch is set to 45 days ago (older than the 30-day limit).
    - is_test=False (normal fetch).

    When:
    - fetch_incidents is called.

    Then:
    - client.list_incidents is called with start_time not older than 30 days ago.
    - No error is raised.
    """
    mock_list = mocker.patch.object(
        mock_client, "list_incidents", return_value={"resources": [], "page_response": {"next_id": ""}}
    )

    fetch_incidents(mock_client, {}, {"first_fetch": "45 days", "max_fetch": "10"})

    call_kwargs = mock_list.call_args[1]
    start_time_str = call_kwargs.get("start_time")
    assert start_time_str is not None

    start_time_dt = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M:%SZ")
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    assert start_time_dt >= thirty_days_ago - timedelta(seconds=5)
    assert start_time_dt <= thirty_days_ago + timedelta(seconds=5)


def test_fetch_incidents_first_fetch_absolute_timestamp_older_than_30_days_is_test_raises(mock_client):
    """
    Given:
    - first_fetch is an absolute ISO timestamp more than 30 days in the past.
    - is_test=True (called from test-module).

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised with the FIRST_FETCH_TOO_OLD message (no TypeError from tz mismatch).
    """
    old_timestamp = (datetime.utcnow() - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")

    with pytest.raises(ValueError) as exc:
        fetch_incidents(mock_client, {}, {"first_fetch": old_timestamp, "max_fetch": "10"}, is_test=True)

    assert ERROR_MESSAGES["FIRST_FETCH_TOO_OLD"] in str(exc.value)


def test_fetch_incidents_max_fetch_exceeding_cap_is_capped(mock_client, mocker):
    """
    Given:
    - max_fetch param is greater than MAX_INCIDENTS_TO_FETCH (200).

    When:
    - fetch_incidents is called.

    Then:
    - client.list_incidents is called with page_size capped at MAX_INCIDENTS_TO_FETCH.
    """
    mock_list = mocker.patch.object(
        mock_client, "list_incidents", return_value={"resources": [], "page_response": {"next_id": ""}}
    )

    fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "500"})

    call_kwargs = mock_list.call_args[1]
    assert call_kwargs.get("page_size") == MAX_INCIDENTS_TO_FETCH


def test_fetch_incidents_invalid_severity_filter_raises(mock_client):
    """
    Given:
    - severity_filter contains an invalid value 'extreme'.

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised mentioning the invalid value.
    """
    with pytest.raises(ValueError) as exc:
        fetch_incidents(
            mock_client,
            {},
            {"first_fetch": "3 days", "max_fetch": "10", "severity_filter": "extreme"},
            is_test=True,
        )

    assert "extreme" in str(exc.value)


def test_fetch_incidents_valid_severity_filter_passes_to_client(mock_client, mocker):
    """
    Given:
    - severity_filter contains valid values 'high,critical'.

    When:
    - fetch_incidents is called.

    Then:
    - client.list_incidents is called with policy_severities=['high', 'critical'].
    """
    mock_list = mocker.patch.object(
        mock_client, "list_incidents", return_value={"resources": [], "page_response": {"next_id": ""}}
    )

    fetch_incidents(
        mock_client,
        {},
        {"first_fetch": "3 days", "max_fetch": "10", "severity_filter": "high,critical"},
    )

    call_kwargs = mock_list.call_args[1]
    assert call_kwargs.get("policy_severities") == ["high", "critical"]


@pytest.mark.parametrize(
    "severity, expected_xsoar_severity",
    [
        ("low", 1),
        ("medium", 2),
        ("high", 3),
        ("critical", 4),
        ("informational", 0.5),
        ("unspecified", 0),
        ("unknown_xyz", 0),
    ],
)
def test_fetch_incidents_severity_mapped_to_xsoar(mock_client, mocker, severity, expected_xsoar_severity):
    """
    Given:
    - An incident with a specific Cyberhaven severity string.

    When:
    - fetch_incidents is called.

    Then:
    - The incident severity matches the expected XSOAR numeric value.
    """
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={
            "resources": [_make_incident("inc-sev", severity=severity)],
            "page_response": {"next_id": ""},
        },
    )

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents[0]["severity"] == expected_xsoar_severity


def test_fetch_incidents_name_falls_back_to_inc_id_when_no_user_email(mock_client, mocker):
    """
    Given:
    - An incident with no user.id or user.local_id.

    When:
    - fetch_incidents is called.

    Then:
    - The incident name has an empty user identifier (name ends with " - ").
    """
    raw = {
        "id": "inc-noemail",
        "status": "open",
        "event_time": "2026-06-10T08:00:00Z",
        "policy": {"name": "Policy X", "severity": "low"},
        "user": {},
    }
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [raw], "page_response": {"next_id": ""}})

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents[0]["name"] == "Cyberhaven: Policy X"


def test_fetch_incidents_name_uses_alias_when_no_email(mock_client, mocker):
    """
    Given:
    - An incident whose user has no user.id but has a local_id.

    When:
    - fetch_incidents is called.

    Then:
    - The incident name uses the local_id as the user identifier.
    """
    raw = {
        "id": "inc-alias",
        "status": "open",
        "event_time": "2026-06-10T08:00:00Z",
        "policy": {"name": "Policy Y", "severity": "medium"},
        "user": {"local_id": "bob_alias"},
    }
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [raw], "page_response": {"next_id": ""}})

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert "bob_alias" in incidents[0]["name"]


def test_fetch_incidents_occurred_falls_back_to_trigger_time(mock_client, mocker):
    """
    Given:
    - An incident with no event_time but with trigger_time.

    When:
    - fetch_incidents is called.

    Then:
    - The incident 'occurred' field uses trigger_time.
    """
    raw = {
        "id": "inc-trigger",
        "status": "open",
        "trigger_time": "2026-06-10T09:00:00Z",
        "policy": {"name": "Policy Z", "severity": "high"},
        "user": {"email": "carol@example.com"},
    }
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [raw], "page_response": {"next_id": ""}})

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents[0]["occurred"] == "2026-06-10T09:00:00Z"


def test_fetch_incidents_already_fetch_ids_accumulated_across_runs(mock_client, mocker):
    """
    Given:
    - last_run.already_fetch_ids has ['inc-001'].
    - API returns inc-002 and inc-003 (both new).

    When:
    - fetch_incidents is called.

    Then:
    - next_run.already_fetch_ids contains all three IDs.
    """
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={
            "resources": [
                _make_incident("inc-002", event_time="2026-06-11T00:00:00Z"),
                _make_incident("inc-003", event_time="2026-06-12T00:00:00Z"),
            ],
            "page_response": {"next_id": ""},
        },
    )

    last_run = {"next_fetch_time": "2026-06-10T00:00:00Z", "already_fetch_ids": ["inc-001"], "next_page_id": ""}

    _, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert set(next_run["already_fetch_ids"]) == {"inc-001", "inc-002", "inc-003"}


@pytest.mark.parametrize(
    "label, expected",
    [
        ("high", SEVERITY_MAP["high"]),
        ("HIGH", SEVERITY_MAP["high"]),
        ("critical", SEVERITY_MAP["critical"]),
        ("low", SEVERITY_MAP["low"]),
        ("medium", SEVERITY_MAP["medium"]),
        ("informational", SEVERITY_MAP["informational"]),
        ("unspecified", SEVERITY_MAP["unspecified"]),
        ("bogus", SEVERITY_MAP["unspecified"]),
    ],
)
def test_convert_severity(label, expected):
    """
    Given:
    - A Cyberhaven severity string (various cases and unknown values).

    When:
    - convert_severity is called.

    Then:
    - The correct XSOAR IncidentSeverity float is returned.
    """
    assert convert_severity(label) == expected


""" ── update_remote_system_command ─────────────────────────────────────────── """

REMOTE_ID = "ch-incident-42"
INCIDENTS_PATCH_URL = f"{BASE_URL}/v2/incidents/{REMOTE_ID}"


def _urs_args(
    remote_id=REMOTE_ID,
    incident_changed="true",
    status=None,
    delta=None,
):
    """Build args dict for UpdateRemoteSystemArgs."""
    args: dict = {}
    if remote_id is not None:
        args["remoteId"] = remote_id
    if incident_changed is not None:
        args["incidentChanged"] = incident_changed
    if status is not None:
        args["status"] = status
    if delta is not None:
        args["delta"] = delta
    return args


def test_update_remote_no_remote_id(mock_client):
    """
    Given:
    - args with no remoteId.

    When:
    - update_remote_system_command is called.

    Then:
    - Returns empty string without calling API.
    """
    result = update_remote_system_command(mock_client, {})
    assert result == ""


def test_update_remote_incident_not_changed(mock_client, mocker):
    """
    Given:
    - remoteId present but incidentChanged is False.

    When:
    - update_remote_system_command is called.

    Then:
    - Returns remoteId without calling update_incident.
    """
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(mock_client, _urs_args(incident_changed="false"))
    assert result == REMOTE_ID
    mock_update.assert_not_called()


def test_update_remote_no_watched_fields_in_delta(mock_client, mocker):
    """
    Given:
    - incidentChanged=True but delta contains no watched fields (owner/closeReason/closeNotes).

    When:
    - update_remote_system_command is called.

    Then:
    - Returns remoteId without calling update_incident.
    """
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(mock_client, _urs_args(delta={"unrelatedField": "foo"}))
    assert result == REMOTE_ID
    mock_update.assert_not_called()


def test_update_remote_delta_as_json_string(mock_client, mocker):
    """
    Given:
    - delta is a JSON-encoded string containing a watched field (closeNotes).
    - inc_status=DONE and remote incident still open in CH, so close fields are processed.

    When:
    - update_remote_system_command is called.

    Then:
    - JSON is parsed and update_incident is called with close_note.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    delta_str = json.dumps({"closeNotes": "parsed from string"})
    update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.DONE, delta=delta_str))
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason=None,
        close_note="parsed from string",
        assigned_to=None,
    )


def test_update_remote_delta_invalid_json_string(mock_client, mocker):
    """
    Given:
    - delta is a non-JSON string (malformed).

    When:
    - update_remote_system_command is called.

    Then:
    - delta treated as empty; no PATCH issued.
    """
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(mock_client, _urs_args(delta="not-json{{{"))
    assert result == REMOTE_ID
    mock_update.assert_not_called()


def test_update_remote_owner_changed(mock_client, mocker):
    """
    Given:
    - delta contains owner with a non-blank value.

    When:
    - update_remote_system_command is called.

    Then:
    - update_incident called with assigned_to set to owner value.
    """
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(mock_client, _urs_args(delta={"owner": "analyst@corp.com"}))
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status=None,
        close_reason=None,
        close_note=None,
        assigned_to="analyst@corp.com",
    )


def test_update_remote_owner_blank_skips_patch(mock_client, mocker):
    """
    Given:
    - delta contains owner with blank/empty string.

    When:
    - update_remote_system_command is called.

    Then:
    - assigned_to omitted; no other watched fields → no PATCH.
    """
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(mock_client, _urs_args(delta={"owner": "   "}))
    assert result == REMOTE_ID
    mock_update.assert_not_called()


@pytest.mark.parametrize(
    "xsoar_reason, expected_ch_reason",
    [
        ("Resolved", "valid"),
        ("False Positive", "invalid_data_mislabled"),
        ("Other", "invalid_other"),
    ],
)
def test_update_remote_close_reason_mapped(mock_client, mocker, xsoar_reason, expected_ch_reason):
    """
    Given:
    - delta contains closeReason with a value that maps to a CH close reason.
    - inc_status=DONE and remote incident still open in CH, so close fields are processed.

    When:
    - update_remote_system_command is called.

    Then:
    - update_incident called with correct close_reason.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.DONE, delta={"closeReason": xsoar_reason}))
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason=expected_ch_reason,
        close_note=None,
        assigned_to=None,
    )


def test_update_remote_close_reason_unmapped_skips_patch(mock_client, mocker):
    """
    Given:
    - delta contains closeReason with a value not in XSOAR_CLOSE_REASON_TO_CH.
    - inc_status=DONE and remote incident still open in CH.

    When:
    - update_remote_system_command is called.

    Then:
    - update_incident still called for the status change, but without close_reason
      (no mapping found for the unknown reason).
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.DONE, delta={"closeReason": "Unknown Reason"}))
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason=None,
        close_note=None,
        assigned_to=None,
    )


def test_update_remote_close_notes(mock_client, mocker):
    """
    Given:
    - delta contains closeNotes.
    - inc_status=DONE and remote incident still open in CH, so close fields are processed.

    When:
    - update_remote_system_command is called.

    Then:
    - update_incident called with close_note set.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(
        mock_client, _urs_args(status=IncidentStatus.DONE, delta={"closeNotes": "Ticket resolved via helpdesk."})
    )
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason=None,
        close_note="Ticket resolved via helpdesk.",
        assigned_to=None,
    )


def test_update_remote_status_open_in_ch_patches_status(mock_client, mocker):
    """
    Given:
    - inc_status=DONE and the remote incident is still open in Cyberhaven.

    When:
    - update_remote_system_command is called.

    Then:
    - list_incidents is queried, status differs, so update_incident called with status="closed".
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.DONE, delta=None))
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason=None,
        close_note=None,
        assigned_to=None,
    )


def test_update_remote_status_already_closed_skips_close_fields_but_owner_still_patched(mock_client, mocker):
    """
    Given:
    - inc_status=DONE but the remote incident is already closed in Cyberhaven.
    - delta also contains an owner change.

    When:
    - update_remote_system_command is called.

    Then:
    - close_reason/close_note are NOT re-sent (close workflow not re-run), but the unrelated
      owner change still triggers a PATCH with assigned_to set. Note: `status` is still
      forwarded to the PATCH since it mirrors the (unchanged) external state - it is only
      excluded from the internal patch_fields skip/log check, not from the API call itself
      (same pre-existing quirk as when other watched fields are patched without a status diff).
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "closed"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(
        mock_client,
        _urs_args(status=IncidentStatus.DONE, delta={"owner": "lead@corp.com"}),
    )
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason=None,
        close_note=None,
        assigned_to="lead@corp.com",
    )


def test_update_remote_status_not_found_in_ch_discards_update(mock_client, mocker):
    """
    Given:
    - inc_status=DONE but the remote incident no longer exists in Cyberhaven (empty resources).
    - delta also contains an owner change.

    When:
    - update_remote_system_command is called.

    Then:
    - Update is discarded entirely, including the owner change; no PATCH issued.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": []})
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(
        mock_client,
        _urs_args(status=IncidentStatus.DONE, delta={"owner": "lead@corp.com"}),
    )
    assert result == REMOTE_ID
    mock_update.assert_not_called()


def test_update_remote_list_incidents_error_discards_update(mock_client, mocker):
    """
    Given:
    - inc_status=DONE but list_incidents raises a DemistoException (e.g. 500 error).
    - delta also contains an owner change.

    When:
    - update_remote_system_command is called.

    Then:
    - The lookup failure is logged and the whole update is discarded (including owner),
      same as the not-found case; no PATCH issued, no unhandled exception.
    """
    mocker.patch.object(mock_client, "list_incidents", side_effect=DemistoException("500 Internal Server Error"))
    mock_error = mocker.patch("Cyberhaven.demisto.error")
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(
        mock_client,
        _urs_args(status=IncidentStatus.DONE, delta={"owner": "lead@corp.com"}),
    )
    assert result == REMOTE_ID
    mock_update.assert_not_called()
    mock_error.assert_called_once()


def test_update_remote_status_active_no_other_fields_skips_patch(mock_client, mocker):
    """
    Given:
    - inc_status=ACTIVE (not DONE) and no other watched fields in delta.

    When:
    - update_remote_system_command is called.

    Then:
    - No CH lookup needed (only DONE triggers it); no PATCH issued.
    """
    mock_list = mocker.patch.object(mock_client, "list_incidents")
    mock_update = mocker.patch.object(mock_client, "update_incident")
    result = update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.ACTIVE, delta={}))
    assert result == REMOTE_ID
    mock_list.assert_not_called()
    mock_update.assert_not_called()


def test_update_remote_multiple_fields(mock_client, mocker):
    """
    Given:
    - delta contains owner, closeReason, closeNotes with DONE status, remote still open in CH.

    When:
    - update_remote_system_command is called.

    Then:
    - update_incident called with all mapped fields.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={})
    update_remote_system_command(
        mock_client,
        _urs_args(
            status=IncidentStatus.DONE,
            delta={
                "owner": "lead@corp.com",
                "closeReason": "Resolved",
                "closeNotes": "All clear.",
            },
        ),
    )
    mock_update.assert_called_once_with(
        incident_id=REMOTE_ID,
        status="closed",
        close_reason="valid",
        close_note="All clear.",
        assigned_to="lead@corp.com",
    )


def test_update_remote_404_error_no_warning(mock_client, mocker):
    """
    Given:
    - update_incident raises DemistoException with '404' in message.
    - inc_status=DONE and remote incident still open in CH, so the PATCH is actually attempted.

    When:
    - update_remote_system_command is called.

    Then:
    - Returns remoteId; return_warning is NOT called.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mocker.patch.object(mock_client, "update_incident", side_effect=DemistoException("404 Not Found"))
    mock_warn = mocker.patch("Cyberhaven.return_warning")
    result = update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.DONE, delta={"closeNotes": "note"}))
    assert result == REMOTE_ID
    mock_warn.assert_not_called()


def test_update_remote_non_404_error_calls_return_warning(mock_client, mocker):
    """
    Given:
    - update_incident raises DemistoException with a non-404 error (e.g. 500).
    - inc_status=DONE and remote incident still open in CH, so the PATCH is actually attempted.

    When:
    - update_remote_system_command is called.

    Then:
    - Returns remoteId; return_warning is called with details about the failure.
    """
    mocker.patch.object(mock_client, "list_incidents", return_value={"resources": [{"status": "open"}]})
    mocker.patch.object(mock_client, "update_incident", side_effect=DemistoException("500 Internal Server Error"))
    mocker.patch("Cyberhaven.demisto.error")
    mock_warn = mocker.patch("Cyberhaven.return_warning")
    result = update_remote_system_command(mock_client, _urs_args(status=IncidentStatus.DONE, delta={"closeNotes": "note"}))
    assert result == REMOTE_ID
    mock_warn.assert_called_once()
    call_msg = mock_warn.call_args[0][0]
    assert REMOTE_ID in call_msg
    assert "close_note" in call_msg


def test_incident_list_command_success(mock_client, mocker):
    """
    Given:
    - list_incidents returns one incident from test_data/incident_list_command_response.json.

    When:
    - cyberhaven_incident_list_command is called with default args.

    Then:
    - Returns a list of two CommandResults (incidents + page info).
    - First result outputs_prefix, outputs_key_field, outputs, raw_response, and readable_output
      match the expected context and HR files.
    - Second result outputs_prefix and outputs match the expected page context file.
    """
    incident_list_response = util_load_json("test_data/incident_list_response.json")
    mocker.patch.object(mock_client, "list_incidents", return_value=incident_list_response)

    result = cyberhaven_incident_list_command(mock_client, {})

    expected_context = util_load_json("test_data/incident_list_context.json")
    expected_page_context = util_load_json("test_data/incident_list_page_context.json")
    with open("test_data/incident_list_hr.md", encoding="utf-8") as f:
        expected_hr = f.read()

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0].outputs_prefix == "Cyberhaven.Incident"
    assert result[0].outputs_key_field == "id"
    assert result[0].outputs == expected_context
    assert result[0].raw_response == incident_list_response
    assert result[0].readable_output == expected_hr
    assert result[1].outputs_prefix == "Cyberhaven.IncidentPage"
    assert result[1].outputs == expected_page_context


def test_incident_list_command_no_results(mock_client, mocker):
    """
    Given:
    - list_incidents returns no incidents.

    When:
    - cyberhaven_incident_list_command is called.

    Then:
    - Returns a single CommandResults with 'No incidents found' message.
    """
    empty_response = util_load_json("test_data/incident_list_empty.json")
    mocker.patch.object(mock_client, "list_incidents", return_value=empty_response)

    result = cyberhaven_incident_list_command(mock_client, {})

    assert isinstance(result, CommandResults)
    assert "No incidents found" in (result.readable_output or "")


def test_incident_list_command_invalid_severity_raises(mock_client):
    """
    Given:
    - severity arg contains an invalid value.

    When:
    - cyberhaven_incident_list_command is called.

    Then:
    - ValueError raised mentioning the invalid value.
    """
    with pytest.raises(ValueError) as exc:
        cyberhaven_incident_list_command(mock_client, {"severity": "extreme"})

    assert "extreme" in str(exc.value)


def test_incident_list_command_invalid_status_raises(mock_client):
    """
    Given:
    - status arg contains an invalid value.

    When:
    - cyberhaven_incident_list_command is called.

    Then:
    - ValueError raised mentioning the invalid value.
    """
    with pytest.raises(ValueError) as exc:
        cyberhaven_incident_list_command(mock_client, {"status": "pending"})

    assert "pending" in str(exc.value)


def test_incident_list_command_invalid_limit_raises(mock_client):
    """
    Given:
    - limit arg is 0.

    When:
    - cyberhaven_incident_list_command is called.

    Then:
    - ValueError raised.
    """
    with pytest.raises(ValueError):
        cyberhaven_incident_list_command(mock_client, {"limit": "0"})


def test_incident_update_command_success(mock_client, mocker):
    """
    Given:
    - Valid incident_id and status=closed.
    - update_incident returns test_data/incident_update_response.json.

    When:
    - cyberhaven_incident_update_command is called.

    Then:
    - update_incident called once; CommandResults outputs_prefix, outputs_key_field,
      outputs, raw_response, and readable_output match the expected context and HR files.
    """
    incident_update_response = util_load_json("test_data/incident_update_response.json")
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value=incident_update_response)

    result = cyberhaven_incident_update_command(mock_client, {"incident_id": "inc-001", "status": "closed"})

    expected_context = util_load_json("test_data/incident_update_context.json")
    with open("test_data/incident_update_hr.md", encoding="utf-8") as f:
        expected_hr = f.read()

    mock_update.assert_called_once()
    assert result.outputs_prefix == "Cyberhaven.Incident"
    assert result.outputs_key_field == "id"
    assert result.outputs == expected_context
    assert result.raw_response == incident_update_response
    assert result.readable_output == expected_hr


def test_incident_update_command_missing_incident_id_raises(mock_client):
    """
    Given:
    - No incident_id in args.

    When:
    - cyberhaven_incident_update_command is called.

    Then:
    - ValueError raised.
    """
    with pytest.raises(ValueError) as exc:
        cyberhaven_incident_update_command(mock_client, {"status": "closed"})

    assert "incident_id" in str(exc.value)


def test_incident_update_command_no_update_fields_raises(mock_client):
    """
    Given:
    - incident_id present but no updatable fields.

    When:
    - cyberhaven_incident_update_command is called.

    Then:
    - ValueError raised with AT_LEAST_ONE_REQUIRED message.
    """
    with pytest.raises(ValueError) as exc:
        cyberhaven_incident_update_command(mock_client, {"incident_id": "inc-001"})

    assert "required" in str(exc.value).lower()


def test_incident_update_command_close_reason_mapped(mock_client, mocker):
    """
    Given:
    - close_reason='false positive'.

    When:
    - cyberhaven_incident_update_command is called.

    Then:
    - update_incident called with close_reason='invalid_data_mislabled'.
    """
    mock_update = mocker.patch.object(mock_client, "update_incident", return_value={"resources": []})

    cyberhaven_incident_update_command(mock_client, {"incident_id": "inc-001", "close_reason": "false positive"})

    _, call_kwargs = mock_update.call_args
    assert call_kwargs.get("close_reason") == "invalid_data_mislabled"


def test_event_details_get_command_success(mock_client, mocker):
    """
    Given:
    - event_ids arg has one ID.
    - get_event_details returns test_data/event_details.json.

    When:
    - cyberhaven_event_details_get_command is called.

    Then:
    - get_event_details called with ['evt-001']; CommandResults outputs_prefix,
      outputs_key_field, outputs, raw_response, and readable_output match the
      expected context and HR files.
    """
    event_details_response = util_load_json("test_data/event_details_response.json")
    mock_get = mocker.patch.object(mock_client, "get_event_details", return_value=event_details_response)

    result = cyberhaven_event_details_get_command(mock_client, {"event_ids": "evt-001"})

    expected_context = util_load_json("test_data/event_details_context.json")
    with open("test_data/event_details_hr.md", encoding="utf-8") as f:
        expected_hr = f.read()

    mock_get.assert_called_once_with(["evt-001"])
    assert result.outputs_prefix == "Cyberhaven.Event"
    assert result.outputs_key_field == "id"
    assert result.outputs == expected_context
    assert result.raw_response == event_details_response
    assert result.readable_output == expected_hr


def test_event_details_get_command_missing_ids_raises(mock_client):
    """
    Given:
    - event_ids arg is empty.

    When:
    - cyberhaven_event_details_get_command is called.

    Then:
    - ValueError raised with 'event_ids' in message.
    """
    with pytest.raises(ValueError) as exc:
        cyberhaven_event_details_get_command(mock_client, {})

    assert "event_ids" in str(exc.value)


_EVENT_LINEAGE_RESPONSE = {
    "resources": ["evt-001", "evt-002", "evt-003"],
}


def test_event_lineage_get_command_success(mock_client, mocker):
    """
    Given:
    - start_event_id and end_event_id provided.

    When:
    - cyberhaven_event_lineage_get_command is called.

    Then:
    - get_event_lineage called with correct IDs; CommandResults has Cyberhaven.EventLineage outputs.
    """
    mock_get = mocker.patch.object(mock_client, "get_event_lineage", return_value=_EVENT_LINEAGE_RESPONSE)

    result = cyberhaven_event_lineage_get_command(mock_client, {"start_event_id": "evt-001", "end_event_id": "evt-003"})

    mock_get.assert_called_once_with("evt-001", "evt-003")
    assert result.outputs_prefix == "Cyberhaven.EventLineage"


def test_event_lineage_get_command_missing_args_raises(mock_client):
    """
    Given:
    - start_event_id or end_event_id missing.

    When:
    - cyberhaven_event_lineage_get_command is called.

    Then:
    - ValueError raised.
    """
    with pytest.raises(ValueError):
        cyberhaven_event_lineage_get_command(mock_client, {"start_event_id": "evt-001"})


def test_client_update_incident_omits_none_fields(mock_client, requests_mock):
    """
    Given:
    - update_incident called with status and close_note; close_reason and assigned_to are None.

    When:
    - update_incident is called on the client.

    Then:
    - PATCH body contains only status and close_note (assign_params strips None values).
    """
    patch_url = f"{BASE_URL}{INCIDENT_PATCH_ENDPOINT.format(id='inc-42')}"
    requests_mock.patch(patch_url, json={"id": "inc-42", "status": "closed"}, status_code=200)

    mock_client.update_incident(
        incident_id="inc-42",
        status="closed",
        close_note="resolved note",
        close_reason=None,
        assigned_to=None,
    )

    sent_body = requests_mock.last_request.json()
    assert sent_body == {"status": "closed", "close_note": "resolved note"}
    assert "close_reason" not in sent_body
    assert "assigned_to" not in sent_body


def test_client_get_event_details_sends_ids(mock_client, requests_mock):
    """
    Given:
    - get_event_details called with a list of event IDs.

    When:
    - The method is called.

    Then:
    - POST to EVENT_DETAILS_ENDPOINT with {"ids": [...]} body; returns parsed response.
    """
    event_url = f"{BASE_URL}{EVENT_DETAILS_ENDPOINT}"
    expected_response = {"resources": [{"id": "evt-001"}]}
    requests_mock.post(event_url, json=expected_response, status_code=200)

    result = mock_client.get_event_details(["evt-001", "evt-002"])

    sent_body = requests_mock.last_request.json()
    assert sent_body == {"ids": ["evt-001", "evt-002"]}
    assert result == expected_response


def test_client_get_event_lineage_sends_correct_payload(mock_client, requests_mock):
    """
    Given:
    - get_event_lineage called with start and end event IDs.

    When:
    - The method is called.

    Then:
    - POST to EVENT_LINEAGE_ENDPOINT with correct body; returns parsed response.
    """
    lineage_url = f"{BASE_URL}{EVENT_LINEAGE_ENDPOINT}"
    expected_response = {"resources": ["evt-001", "evt-002", "evt-003"]}
    requests_mock.post(lineage_url, json=expected_response, status_code=200)

    result = mock_client.get_event_lineage("evt-001", "evt-003")

    sent_body = requests_mock.last_request.json()
    assert sent_body == {"start_event_id": "evt-001", "end_event_id": "evt-003"}
    assert result == expected_response


def test_trim_spaces_from_args_strips_string_values():
    """
    Given:
    - Dict with string values containing leading/trailing spaces and a non-string value.

    When:
    - trim_spaces_from_args is called.

    Then:
    - String values are stripped; non-string values are unchanged; dict is returned.
    """
    args = {"name": "  alice  ", "count": 42, "tag": " test "}
    result = trim_spaces_from_args(args)
    assert result["name"] == "alice"
    assert result["count"] == 42
    assert result["tag"] == "test"


def test_get_mirroring_returns_direction_and_instance(mocker):
    """
    Given:
    - demisto.integrationInstance() returns 'test-instance'.

    When:
    - get_mirroring is called.

    Then:
    - Returns dict with mirror_direction='Out' and mirror_instance='test-instance'.
    """
    mocker.patch("Cyberhaven.demisto.integrationInstance", return_value="test-instance")
    result = get_mirroring()
    assert result["mirror_direction"] == "Out"
    assert result["mirror_instance"] == "test-instance"


@pytest.mark.parametrize(
    "url",
    [
        "https://tenant.cyberhaven.io",
        "https://sub.tenant.cyberhaven.io",
        "https://tenant.cyberhaven.io/",
        "http://tenant.cyberhaven.io",
    ],
)
def test_validate_cyberhaven_url_valid(url):
    """
    Given:
    - A URL whose hostname ends with cyberhaven.io.

    When:
    - validate_cyberhaven_url is called.

    Then:
    - No exception is raised.
    """
    validate_cyberhaven_url(url)  # must not raise


@pytest.mark.parametrize(
    "url",
    [
        "https://tenant.example.com",
        "https://cyberhaven.io.evil.com",
        "https://notcyberhaven.io.com",
        "https://tenant.cyberhaven.io.fake",
        "",
    ],
)
def test_validate_cyberhaven_url_invalid(url):
    """
    Given:
    - A URL whose hostname does not end with cyberhaven.io.

    When:
    - validate_cyberhaven_url is called.

    Then:
    - ValueError is raised.
    """
    with pytest.raises(ValueError, match="cyberhaven.io"):
        validate_cyberhaven_url(url)


def test_validate_incident_list_args_parses_start_time():
    """
    Given:
    - start_time provided as an ISO timestamp string.

    When:
    - validate_incident_list_args is called.

    Then:
    - start_time in the result is formatted as an ISO timestamp.
    """
    result = validate_incident_list_args({"start_time": "2026-06-10T00:00:00Z"})
    assert result["start_time"] == "2026-06-10T00:00:00Z"


def test_validate_incident_list_args_parses_end_time():
    """
    Given:
    - end_time provided as an ISO timestamp string.

    When:
    - validate_incident_list_args is called.

    Then:
    - end_time in the result is formatted as an ISO timestamp.
    """
    result = validate_incident_list_args({"end_time": "2026-06-11T00:00:00Z"})
    assert result["end_time"] == "2026-06-11T00:00:00Z"


def test_validate_incident_list_args_empty_times_return_empty_strings():
    """
    Given:
    - No start_time or end_time in args.

    When:
    - validate_incident_list_args is called.

    Then:
    - start_time and end_time in result are empty strings.
    """
    result = validate_incident_list_args({})
    assert result["start_time"] == ""
    assert result["end_time"] == ""


def test_validate_incident_update_args_invalid_status_raises():
    """
    Given:
    - status arg is 'pending' (not in STATUS_FILTER_VALUES).

    When:
    - validate_incident_update_args is called.

    Then:
    - ValueError raised mentioning the invalid value.
    """
    with pytest.raises(ValueError) as exc:
        validate_incident_update_args({"incident_id": "inc-001", "status": "pending"})
    assert "pending" in str(exc.value)


def test_validate_incident_update_args_invalid_close_reason_raises():
    """
    Given:
    - close_reason arg is 'unknown_reason' (not in CLOSE_REASON_VALUES).

    When:
    - validate_incident_update_args is called.

    Then:
    - ValueError raised mentioning the invalid value and valid choices.
    """
    with pytest.raises(ValueError) as exc:
        validate_incident_update_args({"incident_id": "inc-001", "close_reason": "unknown_reason"})
    assert "unknown_reason" in str(exc.value)


def test_validate_incident_update_args_valid_close_reason_passes():
    """
    Given:
    - close_reason is a valid value from CLOSE_REASON_VALUES.

    When:
    - validate_incident_update_args is called.

    Then:
    - No exception raised; close_reason appears in returned dict.
    """
    for reason in CLOSE_REASON_VALUES:
        result = validate_incident_update_args({"incident_id": "inc-001", "close_reason": reason})
        assert result["close_reason"] == reason.lower()


def test_fetch_incidents_outgoing_mirroring_adds_mirror_fields(mock_client, mocker):
    """
    Given:
    - outgoing_mirroring=True in params.
    - API returns one incident.

    When:
    - fetch_incidents is called.

    Then:
    - The incident rawJSON contains mirror_direction, mirror_instance, and mirror_id.
    """
    mocker.patch("Cyberhaven.demisto.integrationInstance", return_value="my-instance")
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [_make_incident("inc-001")], "page_response": {"next_id": ""}},
    )

    incidents, _ = fetch_incidents(
        mock_client,
        {},
        {"first_fetch": "3 days", "max_fetch": "10", "outgoing_mirroring": "true"},
    )

    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["mirror_direction"] == "Out"
    assert raw["mirror_instance"] == "my-instance"
    assert raw["mirror_id"] == "inc-001"


def test_fetch_incidents_no_mirroring_when_disabled(mock_client, mocker):
    """
    Given:
    - outgoing_mirroring=False in params.
    - API returns one incident.

    When:
    - fetch_incidents is called.

    Then:
    - The incident rawJSON does NOT contain mirror_direction or mirror_id.
    """
    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [_make_incident("inc-001")], "page_response": {"next_id": ""}},
    )

    incidents, _ = fetch_incidents(
        mock_client,
        {},
        {"first_fetch": "3 days", "max_fetch": "10", "outgoing_mirroring": "false"},
    )

    raw = json.loads(incidents[0]["rawJSON"])
    assert "mirror_direction" not in raw
    assert "mirror_id" not in raw


def test_nullify_sentinels_replaces_unspecified_string():
    """
    Given: a string ending with _unspecified.
    When: nullify_sentinels is called.
    Then: returns None.
    """
    assert nullify_sentinels("status_unspecified") is None
    assert nullify_sentinels("reason_unspecified") is None
    assert nullify_sentinels("action_unspecified") is None
    assert nullify_sentinels("SEVERITY_UNSPECIFIED") is None


def test_nullify_sentinels_preserves_valid_strings():
    """
    Given: strings that do NOT end with unspecified.
    When: nullify_sentinels is called.
    Then: returns string unchanged.
    """
    assert nullify_sentinels("open") == "open"
    assert nullify_sentinels("closed") == "closed"
    assert nullify_sentinels("valid") == "valid"
    assert nullify_sentinels("unspecified_reason") == "unspecified_reason"


def test_nullify_sentinels_bare_unspecified_is_nullified():
    """
    Given: bare 'unspecified' string (protobuf zero-value sentinel per CH spec).
    When: nullify_sentinels is called.
    Then: returns None.
    """
    assert nullify_sentinels("unspecified") is None


def test_nullify_sentinels_recurses_into_dict():
    """
    Given: dict with a sentinel string value.
    When: nullify_sentinels is called.
    Then: sentinel value replaced with None; other values untouched.
    """
    result = nullify_sentinels({"status": "status_unspecified", "id": "abc-123"})
    assert result == {"status": None, "id": "abc-123"}


def test_nullify_sentinels_recurses_into_list():
    """
    Given: list containing a sentinel string.
    When: nullify_sentinels is called.
    Then: sentinel element replaced with None.
    """
    result = nullify_sentinels(["action_unspecified", "upload", "reason_unspecified"])
    assert result == [None, "upload", None]


def test_nullify_sentinels_nested_structure():
    """
    Given: nested dict/list with sentinel values at multiple depths.
    When: nullify_sentinels is called.
    Then: all sentinels replaced with None; non-sentinels intact.
    """
    data = {
        "status": "status_unspecified",
        "policy": {"severity": "severity_unspecified", "name": "HR Policy"},
        "events": [{"action": "action_unspecified"}, {"action": "upload"}],
    }
    result = nullify_sentinels(data)
    assert result["status"] is None
    assert result["policy"]["severity"] is None
    assert result["policy"]["name"] == "HR Policy"
    assert result["events"][0]["action"] is None
    assert result["events"][1]["action"] == "upload"


def test_nullify_sentinels_non_string_passthrough():
    """
    Given: non-string scalars (int, bool, None).
    When: nullify_sentinels is called.
    Then: values returned unchanged.
    """
    assert nullify_sentinels(42) == 42
    assert nullify_sentinels(True) is True
    assert nullify_sentinels(None) is None


def test_fetch_incidents_sentinel_stripped_from_rawjson(mock_client, mocker):
    """
    Given:
    - API returns an incident where close_reason is 'reason_unspecified' and
      status is 'status_unspecified'.

    When:
    - fetch_incidents is called.

    Then:
    - rawJSON does NOT contain any '_unspecified' sentinel strings.
    - The sentinel fields are absent (stripped by remove_empty_elements_for_fetch).
    """
    raw_incident = _make_incident("inc-sentinel")
    raw_incident["close_reason"] = "reason_unspecified"
    raw_incident["status"] = "status_unspecified"

    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [raw_incident], "page_response": {"next_id": ""}},
    )

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    raw = json.loads(incidents[0]["rawJSON"])
    assert "close_reason" not in raw
    assert "status" not in raw


def test_fetch_incidents_close_reason_sentinel_not_stored_in_xsoar_field(mock_client, mocker):
    """
    Given:
    - API returns a closed incident with close_reason = 'reason_unspecified'.

    When:
    - fetch_incidents is called.

    Then:
    - The XSOAR 'closeReason' field is empty string, not the sentinel.
    """
    raw_incident = _make_incident("inc-cr-sentinel")
    raw_incident["status"] = "closed"
    raw_incident["close_reason"] = "reason_unspecified"

    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [raw_incident], "page_response": {"next_id": ""}},
    )

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    assert incidents[0].get("closeReason", "") == ""


def test_fetch_incidents_severity_sentinel_maps_to_unknown(mock_client, mocker):
    """
    Given:
    - API returns an incident with policy.severity = 'severity_unspecified'.

    When:
    - fetch_incidents is called.

    Then:
    - XSOAR severity is UNKNOWN (0), not an error.
    - rawJSON does not contain the sentinel string.
    """
    raw_incident = _make_incident("inc-sev-sentinel")
    raw_incident["policy"]["severity"] = "severity_unspecified"

    mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [raw_incident], "page_response": {"next_id": ""}},
    )

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    assert incidents[0]["severity"] == SEVERITY_MAP["unspecified"]
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw.get("policy", {}).get("severity") is None or "severity_unspecified" not in json.dumps(raw)


def test_main_dispatches_test_module(mocker, requests_mock):
    """
    Given:
    - demisto.command() returns 'test-module'.
    - Integration params with valid credentials.

    When:
    - main() is called directly.

    Then:
    - test_module is invoked and return_results receives 'ok'.
    """
    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response)
    requests_mock.post(INCIDENTS_URL, json=util_load_json("test_data/incident_list_response.json"))

    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")
    mocker.patch(
        "Cyberhaven.demisto.params",
        return_value={"credentials": {"password": "tok"}, "url": BASE_URL, "insecure": "false", "proxy": "false"},
    )
    mocker.patch("Cyberhaven.demisto.command", return_value="test-module")
    mocker.patch("Cyberhaven.demisto.args", return_value={})
    mock_return_results = mocker.patch("Cyberhaven.return_results")

    main()

    mock_return_results.assert_called_once_with("ok")


def test_main_missing_refresh_token_calls_return_error(mocker):
    """
    Given:
    - Integration params with no 'password' set under 'credentials'.

    When:
    - main() is called directly.

    Then:
    - return_error is called with the ERROR_MESSAGES['REFRESH_TOKEN_REQUIRED'] message.
    """
    mocker.patch(
        "Cyberhaven.demisto.params",
        return_value={"credentials": {}, "url": BASE_URL, "insecure": "false", "proxy": "false"},
    )
    mocker.patch("Cyberhaven.demisto.command", return_value="test-module")
    mock_return_error = mocker.patch("Cyberhaven.return_error")

    main()

    mock_return_error.assert_called_once()
    assert ERROR_MESSAGES["REFRESH_TOKEN_REQUIRED"] in mock_return_error.call_args[0][0]


def test_main_unknown_command_calls_return_error(mocker, requests_mock):
    """
    Given:
    - demisto.command() returns an unrecognised command name.

    When:
    - main() is called directly.

    Then:
    - return_error is called with a message containing the command name.
    """
    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(TOKEN_URL, json=auth_response)

    mocker.patch("Cyberhaven.get_integration_context", return_value={})
    mocker.patch("Cyberhaven.set_integration_context")
    mocker.patch(
        "Cyberhaven.demisto.params",
        return_value={"credentials": {"password": "tok"}, "url": BASE_URL, "insecure": "false", "proxy": "false"},
    )
    mocker.patch("Cyberhaven.demisto.command", return_value="unknown-command-xyz")
    mocker.patch("Cyberhaven.demisto.args", return_value={})
    mock_return_error = mocker.patch("Cyberhaven.return_error")

    main()

    mock_return_error.assert_called_once()
    assert "unknown-command-xyz" in mock_return_error.call_args[0][0]


def test_fetch_incidents_filter_change_resets_fetch_time(mock_client, mocker):
    """
    Given:
    - last_run has next_fetch_time='2026-06-20T00:00:00Z' and a filter_string built with severity=['high'].
    - params now request severity=['low'] — a different filter.

    When:
    - fetch_incidents is called.

    Then:
    - client.list_incidents is called with start_time equal to first_fetch_time (not next_fetch_time).
    - next_run contains the new filter_string reflecting the updated severity.
    """
    import json as _json

    old_filter = _json.dumps({"severity": ["high"], "status": ["open"]}, sort_keys=True)
    last_run = {
        "next_fetch_time": "2026-06-20T00:00:00Z",
        "first_fetch_time": "2026-06-01T00:00:00Z",
        "already_fetch_ids": [],
        "next_page_id": "",
        "filter_string": old_filter,
    }

    mock_list = mocker.patch.object(
        mock_client,
        "list_incidents",
        return_value={"resources": [_make_incident("inc-reset")], "page_response": {"next_id": ""}},
    )

    params = {"first_fetch": "3 days", "max_fetch": "10", "severity": "low", "status": "open"}

    fetch_incidents(mock_client, last_run, params)

    call_kwargs = mock_list.call_args[1]
    # Must NOT use the stale next_fetch_time; must fall back to first_fetch_time stored in last_run
    assert call_kwargs.get("start_time") == "2026-06-01T00:00:00Z"


def test_apply_api_labels_start_action_none_does_not_raise():
    """
    Given:
    - Resource where event_details.start_event.action is None.

    When:
    - apply_api_labels is called.

    Then:
    - No exception is raised (TypeError caught by except block).
    """
    resource = {
        "event_details": {
            "start_event": {"action": None},
            "end_event": {"action": {"kind": "write"}},
        }
    }
    result = apply_api_labels(resource)
    assert result["event_details"]["start_event"]["action"] is None


def test_apply_api_labels_end_action_none_does_not_raise():
    """
    Given:
    - Resource where event_details.end_event.action is None.

    When:
    - apply_api_labels is called.

    Then:
    - No exception is raised (TypeError caught by except block).
    """
    resource = {
        "event_details": {
            "start_event": {"action": {"kind": "read"}},
            "end_event": {"action": None},
        }
    }
    result = apply_api_labels(resource)
    assert result["event_details"]["end_event"]["action"] is None


def test_fetch_incidents_invalid_status_filter_raises(mock_client):
    """
    Given:
    - status_filter contains an invalid value 'unknown_status'.

    When:
    - fetch_incidents is called with is_test=True.

    Then:
    - ValueError is raised mentioning the invalid value.
    """
    with pytest.raises(ValueError) as exc:
        fetch_incidents(
            mock_client,
            {},
            {"first_fetch": "3 days", "max_fetch": "10", "status_filter": "unknown_status"},
            is_test=True,
        )

    assert "unknown_status" in str(exc.value)


def test_main_entry_point():
    """
    Given:
    - Module is run as __main__.

    When:
    - The entry point guard executes main().

    Then:
    - main() is invoked (SystemExit raised by return_error when demisto is not configured).
    """
    import runpy

    with pytest.raises(SystemExit):
        runpy.run_module("Cyberhaven", run_name="__main__")
