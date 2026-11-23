"""Idira Identity Response Integration - Unit Tests

Pytest unit tests; all test function names must start with "test_".
More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import httpx
import pytest
from CommonServerPython import DemistoException
from ContentClientApiModule import (
    ContentClientAuthenticationError,
    ContentClientError,
    ContentClientRateLimitError,
)

import IdiraIdentityResponse
from IdiraIdentityResponse import (
    AuthTokenError,
    Client,
    _extract_user_id,
    build_adoption_event,
    disable_access_policy_command,
    disable_user_command,
    enable_access_policy_command,
    expire_password_command,
    force_logout_command,
    get_account_command,
    get_account_details_command,
    get_user_by_name_command,
    list_sessions_command,
    lock_user_command,
    remove_role_command,
    resume_session_command,
    rotate_credential_command,
    suspend_session_command,
    terminate_session_command,
    unlock_user_command,
    vault_account_command,
    verify_credential_command,
)
from IdiraIdentityResponse import test_module as run_test_module

IDENTITY_URL = "https://tenant.id.cyberark.cloud"
PRIVILEGE_CLOUD_URL = "https://tenant.privilegecloud.cyberark.cloud"
SIA_URL = "https://tenant.dpa.cyberark.cloud"
MOCK_CLIENT_ID = "svc-user"
MOCK_CLIENT_SECRET = "svc-secret"
MOCK_ACCESS_TOKEN = "mock-access-token"


@pytest.fixture
def client() -> Client:
    return Client(
        identity_url=IDENTITY_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        verify=False,
        proxy=False,
        privilege_cloud_url=PRIVILEGE_CLOUD_URL,
        sia_url=SIA_URL,
    )


@pytest.fixture
def identity_only_client() -> Client:
    """A client with no Privilege Cloud / SIA hosts configured."""
    return Client(
        identity_url=IDENTITY_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        verify=False,
        proxy=False,
    )


@pytest.fixture(autouse=True)
def _block_network(mocker):
    """Fail any test that would send a real HTTP request (e.g. a real Feature Adoption event).

    Every test must mock ``Client._http_request`` (or a higher-level method), or patch
    ``httpx.AsyncClient.send`` itself. Anything that reaches the real ``requests`` session or the real
    ``httpx`` transport is blocked, and the teardown assertion fails the test even if production code
    swallowed the raised error (``report_adoption_event`` catches all exceptions).
    """
    session_request = mocker.patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("Unmocked network call attempted in a unit test"),
    )
    httpx_send = mocker.patch(
        "httpx.AsyncClient.send",
        side_effect=AssertionError("Unmocked network call attempted in a unit test"),
    )
    yield
    assert session_request.call_count == 0, f"Unmocked network call(s) attempted: {session_request.call_args_list}"
    assert httpx_send.call_count == 0, f"Unmocked network call(s) attempted: {httpx_send.call_args_list}"


@pytest.fixture(autouse=True)
def _mock_multithreading(mocker):
    """ContentClient calls support_multithreading() on init, which needs a real demisto runtime."""
    mocker.patch("ContentClientApiModule.support_multithreading")


@pytest.fixture(autouse=True)
def _quiet_demisto_error(mocker):
    """ContentClient logs request failures via demisto.error(), which demistomock prints to stdout."""
    mocker.patch("demistomock.error")


@pytest.fixture(autouse=True)
def _mock_context(mocker):
    """Isolate integration-context reads/writes in every test."""
    store: dict = {}
    mocker.patch.object(IdiraIdentityResponse, "get_integration_context", side_effect=lambda: dict(store))
    mocker.patch.object(IdiraIdentityResponse, "set_integration_context", side_effect=lambda ctx: store.update(ctx) or store)
    return store


class _Resp:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text if text is not None else ("" if not json_data else "body")
        self.headers = {}

    def json(self):
        return self._json


# ========================================
# Helpers
# ========================================


def test_requests_do_not_send_telemetry_header(mocker, client):
    """Regular API calls no longer carry the legacy x-cybr-telemetry header."""
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    http = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"success": True}))
    client.identity_request("/UserMgmt/SetUserState", json_data={})
    headers = http.call_args.kwargs["headers"]
    assert "x-cybr-telemetry" not in headers
    assert headers["Authorization"] == f"Bearer {MOCK_ACCESS_TOKEN}"


def test_build_adoption_event():
    """The event matches the Feature Adoption authenticated-user schema (no user_id)."""
    event = build_adoption_event()
    assert event == {
        "metric_key": "IDIINT.cortex_identity_response.integration_executed",
        "number_of_events": 1,
        "triggered_by": "BE",
        "tags": {
            "vendor_name": "Palo Alto Networks",
            "integration_version": "1.0",
            "idira_service": "Idira ISPSS",
        },
    }
    assert "user_id" not in event


def test_report_adoption_event_swallows_errors(mocker, client):
    mocker.patch.object(Client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(Client, "_http_request", side_effect=DemistoException("400 invalid metric"))
    client.report_adoption_event()  # must not raise


def test_report_adoption_event_skipped_without_derivable_url(mocker):
    custom_client = Client(identity_url="https://custom.example.com", client_id="c", client_secret="s", verify=False, proxy=False)
    http = mocker.patch.object(Client, "_http_request")
    custom_client.report_adoption_event()
    http.assert_not_called()


@pytest.mark.parametrize(
    "response, expected",
    [({"Result": {"Uuid": "u-3"}}, "u-3")],
)
def test_extract_user_id_variants(response, expected):
    assert _extract_user_id(response) == expected


@pytest.mark.parametrize("result", ["a string", ["list"], 5])
def test_extract_user_id_non_dict_result_raises_clean_error(result):
    """A non-dict Result must raise the documented error, not an AttributeError."""
    with pytest.raises(DemistoException, match="Could not resolve user unique ID"):
        _extract_user_id({"Result": result})


def test_extract_user_id_missing_raises():
    with pytest.raises(DemistoException, match="Could not resolve user unique ID"):
        _extract_user_id({"foo": "bar"})


# ========================================
# Token / auth
# ========================================


def test_get_access_token_caches(mocker, client):
    """A valid cached token is reused without re-hitting the token endpoint."""
    http = mocker.patch.object(client, "_http_request", return_value={"access_token": MOCK_ACCESS_TOKEN, "expires_in": 900})

    assert client._get_access_token() == MOCK_ACCESS_TOKEN
    assert client._get_access_token() == MOCK_ACCESS_TOKEN  # served from cache
    assert http.call_count == 1


@pytest.mark.parametrize("expires_in", ["900", 900.0, "not-a-number", None])
def test_get_access_token_tolerates_non_int_expires_in(mocker, client, _mock_context, expires_in):
    mocker.patch.object(client, "_http_request", return_value={"access_token": MOCK_ACCESS_TOKEN, "expires_in": expires_in})

    assert client._get_access_token() == MOCK_ACCESS_TOKEN
    assert int(_mock_context["valid_until"]) > 0


def test_get_access_token_preserves_other_context_keys(mocker, client, _mock_context):
    _mock_context["unrelated_key"] = "keep-me"
    mocker.patch.object(client, "_http_request", return_value={"access_token": MOCK_ACCESS_TOKEN, "expires_in": 900})

    client._get_access_token()

    assert _mock_context["unrelated_key"] == "keep-me"
    assert _mock_context["access_token"] == MOCK_ACCESS_TOKEN


def test_get_access_token_missing_token_raises(mocker, client):
    mocker.patch.object(client, "_http_request", return_value={})
    with pytest.raises(DemistoException, match="missing access_token"):
        client._get_access_token()


def test_test_module_ok(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    assert run_test_module(client) == "ok"


def test_test_module_auth_error(mocker, client):
    mocker.patch.object(client, "_get_access_token", side_effect=AuthTokenError("Failed to obtain access token", status_code=401))
    assert "Authorization Error" in run_test_module(client)


def test_test_module_non_auth_error_propagates(mocker, client):
    mocker.patch.object(client, "_get_access_token", side_effect=AuthTokenError("Failed to obtain access token", status_code=500))
    with pytest.raises(AuthTokenError):
        run_test_module(client)


# ========================================
# Command happy paths
# ========================================


def test_get_user_by_name_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"Result": {"Uuid": "u-99"}}))

    result = get_user_by_name_command(client, {"username": "jdoe@corp"})

    assert result.outputs_prefix == "IdiraIdentityResponse.User"
    assert result.outputs == {"ID": "u-99", "Username": "jdoe@corp"}
    # Correct endpoint + body key.
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{IDENTITY_URL}/CDirectoryService/GetUserByName"
    assert kwargs["json_data"] == {"username": "jdoe@corp"}


@pytest.mark.parametrize(
    "command, expected_state",
    [
        (lock_user_command, "Locked"),
        (disable_user_command, "Disabled"),
        (unlock_user_command, "None"),
    ],
)
def test_set_user_state_commands(mocker, client, command, expected_state):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=200, json_data={"success": True}))

    result = command(client, {"user_id": "u-1"})

    assert result.outputs_prefix == "IdiraIdentityResponse.UserState"
    assert result.outputs == {"ID": "u-1", "State": expected_state, "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{IDENTITY_URL}/CDirectoryService/SetUserState"
    assert kwargs["json_data"] == {"ID": "u-1", "state": expected_state}


def test_force_logout_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=204))

    result = force_logout_command(client, {"user_id": "u-1"})

    assert result.outputs_prefix == "IdiraIdentityResponse.ForceLogout"
    assert result.outputs == {"ID": "u-1", "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{IDENTITY_URL}/UserMgmt/SignOutEverywhere"
    assert kwargs["json_data"] == {"ID": "u-1"}


def test_remove_role_command_csv(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"success": True}))

    result = remove_role_command(client, {"role_id": "r-1", "user_ids": "u-1,u-2"})

    assert result.outputs == {"RoleId": "r-1", "Users": ["u-1", "u-2"], "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{IDENTITY_URL}/SaasManage/RemoveUsersAndGroupsFromRole"
    assert kwargs["json_data"] == {"Name": "r-1", "Users": ["u-1", "u-2"]}


# ========================================
# Error handling (guide section 10)
# ========================================


def _http_error(status_code: int, message: str = "failure") -> ContentClientError:
    """Build the error ContentClient raises for a failed call, carrying the HTTP response."""
    response = httpx.Response(status_code, request=httpx.Request("POST", IDENTITY_URL), text="server said no")
    error_class = {
        401: ContentClientAuthenticationError,
        403: ContentClientAuthenticationError,
        429: ContentClientRateLimitError,
    }.get(status_code, ContentClientError)
    return error_class(message, response=response)


def test_401_clears_token_and_retries_once(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    clear = mocker.patch.object(client, "_clear_cached_token")
    # First call raises 401, retry succeeds.
    http = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[_http_error(401), _Resp(status_code=200, json_data={"success": True})],
    )

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True
    assert clear.call_count == 1
    assert http.call_count == 2


def test_401_persists_after_retry_raises(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    clear = mocker.patch.object(client, "_clear_cached_token")
    http = mocker.patch.object(client, "_http_request", side_effect=_http_error(401))

    with pytest.raises(DemistoException, match="Authentication failed"):
        lock_user_command(client, {"user_id": "u-1"})
    assert clear.call_count == 1
    assert http.call_count == 2  # exactly one retry, no loop


@pytest.mark.parametrize(
    "status_code, expected_match",
    [
        (403, "Insufficient permissions"),
        (404, "Target not found"),
        (429, "Rate limited"),
    ],
)
def test_error_mapping(mocker, client, status_code, expected_match):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_http_request", side_effect=_http_error(status_code))

    with pytest.raises(DemistoException, match=expected_match):
        lock_user_command(client, {"user_id": "u-1"})


def test_error_mapping_ignores_status_digits_in_message(mocker, client):
    """Mapping keys off the HTTP status, not digits that happen to appear in the error text."""
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    error = _http_error(500, message="request id 4010-4040-4290 failed")
    mocker.patch.object(client, "_http_request", side_effect=error)

    with pytest.raises(ContentClientError, match="request id 4010-4040-4290 failed"):
        lock_user_command(client, {"user_id": "u-1"})


def test_409_conflict_is_idempotent_success(mocker, client):
    """A 409 (already in requested state) is surfaced as a success, not a crash."""
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=409))

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True


# ========================================
# Real ContentClient transport (only httpx's send is faked)
# ========================================


def _httpx_response(status_code: int, json_data=None, headers=None) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=json_data if json_data is not None else {},
        headers=headers,
        request=httpx.Request("POST", IDENTITY_URL),
    )


@pytest.fixture
def no_sleep(mocker):
    """Skip retry backoff delays."""
    mocker.patch("ContentClientApiModule.anyio.sleep", new=mocker.AsyncMock())


def test_transport_success_sends_bearer_and_json(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    send = mocker.patch("httpx.AsyncClient.send", side_effect=[_httpx_response(200, {"success": True})])

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True
    sent_request = send.call_args.args[0]
    assert str(sent_request.url) == f"{IDENTITY_URL}/CDirectoryService/SetUserState"
    assert sent_request.headers["Authorization"] == f"Bearer {MOCK_ACCESS_TOKEN}"
    assert b'"state"' in sent_request.content


def test_transport_401_refreshes_token_and_retries_once(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    clear = mocker.patch.object(client, "_clear_cached_token")
    send = mocker.patch("httpx.AsyncClient.send", side_effect=[_httpx_response(401), _httpx_response(200, {"success": True})])

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True
    assert clear.call_count == 1
    assert send.call_count == 2


def test_transport_persistent_401_stops_after_one_retry(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_clear_cached_token")
    send = mocker.patch("httpx.AsyncClient.send", side_effect=[_httpx_response(401), _httpx_response(401)])

    with pytest.raises(DemistoException, match="Authentication failed"):
        lock_user_command(client, {"user_id": "u-1"})
    assert send.call_count == 2


@pytest.mark.parametrize(
    "status_code, expected_match",
    [(403, "Insufficient permissions"), (404, "Target not found"), (429, "Rate limited")],
)
def test_transport_error_mapping(mocker, client, no_sleep, status_code, expected_match):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch("httpx.AsyncClient.send", side_effect=lambda *_: _httpx_response(status_code))

    with pytest.raises(DemistoException, match=expected_match):
        lock_user_command(client, {"user_id": "u-1"})


def test_transport_409_is_idempotent_success(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch("httpx.AsyncClient.send", side_effect=[_httpx_response(409)])

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True


def test_transport_retries_server_errors(mocker, client, no_sleep):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    send = mocker.patch(
        "httpx.AsyncClient.send",
        side_effect=[_httpx_response(503), _httpx_response(503), _httpx_response(200, {"success": True})],
    )

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True
    assert send.call_count == 3


def test_transport_gives_up_after_configured_retries(mocker, client, no_sleep):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    send = mocker.patch("httpx.AsyncClient.send", side_effect=lambda *_: _httpx_response(503))

    with pytest.raises(ContentClientError):
        lock_user_command(client, {"user_id": "u-1"})
    assert send.call_count == 4  # 1 attempt + 3 retries


def test_transport_token_request_is_single_attempt_form_post(mocker, client, no_sleep):
    """The token call is not retried and posts form-encoded credentials."""
    send = mocker.patch("httpx.AsyncClient.send", side_effect=lambda *_: _httpx_response(503))

    with pytest.raises(AuthTokenError) as excinfo:
        client._get_access_token()

    assert send.call_count == 1
    assert excinfo.value.status_code == 503
    assert MOCK_CLIENT_SECRET not in str(excinfo.value)


def test_transport_token_success_is_cached(mocker, client):
    send = mocker.patch(
        "httpx.AsyncClient.send", side_effect=[_httpx_response(200, {"access_token": MOCK_ACCESS_TOKEN, "expires_in": 900})]
    )

    assert client._get_access_token() == MOCK_ACCESS_TOKEN
    assert client._get_access_token() == MOCK_ACCESS_TOKEN
    sent_request = send.call_args.args[0]
    assert str(sent_request.url) == f"{IDENTITY_URL}/oauth2/platformtoken"
    assert b"grant_type=client_credentials" in sent_request.content
    assert send.call_count == 1


def test_transport_test_module_reports_bad_credentials(mocker, client):
    mocker.patch("httpx.AsyncClient.send", side_effect=[_httpx_response(401)])
    assert "Authorization Error" in run_test_module(client)


def test_transport_adoption_report_is_single_attempt_and_never_raises(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    send = mocker.patch("httpx.AsyncClient.send", side_effect=lambda *_: _httpx_response(503))

    client.report_adoption_event()  # must not raise

    assert send.call_count == 1


# ========================================
# Identity — expire password
# ========================================


def test_expire_password_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"success": True}))

    result = expire_password_command(client, {"username": "jdoe"})

    assert result.outputs == {"Name": "jdoe", "ForcePasswordChangeNext": True, "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{IDENTITY_URL}/CDirectoryService/ChangeUser"
    assert kwargs["json_data"] == {"Name": "jdoe", "ForcePasswordChangeNext": True}


# ========================================
# Privilege Cloud — accounts
# ========================================


def test_get_account_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(
        client,
        "_http_request",
        return_value=_Resp(json_data={"value": [{"id": "12_34", "name": "svc-sql", "safeName": "IR"}]}),
    )

    result = get_account_command(client, {"search": "svc-sql"})

    assert result.outputs == [
        {
            "id": "12_34",
            "name": "svc-sql",
            "userName": None,
            "safeName": "IR",
            "platformId": None,
            "address": None,
            "secretType": None,
        }
    ]
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/Accounts"
    assert kwargs["method"] == "GET"
    assert kwargs["params"] == {"search": "svc-sql", "searchType": "contains", "limit": 50}


def test_get_account_details_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"id": "12_34", "name": "svc-sql"}))

    result = get_account_details_command(client, {"account_id": "12_34"})

    assert result.outputs["id"] == "12_34"
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/Accounts/12_34"


def test_command_requires_privilege_cloud_url(mocker, identity_only_client):
    """Privilege Cloud commands raise a clear error when the host is unconfigured."""
    mocker.patch.object(identity_only_client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    with pytest.raises(DemistoException, match="requires the Privilege Cloud URL"):
        get_account_command(identity_only_client, {"search": "svc-sql"})


# ========================================
# Privilege Cloud — sessions
# ========================================


def test_list_sessions_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(
        client,
        "_http_request",
        return_value=_Resp(json_data={"LiveSessions": [{"SessionGuid": "s-1", "CanTerminate": True}]}),
    )

    result = list_sessions_command(client, {"search": "jdoe"})

    assert result.outputs[0]["SessionGuid"] == "s-1"
    assert result.outputs[0]["CanTerminate"] is True
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/LiveSessions"
    assert kwargs["params"] == {"Search": "jdoe", "Limit": 25}


@pytest.mark.parametrize(
    "command, action",
    [
        (terminate_session_command, "Terminate"),
        (suspend_session_command, "Suspend"),
        (resume_session_command, "Resume"),
    ],
)
def test_session_actions(mocker, client, command, action):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=200))

    result = command(client, {"session_guid": "s-1"})

    assert result.outputs == {"SessionGuid": "s-1", "Action": action, "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/LiveSessions/s-1/{action}/"


# ========================================
# Privilege Cloud — credentials
# ========================================


def test_rotate_credential_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=200))

    result = rotate_credential_command(client, {"account_id": "12_34"})

    assert result.outputs == {"AccountId": "12_34", "Action": "Rotate", "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/Accounts/12_34/Change/"
    assert kwargs["json_data"] == {"ChangeCredsForGroup": False}


def test_verify_credential_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=200))

    result = verify_credential_command(client, {"account_id": "12_34"})

    assert result.outputs == {"AccountId": "12_34", "Action": "Verify", "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/Accounts/12_34/Verify/"


def test_vault_account_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"id": "99_1"}))

    result = vault_account_command(
        client,
        {
            "platform_id": "WinServerLocal",
            "safe_name": "IR",
            "name": "risky",
            "automatic_management_enabled": "true",
        },
    )

    assert result.outputs["id"] == "99_1"
    assert result.outputs["Success"] is True
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{PRIVILEGE_CLOUD_URL}/PasswordVault/API/Accounts"
    assert kwargs["json_data"] == {
        "platformId": "WinServerLocal",
        "safeName": "IR",
        "name": "risky",
        "secretManagement": {"automaticManagementEnabled": True},
    }


# ========================================
# SIA — access policy
# ========================================


POLICY = {
    "policyId": None,
    "policyName": "Prod SSH",
    "policyType": "VM",
    "description": "prod access",
    "status": "Enabled",
    "startDate": "2023-01-10",
    "providersData": {"AWS": {"regions": ["us-east-1"]}},
    "userAccessRules": [{"ruleName": "dev-team-access", "userData": {"roles": ["DEV_TEAM_ROLE"]}}],
    "activationType": "RECURRING",
}


def _mock_policy_calls(mocker, client, policy):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    return mocker.patch.object(
        client,
        "_http_request",
        side_effect=[_Resp(status_code=200, json_data=policy), _Resp(status_code=200)],
    )


def test_disable_access_policy_command(mocker, client):
    http = _mock_policy_calls(mocker, client, POLICY)

    result = disable_access_policy_command(client, {"policy_id": "p-1"})

    assert result.outputs == {
        "PolicyId": "p-1",
        "PolicyName": "Prod SSH",
        "PreviousStatus": "Enabled",
        "Status": "Disabled",
        "Success": True,
    }
    get_kwargs, put_kwargs = (call.kwargs for call in http.call_args_list)
    assert get_kwargs["method"] == "GET"
    assert get_kwargs["full_url"] == f"{SIA_URL}/api/access-policies/p-1"
    assert put_kwargs["method"] == "PUT"
    assert put_kwargs["full_url"] == f"{SIA_URL}/api/access-policies/p-1"


def test_access_policy_update_preserves_policy_body(mocker, client):
    """The PUT replaces the whole policy, so only status/policyId may differ from the GET response."""
    http = _mock_policy_calls(mocker, client, POLICY)

    disable_access_policy_command(client, {"policy_id": "p-1"})

    body = http.call_args_list[1].kwargs["json_data"]
    expected = {key: value for key, value in POLICY.items() if key != "activationType"}
    expected.update({"policyId": "p-1", "status": "Disabled"})
    assert body == expected


def test_enable_access_policy_command(mocker, client):
    http = _mock_policy_calls(mocker, client, {**POLICY, "status": "Disabled"})

    result = enable_access_policy_command(client, {"policy_id": "p-1"})

    assert result.outputs["Status"] == "Enabled"
    assert result.outputs["PreviousStatus"] == "Disabled"
    assert http.call_args_list[1].kwargs["json_data"]["status"] == "Enabled"


def test_access_policy_unexpected_get_response_does_not_update(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    http = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=200))

    with pytest.raises(DemistoException, match="Could not read access policy"):
        disable_access_policy_command(client, {"policy_id": "p-1"})
    assert http.call_count == 1  # no PUT was sent


def test_access_policy_requires_sia_url(mocker, identity_only_client):
    mocker.patch.object(identity_only_client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    with pytest.raises(DemistoException, match="requires the Secure Infrastructure Access"):
        disable_access_policy_command(identity_only_client, {"policy_id": "p-1"})
    with pytest.raises(DemistoException, match="requires the Secure Infrastructure Access"):
        enable_access_policy_command(identity_only_client, {"policy_id": "p-1"})


# ========================================
# Usage reporting opt-out
# ========================================


def test_report_adoption_event_skipped_when_usage_reporting_disabled(mocker):
    """With the opt-out checked, nothing is sent: no token request and no event POST."""
    opted_out_client = Client(
        identity_url=IDENTITY_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        verify=False,
        proxy=False,
        usage_reporting_enabled=False,
    )
    token = mocker.patch.object(Client, "_get_access_token")
    http = mocker.patch.object(Client, "_http_request")
    opted_out_client.report_adoption_event()
    token.assert_not_called()
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
    params = {
        "identity_url": IDENTITY_URL,
        "client_id": MOCK_CLIENT_ID,
        "credentials": {"password": MOCK_CLIENT_SECRET},
    }
    if disable_param is not None:
        params["disable_usage_reporting"] = disable_param
    mocker.patch.object(IdiraIdentityResponse.demisto, "params", return_value=params)
    mocker.patch.object(IdiraIdentityResponse.demisto, "args", return_value={"user_id": "u-1"})
    mocker.patch.object(IdiraIdentityResponse.demisto, "command", return_value="idira-identity-response-unlock-user")
    mocker.patch.dict(IdiraIdentityResponse.COMMAND_MAP, {"idira-identity-response-unlock-user": lambda client, args: "result"})
    mocker.patch.object(IdiraIdentityResponse, "return_results")
    seen: list[bool] = []
    mocker.patch.object(
        Client, "report_adoption_event", autospec=True, side_effect=lambda client: seen.append(client.usage_reporting_enabled)
    )
    IdiraIdentityResponse.main()
    assert seen == [expected_enabled]
