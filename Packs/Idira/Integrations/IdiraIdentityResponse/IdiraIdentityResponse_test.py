"""Idira Identity Response Integration - Unit Tests

Pytest unit tests; all test function names must start with "test_".
More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import base64

import pytest
from CommonServerPython import DemistoException

import IdiraIdentityResponse
from IdiraIdentityResponse import (
    Client,
    _extract_user_id,
    disable_user_command,
    expire_password_command,
    force_logout_command,
    generate_telemetry_header,
    get_user_by_name_command,
    lock_user_command,
    remove_role_command,
    unlock_user_command,
)
from IdiraIdentityResponse import test_module as run_test_module

IDENTITY_URL = "https://tenant.id.cyberark.cloud"
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
    )


@pytest.fixture(autouse=True)
def _mock_context(mocker):
    """Isolate integration-context reads/writes in every test."""
    store: dict = {}
    mocker.patch.object(IdiraIdentityResponse, "get_integration_context", side_effect=lambda: dict(store))
    mocker.patch.object(
        IdiraIdentityResponse, "set_integration_context", side_effect=lambda ctx: store.update(ctx) or store
    )
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


def test_generate_telemetry_header():
    """The telemetry header base64-decodes to the expected key=value pairs."""
    decoded = base64.b64decode(generate_telemetry_header()).decode()
    assert "in=Idira Identity Response" in decoded
    assert "it=SOAR" in decoded
    assert "iv=1.0" in decoded
    assert "vn=Palo Alto Networks" in decoded


@pytest.mark.parametrize(
    "response, expected",
    [
        ({"Result": {"Uuid": "u-3"}}, "u-3")
    ],
)
def test_extract_user_id_variants(response, expected):
    assert _extract_user_id(response) == expected


def test_extract_user_id_missing_raises():
    with pytest.raises(DemistoException, match="Could not resolve user unique ID"):
        _extract_user_id({"foo": "bar"})


# ========================================
# Token / auth
# ========================================


def test_get_access_token_caches(mocker, client):
    """A valid cached token is reused without re-hitting the token endpoint."""
    http = mocker.patch.object(
        client, "_http_request", return_value={"access_token": MOCK_ACCESS_TOKEN, "expires_in": 900}
    )

    assert client._get_access_token() == MOCK_ACCESS_TOKEN
    assert client._get_access_token() == MOCK_ACCESS_TOKEN  # served from cache
    assert http.call_count == 1


def test_get_access_token_missing_token_raises(mocker, client):
    mocker.patch.object(client, "_http_request", return_value={})
    with pytest.raises(DemistoException, match="missing access_token"):
        client._get_access_token()


def test_test_module_ok(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    assert run_test_module(client) == "ok"


def test_test_module_auth_error(mocker, client):
    mocker.patch.object(client, "_get_access_token", side_effect=DemistoException("Error 401 Unauthorized"))
    assert "Authorization Error" in run_test_module(client)


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
    assert kwargs["json_data"] == {"name": "jdoe@corp"}


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
    assert kwargs["json_data"] == {"ID": "u-1", "State": expected_state}


def test_force_logout_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=204))

    result = force_logout_command(client, {"user_id": "u-1"})

    assert result.outputs_prefix == "IdiraIdentityResponse.ForceLogout"
    assert result.outputs == {"ID": "u-1", "Success": True}
    _, kwargs = resp.call_args
    assert kwargs["full_url"] == f"{IDENTITY_URL}/UserMgmt/SignOutEverywhere"
    assert kwargs["json_data"] == {"ID": "u-1"}


def test_expire_password_command(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    resp = mocker.patch.object(client, "_http_request", return_value=_Resp(json_data={"success": True}))

    result = expire_password_command(client, {"username": "jdoe"})

    assert result.outputs_prefix == "IdiraIdentityResponse.PasswordExpiry"
    assert result.outputs["ForcePasswordChangeNext"] is True
    _, kwargs = resp.call_args
    assert kwargs["json_data"] == {"Name": "jdoe", "ForcePasswordChangeNext": True}


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


def test_409_treated_as_idempotent_success(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_http_request", return_value=_Resp(status_code=409))

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True
    assert "already in requested state" in result.readable_output


def test_401_clears_token_and_retries_once(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    clear = mocker.patch.object(client, "_clear_cached_token")
    # First call raises 401, retry succeeds.
    http = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[DemistoException("Error 401 Unauthorized"), _Resp(status_code=200, json_data={"ok": True})],
    )

    result = lock_user_command(client, {"user_id": "u-1"})

    assert result.outputs["Success"] is True
    assert clear.call_count == 1
    assert http.call_count == 2


def test_401_persists_after_retry_raises(mocker, client):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_clear_cached_token")
    mocker.patch.object(client, "_http_request", side_effect=DemistoException("Error 401 Unauthorized"))

    with pytest.raises(DemistoException, match="Authentication failed"):
        lock_user_command(client, {"user_id": "u-1"})


@pytest.mark.parametrize(
    "error_text, expected_match",
    [
        ("Error 403 Forbidden", "Insufficient permissions"),
        ("Error 404 Not Found", "Target not found"),
        ("Error 429 Too Many Requests", "Rate limited"),
    ],
)
def test_error_mapping(mocker, client, error_text, expected_match):
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_http_request", side_effect=DemistoException(error_text))

    with pytest.raises(DemistoException, match=expected_match):
        lock_user_command(client, {"user_id": "u-1"})
