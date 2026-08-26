import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

"""
Idira Identity Response Actions
Command-based SOAR response integration for the Idira Identity Security Platform.

Implementation of the Identity (workforce) response actions: resolve a user, lock/disable/unlock, force logout, expire
password, and remove a privileged role. All actions target the Idira Identity
host (https://<tenant>.id.cyberark.cloud) with a single OAuth2 client_credentials
Bearer token obtained from /oauth2/platformtoken.

Privilege Cloud (session/credential) and SIA (access-policy) actions are planned
for a follow-up phase; EPM endpoint containment is delegated to the
IdiraEPMSOCResponse integration.
"""

INTEGRATION_NAME = "Idira Identity Response"

# region Constants


class Config:
    """Global static configuration (telemetry vendor fields, token defaults)."""

    # Telemetry (guide section 6). Confirm final values with the Idira TAM
    # before certification.
    INTEGRATION_VERSION = "1.0"
    INTEGRATION_TYPE = "SOAR"
    VENDOR_NAME = "Palo Alto Networks"

    # Token default settings
    DEFAULT_TOKEN_TTL_SECONDS = 6 * 60 * 60  # 6 hours
    CACHE_BUFFER_SECONDS = 60


# Integration-context cache keys for the OAuth2 token.
ACCESS_TOKEN = "access_token"
EXPIRES_IN = "expires_in"
VALID_UNTIL = "valid_until"

# Identity workforce user states (SetUserState).
STATE_LOCKED = "Locked"
STATE_DISABLED = "Disabled"
STATE_NONE = "None"

# ---------------------------------------------------------------------------
# [TBD] field names — the development guide flags these JSON keys as unconfirmed
# ("confirm against your tenant Swagger at /identity-docs-api"). They are
# isolated here so a single-line change fixes them once verified against a live
# tenant. See the README "Known Limitations" section.
# ---------------------------------------------------------------------------
# GetUserByName request body key (guide 7.1 curl shows lowercase "name").
GETUSER_NAME_KEY = "name"
# SignOutEverywhere request body key carrying the user unique ID (guide 7.4).
# Defaulted to "ID" for consistency with SetUserState; verify against Swagger.
SIGNOUT_USER_ID_KEY = "ID"

# endregion

# region Helpers


def generate_telemetry_header() -> str:
    """Build the base64-encoded ``x-cybr-telemetry`` header value.

    Format (guide section 6): ampersand-delimited key=value pairs
    ``in=<name>&it=<type>&iv=<version>&vn=<vendor>``.
    """
    telemetry_data = (
        f"in={INTEGRATION_NAME}&"
        f"it={Config.INTEGRATION_TYPE}&"
        f"iv={Config.INTEGRATION_VERSION}&"
        f"vn={Config.VENDOR_NAME}"
    )
    encoded = base64.b64encode(telemetry_data.encode()).decode()
    demisto.debug(f"[Telemetry] Generated header: {telemetry_data}")
    return encoded


def _extract_user_id(response: dict[str, Any]) -> str:
    """Read the user's unique ID from a GetUserByName response.

    The exact response shape is unconfirmed against a live tenant, so we probe a
    few documented/likely locations in order:
    ``UUID`` -> ``ID`` -> ``Result.ID`` -> ``Result.Users[0].ID``.
    Raises a clear error if none is present.
    """
    if not isinstance(response, dict):
        raise DemistoException("Unexpected GetUserByName response: not a JSON object.")

    for key in ("UUID", "ID"):
        value = response.get(key)
        if value:
            return str(value)

    result = response.get("Result")
    if isinstance(result, dict):
        if result.get("ID"):
            return str(result["ID"])
        users = result.get("Users")
        if isinstance(users, list) and users and isinstance(users[0], dict) and users[0].get("ID"):
            return str(users[0]["ID"])

    raise DemistoException(
        "Could not resolve user unique ID from GetUserByName response. "
        f"Response keys: {list(response.keys())}. Verify the response shape against your tenant Swagger."
    )


# endregion

# region Client


class Client(BaseClient):
    """Idira Identity Response API client.

    Holds a single ISPSS Bearer token (cached in integration context) and calls
    the Identity host via absolute ``full_url``. Structured so Privilege Cloud
    and SIA request wrappers can be added in a follow-up phase without touching
    the token logic.
    """

    def __init__(
        self,
        identity_url: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
    ):
        super().__init__(base_url=identity_url, verify=verify, proxy=proxy)
        self.identity_url = identity_url.rstrip("/")
        self.token_url = f"{self.identity_url}/oauth2/platformtoken"
        self.client_id = client_id
        self.client_secret = client_secret
        self.telemetry_header = generate_telemetry_header()

    def _get_access_token(self) -> str:
        """Get or refresh the OAuth2 client_credentials token with caching."""
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ACCESS_TOKEN)
        cached_valid_until = cached_context.get(VALID_UNTIL)

        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(float(cached_valid_until))
                if current_timestamp < valid_until_timestamp:
                    demisto.debug("[Token Cache] Hit! Token is still valid.")
                    return cached_token
                demisto.debug("[Token Cache] Miss. Token expired.")
            except (ValueError, TypeError):
                demisto.debug("[Token Cache] Error parsing cache. Ignoring.")

        demisto.debug(f"[Token Request] Requesting new token from {self.token_url}")

        token_data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            token_response = self._http_request(
                method="POST",
                full_url=self.token_url,
                data=token_data,
                headers=headers,
                resp_type="json",
            )
        except DemistoException as error:
            error_msg = str(error)
            demisto.error(f"[Token Request] Failed: {error_msg}")
            raise DemistoException(f"Failed to obtain access token: {error_msg}")

        access_token = token_response.get(ACCESS_TOKEN)
        if not access_token:
            raise DemistoException("Failed to obtain access token. Response missing access_token.")

        token_expires_in = token_response.get(EXPIRES_IN, Config.DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - Config.CACHE_BUFFER_SECONDS
        demisto.debug(f"[Token Request] Success. Expires in {token_expires_in}s.")

        set_integration_context({ACCESS_TOKEN: access_token, VALID_UNTIL: str(token_valid_until)})
        return access_token

    def _clear_cached_token(self) -> None:
        """Drop the cached token so the next call re-authenticates."""
        context = get_integration_context() or {}
        context.pop(ACCESS_TOKEN, None)
        context.pop(VALID_UNTIL, None)
        set_integration_context(context)

    def _request(
        self,
        method: str,
        full_url: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        _is_retry: bool = False,
    ) -> Any:
        """Execute an authenticated request and map errors per guide section 10.

        Returns the parsed JSON body (``{}`` for 204/empty). A 409 is treated as
        an idempotent success and returns ``{"status_code": 409}`` so callers can
        surface an "already in requested state" note.
        """
        access_token = self._get_access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "x-cybr-telemetry": self.telemetry_header,
            "Content-Type": "application/json",
        }

        demisto.debug(f"[HTTP Call] {method} {full_url}")
        try:
            http_response = self._http_request(
                method=method,
                full_url=full_url,
                json_data=json_data,
                params=params,
                headers=headers,
                resp_type="response",
                ok_codes=(200, 201, 202, 204, 409),
                retries=3,
                backoff_factor=2,
            )
        except DemistoException as error:
            error_msg = str(error)
            if "401" in error_msg and not _is_retry:
                # Token may have been revoked server-side before local expiry.
                demisto.debug("[HTTP Error] 401 received; clearing cached token and retrying once.")
                self._clear_cached_token()
                return self._request(method, full_url, json_data=json_data, params=params, _is_retry=True)
            if "401" in error_msg:
                raise DemistoException(
                    f"Authentication failed: {error_msg}. Verify Client ID / Client Secret and that the "
                    "service account uses ISPSS (Bearer) auth."
                )
            if "403" in error_msg:
                raise DemistoException(
                    f"Insufficient permissions: {error_msg}. Identity workforce actions require "
                    "system-administrator or user-management rights."
                )
            if "404" in error_msg:
                raise DemistoException(
                    f"Target not found: {error_msg}. Re-run idira-identity-response-get-user-by-name to "
                    "resolve the user unique ID."
                )
            if "429" in error_msg:
                raise DemistoException(f"Rate limited: {error_msg}. Retry later; do not retry in a tight loop.")
            raise

        status_code = http_response.status_code
        demisto.debug(f"[HTTP Call] Response Status: {status_code}")

        if status_code == 409:
            demisto.debug("[HTTP Call] 409 Conflict; treating as idempotent success.")
            return {"status_code": 409}

        if status_code == 204 or not http_response.text:
            return {}

        try:
            return http_response.json()
        except ValueError:
            demisto.debug(f"[HTTP Error] Non-JSON response. Status: {status_code}, Body: {http_response.text[:200]}")
            raise DemistoException(f"API returned non-JSON response with status {status_code}")

    def identity_request(
        self,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        method: str = "POST",
    ) -> Any:
        """Call an Idira Identity endpoint (host https://<tenant>.id.cyberark.cloud)."""
        return self._request(method=method, full_url=f"{self.identity_url}{path}", json_data=json_data, params=params)


# endregion

# region Command implementations


def test_module(client: Client) -> str:
    """Validate connectivity/auth by requesting an OAuth2 token."""
    try:
        client._get_access_token()
        return "ok"
    except Exception as error:
        error_msg = str(error)
        if "401" in error_msg or "403" in error_msg:
            return "Authorization Error: verify Identity URL, Client ID, and Client Secret."
        raise


def get_user_by_name_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Resolve a username to its user unique ID (guide 7.1)."""
    username = args["username"]
    response = client.identity_request("/CDirectoryService/GetUserByName", {GETUSER_NAME_KEY: username})
    user_id = _extract_user_id(response)

    outputs = {"ID": user_id, "Username": username}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.User",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Idira Identity User: {username}", outputs),
        raw_response=response,
    )


def _set_user_state(client: Client, user_id: str, state: str) -> CommandResults:
    """Set a user's account state via SetUserState (guide 7.4)."""
    response = client.identity_request("/CDirectoryService/SetUserState", {"ID": user_id, "State": state})
    already = isinstance(response, dict) and response.get("status_code") == 409

    outputs = {"ID": user_id, "State": state, "Success": True}
    note = " (already in requested state)" if already else ""
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.UserState",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=tableToMarkdown(f"User {user_id} state set to {state}{note}", outputs),
        raw_response=response,
    )


def lock_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _set_user_state(client, args["user_id"], STATE_LOCKED)


def disable_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _set_user_state(client, args["user_id"], STATE_DISABLED)


def unlock_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Reverse a lock/disable by setting the state back to None (guide table)."""
    return _set_user_state(client, args["user_id"], STATE_NONE)


def force_logout_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """End all of a user's sessions/cookies (guide 7.4, SignOutEverywhere)."""
    user_id = args["user_id"]
    response = client.identity_request("/UserMgmt/SignOutEverywhere", {SIGNOUT_USER_ID_KEY: user_id})

    outputs = {"ID": user_id, "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.ForceLogout",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Forced logout of all sessions for user {user_id}", outputs),
        raw_response=response,
    )


def expire_password_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Require the user to set a new password at next login (guide 7.4, ChangeUser)."""
    username = args["username"]
    response = client.identity_request(
        "/CDirectoryService/ChangeUser", {"Name": username, "ForcePasswordChangeNext": True}
    )

    outputs = {"Name": username, "ForcePasswordChangeNext": True, "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.PasswordExpiry",
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=tableToMarkdown(f"User {username} required to change password at next login", outputs),
        raw_response=response,
    )


def remove_role_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Strip standing privilege by removing users from a role (guide 7.4)."""
    role_id = args["role_id"]
    user_ids = argToList(args["user_ids"])
    response = client.identity_request(
        "/SaasManage/RemoveUsersAndGroupsFromRole", {"Name": role_id, "Users": user_ids}
    )

    outputs = {"RoleId": role_id, "Users": user_ids, "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.RoleRemoval",
        outputs_key_field="RoleId",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Removed {len(user_ids)} user(s) from role {role_id}", outputs),
        raw_response=response,
    )


# endregion

# region Main router

COMMAND_MAP: dict[str, Any] = {
    "idira-identity-response-get-user-by-name": get_user_by_name_command,
    "idira-identity-response-lock-user": lock_user_command,
    "idira-identity-response-disable-user": disable_user_command,
    "idira-identity-response-unlock-user": unlock_user_command,
    "idira-identity-response-force-logout": force_logout_command,
    "idira-identity-response-expire-password": expire_password_command,
    "idira-identity-response-remove-role": remove_role_command,
}


def main() -> None:
    """Main entry point for the Idira Identity Response integration."""
    command = demisto.command()
    demisto.debug(f"{INTEGRATION_NAME}: command '{command}'")

    params = demisto.params()
    identity_url = (params.get("identity_url") or "").strip().rstrip("/")
    client_id = (params.get("client_id") or "").strip()
    client_secret = (params.get("credentials") or {}).get("password", "")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    try:
        if not identity_url:
            raise DemistoException("Identity URL is required.")
        if not client_id:
            raise DemistoException("Client ID is required.")
        if not client_secret:
            raise DemistoException("Client Secret is required.")

        client = Client(
            identity_url=identity_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command in COMMAND_MAP:
            return_results(COMMAND_MAP[command](client, demisto.args()))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented")

    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(error)}")


# endregion


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
