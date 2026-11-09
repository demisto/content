from urllib.parse import urlparse

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

EPM endpoint containment is delegated to the IdiraEPMSOCResponse integration.
"""

INTEGRATION_NAME = "Idira Identity Response"

# region Constants


class Config:
    """Global static configuration (Feature Adoption reporting fields, token defaults)."""
    INTEGRATION_VERSION = "1.0"
    VENDOR_NAME = "Palo Alto Networks"

    # Feature Adoption service (metric_key = <service_code>.<master_feature_name>.<metric_name>).
    ADOPTION_SERVICE_CODE = "IDIINT"
    ADOPTION_FEATURE_NAME = "cortex_idira_identity_response"
    ADOPTION_METRIC_NAME = "integration_executed"
    ADOPTION_IDIRA_SERVICE = "Idira ISPSS"
    ADOPTION_TRIGGERED_BY = "BE"  # allowed: "BE", "UI", "N/A"
    ADOPTION_ENDPOINT_PATH = "/api/feature-adoption"
    ADOPTION_HOST_PREFIX = "us-east-1-featureadopt.featureadopt"
    ADOPTION_TIMEOUT_SECONDS = 10

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
STATE_EXPIRED = "Expired"
STATE_NONE = "None"

# SIA access-policy status values (disable-access-policy).
POLICY_STATUS_DISABLED = "Disabled"
POLICY_STATUS_ENABLED = "Enabled"

# endregion

# region Helpers


def build_adoption_event() -> dict[str, Any]:
    """Build the Feature Adoption event body (authenticated-user schema).

    ``user_id`` is intentionally omitted: for authenticated callers the service
    extracts it from the JWT. Tag keys must be snake_case alphanumeric strings.
    """
    return {
        "metric_key": f"{Config.ADOPTION_SERVICE_CODE}.{Config.ADOPTION_FEATURE_NAME}.{Config.ADOPTION_METRIC_NAME}",
        "number_of_events": 1,
        "triggered_by": Config.ADOPTION_TRIGGERED_BY,
        "tags": {
            "vendor_name": Config.VENDOR_NAME,
            "integration_version": Config.INTEGRATION_VERSION,
            "idira_service": Config.ADOPTION_IDIRA_SERVICE,
        },
    }


def get_adoption_url(identity_url: str) -> str:
    """Derive the Feature Adoption API URL from the tenant Identity URL.

    ``https://<tenant>.id.<root domain>`` -> ``https://us-east-1-featureadopt.featureadopt.<root domain>/api/feature-adoption``.
    Returns an empty string if the root domain cannot be determined.
    """
    host = urlparse(identity_url).hostname or ""
    _, separator, root_domain = host.partition(".id.")
    if not separator or not root_domain:
        return ""
    return f"https://{Config.ADOPTION_HOST_PREFIX}.{root_domain}{Config.ADOPTION_ENDPOINT_PATH}"


def _extract_user_id(response: dict[str, Any]) -> str:
    """Read the user's unique ID from a GetUserByName response.

    The exact response shape is unconfirmed against a live tenant, so we probe a
    few documented/likely locations in order:
    ``UUID`` -> ``ID`` -> ``Result.ID`` -> ``Result.Users[0].ID``.
    Raises a clear error if none is present.
    """
    if not isinstance(response, dict):
        raise DemistoException("Unexpected GetUserByName response: not a JSON object.")

    result = response.get("Result")
    if not result or not result.get("Uuid"):
        raise DemistoException(
            "Could not resolve user unique ID from GetUserByName response. "
            f"Response keys: {list(response.keys())}. Verify the response shape against your tenant Swagger."
        )
    return result.get("Uuid")


def _identity_success(response: dict[str, Any]) -> bool:
    """Read the ``success`` flag from an Idira Identity response.

    Identity endpoints return the flag at the top level as ``{"success": bool, ...}``.
    A 409 (idempotent conflict) is surfaced as ``{"status_code": 409}`` by the
    request layer and is treated as success (target already in requested state).
    """
    if not isinstance(response, dict):
        return False
    if response.get("status_code") == 409:
        return True
    return bool(response.get("success"))

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
        privilege_cloud_url: str = "",
        sia_url: str = "",
    ):
        super().__init__(base_url=identity_url, verify=verify, proxy=proxy)
        self.identity_url = identity_url.rstrip("/")
        self.token_url = f"{self.identity_url}/oauth2/platformtoken"
        self.client_id = client_id
        self.client_secret = client_secret
        # Optional shared-services hosts. All three use the same ISPSS Bearer
        # token, so a single _get_access_token() serves every request wrapper.
        self.privilege_cloud_url = privilege_cloud_url.rstrip("/")
        self.sia_url = sia_url.rstrip("/")

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
        """Execute an authenticated request and map.

        Returns the parsed JSON body (``{}`` for 204/empty). A 409 is treated as
        an idempotent success and returns ``{"status_code": 409}`` so callers can
        surface an "already in requested state" note.
        """
        access_token = self._get_access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
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

    def report_adoption_event(self) -> None:
        """Report an ``integration_executed`` event to the Feature Adoption service.

        Best effort: a single attempt with a short timeout. Any failure is logged
        and swallowed so telemetry can never break a response action.
        """
        adoption_url = get_adoption_url(self.identity_url)
        if not adoption_url:
            demisto.debug(f"[Adoption] Could not derive the Feature Adoption URL from {self.identity_url}; skipping.")
            return
        try:
            self._http_request(
                method="POST",
                full_url=adoption_url,
                json_data=build_adoption_event(),
                headers={"Authorization": f"Bearer {self._get_access_token()}", "Content-Type": "application/json"},
                resp_type="response",
                ok_codes=(200, 202),
                timeout=Config.ADOPTION_TIMEOUT_SECONDS,
            )
            demisto.debug("[Adoption] Event reported.")
        except Exception as error:
            demisto.debug(f"[Adoption] Failed to report event (ignored): {error}")

    def identity_request(
        self,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        method: str = "POST",
    ) -> Any:
        """Call an Idira Identity endpoint (host https://<tenant>.id.cyberark.cloud)."""
        return self._request(method=method, full_url=f"{self.identity_url}{path}", json_data=json_data, params=params)

    def privilege_cloud_request(
        self,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        method: str = "POST",
    ) -> Any:
        """Call an Idira Privilege Cloud PVWA endpoint.

        Host https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API.
        Raises if the Privilege Cloud URL was not configured on the instance.
        """
        if not self.privilege_cloud_url:
            raise DemistoException(
                "This command requires the Privilege Cloud URL. Set it in the integration instance configuration "
                "(e.g., https://<subdomain>.privilegecloud.cyberark.cloud)."
            )
        full_url = f"{self.privilege_cloud_url}/PasswordVault/API{path}"
        return self._request(method=method, full_url=full_url, json_data=json_data, params=params)

    def sia_request(
        self,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        method: str = "POST",
    ) -> Any:
        """Call an Idira Secure Infrastructure Access (SIA) endpoint.

        Host https://<subdomain>.dpa.cyberark.cloud/api. Raises if the SIA URL
        was not configured on the instance.
        """
        if not self.sia_url:
            raise DemistoException(
                "This command requires the Secure Infrastructure Access (SIA) URL. Set it in the integration "
                "instance configuration (e.g., https://<subdomain>.dpa.cyberark.cloud)."
            )
        full_url = f"{self.sia_url}/api{path}"
        return self._request(method=method, full_url=full_url, json_data=json_data, params=params)


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
    """Resolve a username to its user unique ID."""
    username = args["username"]
    response = client.identity_request("/CDirectoryService/GetUserByName", {'username': username})
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
    """Set a user's account state via SetUserState."""
    response = client.identity_request("/CDirectoryService/SetUserState", {"ID": user_id, "state": state})

    success = _identity_success(response)
    outputs = {"ID": user_id, "State": state, "Success": success}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.UserState",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=tableToMarkdown(f"User {user_id} state set to {state}", outputs),
        raw_response=response,
    )


def lock_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _set_user_state(client, args["user_id"], STATE_LOCKED)


def disable_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _set_user_state(client, args["user_id"], STATE_DISABLED)


def unlock_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Reverse a lock/disable by setting the state back to None."""
    return _set_user_state(client, args["user_id"], STATE_NONE)


def force_logout_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """End all of a user's sessions/cookies"""
    user_id = args["user_id"]
    response = client.identity_request("/UserMgmt/SignOutEverywhere", {'ID': user_id})

    outputs = {"ID": user_id, "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.ForceLogout",
        outputs_key_field="ID",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Forced logout of all sessions for user {user_id}", outputs),
        raw_response=response,
    )


def expire_password_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Require the user to set a new password at next login."""
    username = args["username"]
    response = client.identity_request(
        "/CDirectoryService/ChangeUser", {"Name": username, "ForcePasswordChangeNext": True}
    )

    success = _identity_success(response)
    outputs = {"Name": username, "ForcePasswordChangeNext": True, "Success": success}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.PasswordExpiry",
        outputs_key_field="Name",
        outputs=outputs,
        readable_output=tableToMarkdown(f"User {username} required to change password at next login", outputs),
        raw_response=response,
    )


def remove_role_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Strip standing privilege by removing users from a role."""
    role_id = args["role_id"]
    user_ids = argToList(args["user_ids"])
    response = client.identity_request(
        "/SaasManage/RemoveUsersAndGroupsFromRole", {"Name": role_id, "Users": user_ids}
    )
    success = _identity_success(response)
    outputs = {"RoleId": role_id, "Users": user_ids, "Success": success}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.RoleRemoval",
        outputs_key_field="RoleId",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Removed {len(user_ids)} user(s) from role {role_id}", outputs),
        raw_response=response,
    )


# --- Privilege Cloud: account resolution -----------------------------------


ACCOUNT_OUTPUT_FIELDS = ("id", "name", "userName", "safeName", "platformId", "address", "secretType")


def get_account_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Resolve privileged account(s) to their internal ID(s).

    Rotate and verify calls require the internal account ID; run this first.
    """
    params: dict[str, Any] = {
        "search": args.get("search"),
        "searchType": args.get("search_type", "contains"),
        "safeName": args.get("safe_name"),
        "limit": arg_to_number(args.get("limit")) or 50,
    }
    params = {key: value for key, value in params.items() if value not in (None, "")}
    response = client.privilege_cloud_request("/Accounts", params=params, method="GET")

    accounts = response.get("value") or []
    outputs = [{field: account.get(field) for field in ACCOUNT_OUTPUT_FIELDS} for account in accounts]
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.Account",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown(
            f"Idira Privilege Cloud Accounts ({len(outputs)})", outputs, headers=list(ACCOUNT_OUTPUT_FIELDS)
        ),
        raw_response=response,
    )


def get_account_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch a single account's details by ID."""
    account_id = args["account_id"]
    response = client.privilege_cloud_request(f"/Accounts/{account_id}", method="GET")

    outputs = {field: response.get(field) for field in ACCOUNT_OUTPUT_FIELDS}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.Account",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Idira Privilege Cloud Account: {account_id}", outputs),
        raw_response=response,
    )


# --- Privilege Cloud: privileged sessions ----------------------------------


SESSION_OUTPUT_FIELDS = (
    "SessionGuid",
    "User",
    "AccountUsername",
    "AccountAddress",
    "RemoteMachine",
    "Protocol",
    "RiskScore",
    "CanTerminate",
    "CanSuspend",
    "CanMonitor",
)


def list_sessions_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List active privileged sessions to resolve a SessionGuid.

    Check the ``CanTerminate`` / ``CanSuspend`` flags before acting on a session.
    """
    params: dict[str, Any] = {
        "Search": args.get("search"),
        "Safe": args.get("safe"),
        "Limit": arg_to_number(args.get("limit")) or 25,
    }
    params = {key: value for key, value in params.items() if value not in (None, "")}
    response = client.privilege_cloud_request("/LiveSessions", params=params, method="GET")

    sessions = response.get("LiveSessions") or response.get("value") or []
    outputs = [{field: session.get(field) for field in SESSION_OUTPUT_FIELDS} for session in sessions]
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.Session",
        outputs_key_field="SessionGuid",
        outputs=outputs,
        readable_output=tableToMarkdown(
            f"Idira Privilege Cloud Live Sessions ({len(outputs)})", outputs, headers=list(SESSION_OUTPUT_FIELDS)
        ),
        raw_response=response,
    )


def terminate_session_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Terminate a live privileged session by GUID."""
    session_guid = args["session_guid"]
    response = client.privilege_cloud_request(f"/LiveSessions/{session_guid}/Terminate/")

    outputs = {"SessionGuid": session_guid, "Action": "Terminate", "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.SessionAction",
        outputs_key_field="SessionGuid",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Terminated session {session_guid}", outputs),
        raw_response=response,
    )


def _session_pause_action(client: Client, session_guid: str, action: str) -> CommandResults:
    """Suspend or resume a live session by GUID. Not for SSH/OPM."""
    response = client.privilege_cloud_request(f"/LiveSessions/{session_guid}/{action}/")

    outputs = {"SessionGuid": session_guid, "Action": action, "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.SessionAction",
        outputs_key_field="SessionGuid",
        outputs=outputs,
        readable_output=tableToMarkdown(f"{action}d session {session_guid}", outputs),
        raw_response=response,
    )


def suspend_session_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _session_pause_action(client, args["session_guid"], "Suspend")


def resume_session_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return _session_pause_action(client, args["session_guid"], "Resume")


# --- Privilege Cloud: credential actions -----------------------------------


def rotate_credential_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Trigger an immediate CPM credential change on an account."""
    account_id = args["account_id"]
    change_for_group = argToBoolean(args.get("change_creds_for_group", False))
    response = client.privilege_cloud_request(
        f"/Accounts/{account_id}/Change/", {"ChangeCredsForGroup": change_for_group}
    )

    outputs = {"AccountId": account_id, "Action": "Rotate", "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.CredentialAction",
        outputs_key_field="AccountId",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Rotation triggered for account {account_id}", outputs),
        raw_response=response,
    )


def verify_credential_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Mark an account for CPM verification."""
    account_id = args["account_id"]
    response = client.privilege_cloud_request(f"/Accounts/{account_id}/Verify/")

    outputs = {"AccountId": account_id, "Action": "Verify", "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.CredentialAction",
        outputs_key_field="AccountId",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Verification triggered for account {account_id}", outputs),
        raw_response=response,
    )


def vault_account_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bring an unmanaged risky account under Idira management."""
    body: dict[str, Any] = {
        "platformId": args["platform_id"],
        "safeName": args["safe_name"],
    }
    for arg_key, body_key in (
        ("name", "name"),
        ("address", "address"),
        ("username", "userName"),
        ("secret_type", "secretType"),
        ("secret", "secret"),
    ):
        value = args.get(arg_key)
        if value not in (None, ""):
            body[body_key] = value
    if "automatic_management_enabled" in args:
        body["secretManagement"] = {
            "automaticManagementEnabled": argToBoolean(args["automatic_management_enabled"])
        }

    response = client.privilege_cloud_request("/Accounts", body)

    account_id = response.get("id") if isinstance(response, dict) else None
    outputs = {
        "id": account_id,
        "name": body.get("name"),
        "safeName": body["safeName"],
        "platformId": body["platformId"],
        "Success": bool(account_id),
    }
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.Account",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Vaulted account in Safe {body['safeName']}", outputs),
        raw_response=response,
    )


# --- Secure Infrastructure Access: access policy ---------------------------


def disable_access_policy_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Revoke standing/JIT access by disabling a SIA access policy.

    Reversible: re-run with ``status=Enabled``.
    """
    policy_id = args["policy_id"]
    policy_name = args["policy_name"]
    status = args.get("status", POLICY_STATUS_DISABLED)
    response = client.sia_request(
        f"/access-policies/{policy_id}",
        {"policyId": policy_id, "policyName": policy_name, "status": status},
        method="PUT",
    )

    outputs = {"PolicyId": policy_id, "PolicyName": policy_name, "Status": status, "Success": True}
    return CommandResults(
        outputs_prefix="IdiraIdentityResponse.AccessPolicy",
        outputs_key_field="PolicyId",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Access policy {policy_id} set to {status}", outputs),
        raw_response=response,
    )


# endregion

# region Main router

COMMAND_MAP: dict[str, Any] = {
    # Identity (workforce)
    "idira-identity-response-get-user-by-name": get_user_by_name_command,
    "idira-identity-response-lock-user": lock_user_command,
    "idira-identity-response-disable-user": disable_user_command,
    "idira-identity-response-unlock-user": unlock_user_command,
    "idira-identity-response-force-logout": force_logout_command,
    "idira-identity-response-expire-password": expire_password_command,
    "idira-identity-response-remove-role": remove_role_command,
    # Privilege Cloud: account resolution
    "idira-identity-response-get-account": get_account_command,
    "idira-identity-response-get-account-details": get_account_details_command,
    # Privilege Cloud: privileged sessions
    "idira-identity-response-list-sessions": list_sessions_command,
    "idira-identity-response-terminate-session": terminate_session_command,
    "idira-identity-response-suspend-session": suspend_session_command,
    "idira-identity-response-resume-session": resume_session_command,
    # Privilege Cloud: credential actions
    "idira-identity-response-rotate-credential": rotate_credential_command,
    "idira-identity-response-verify-credential": verify_credential_command,
    "idira-identity-response-vault-account": vault_account_command,
    # Secure Infrastructure Access
    "idira-identity-response-disable-access-policy": disable_access_policy_command,
}


def main() -> None:
    """Main entry point for the Idira Identity Response integration."""
    command = demisto.command()
    demisto.debug(f"{INTEGRATION_NAME}: command '{command}'")

    params = demisto.params()
    identity_url = (params.get("identity_url") or "").strip().rstrip("/")
    client_id = (params.get("client_id") or "").strip()
    client_secret = (params.get("credentials") or {}).get("password", "")
    privilege_cloud_url = (params.get("privilege_cloud_url") or "").strip().rstrip("/")
    sia_url = (params.get("sia_url") or "").strip().rstrip("/")
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
            privilege_cloud_url=privilege_cloud_url,
            sia_url=sia_url,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command in COMMAND_MAP:
            results = COMMAND_MAP[command](client, demisto.args())
            client.report_adoption_event()  # only reached when the command succeeded
            return_results(results)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented")

    except Exception as error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(error)}")


# endregion


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
