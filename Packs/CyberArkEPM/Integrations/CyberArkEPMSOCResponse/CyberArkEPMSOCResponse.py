from urllib.parse import urlparse

import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

CONTEXT_KEY = "CyberArkEPMSOCResponse_Context"
RISK_PLAN_ACTION_ADD = "add"
RISK_PLAN_ACTION_REMOVE = "remove"

GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
ACCESS_TOKEN = "access_token"
TENANT_URL = "tenantUrl"
EXPIRES_IN = "expires_in"
VALID_UNTIL = "valid_until"
DEFAULT_TOKEN_TTL_SECONDS = 6 * 60 * 60
CACHE_BUFFER_SECONDS = 60

# Feature Adoption service (metric_key = <service_code>.<master_feature_name>.<metric_name>).
# The metric key must be enrolled in the Developer Portal or the service rejects the event.
INTEGRATION_VERSION = "1.0"
VENDOR_NAME = "Palo Alto Networks"
ADOPTION_SERVICE_CODE = "IDIINT"
ADOPTION_FEATURE_NAME = "cortex_epm_soc_response"
ADOPTION_METRIC_NAME = "integration_executed"
ADOPTION_IDIRA_SERVICE = "Idira EPM"
ADOPTION_TRIGGERED_BY = "BE"  # allowed: "BE", "UI", "N/A"; commands run in the backend, not the UI
ADOPTION_ENDPOINT_PATH = "/api/feature-adoption"
ADOPTION_HOST_PREFIX = "us-east-1-featureadopt.featureadopt"
ADOPTION_TIMEOUT_SECONDS = 10
PLATFORM_TOKEN_PATH = "/oauth2/platformtoken"

""" ADOPTION HELPERS """


def build_adoption_event() -> dict[str, Any]:
    """Build the Feature Adoption event body (authenticated-user schema).

    ``user_id`` is intentionally omitted: for authenticated callers the service
    extracts it from the JWT. Tag keys must be snake_case alphanumeric strings.
    """
    return {
        "metric_key": f"{ADOPTION_SERVICE_CODE}.{ADOPTION_FEATURE_NAME}.{ADOPTION_METRIC_NAME}",
        "number_of_events": 1,
        "triggered_by": ADOPTION_TRIGGERED_BY,
        "tags": {
            "vendor_name": VENDOR_NAME,
            "integration_version": INTEGRATION_VERSION,
            "idira_service": ADOPTION_IDIRA_SERVICE,
        },
    }


def get_adoption_url(identity_url: str) -> str:
    """Derive the Feature Adoption API URL from the tenant Identity URL.

    The root domain is taken from the ``<tenant>.id.<root domain>`` Identity host.
    Returns an empty string if the root domain cannot be determined.
    """
    host = urlparse(identity_url or "").hostname or ""
    _, separator, root_domain = host.partition(".id.")
    if not separator or not root_domain:
        return ""
    return f"https://{ADOPTION_HOST_PREFIX}.{root_domain}{ADOPTION_ENDPOINT_PATH}"


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self,
        base_tenant_url: str,
        identity_url: str,
        client_id: str,
        client_secret: str,
        web_app_id: str,
        verify: bool = True,
        proxy: bool = False,
        usage_reporting_enabled: bool = True,
    ):
        super().__init__(base_url="", verify=verify, proxy=proxy)
        self.usage_reporting_enabled = usage_reporting_enabled
        self.identity_url = identity_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.web_app_id = web_app_id
        self.base_tenant_url = base_tenant_url
        self.token_url = f"{self.identity_url.rstrip('/')}/oauth2/token/{self.web_app_id}"

    def _get_access_token(self) -> str:
        """Get or refresh OAuth2 access token with caching."""
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ACCESS_TOKEN)
        cached_valid_until = cached_context.get(VALID_UNTIL)

        # Check if cached token is valid
        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(float(cached_valid_until))
                if current_timestamp < valid_until_timestamp:
                    demisto.debug("[Token Cache] Hit! Token is still valid.")
                    return cached_token
                demisto.debug("[Token Cache] Miss. Token expired.")
            except (ValueError, TypeError):
                demisto.debug("[Token Cache] Error parsing cache. Ignoring.")

        # Request new token
        demisto.debug(f"[Token Request] Requesting new token from {self.token_url}")

        # Prepare request data
        token_data = {
            "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
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

        # Update Cache
        token_expires_in = token_response.get(EXPIRES_IN, DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - CACHE_BUFFER_SECONDS

        demisto.debug(f"[Token Request] Success. Expires in {token_expires_in}s.")

        new_context = {ACCESS_TOKEN: access_token, VALID_UNTIL: str(token_valid_until)}
        set_integration_context(new_context)

        return access_token

    def _get_tenant_url(self, access_token: str) -> str:
        cached_context = get_integration_context() or {}
        cached_tenant_url = cached_context.get(TENANT_URL)

        if cached_tenant_url:
            return cached_tenant_url

        headers = {"authorization": f"Bearer {access_token}", "Content-Type": "application/json", "Accept": "application/json"}

        try:
            tenant_url_response = self._http_request(
                method="GET",
                full_url=f"{self.base_tenant_url.rstrip('/')}/epm/api/accounts/tenanturl",
                headers=headers,
                resp_type="json",
            )
        except DemistoException as error:
            error_msg = str(error)
            demisto.error(f"[Tenant URL Request] Failed: {error_msg}")
            raise DemistoException(f"Failed to obtain tenant URL: {error_msg}")

        tenant_url = tenant_url_response.get(TENANT_URL)
        if not tenant_url:
            raise DemistoException("Failed to obtain tenant URL. Response missing tenant URL.")

        tenant_url = tenant_url_response.get(TENANT_URL).rstrip("/")
        demisto.debug(f"[Tenant URL Request] Success. tenant URL: {tenant_url}.")
        cached_context = get_integration_context() or {}
        cached_context[TENANT_URL] = tenant_url
        set_integration_context(cached_context)

        return tenant_url

    def _get_platform_token(self) -> str:
        """Fetch an Identity platform token for the Feature Adoption service.

        The EPM web-app token (``/oauth2/token/<web_app_id>``) is scoped to the EPM app and is rejected by the
        adoption service (401), which requires a platform token. It is fetched on demand and deliberately not
        cached, so it cannot collide with the EPM token cache.
        """
        token_response = self._http_request(
            method="POST",
            full_url=f"{self.identity_url.rstrip('/')}{PLATFORM_TOKEN_PATH}",
            data={
                "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            resp_type="json",
            timeout=ADOPTION_TIMEOUT_SECONDS,
        )
        platform_token = token_response.get(ACCESS_TOKEN)
        if not platform_token:
            raise DemistoException("Platform token response is missing access_token.")
        return platform_token

    def report_adoption_event(self) -> None:
        """Report an ``integration_executed`` event to the Feature Adoption service.

        Best effort: a single attempt with a short timeout. Any failure is logged
        and swallowed so telemetry can never break a response action.
        Skipped entirely (no token request either) when the user disabled usage reporting.
        """
        if not self.usage_reporting_enabled:
            demisto.debug("[Adoption] Usage reporting is disabled in the instance configuration; skipping.")
            return
        adoption_url = get_adoption_url(self.identity_url)
        if not adoption_url:
            demisto.debug(f"[Adoption] Could not derive the Feature Adoption URL from {self.identity_url}; skipping.")
            return
        try:
            self._http_request(
                method="POST",
                full_url=adoption_url,
                json_data=build_adoption_event(),
                headers={"Authorization": f"Bearer {self._get_platform_token()}", "Content-Type": "application/json"},
                resp_type="response",
                ok_codes=(200, 202),
                timeout=ADOPTION_TIMEOUT_SECONDS,
            )
            demisto.debug("[Adoption] Event reported.")
        except Exception as error:
            demisto.debug(f"[Adoption] Failed to report event (ignored): {error}")

    def http_request(
        self,
        method: str,
        url_suffix: str,
        json_data: dict[str, Any] | None = None,
        return_full_response: bool = False,
    ) -> Any:
        """Execute HTTP request with authentication and detailed logging."""
        access_token = self._get_access_token()
        tenant_url = self._get_tenant_url(access_token)

        auth_headers = {
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        demisto.debug(f"[HTTP Call] {method} {url_suffix}")
        full_url = f"{tenant_url}/epm/api/{url_suffix}"

        try:
            http_response = self._http_request(
                method=method,
                full_url=full_url,
                json_data=json_data,
                headers=auth_headers,
                resp_type="response",
                ok_codes=(200, 201, 202, 204),
                retries=3,
                backoff_factor=2,
            )
        except DemistoException as error:
            error_msg = str(error)
            if "401" in error_msg or "403" in error_msg:
                demisto.error(f"[HTTP Error] Authentication failed: {error_msg}")
                raise DemistoException(f"Authentication error: {error_msg}. Please check credentials.")
            raise

        status_code = http_response.status_code
        demisto.debug(f"[HTTP Call] Response Status: {status_code}")

        if status_code == 204:
            demisto.debug("[HTTP Call] 204 No Content received.")
            return ({}, http_response.headers) if return_full_response else {}

        try:
            response_json = http_response.json()
        except ValueError:
            demisto.debug(f"[HTTP Error] Failed to parse JSON. Status: {status_code}, Body: {http_response.text[:200]}")
            raise DemistoException(f"API returned non-JSON response with status {status_code}")

        if return_full_response:
            return response_json, http_response.headers

        return response_json


""" HELPER FUNCTIONS """


def get_sets(client: Client) -> list:
    sets_response = client.http_request("GET", url_suffix="Sets")
    return sets_response.get("Sets", [])


def search_endpoints(endpoint_name: str, logged_in_user: str, set_id: str, client: Client) -> list[str]:
    """Searches for endpoints by name within a single set.

    Args:
        endpoint_name (str): The name of the endpoint to search for.
        logged_in_user (str): The logged-in username of the endpoint.
        set_id (str): The ID of the set to search within.
        client (Client): The CyberArk EPM client.

    Returns:
        list[str]: A list of endpoint IDs that match the search criteria.
    """
    search_filter = f"name CONTAINS {endpoint_name}{f' and loggedInUser CONTAINS {logged_in_user}' if logged_in_user else ''}"
    demisto.info(f"Endpoint Search filter: {search_filter}")
    data = {"filter": search_filter}
    url_suffix = f"Sets/{set_id}/Endpoints/Search"
    result = client.http_request("POST", url_suffix=url_suffix, json_data=data)
    return [endpoint.get("id") for endpoint in result.get("endpoints", [])]


def search_endpoint_group_id(group_name: str, set_id: str, client: Client) -> str:
    """Searches for an endpoint group ID by its name within a specific set.

    Args:
        group_name (str): The name of the endpoint group.
        set_id (str): The ID of the set to search within.
        client (Client): The CyberArk EPM client.

    Returns:
        str: The ID of the endpoint group, or empty string if not found.
    """
    group_id = ""
    data = {"filter": f"name CONTAINS {group_name}"}
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/Search"
    result = client.http_request("POST", url_suffix=url_suffix, json_data=data)
    if result and len(result) > 0:
        endpoint_group_id = result[0].get("id")
        group_id = endpoint_group_id
    return group_id


def add_endpoint_to_group(endpoint_ids: list[str], endpoint_group_id: str, set_id: str, client: Client) -> dict:
    """Adds an endpoint to a specified group.

    Args:
        endpoint_ids (list): The IDs of the endpoints to add.
        endpoint_group_id (str): The ID of the group to add the endpoint to.
        set_id (str): The ID of the set the group belongs to.
        client (Client): The CyberArk EPM client.
    """
    data = {"membersIds": endpoint_ids}
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids"
    return client.http_request("POST", url_suffix=url_suffix, json_data=data)


def remove_endpoint_from_group(endpoint_ids: list[str], endpoint_group_id: str, set_id: str, client: Client) -> dict:
    """Removes an endpoint from a specified group.

    Args:
        endpoint_ids (list): The IDs of the endpoints to remove.
        endpoint_group_id (str): The ID of the group to remove the endpoint from.
        set_id (str): The ID of the set the group belongs to.
        client (Client): The CyberArk EPM client.
    """
    data = {"membersIds": endpoint_ids}
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids/remove"
    return client.http_request("POST", url_suffix=url_suffix, json_data=data)


""" COMMAND FUNCTIONS """


def change_risk_plan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    risk_plan = args.get("risk_plan", "")
    endpoint_name = args.get("endpoint_name", "")
    logged_in_user = args.get("logged_in_user", "")
    action = args.get("action", RISK_PLAN_ACTION_ADD)

    if action not in (RISK_PLAN_ACTION_ADD, RISK_PLAN_ACTION_REMOVE):
        raise DemistoException(f"Invalid action: {action}")

    sets = get_sets(client=client)
    result_rows: list[dict] = []

    for epm_set in sets:
        set_id: str = epm_set["Id"]

        endpoint_ids = search_endpoints(endpoint_name, logged_in_user, set_id, client)
        if not endpoint_ids:
            continue

        endpoint_group_id = search_endpoint_group_id(risk_plan, set_id, client)
        group_action_performed = False
        if endpoint_group_id:
            if action == RISK_PLAN_ACTION_ADD:
                add_endpoint_to_group(endpoint_ids, endpoint_group_id, set_id, client)
            else:
                remove_endpoint_from_group(endpoint_ids, endpoint_group_id, set_id, client)
            group_action_performed = True

        result_rows.append(
            {
                "SetID": set_id,
                "EndpointIDs": ",".join(endpoint_ids),
                "RiskPlan": risk_plan,
                "Action": action,
                "GroupActionPerformed": group_action_performed,
            }
        )

    if not result_rows:
        raise DemistoException(f"No Endpoints found matching the name: {endpoint_name} and Logged-in username: {logged_in_user}")

    human_readable = tableToMarkdown(
        name="Risk Plan Change Results",
        t=result_rows,
        headers=["SetID", "EndpointIDs", "RiskPlan", "Action", "GroupActionPerformed"],
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="CyberArkEPMSOCResponse",
        outputs_key_field="EndpointIDs",
        outputs=result_rows,
    )


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    get_sets(client=client)
    return "ok"


def main():
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    # Parse parameters
    base_url = params.get("url")
    identity_url = params.get("identity_url")
    web_app_id = params.get("web_app_id")
    client_id = params.get("client_id")
    client_secret = params.get("credentials").get("password")
    proxy = argToBoolean(params.get("proxy", False))
    verify_certificate = not argToBoolean(params.get("insecure", False))
    usage_reporting_enabled = not argToBoolean(params.get("disable_usage_reporting", False))

    try:
        result: Any = None
        client = Client(
            base_tenant_url=base_url,
            identity_url=identity_url,
            client_id=client_id,
            client_secret=client_secret,
            web_app_id=web_app_id,
            verify=verify_certificate,
            proxy=proxy,
            usage_reporting_enabled=usage_reporting_enabled,
        )
        if command == "test-module":
            return_results(test_module(client))
            return  # connectivity test only: do not report adoption
        elif command == "cyberarkepm-activate-risk-plan":
            args["action"] = RISK_PLAN_ACTION_ADD
            result = change_risk_plan_command(client, args)
        elif command == "cyberarkepm-deactivate-risk-plan":
            args["action"] = RISK_PLAN_ACTION_REMOVE
            result = change_risk_plan_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        client.report_adoption_event()  # only reached when the command succeeded
        return_results(result)
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
