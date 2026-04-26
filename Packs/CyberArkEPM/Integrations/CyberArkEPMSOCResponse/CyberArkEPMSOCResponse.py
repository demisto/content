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
    ):
        super().__init__(base_url="", verify=verify, proxy=proxy)
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
            "x-cybr-telemetry": "aW49RVBNIFNPQyBSZXNwb25zZSZpdj0xLjAmdm49UGFsbyBBbHRvJml0PUVQTQ==",
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


def search_endpoints(endpoint_name: str, logged_in_user: str, client: Client) -> list:
    """Searches for endpoints by name and IP address.

    Args:
        endpoint_name (str): The name of the endpoint to search for.
        logged_in_user (str): The logged-in username of the endpoint.
        client (Client): The CyberArk EPM client.

    Returns:
        list: A list of endpoint IDs that match the search criteria.
    """
    search_filter = f"name CONTAINS {endpoint_name}{f' and loggedInUser CONTAINS {logged_in_user}' if logged_in_user else ''}"
    demisto.info(f"Endpoint Search filter: {search_filter}")
    data = {"filter": search_filter}
    sets = get_sets(client=client)
    set_ids = [set["Id"] for set in sets]
    for set_id in set_ids:
        url_suffix = f"Sets/{set_id}/Endpoints/Search"
        result = client.http_request("POST", url_suffix=url_suffix, json_data=data)
        if result.get("endpoints"):
            endpoint_ids = [endpoint.get("id") for endpoint in result.get("endpoints")]
            cached_context = get_integration_context() or {}
            cached_context["set_id"] = set_id
            set_integration_context(cached_context)
            return endpoint_ids
    return []


def search_endpoint_group_id(group_name: str, client: Client) -> str:
    """Searches for an endpoint group ID by its name.

    Args:
        group_name (str): The name of the endpoint group.
        client (Client): The CyberArk EPM client.

    Returns:
        str: The ID of the endpoint group, or None if not found.
    """
    group_id = ""
    data = {"filter": f"name CONTAINS {group_name}"}
    context = get_integration_context() or {}
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/Search"
    result = client.http_request("POST", url_suffix=url_suffix, json_data=data)
    if result and len(result) > 0:
        endpoint_group_id = result[0].get("id")
        group_id = endpoint_group_id
    return group_id


def add_endpoint_to_group(endpoint_ids: list[str], endpoint_group_id: str, client: Client) -> dict:
    """Adds an endpoint to a specified group.

    Args:
        endpoint_ids (list): The IDs of the endpoints to add.
        endpoint_group_id (str): The ID of the group to add the endpoint to.
        client (Client): The CyberArk EPM client.
    """
    data = {"membersIds": endpoint_ids}
    context = get_integration_context() or {}
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids"
    return client.http_request("POST", url_suffix=url_suffix, json_data=data)


def remove_endpoint_from_group(endpoint_ids: list[str], endpoint_group_id: str, client: Client) -> dict:
    """Removes an endpoint from a specified group.

    Args:
        endpoint_ids (list): The IDs of the endpoints to remove.
        endpoint_group_id (str): The ID of the group to remove the endpoint from.
        client (Client): The CyberArk EPM client.
    """
    data = {"membersIds": endpoint_ids}
    context = get_integration_context() or {}
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids/remove"
    return client.http_request("POST", url_suffix=url_suffix, json_data=data)


""" COMMAND FUNCTIONS """


def change_risk_plan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    risk_plan = args.get("risk_plan", "")
    endpoint_name = args.get("endpoint_name", "")
    logged_in_user = args.get("logged_in_user", "")
    action = args.get("action", RISK_PLAN_ACTION_ADD)

    # Search for endpoints
    endpoint_ids = search_endpoints(endpoint_name=endpoint_name, logged_in_user=logged_in_user, client=client)

    if not endpoint_ids:
        raise DemistoException(f"No Endpoints found matching the name: {endpoint_name} and Logged-in username: {logged_in_user}")

    # Search for endpoint group by risk plan name
    endpoint_group_id = search_endpoint_group_id(risk_plan, client)
    if not endpoint_group_id:
        raise DemistoException(f"No Endpoint Group found matching the name: {risk_plan}")

    if action == RISK_PLAN_ACTION_ADD:
        raw_result = add_endpoint_to_group(endpoint_ids, endpoint_group_id, client)
    elif action == RISK_PLAN_ACTION_REMOVE:
        raw_result = remove_endpoint_from_group(endpoint_ids, endpoint_group_id, client)
    else:
        raise DemistoException(f"Invalid action: {action}")
    result_context = {"EndpointIDs": ",".join(endpoint_ids), "RiskPlan": risk_plan, "Action": action}
    human_readable = tableToMarkdown(
        name="Risk Plan changed successfully", t=result_context, headers=["EndpointIDs", "RiskPlan", "Action"]
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="CyberArkEPMSOCResponse",
        outputs_key_field="EndpointIDs",
        outputs=result_context,
        raw_response=raw_result,
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
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command == "cyberarkepm-activate-risk-plan":
            args["action"] = RISK_PLAN_ACTION_ADD
            result = change_risk_plan_command(client, args)
        elif command == "cyberarkepm-deactivate-risk-plan":
            args["action"] = RISK_PLAN_ACTION_REMOVE
            result = change_risk_plan_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(result)
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
