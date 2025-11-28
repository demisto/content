import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

CONTEXT_KEY = "CyberArkEPMSOCResponse_Context"
RISK_PLAN_ACTION_ADD = "add"
RISK_PLAN_ACTION_REMOVE = "remove"

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, username, password, application_id, set_name=None, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-cybr-telemetry": "aW49RVBNIFNPQyBSZXNwb25zZSZpdj0xLjAmdm49UGFsbyBBbHRvJml0PUVQTQ=="
        }
        self.username = username
        self.password = password
        self.application_id = application_id
        self.set_name = set_name
        self.epm_auth_to_cyber_ark()

    def epm_auth_to_cyber_ark(self):  # pragma: no cover
        data = {
            "Username": self.username,
            "Password": self.password,
            "ApplicationID": self.application_id or "CyberArkXSOAR",
        }
        result = self._http_request("POST", url_suffix="/EPM/API/Auth/EPM/Logon", json_data=data)

        if result.get("IsPasswordExpired"):
            return_error("CyberArk is reporting that the user password is expired. Terminating script.")
        self._base_url = urljoin(result.get("ManagerURL"), "/EPM/API/")
        self._headers["Authorization"] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_sets(self) -> dict:
        return self._http_request("GET", url_suffix="Sets")


""" HELPER FUNCTIONS """


def search_endpoints(endpoint_name: str, external_ip: str, allow_multiple_endpoints: bool, client: Client) -> list:
    """Searches for endpoints by name and IP address.

    Args:
        endpoint_name (str): The name of the endpoint to search for.
        external_ip (str): The external IP address of the endpoint.
        allow_multiple_endpoints (bool): Whether to allow multiple endpoints matched to be acted on.
        client (Client): The CyberArk EPM client.

    Returns:
        list: A list of endpoint IDs that match the search criteria.
    """
    search_filter = f"name EQ {endpoint_name}{'and ip EQ {external_ip}' if external_ip else ''}"
    demisto.info(f"Endpoint Search filter: {search_filter}")
    data = {"filter": search_filter}
    sets = client.get_sets()
    if client.set_name:
        set_ids = [set["Id"] for set in sets.get("Sets", []) if client.set_name in set.get("Name")]
    else:
        set_ids = [set["Id"] for set in sets.get("Sets", [])]
    for set_id in set_ids:
        url_suffix = f"Sets/{set_id}/Endpoints/Search"
        result = client._http_request("POST", url_suffix=url_suffix, json_data=data)
        if result.get("endpoints"):
            if allow_multiple_endpoints:
                endpoint_ids = [
                    endpoint.get("id") for endpoint in result.get("endpoints") if endpoint.get("connectionStatus") == "Connected"
                ]
            else:
                endpoint_ids = [result.get("endpoints")[0].get("id")]
            set_integration_context({CONTEXT_KEY: {"set_id": set_id}})
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
    data = {"filter": f"name EQ {group_name}"}
    context = get_integration_context().get(CONTEXT_KEY, {})
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/Search"
    result = client._http_request("POST", url_suffix=url_suffix, json_data=data)
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
    context = get_integration_context().get(CONTEXT_KEY, {})
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids"
    return client._http_request("POST", url_suffix=url_suffix, json_data=data)


def remove_endpoint_from_group(endpoint_ids: list[str], endpoint_group_id: str, client: Client) -> dict:
    """Removes an endpoint from a specified group.

    Args:
        endpoint_ids (list): The IDs of the endpoints to remove.
        endpoint_group_id (str): The ID of the group to remove the endpoint from.
        client (Client): The CyberArk EPM client.
    """
    data = {"membersIds": endpoint_ids}
    context = get_integration_context().get(CONTEXT_KEY, {})
    set_id = context.get("set_id")
    url_suffix = f"Sets/{set_id}/Endpoints/Groups/{endpoint_group_id}/Members/ids/remove"
    return client._http_request("POST", url_suffix=url_suffix, json_data=data)


""" COMMAND FUNCTIONS """


def change_risk_plan_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    risk_plan = args.get("risk_plan", "")
    endpoint_name = args.get("endpoint_name", "")
    external_ip = args.get("external_ip", "")
    action = args.get("action", RISK_PLAN_ACTION_ADD)
    allow_multiple_endpoints = args.get("allow_multiple_endpoints", True)

    # Search for endpoints
    endpoint_ids = search_endpoints(
        endpoint_name=endpoint_name, external_ip=external_ip, allow_multiple_endpoints=allow_multiple_endpoints, client=client
    )

    if not endpoint_ids:
        raise DemistoException(f"No Endpoints found matching the name: {endpoint_name} and External IP: {external_ip}")

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
    result_context = {"Endpoint_IDs": ",".join(endpoint_ids), "Risk_Plan": risk_plan, "Action": action}
    human_readable = tableToMarkdown(
        name="Risk Plan changed successfully", t=result_context, headers=["Endpoint_IDs", "Risk_Plan", "Action"]
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="CyberArkEPMSOCResponse",
        outputs_key_field="Endpoint_IDs",
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
    client.get_sets()
    return "ok"


def main():
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    # Parse parameters
    base_url = params.get("url")
    application_id = params.get("application_id")
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    set_name = params.get("set_name")

    try:
        result: Any = None
        client = Client(base_url=base_url, username=username, password=password, application_id=application_id, set_name=set_name)
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
