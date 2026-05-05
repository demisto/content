"""
Sysdig Response Actions Integration
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import re
import time
from typing import Any
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

SYSTEM_CAPTURES_REQUIRED_FIELDS = ["container_id", "host_name", "capture_name", "agent_id", "customer_id", "machine_id"]
RESPONSE_ACTIONS_REQUIRED_FIELDS = ["actionType", "callerId"]
RESPONSE_ACTIONS_PARAMS: dict[str, list[str]] = {
    "KILL_PROCESS": ["host.id", "process.id", "startTime"],
    "KILL_CONTAINER": ["host.id", "container.id"],
    "PAUSE_CONTAINER": ["host.id", "container.id"],
    "STOP_CONTAINER": ["host.id", "container.id"],
    "UNPAUSE_CONTAINER": ["host.id", "container.id"],
    "START_CONTAINER": ["host.id", "container.id"],
    "FILE_QUARANTINE": ["host.id", "path.absolute"],
    "FILE_ACQUIRE": ["host.id", "path.absolute"],
    "FILE_UNQUARANTINE": ["host.id", "path.absolute", "quarantined_file_path"],
    "DELETE_POD": ["kubernetes.cluster.name", "kubernetes.namespace.name", "kubernetes.pod.name"],
    "ROLLOUT_RESTART": ["kubernetes.cluster.name", "kubernetes.namespace.name", "kubernetes.workload.type", "kubernetes.workload.name"],
    "ISOLATE_NETWORK": ["kubernetes.cluster.name", "kubernetes.namespace.name", "kubernetes.workload.type", "kubernetes.workload.name"],
    "DELETE_NETWORK_POLICY": ["kubernetes.cluster.name", "kubernetes.namespace.name", "network_policy_name"],
    "GET_LOGS": ["kubernetes.cluster.name", "kubernetes.namespace.name"],
    "KUBERNETES_VOLUME_SNAPSHOT": ["kubernetes.cluster.name", "kubernetes.namespace.name"],
    "KUBERNETES_DELETE_VOLUME_SNAPSHOT": ["kubernetes.cluster.name", "kubernetes.namespace.name", "kubernetes.persistentvolume.claim.name", "kubernetes.volume.snapshot.name"],
    "CAPTURE": ["host.id", "capture.remote_storage_configuration_id", "capture.duration_ns", "capture.past_duration_ns"],
    "IAM_QUARANTINE": ["cloudProvider.name", "cloudProvider.account.id"],
    "IAM_UNQUARANTINE": ["cloudProvider.name", "cloudProvider.account.id", "iam_policy_name", "ct.user.identitytype", "ct.user"],
    "MAKE_PRIVATE_CLOUD_RESOURCE": ["cloudProvider.name", "cloudProvider.account.id", "cloudResourceType", "cloudResourceName"],
    "UNDO_MAKE_PRIVATE_CLOUD_RESOURCE": ["cloudProvider.name", "cloudProvider.account.id", "cloudResourceType", "cloudResourceName", "previousPublicAccessSettings"],
    "CLOUD_VOLUME_SNAPSHOT": ["cloudProvider.name", "cloudProvider.account.id", "cloudProvider.region", "aws.instanceId"],
    "UNDO_CLOUD_VOLUME_SNAPSHOT": ["cloudProvider.name", "cloudProvider.account.id", "cloudProvider.region", "snapshotIds", "aws.instanceId"],
    "FETCH_CLOUD_LOGS": ["cloudProvider.name", "cloudProvider.account.id", "cloudProvider.region", "fromTimestamp", "toTimestamp"],
}
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServerPython.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(
        self, base_url: str, verify: bool, headers: dict[str, str], proxy: bool, ok_codes: tuple[int, ...] = (200, 201, 202)
    ):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers
        self.proxy = proxy
        self.ok_codes = ok_codes
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy, ok_codes=ok_codes)

    def call_sysdig_api(
        self,
        method: str = "GET",
        url_suffix: str = "/secure/response-actions/v1alpha1/action-executions",
        params: dict = None,
        data: dict = None,
        json_data: dict = None,
        resp_type: str = "json",
        full_url: str = None,
    ) -> dict[str, Any] | bytes | str:
        """
        Call the Sysdig API

        Args:
            method: The HTTP method to use
            url_suffix: The URL suffix to use
            params: The parameters to use
            data: The data to use
            json_data: The JSON data to use
            resp_type: The response type to use
            full_url: The full URL to use
        Returns:
            The response from the API
        """
        demisto.debug(f"Calling endpoint: {self.base_url + url_suffix}")
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            data=data,
            json_data=json_data,
            resp_type=resp_type,
            full_url=full_url,
        )


""" HELPER FUNCTIONS """


def _build_data_payload(args: dict[str, Any]) -> dict[str, Any]:
    """
    Parse the input parameters to the data payload to execute an action

    Args:
        args: The input parameters
    Returns:
        The data payload
    """
    data = {field: args.get(field) for field in RESPONSE_ACTIONS_REQUIRED_FIELDS}

    if not all(data.values()):
        missing_fields = [field for field in RESPONSE_ACTIONS_REQUIRED_FIELDS if not data.get(field)]
        raise ValueError(f"The following fields are required and cannot be null: {', '.join(missing_fields)}")

    PARAM_ARG_MAP = {
        "container.id": "container_id",
        "host.id": "host_id",
        "path.absolute": "path_absolute",
        "process.id": "process_id",
        "startTime": "startTime",
        "quarantined_file_path": "quarantined_file_path",
        "kubernetes.cluster.name": "k8s_cluster_name",
        "kubernetes.namespace.name": "k8s_namespace_name",
        "kubernetes.pod.name": "k8s_pod_name",
        "kubernetes.workload.type": "k8s_workload_type",
        "kubernetes.workload.name": "k8s_workload_name",
        "kubernetes.persistentvolume.claim.name": "k8s_pvc_name",
        "kubernetes.volume.snapshot.name": "k8s_volume_snapshot_name",
        "kubernetes.container.name": "k8s_container_name",
        "network_policy_name": "network_policy_name",
        "network.protocol": "network_protocol",
        "network.port": "network_port",
        "network.cidr": "network_cidr",
        "network.direction": "network_direction",
        "previous": "previous",
        "allContainers": "all_containers",
        "capture.remote_storage_configuration_id": "capture_storage_config_id",
        "capture.duration_ns": "capture_duration_ns",
        "capture.past_duration_ns": "capture_past_duration_ns",
        "capture.filters": "capture_filters",
        "capture.max_size": "capture_max_size",
        "capture.token": "capture_token",
        "cloudProvider.name": "cloud_provider",
        "cloudProvider.account.id": "cloud_account_id",
        "cloudProvider.region": "cloud_region",
        "ct.user.arn": "ct_user_arn",
        "ct.user.identitytype": "ct_user_identity_type",
        "ct.user": "ct_user",
        "ct.originaluser": "ct_original_user",
        "ct.name": "ct_name",
        "ct.src": "ct_src",
        "iam_policy_name": "iam_policy_name",
        "cloudResourceType": "cloud_resource_type",
        "cloudResourceName": "cloud_resource_name",
        "previousPublicAccessSettings": "previous_public_access_settings",
        "aws.instanceId": "aws_instance_id",
        "snapshotIds": "snapshot_ids",
        "fromTimestamp": "from_timestamp",
        "toTimestamp": "to_timestamp",
    }
    INTEGER_PARAMS = {"process.id", "startTime", "capture.duration_ns", "capture.past_duration_ns", "capture.max_size"}

    parameters: dict[str, Any] = {}
    for api_key, arg_name in PARAM_ARG_MAP.items():
        val = args.get(arg_name)
        if val in (None, "", "null"):
            continue
        if api_key in INTEGER_PARAMS:
            val = int(val)
        if api_key == "previous" or api_key == "allContainers":
            val = argToBoolean(val)
        parameters[api_key] = val

    if args.get("process_id") and "startTime" not in parameters:
        parameters["startTime"] = -1

    data["parameters"] = parameters
    _validate_response_actions_params(data)

    return data


def _build_capture_payload(args: dict[str, Any]) -> dict[str, Any]:
    """
    Parse the input parameters to the data payload to create a system capture.
    """
    _validate_captures_params(args)

    # Extract required and optional fields with defaults
    data = {
        "containerId": args.get("container_id"),
        "duration": args.get("scan_duration", 15),  # Default duration is 15 seconds
        "hostName": args.get("host_name"),
        "name": args.get("capture_name"),
        "filters": args.get("scap_filter", ""),
        "bucketName": "",
        "agent": {
            "id": args.get("agent_id"),
            "customer": args.get("customer_id"),
            "machineID": args.get("machine_id"),
            "hostName": args.get("host_name"),
        },
        "annotations": {"manual": "true"},
        "source": "SDS",
        "storageType": "S3",
        "folder": "/",
    }

    return data


def _validate_captures_params(args: dict[str, Any]) -> None:
    """
    Validate the input parameters to create a system capture. Raise ValueError if any required parameter is missing
    """
    missing_fields = [field for field in SYSTEM_CAPTURES_REQUIRED_FIELDS if not args.get(field) or args.get(field) == "null"]

    if missing_fields:
        raise ValueError(f"The following fields are required and cannot be null: {', '.join(missing_fields)}")


def _validate_response_actions_params(args: dict[str, Any]) -> None:
    """
    Validate the input parameters to execute an action. Raise ValueError if any required parameter is missing
    """
    actionType: str = args.get("actionType", "")
    parameters: dict = args.get("parameters", {})

    for key in list(parameters):
        if parameters[key] in ("null", ""):
            parameters[key] = None

    required = RESPONSE_ACTIONS_PARAMS.get(actionType, [])
    missing_params = [param for param in required if not parameters.get(param)]

    if missing_params:
        raise ValueError(f"Missing required parameters for {actionType}: {', '.join(missing_params)}")


def _get_public_api_url(base_url: str) -> str:
    """
    Get the public API URL from the base URL.

    Args:
        base_url: The base URL of the Sysdig API
    Returns:
        The public API URL
    """
    # Regex to capture the region pattern (like us2, us3, au1, etc.)
    # This assumes the region is a subdomain that starts with 2 lowercase letters and ends with a digit
    pattern = re.search(r"https://(?:(?P<region1>[a-z]{2}\d)\.app|app\.(?P<region2>[a-z]{2}\d))\.sysdig\.com", base_url)
    if pattern:
        region = pattern.group(1)  # Extract the region
        return f"https://api.{region}.sysdig.com"
    else:
        # Edge case for the secure API URL that is us1
        return "https://api.us1.sysdig.com"


""" COMMAND FUNCTIONS """


def execute_response_action_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Call the Actions Response API
    """
    full_url = _get_public_api_url(client.base_url) + "/secure/response-actions/v1alpha1/action-executions"
    data = _build_data_payload(args)

    result: dict = client.call_sysdig_api(method="POST", full_url=full_url, json_data=data)  # type: ignore[assignment]
    readable_output = (
        f"## Response Action: {result.get('actionType')}\n"
        f"Triggered successfully by callerId: **{result.get('callerId')}** with status: **{result.get('status')}**\n"
        f"Result ID: **{result.get('id')}**\n"
        f"Parameters: `{result.get('parameters')}`\n"
        f"Outputs: `{result.get('outputs')}`\n"
    )

    return CommandResults(
        outputs_prefix="execute_response_action.Output",
        outputs=result,
        readable_output=readable_output,
        raw_response=result,
    )


def get_action_execution_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get the status of an action execution
    """
    action_execution_id = args.get("action_execution_id")
    full_url = _get_public_api_url(client.base_url) + f"/secure/response-actions/v1alpha1/action-executions/{action_execution_id}"

    result: dict = client.call_sysdig_api(method="GET", full_url=full_url)  # type: ignore[assignment]
    readable_output = (
        f"## Action Execution Status\n"
        f"- **Action Type:** {result.get('actionType')}\n"
        f"- **Caller ID:** {result.get('callerId')}\n"
        f"- **Status:** {result.get('status')}\n"
        f"- **Result ID:** {result.get('id')}\n"
        f"- **Parameters:** `{result.get('parameters')}`\n"
        f"- **Outputs:** `{result.get('outputs')}`\n"
    )

    return CommandResults(
        outputs_prefix="get_action_execution.Output",
        outputs=result,
        readable_output=readable_output,
        raw_response=result,
    )


def create_system_capture_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Trigger a sysdig system capture
    """
    data = _build_capture_payload(args)
    result: dict = client.call_sysdig_api(method="POST", url_suffix="/api/v1/captures",
                                          json_data=data)  # type: ignore[assignment]
    readable_output = (
        f"## Capture: {result.get('capture', {}).get('name')}\n"
        f"- **Status:** {result.get('capture', {}).get('status')}\n"
        f"- **Capture ID:** {result.get('capture', {}).get('id')}\n"
    )

    return CommandResults(
        outputs_prefix="create_system_capture.Output",
        outputs=result,
        readable_output=readable_output,
        raw_response=result,
    )


def get_capture_file_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Download a sysdig capture file (.scap). You must provide the capture ID.
    You can then use the scap file to analyze it with Stratoshark for example.
    """

    capture_id = args.get("capture_id")
    if not capture_id:
        raise ValueError("capture_id is required")
    url_suffix = f"/api/v1/captures/{capture_id}/download"

    # The response is a binary file, so we set the resp_type to 'content'
    result: str | bytes = client.call_sysdig_api(url_suffix=url_suffix, resp_type="content")  # type: ignore[assignment]
    incident_id = demisto.incident().get("id")
    file_name = f"{incident_id}_{capture_id}.scap"

    # Save the file in the War Room
    demisto.results(fileResult(file_name, result, EntryType.FILE))

    readable_output = f"# Capture Taken\n**{file_name}** saved successfully to the War Room"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="get_capture_file.Output",
    )


def _cache_is_valid(entry: dict | None, ttl: int = 3600) -> bool:
    if not entry or "cached_at" not in entry:
        return False
    return (time.time() - entry["cached_at"]) < ttl


def get_agent_by_mac_command(client: Client, args: dict[str, Any]) -> CommandResults:
    machine_id = args.get("machine_id")
    if not machine_id:
        raise ValueError("machine_id (MAC address) is required.")

    ctx = demisto.getIntegrationContext()
    cache_key = f"agent_{machine_id}"
    cached = ctx.get(cache_key)
    force = argToBoolean(args.get("force_refresh", "false"))

    if _cache_is_valid(cached) and not force:
        agent = cached["data"]
    else:
        result: dict = client.call_sysdig_api("GET", url_suffix="/api/agents/connected")
        agents = result.get("agents", result) if isinstance(result, dict) else result
        agent = None
        for a in agents:
            if a.get("machineId") == machine_id:
                agent = {
                    "agentId": str(a.get("id", "")),
                    "customerId": str(a.get("customer", "")),
                    "hostName": a.get("hostName", ""),
                    "machineId": a.get("machineId", ""),
                    "hostId": a.get("opaqueUid", ""),
                    "clusterName": a.get("attributes", {}).get("clusterName", ""),
                }
                ctx[cache_key] = {"data": agent, "cached_at": time.time()}
                demisto.setIntegrationContext(ctx)
                break

        if not agent:
            raise ValueError(f"No connected agent found with machineId (MAC) '{machine_id}'.")

    return CommandResults(
        outputs_prefix="Sysdig.Agent",
        outputs_key_field="machineId",
        outputs=agent,
        readable_output=(
            f"**Agent ID:** {agent['agentId']}\n"
            f"**Customer ID:** {agent['customerId']}\n"
            f"**Hostname:** {agent['hostName']}\n"
            f"**Host ID:** {agent['hostId']}\n"
            f"**Cluster:** {agent['clusterName']}"
        ),
    )


def get_customer_info_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ctx = demisto.getIntegrationContext()
    cached = ctx.get("customer_info")
    force = argToBoolean(args.get("force_refresh", "false"))

    if _cache_is_valid(cached) and not force:
        customer_id = cached["data"]["customer_id"]
        customer_name = cached["data"].get("customer_name", "")
    else:
        result: dict = client.call_sysdig_api("GET", url_suffix="/api/users/me")
        user: dict = result.get("user", {})
        customer = user.get("customer", {})
        customer_id = customer.get("id") or user.get("customerId")
        customer_name = customer.get("name") or user.get("customerName", "")
        if customer_id:
            ctx["customer_info"] = {
                "data": {"customer_id": str(customer_id), "customer_name": customer_name},
                "cached_at": time.time(),
            }
            demisto.setIntegrationContext(ctx)

    if not customer_id:
        raise ValueError("Could not retrieve customer ID from Sysdig API.")

    output = {"customerId": str(customer_id), "customerName": customer_name}
    return CommandResults(
        outputs_prefix="Sysdig.Customer",
        outputs_key_field="customerId",
        outputs=output,
        readable_output=f"**Sysdig Customer ID:** {customer_id}\n**Customer Name:** {customer_name}",
    )


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: The Sysdig client to use for the API call

    Returns:
        'ok' if test passed, anything else will fail the test
    """

    result: dict = client.call_sysdig_api("GET", url_suffix="/api/users/me")  # type: ignore[assignment]
    user: dict = result.get("user", {})
    if user and user.get("id"):
        return "ok"
    else:
        return "Test failed. Could not retrieve user information from Sysdig API. Please check your credentials and API URL."


def main():  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    # Get the service API key for the Bearer auth from the credentials service
    api_key = demisto.params().get("credentials", {}).get("password")
    # get the service API url
    base_url = params.get("url")

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not argToBoolean(params.get("insecure", False))

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()

    try:
        headers = {"accept": "application/json", "Authorization": "Bearer " + api_key, "Content-Type": "application/json"}

        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)
        args = demisto.args()

        if command == "execute-response-action":
            result = execute_response_action_command(client, args)
        elif command == "create-system-capture":
            result = create_system_capture_command(client, args)
        elif command == "get-capture-file":
            result = get_capture_file_command(client, args)
        elif command == "get-action-execution":
            result = get_action_execution_command(client, args)
        elif command == "sysdig-get-agent-info":
            result = get_agent_by_mac_command(client, args)
        elif command == "sysdig-get-customer-info":
            result = get_customer_info_command(client, args)
        elif command == "test-module":
            result = test_module(client)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(result)  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
