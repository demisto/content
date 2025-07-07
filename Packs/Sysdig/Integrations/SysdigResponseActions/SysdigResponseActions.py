"""
Sysdig Response Actions Integration
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import re
from typing import Any
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

SYSTEM_CAPTURES_REQUIRED_FIELDS = ["container_id", "host_name", "capture_name", "agent_id", "customer_id", "machine_id"]
RESPONSE_ACTIONS_REQUIRED_FIELDS = ["actionType", "callerId"]
RESPONSE_ACTIONS_PARAMS = {
    "FILE_QUARANTINE": ["path.absolute", "container.id"],
    "KILL_PROCESS": ["process.id", "host.id"],
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

    parameters = {
        key: value
        for key, value in {
            "container.id": args.get("container_id") if args.get("container_id") else None,
            "host.id": args.get("host_id") if args.get("host_id") else None,
            "path.absolute": args.get("path_absolute") if args.get("path_absolute") else None,
            "process.id": int(args["process_id"]) if args.get("process_id") else None,
            "startTime": -1 if args.get("process_id") else None,
        }.items()
        if value is not None
    }

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

    # Normalize parameter values
    for key in ["path.absolute", "process.id", "container.id", "host.id"]:
        if parameters.get(key) in ["null", ""]:
            parameters[key] = None

    # Validate required parameters based on the actionType
    missing_params = [param for param in RESPONSE_ACTIONS_PARAMS.get(actionType, []) if not parameters.get(param)]

    if missing_params:
        raise ValueError(f"{', '.join(missing_params)} are required for actionType {actionType}")


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
    result: dict = client.call_sysdig_api(method="POST", url_suffix="/api/v1/captures", json_data=data)  # type: ignore[assignment]
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
