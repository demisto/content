"""
Sysdig Response Actions Integration
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import requests
from urllib.parse import urljoin
from typing import Any, Dict, Optional, Tuple
import urllib3, traceback, json

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

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
        self,
        base_url: str,
        verify: bool,
        headers: Dict[str, str],
        proxy: bool,
        ok_codes: Tuple[int] = (200, 201, 202)
    ):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers
        self.proxy = proxy
        self.ok_codes = ok_codes
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy, ok_codes=ok_codes)


    def call_sysdig_api(self, method: str = "GET", url_suffix: str = "/secure/response-actions/v1alpha1/action-executions", params: dict = None, data: dict = None, json_data: dict = None, resp_type: str = 'json', full_url: str = None) -> Dict[str, Any]:
        '''
        Call the Sysdig API

        Args:
            method: The HTTP method to use
            url_suffix: The URL suffix to use
            params: The parameters to use
            data: The data to use
            json_data: The JSON data to use
            resp_type: The response type to use
        '''
        demisto.debug(f"Calling endpoint: {self.base_url+url_suffix}")
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params, data=data,
            json_data=json_data,
            resp_type=resp_type,
            full_url=full_url,
            )

""" HELPER FUNCTIONS """

def _build_data_payload(args : Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse the input parameters to the data payload to execute an action
    """
    actionType = args.get("actionType", None)
    callerId = args.get("callerId", None)
    container_id = args.get("container_id", None)
    host_id = args.get("host_id", None)
    path_absolute = args.get("path_absolute", None)
    process_id = args.get("process_id", None)

    parameters = {}
    if container_id:
        parameters['container.id'] = container_id
    if host_id:
        parameters['host.id'] = host_id
    if path_absolute:
        parameters['path.absolute'] = path_absolute
    if process_id:
        parameters['process.id'] = int(process_id)
        parameters['startTime'] = -1 # To search from the beginning time

    data = {
        'actionType': actionType,
        'callerId': callerId,
        'parameters': parameters
    }

    _validate_response_actions_params(data)

    return data

def _build_capture_payload(args : Dict[str, Any]) -> Dict[str, Any]:
    '''
    Parse the input parameters to the data payload to create a system capture
    '''
    _validate_captures_params(args)

    container_id = args.get("container_id", None)
    host_name = args.get("host_name", None)
    capture_name = args.get("capture_name", None)
    agent_id = args.get("agent_id", None)
    customer_id = args.get("customer_id", None)
    machine_id = args.get("machine_id", None)

    data = {
        'containerId': container_id,
        'duration': 15,
        'hostName': host_name,
        'name': capture_name,
        'filters': "",
        'bucketName': "",
        'agent': {
            'id': agent_id,
            'customer': customer_id,
            'machineID': machine_id,
            'hostName': host_name
        },
        'annotations': {'manual': 'true'},
        'source': 'SDS',
        'storageType': 'S3',
        'folder': '/'
    }
    return data

def _validate_captures_params(args: Dict[str, Any]) -> None:
    """
    Validate the input parameters to create a system capture. Raise ValueError if any required parameter is missing
    """
    container_id = args.get("container_id", None)
    host_name = args.get("host_name", None)
    capture_name = args.get("capture_name", None)
    agent_id = args.get("agent_id", None)
    customer_id = args.get("customer_id", None)
    machine_id = args.get("machine_id", None)

    if not container_id or args.get("container_id") == "null":
        raise ValueError("container_id is required")
    if not host_name or args.get("host_name") == "null":
        raise ValueError("host_name is required")
    if not capture_name or args.get("capture_name") == "null":
        raise ValueError("capture_name is required")
    if not agent_id or args.get("agent_id") == "null":
        raise ValueError("agent_id is required")
    if not customer_id or args.get("customer_id") == "null":
        raise ValueError("customer_id is required")
    if not machine_id or args.get("machine_id") == "null":
        raise ValueError("machine_id is required")

def _validate_response_actions_params(args: Dict[str, Any]) -> None:
    """
    Validate the input parameters to execute an action. Raise ValueError if any required parameter is missing
    """
    actionType = args.get("actionType", None)
    callerId = args.get("callerId", None)
    parameters = args.get("parameters", None)
    # Validate required parameters
    if not actionType:
        raise ValueError("actionType is required")
    if not callerId:
        raise ValueError("callerId is required")
    if not parameters:
        raise ValueError("parameters is required")
    
    # Validate parameters values and set to None if value is "null"
    if parameters.get('path.absolute', None) == "null":
        parameters['path.absolute'] = None
    if parameters.get('process.id', None) == "null":
        parameters['process.id'] = None
    if parameters.get('container.id', None) == "null":
        parameters['container.id'] = None
    if parameters.get('host.id', None) == "null":
        parameters['host.id'] = None

    # Validate required parameters based on the actionType
    if actionType == "FILE_QUARANTINE" and not 'path.absolute' in parameters and not 'container.id' in parameters:
        raise ValueError("path.absolute and container.id are required for actionType FILE_QUARANTINE")
    if actionType == "KILL_PROCESS" and not 'process.id' in parameters and not 'host.id' in parameters:
        raise ValueError("process.id and host.id are required for actionType KILL_PROCESS")


""" COMMAND FUNCTIONS """

def call_response_api_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Call the Actions Response API
    """
    method = args.get("method")
    url_suffix = args.get("url_suffix")
    data = None
    if method == "POST" or method == "PUT":
        data = _build_data_payload(args)

    result = client.call_sysdig_api(method = method, url_suffix = url_suffix, json_data = data)

    return CommandResults(
        outputs_prefix="call_response_api.Output",
        outputs=result
    )

def create_system_capture_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Trigger a sysdig system capture
    """
    method = args.get("method")
    url_suffix = args.get("url_suffix")
    data = _build_capture_payload(args)

    result = client.call_sysdig_api(method = method, url_suffix = url_suffix, json_data = data)

    return CommandResults(
        outputs_prefix="create_system_capture.Output",
        outputs=result
    )

def download_capture_file_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Download a sysdig capture file (.scap). You must provide the capture ID. You can then use the scap file to analyze it with Stratoshark for example.
    """

    capture_id = args.get("capture_id") 
    if not capture_id:
        raise ValueError("capture_id is required")
    capture_id = int(capture_id)
    url_suffix = f"/api/v1/captures/{capture_id}/download"

    # The response is a binary file, so we set the resp_type to 'content'
    result = client.call_sysdig_api(url_suffix = url_suffix, resp_type='content')
    incident_id = demisto.incident().get('id')
    file_name = f'{incident_id}_{capture_id}.scap'

    # Save the file in the War Room
    demisto.results(fileResult(file_name, result, EntryType.FILE))

    readable_output = f"# Capture Taken\n**{file_name}** saved successfully to the War Room"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="download_capture_file.Output",
    )


def print_exc(exception):
    traceback.print_exception(type(exception), exception, exception.__traceback__)

def main():
    """main function, parses params and runs command functions"""

    params = demisto.params()
    # Get the service API key for the Bearer auth
    api_key = params.get('apikey')
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

    # demisto.debug(f"Command being called is {command}")
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers = {
            "accept": "application/json",
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json"
        }

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )
        args = demisto.args()

        if command == "call-response-api":
            result = call_response_api_command(client, args)
        elif command == "create-system-capture":
            result = create_system_capture_command(client, args)
        elif command == "download-capture-file":
            result = download_capture_file_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
