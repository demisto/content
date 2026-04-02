from typing import Any

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable warnings for insecure requests when cert validation is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def IS_2XX(x: int) -> bool:
    # Returns true if HTTP status code is in the 2xx success range
    return int(x / 100) == 2


class CyberTriageClient(BaseClient):

    def __init__(
        self,
        server: str,
        rest_port: str,
        api_auth_token: str,
        user: str,
        password: str,
        verify_server_cert: bool,
    ):
        # Normalize the server URL: prepend https:// if no scheme is present
        base_url = (
            f"https://{server}:{rest_port}/api/"
            if not (server.startswith(("https://", "http://")))
            else f"{server}:{rest_port}/api/"
        )
        # Use a Bearer token for API authentication
        req_headers = {"Authorization": f"Bearer {api_auth_token}"}
        # Store credentials used when initiating live collection sessions
        self._user = user
        self._password = password
        super().__init__(base_url=base_url, verify=verify_server_cert, headers=req_headers)

    def test_connection(self):
        # Fetch the current user profile to verify credentials and connectivity
        response = self._http_request("GET", url_suffix="users/me", resp_type="response")
        return response

    def triage_endpoint(
        self,
        is_hash_upload_on: bool,
        is_file_upload_on: bool,
        host_name: str,
        scan_options: str,
        incident_name: str
    ):
        # Build the POST body for the live-session collection request
        api_data = {
            "incidentName": incident_name,
            "hostName": host_name,
            "userId": self._user,
            "password": self._password,
            "scanOptions": scan_options,
            "malwareScanRequested": is_hash_upload_on,  # Upload file hashes for malware analysis
            "sendContent": is_file_upload_on,            # Upload file content to the server
            "sendIpAddress": False                        # Do not resolve/send the collector IP
        }
        response = self._http_request("POST", url_suffix="v2/livesessions", json_data=api_data, resp_type="response")
        return response


def test_connection_command(client: CyberTriageClient) -> str:
    # Verify that the integration can reach the CyberTriage server with the configured credentials
    response = client.test_connection()
    response.raise_for_status()
    return "ok"


def triage_endpoint_command(client: CyberTriageClient, args: dict[str, Any]) -> CommandResults:
    # XSOAR passes boolean-style args as the string "yes"/"no"
    def is_true(x: str) -> bool:
        return x == "yes"

    is_hash_upload_on = is_true(args.get("malware_scan_requested", ""))
    is_file_upload_on = is_true(args.get("send_content", ""))
    host_name = args.get("host_name", "")
    scan_options = args.get("scan_options", "")
    incident_name = args.get("incident_name", "")

    response = client.triage_endpoint(is_hash_upload_on, is_file_upload_on, host_name, scan_options, incident_name)

    if response.status_code >= 400:
        raise Exception(f"HTTP {response.status_code} error from triage endpoint: {response.text}")

    response.raise_for_status()

    # Build the Endpoint context entry using whichever identifier was provided
    if is_ip_valid(host_name):
        endpoint_context = {"IPAddress": host_name}
    else:
        endpoint_context = {"Hostname": host_name}

    data = response.json()
    # Merge CyberTriage session data and endpoint identity into the context
    ec = {"CyberTriage": data, "Endpoint": endpoint_context}

    return CommandResults(readable_output=f"A collection has been scheduled for {host_name}", outputs=ec, raw_response=data)


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    # Pull connection details from the integration instance configuration
    server = params.get("server", "")
    rest_port = params.get("rest_port", "")
    # api_auth_token is stored as a credential; the token value is in the "password" field
    api_auth_token = params.get("api_auth_token", {}).get("password", "")
    user = params.get("credentials", {}).get("identifier", "")
    password = params.get("credentials", {}).get("password", "")
    # "insecure" being True means the user opted to skip cert verification
    verify_server_cert = not params.get("insecure", True)
    handle_proxy()

    demisto.debug(f"Command being called is {command}")
    try:
        client = CyberTriageClient(server, rest_port, api_auth_token, user, password, verify_server_cert)

        if command == "ct-triage-endpoint":
            return_results(triage_endpoint_command(client, args))
        elif command == "test-module":
            return_results(test_connection_command(client))
        else:
            raise NotImplementedError(f"command={command} not implemented in this integration")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
