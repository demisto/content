from typing import Any

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable warnings for insecure requests when cert validation is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def IS_2XX(x: int) -> bool:
    return int(x / 100) == 2  # Returns true if status code (int) is 2xx


class CyberTriageClient(BaseClient):
    SCAN_OPTIONS = ["pr", "nw", "nc", "st", "sc", "ru", "co", "lo", "ns", "wb", "fs"]

    def __init__(
        self,
        server: str,
        rest_port: str,
        api_auth_token: str,
        user: str,
        password: str,
        verify_server_cert: bool,
    ):
        base_url = (
            f"https://{server}:{rest_port}/api/"
            if not (server.startswith(("https://", "http://")))
            else f"{server}:{rest_port}/api/"
        )
        req_headers = {"Authorization": f"Bearer {api_auth_token}"}
        self._user = user
        self._password = password
        super().__init__(base_url=base_url, verify=verify_server_cert, headers=req_headers)

    def test_connection(self):
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
        # Validate scan options
        invalid_options = []
        if scan_options:
            invalid_options = [opt for opt in scan_options.split(",") if opt not in self.SCAN_OPTIONS]
        if invalid_options:
            raise DemistoException("The following are not valid scan options: {}".format(",".join(invalid_options)))

        api_data = {
            "incidentName": incident_name,
            "hostName": host_name,
            "userId": self._user,
            "password": self._password,
            "scanOptions": scan_options,
            "malwareScanRequested": is_hash_upload_on,
            "sendContent": is_file_upload_on,
            "sendIpAddress": False
        }
        response = self._http_request("POST", url_suffix="v2/livesessions", data=api_data, resp_type="response")
        return response


def test_connection_command(client: CyberTriageClient) -> str:
    response = client.test_connection()
    response.raise_for_status()
    return "ok"


def triage_host_name_command(client: CyberTriageClient, args: dict[str, Any]) -> CommandResults:
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

    if is_ip_valid(endpoint):
        endpoint_context = {"IPAddress": host_name}
    else:
        endpoint_context = {"Hostname": host_name}

    data = response.json()
    ec = {"CyberTriage": data, "Endpoint": endpoint_context}

    return CommandResults(readable_output=f"A collection has been scheduled for {host_name}", outputs=ec, raw_response=data)


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    server = params.get("server", "")
    rest_port = params.get("rest_port", "")
    api_auth_token = params.get("api_auth_token", {}).get("password", "")
    user = params.get("credentials", {}).get("identifier", "")
    password = params.get("credentials", {}).get("password", "")
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
