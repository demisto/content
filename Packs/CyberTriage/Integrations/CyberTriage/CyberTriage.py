from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable warnings for insecure requests when cert validation is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PUBLIC_API_HINT = (
    "Make sure the public API is enabled in Cyber Triage (Options > Team Settings > Enable the "
    "public API) and that the API key belongs to an account allowed to list and create incidents."
)


class CyberTriageClient(BaseClient):
    def __init__(
        self,
        server: str,
        rest_port: str,
        api_auth_token: str,
        user: str,
        password: str,
        verify_server_cert: bool,
        proxy: bool = False,
    ):
        # Normalize the server URL: prepend https:// if no scheme is present
        base_url = (
            f"https://{server}:{rest_port}/api/"
            if not (server.startswith(("https://", "http://")))
            else f"{server}:{rest_port}/api/"
        )
        # Use a Bearer token for API authentication
        req_headers = {"Authorization": f"Bearer {api_auth_token}"}
        # Store credentials used when launching live collections
        self._user = user
        self._password = password
        super().__init__(base_url=base_url, verify=verify_server_cert, headers=req_headers, proxy=proxy)

    def list_incidents(self, name: str | None = None) -> list[dict[str, Any]]:
        # The name filter is a case-insensitive substring match
        params = {"name": name} if name else None
        return self._http_request("GET", url_suffix="incidents", params=params)

    def create_incident(self, name: str) -> dict[str, Any]:
        return self._http_request("POST", url_suffix="incidents", json_data={"name": name})

    def get_or_create_incident_id(self, name: str) -> int:
        # Incident names are unique case-insensitively, so match the same way the server does
        wanted = name.strip().lower()
        for incident in self.list_incidents(name):
            if incident.get("name", "").strip().lower() == wanted:
                return incident["incidentId"]
        return self.create_incident(name)["incidentId"]

    def live_psexec(self, incident_id: int, request: dict[str, Any]) -> dict[str, Any]:
        request = {"userId": self._user, "password": self._password, **request}
        return self._http_request("POST", url_suffix=f"incidents/{incident_id}/hosts/live-psexec", json_data=request)


def test_module(client: CyberTriageClient) -> str:
    # Listing incidents is a public API call, so it proves the token and the public API switch
    try:
        client.list_incidents()
    except DemistoException as e:
        if e.res is not None and e.res.status_code in (401, 403):
            raise DemistoException(f"Authorization failed: {e}. {PUBLIC_API_HINT}")
        raise
    return "ok"


def optional_bool(value: Any) -> bool | None:
    # Unset stays None so the server's configured default applies
    return argToBoolean(value) if value else None


def triage_endpoint_command(client: CyberTriageClient, args: dict[str, Any]) -> CommandResults:
    host_name = args.get("host_name", "")
    incident_name = (args.get("incident_name") or "").strip() or "Default"

    request = assign_params(
        hostName=host_name,
        scanOptions=args.get("scan_options"),
        malwareScanRequested=optional_bool(args.get("malware_scan_requested")),
        sendContent=optional_bool(args.get("send_content")),
    )

    incident_id = client.get_or_create_incident_id(incident_name)
    host = client.live_psexec(incident_id, request)

    # Build the Endpoint context entry using whichever identifier was provided
    if is_ip_valid(host_name):
        endpoint_context = {"IPAddress": host_name}
    else:
        endpoint_context = {"Hostname": host_name}

    # hostId is the same ID the older API returned as SessionId
    ec = {"CyberTriage": {"SessionId": str(host["hostId"])}, "Endpoint": endpoint_context}

    return CommandResults(readable_output=f"A collection has been scheduled for {host_name}", outputs=ec, raw_response=host)


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
    verify_server_cert = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.debug(f"Command being called is {command}")
    try:
        client = CyberTriageClient(server, rest_port, api_auth_token, user, password, verify_server_cert, proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "ct-triage-endpoint":
            return_results(triage_endpoint_command(client, args))
        else:
            raise NotImplementedError(f"command={command} not implemented in this integration")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
