import demistomock as demisto
from CommonServerPython import *

MIRROR_DIRECTION = {"None": None, "Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}
OUTGOING_MIRRORED_FIELDS_OBJ = {
    "Status",
    "Severity",
}
OUTGOING_MIRRORED_FIELDS = {filed: pascalToSpace(filed) for filed in OUTGOING_MIRRORED_FIELDS_OBJ}
SCRIPT_BRAND = "CheckPointXDR"


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, access_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.access_key = access_key
        self.token: Optional[str] = None

    def _login(self) -> None:
        if self._session.cookies:
            self._session.cookies.clear()

        auth_data = {"clientId": self.client_id, "accessKey": self.access_key}
        res = self._http_request("POST", url_suffix="/auth/external", data=auth_data, resp_type="response")

        if res.status_code == 200:
            self.token = res.json().get("data").get("token")
            demisto.debug("Log-in successful! client's token was set!")
        else:
            raise DemistoException(f"Log-in failed: {str(res.status_code)}: {res.text}")

    def get_incidents(self, startTS: str, max_fetch: int):
        self._login()
        headers = {"Authorization": f"Bearer {self.token}"}
        demisto.debug(f"Fetching XDR incidents with start timestamp: {startTS} and max fetch: {max_fetch}")

        all_incidents = []
        offset = 0
        has_more = True

        while has_more:
            try:
                url = f"/app/xdr/api/xdr/v1/incidents?limit={max_fetch}&offset={offset}&from={startTS}"
                res = self._http_request("GET", url_suffix=url, headers=headers, resp_type="response")
                incidents = res.json().get("data", {}).get("incidents", [])

                demisto.debug(f"Fetched {len(incidents)} XDR incidents at offset {offset}.")
                all_incidents.extend(incidents)

                has_more = len(incidents) == max_fetch
                offset += max_fetch

            except Exception as e:
                demisto.error(f"Failed to fetch XDR incidents: {str(e)}")
                raise DemistoException(f"Failed to fetch XDR incidents: {str(e)}")

        demisto.debug(f"Total incidents fetched: {len(all_incidents)}")
        return all_incidents

    def update_incident(self, status: int, close_reason: str = "", incident_id: str = "") -> dict:
        """
        Update an incident in CheckPoint XDR.

        Args:
            status (Optional[str]): The new status of the incident.
            incident_id (Optional[str]): The ID of the incident to update.

        Returns:
            dict: The response from the API.
        """
        demisto.debug(f"XDR - Starting to update_incident with status: {status}")

        if not incident_id:
            raise DemistoException("No incident ID provided")

        demisto.debug(f"XDR - Updating incident with ID: {incident_id}")

        # Log in to ensure we have a valid token
        self._login()

        headers = {"Authorization": f"Bearer {self.token}"}
        update_data = {}

        # Only include status in the update if it was provided
        # if status:
        # new, in progress, close - handled, close - prevented, close - false positive, close - known activity
        status_map = {
            "Resolved": "close - handled",
            "Duplicate": "close - known activity",
            "False Positive": "close - false positive",
            "Other": "close - prevented",
        }
        update_data["status"] = status_map[close_reason]

        # If no fields to update, log and return
        if not update_data:
            demisto.debug("XDR - No fields to update, skipping API call")
            return {}

        demisto.debug(f"XDR - Sending update with data: {update_data}")

        try:
            res = self._http_request(
                "PUT",
                url_suffix=f"/app/xdr/api/xdr/v1/incidents/{incident_id}",
                headers=headers,
                json_data=update_data,
                resp_type="response",
            )

            if res.status_code != 200:
                raise DemistoException(f"Failed to update XDR incident: {str(res.status_code)}: {res.text}")

            response_data = res.json().get("data", {})
            demisto.debug(f"XDR - Successfully updated incident {incident_id}")
            return response_data

        except Exception as e:
            demisto.error(f"XDR - Error updating incident {incident_id}: {str(e)}")
            raise DemistoException(f"Error updating incident: {str(e)}")


def test_module(client: Client, last_run: dict[str, str], first_fetch: datetime):
    try:
        fetch_incidents(
            client,
            {"mirror_direction": MIRROR_DIRECTION.get("Outgoing"), "mirror_instance": demisto.integrationInstance()},
            last_run,
            first_fetch,
            1,
        )
        return "ok"
    except DemistoException as e:
        return e.message


def map_severity(severity: str) -> int:
    """
    Maps the severity from CheckPoint XDR to XSOAR severity levels.

    Args:
        severity (str): The severity level from CheckPoint XDR.

    Returns:
        int: The corresponding XSOAR severity level.
    """
    severity_mapping = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return severity_mapping.get(severity.lower(), 1)


# If using incoming mapper then this function is not needed - validate
def get_instances_id():
    """
    Get the instance ID for the specified script brand.

    :rtype: ``str``
    :return: Instance ID of the integration with matching brand
    """
    integration_context = demisto.getIntegrationContext()
    instances_id = integration_context.get("instances_id", "")

    return instances_id


def parse_incidents(xdr_incidents: List, mirroring_fields: dict, startTS: int, max_fetch: int):
    incidents: list[dict[str, Any]] = []
    for incident in xdr_incidents:
        incident.update(mirroring_fields)

        # Constructing the XSOAR incident
        incidents.append(
            {
                "dbotMirrorId": incident.get("id", "unknown_id"),
                "occurred": incident.get("created_at", ""),
                "severity": map_severity(incident.get("severity", "medium")),
                "name": f"#{incident.get('display_id', '')} - {incident.get('summary', '')}",
                "details": incident.get("summary", ""),
                "dbotMirrorDirection": "Out",
                "dbotMirrorInstance": get_instances_id(),
                "rawJSON": json.dumps(incident),
            }
        )

    last_time = (
        json.loads(incidents[0]["rawJSON"]).get("updated_at")
        if incidents and incidents[0].get("rawJSON")
        else datetime.utcfromtimestamp(startTS / 1000).isoformat()
    )
    demisto.debug(f"Last incident time: {last_time}")
    return incidents, last_time


def fetch_incidents(client: Client, mirroring_fields: dict, last_run: dict[str, str], first_fetch: datetime, max_fetch: int):
    last_fetch = last_run.get("last_fetch", first_fetch.isoformat())
    last_fetch_time = arg_to_datetime(last_fetch)
    if not last_fetch_time:
        raise Exception(f"Invalid last fetch time value '{last_fetch}'")
    startTS = int(last_fetch_time.timestamp() * 1000)
    demisto.debug(f"Fetching incidents since {last_fetch} (timestamp: {startTS})")
    xdr_incidents = client.get_incidents(last_fetch, max_fetch)
    incidents, last_incident_time = parse_incidents(xdr_incidents, mirroring_fields, startTS, max_fetch)

    return {"last_fetch": last_incident_time}, incidents


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    update_remote_system_args = UpdateRemoteSystemArgs(args)
    remote_incident_id = update_remote_system_args.remote_incident_id
    delta = update_remote_system_args.delta
    incident_changed = update_remote_system_args.incident_changed
    inc_status = update_remote_system_args.inc_status
    data = update_remote_system_args.data

    demisto.debug(
        f"XDR - update_remote_system_command called with {remote_incident_id=}, {delta=}, "
        f"{incident_changed=}, {inc_status=}, {data=}"
    )

    # Check if we're closing the incident
    if inc_status == IncidentStatus.DONE:
        close_reason = delta.get("closeReason", "")
        if argToBoolean(demisto.params().get("close_out", True)):
            demisto.debug("XDR - Incident is being updated, updating remote system")
            try:
                # Update XDR incident to Resolved status
                client.update_incident(status=int(inc_status), close_reason=close_reason, incident_id=remote_incident_id)
                demisto.debug(f"XDR - Successfully closed incident {remote_incident_id} in XDR")
            except Exception as e:
                demisto.error(f"XDR - Failed to close incident {remote_incident_id} in XDR: {str(e)}")
        else:
            demisto.debug("XDR - close_out is not enabled, skipping closure in XDR")

    return remote_incident_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    incident_type_scheme = SchemeTypeMapping(type_name="Check Point XDR Incident")

    for argument, description in OUTGOING_MIRRORED_FIELDS.items():
        incident_type_scheme.add_field(name=argument, description=description)
    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def main() -> None:
    params = demisto.params()

    base_url = params.get("url", "")
    client_id = params.get("credentials", {}).get("identifier")
    access_key = params.get("credentials", {}).get("password")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = int(params.get("max_fetch", 1000))

    fetch_time = params.get("first_fetch", "3 days").strip()
    first_fetch = arg_to_datetime(fetch_time, is_utc=True)
    if not first_fetch:
        raise Exception(f"Invalid first fetch time value '{fetch_time}', must be '<number> <time unit>', e.g., '24 hours'")

    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    mirroring_fields = {
        "mirror_direction": MIRROR_DIRECTION.get(params.get("mirror_direction", "None")),
        "mirror_instance": get_instances_id(),
    }

    try:
        client = Client(base_url, client_id, access_key, verify, proxy)
        last_run = demisto.getLastRun()
        if command == "test-module":
            demisto.debug("XDR - test-module")
            return_results(test_module(client, last_run, first_fetch))
        elif command == "fetch-incidents":
            demisto.debug("XDR - fetch-incidents")
            next_run, incidents = fetch_incidents(client, mirroring_fields, last_run, first_fetch, max_fetch)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
            demisto.debug(f"Set last run to {next_run.get('last_fetch')}")
        elif command == "update-remote-system":
            demisto.debug("XDR - update-remote-system")
            return_results(update_remote_system_command(client, args))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
