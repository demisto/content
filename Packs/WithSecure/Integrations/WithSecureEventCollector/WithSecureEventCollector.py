import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

MAX_FETCH_LIMIT = 1000
VENDOR = "WithSecure"
PRODUCT = "Endpoint Protection"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url, verify, proxy, client_id, client_secret):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self) -> tuple[str, int]:
        """Get the access token from the WithSecure API.

        Returns:
            tuple[str,int]: The token and its expiration time in seconds received from the API.
        """

        response = self._http_request(
            method="POST",
            url_suffix="as/token.oauth2",
            auth=(self.client_id, self.client_secret),
            data={"grant_type": "client_credentials"},
            error_handler=access_token_error_handler,
        )

        return response.get("access_token"), response.get("expires_in")

    def get_access_token(self):
        """Return the token stored in integration context or returned from the API call.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Returns:
            str: Authentication token.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate()
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,
        }
        set_integration_context(integration_context)

        return token

    def get_events_api_call(self, fetch_from: str, limit: int, next_anchor: str = None):
        params = {"persistenceTimestampStart": fetch_from, "limit": limit, "order": "asc"}
        if next_anchor:
            params["anchor"] = next_anchor
        return self._http_request(
            method="GET",
            url_suffix="security-events/v1/security-events",
            headers={"Authorization": f"Bearer {self.get_access_token()}"},
            params=params,
        )

    def get_incidents(self, incident_id: str = None, status: str = None, risk_level: str = None,
                      limit: int = 20, source: str = None, next_anchor: str = None):
        """Get EDR incidents (Broad Context Detections)."""
        params = {"limit": limit, "archived": "false"}
        if incident_id:
            params["incidentId"] = incident_id
        if status:
            params["status"] = status
        if risk_level:
            params["riskLevel"] = risk_level
        if source:
            params["source"] = source
        if next_anchor:
            params["anchor"] = next_anchor
        return self._http_request(
            method="GET",
            url_suffix="incidents/v1/incidents",
            headers={"Authorization": f"Bearer {self.get_access_token()}"},
            params=params,
        )

    def update_incident_status(self, incident_id: str, status: str, resolution: str = None):
        """Update incident status."""
        data = {"targets": [incident_id], "status": status}
        if resolution:
            data["resolution"] = resolution
        return self._http_request(
            method="PATCH",
            url_suffix="incidents/v1/incidents",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
            },
            json_data=data,
        )

    def add_incident_comment(self, incident_ids: list[str], comment: str):
        """Add comment to incidents."""
        data = {"targets": incident_ids, "comment": comment}
        return self._http_request(
            method="POST",
            url_suffix="incidents/v1/comments",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
            },
            json_data=data,
        )

    def get_incident_detections(self, incident_id: str, limit: int = 100, next_anchor: str = None):
        """Get detections for a specific incident."""
        params = {"incidentId": incident_id, "limit": limit}
        if next_anchor:
            params["anchor"] = next_anchor
        return self._http_request(
            method="GET",
            url_suffix="incidents/v1/detections",
            headers={"Authorization": f"Bearer {self.get_access_token()}"},
            params=params,
        )

    def get_devices(self, device_id: str = None, name: str = None, device_type: str = None,
                    state: str = None, online: str = None, protection_status: str = None,
                    limit: int = 50, next_anchor: str = None):
        """Get devices from WithSecure."""
        params = {"limit": limit}
        if device_id:
            params["deviceId"] = device_id
        if name:
            params["name"] = name
        if device_type:
            params["type"] = device_type
        if state:
            params["state"] = state
        if online:
            params["online"] = online.lower()
        if protection_status:
            params["protectionStatusOverview"] = protection_status
        if next_anchor:
            params["anchor"] = next_anchor
        return self._http_request(
            method="GET",
            url_suffix="devices/v1/devices",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Accept": "application/json",
            },
            params=params,
        )

    def isolate_endpoint(self, device_ids: list[str], message: str = None):
        """Isolate endpoints from network."""
        data = {"operation": "isolateFromNetwork", "targets": device_ids}
        if message:
            data["parameters"] = {"message": message}
        return self._http_request(
            method="POST",
            url_suffix="devices/v1/operations",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
            },
            json_data=data,
        )

    def release_endpoint(self, device_ids: list[str]):
        """Release endpoints from network isolation."""
        data = {"operation": "releaseFromNetworkIsolation", "targets": device_ids}
        return self._http_request(
            method="POST",
            url_suffix="devices/v1/operations",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
            },
            json_data=data,
        )

    def scan_endpoint(self, device_ids: list[str]):
        """Trigger malware scan on endpoints."""
        data = {"operation": "scanForMalware", "targets": device_ids}
        return self._http_request(
            method="POST",
            url_suffix="devices/v1/operations",
            headers={
                "Authorization": f"Bearer {self.get_access_token()}",
                "Content-Type": "application/json",
            },
            json_data=data,
        )

    def get_device_operations(self, device_id: str):
        """Get operations for a specific device."""
        params = {"deviceId": device_id}
        return self._http_request(
            method="GET",
            url_suffix="devices/v1/operations",
            headers={"Authorization": f"Bearer {self.get_access_token()}"},
            params=params,
        )


""" HELPER FUNCTIONS """


def access_token_error_handler(response: requests.Response):
    """
    Error Handler for WithSecure access_token
    Args:
        response (response): WithSecure Token url response
    Raise:
         DemistoException
    """
    if response.status_code == 401:
        raise DemistoException(
            "Authorization Error: The provided credentials for WithSecure are "
            "invalid. Please provide a valid Client ID and Client Secret."
        )
    elif response.status_code >= 400:
        raise DemistoException("Error: something went wrong, please try again.")


def parse_date(dt: str) -> str:
    date_time = dateparser.parse(dt, settings={"TIMEZONE": "UTC"})
    return date_time.strftime(DATE_FORMAT)  # type: ignore


def parse_events(events: list, last_fetch: str, last_event_id: str) -> tuple[str, str, list]:
    last_fetch_timestamp = date_to_timestamp(last_fetch, DATE_FORMAT)
    last_event_timestamp = last_fetch_timestamp
    last_event_time = last_fetch
    new_event_id = last_event_id
    parsed_events: list = []
    for event in events:
        event_time = date_to_timestamp(parse_date(event.get("serverTimestamp")), DATE_FORMAT)
        ev_id = event.get("id")
        # the event was already fetched
        if last_fetch_timestamp == event_time and last_event_id == ev_id:
            continue
        event["_time"] = parse_date(event.get("clientTimestamp"))
        if last_event_timestamp < event_time:
            last_event_timestamp = event_time
            last_event_time = event.get("serverTimestamp")
            new_event_id = ev_id

        parsed_events.append(event)

    return parse_date(last_event_time), new_event_id, parsed_events


def get_events(client: Client, fetch_from: str, limit: int) -> list:
    events: list = []
    next_anchor = "first"
    while next_anchor and len(events) < limit:
        req_limit = min(MAX_FETCH_LIMIT, limit - len(events))
        res = client.get_events_api_call(fetch_from, req_limit, next_anchor if next_anchor != "first" else None)
        events.extend(res.get("items"))
        next_anchor = res.get("nextAnchor")

    return events


def fetch_events(client: Client, fetch_from: str, limit: int, next_anchor):
    events: list = []
    req_limit = min(limit, MAX_FETCH_LIMIT)
    res = client.get_events_api_call(fetch_from, req_limit, next_anchor if next_anchor else None)
    events.extend(res.get("items"))
    next_anchor = res.get("nextAnchor")

    return events, next_anchor


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.get_access_token()
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Gets all the events from the WithSecure API for each log type.
    Args:
        client (Client): client to use.
        args: dict, demisto args.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """
    fetch_from = parse_date(args.get("fetch_from") or demisto.params().get("first_fetch", "3 days"))
    limit = arg_to_number(args.get("limit")) or MAX_FETCH_LIMIT
    events = get_events(client, fetch_from, limit)

    events = events[:limit]
    hr = tableToMarkdown(name="With Secure Events", t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events_command(client: Client, first_fetch: str, limit: int) -> tuple[list, dict]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that events are fetched only once and no events are missed.
    By default it's invoked by XSIAM every minute. It will use last_run to save the timestamp of the last event it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): WithSecure client to use.
        first_fetch (str): Timestamp to start fetch from
        limit (int): Maximum numbers of events per fetch.
    Returns:
        list: List of events that will be created in XSIAM.
        dict: The lastRun object for the next fetch run
    """
    last_run = demisto.getLastRun()
    fetch_from = last_run.get("fetch_from") or first_fetch
    next_anchor = last_run.get("next_anchor")
    event_id = last_run.get("event_id", "")
    events, next_anchor = fetch_events(client, fetch_from, limit, next_anchor)

    last_fetch, event_id, parsed_events = parse_events(events[:limit], fetch_from, event_id)
    next_run = {"fetch_from": last_fetch, "next_anchor": next_anchor, "event_id": event_id}

    return parsed_events, next_run


def get_incidents_command(client: Client, args: dict) -> CommandResults:
    """Get EDR incidents (Broad Context Detections)."""
    incident_id = args.get("incident_id")
    status = args.get("status")
    risk_level = args.get("risk_level")
    limit = arg_to_number(args.get("limit", 20))
    source = args.get("source")

    result = client.get_incidents(incident_id, status, risk_level, limit, source)
    incidents = result.get("items", [])

    return CommandResults(
        outputs_prefix="WithSecure.Incident",
        outputs_key_field="incidentId",
        outputs=incidents,
        readable_output=tableToMarkdown("WithSecure EDR Incidents", incidents, headers=[
            "incidentId", "incidentPublicId", "name", "status", "severity", "riskLevel",
            "riskScore", "categories", "sources", "createdTimestamp"
        ])
    )


def update_incident_status_command(client: Client, args: dict) -> CommandResults:
    """Update incident status."""
    incident_id = args.get("incident_id")
    status = args.get("status")
    resolution = args.get("resolution")

    if status == "closed" and not resolution:
        raise DemistoException("Resolution is required when closing an incident.")

    result = client.update_incident_status(incident_id, status, resolution)
    multistatus = result.get("multistatus", [])

    return CommandResults(
        outputs_prefix="WithSecure.IncidentUpdate",
        outputs_key_field="incidentId",
        outputs=[{"incidentId": incident_id, "status": multistatus[0].get("status") if multistatus else None}],
        readable_output=f"Successfully updated incident {incident_id} to status: {status}"
    )


def add_incident_comment_command(client: Client, args: dict) -> CommandResults:
    """Add comment to incidents."""
    incident_ids = argToList(args.get("incident_ids"))
    comment = args.get("comment")

    if len(incident_ids) > 10:
        raise DemistoException("Maximum 10 incidents can be commented at once.")

    result = client.add_incident_comment(incident_ids, comment)
    items = result.get("items", [])

    return CommandResults(
        readable_output=f"Successfully added comment to {len(items)} incident(s).",
        outputs_prefix="WithSecure.IncidentComment",
        outputs=items
    )


def get_incident_detections_command(client: Client, args: dict) -> CommandResults:
    """Get detections for a specific incident."""
    incident_id = args.get("incident_id")
    limit = arg_to_number(args.get("limit", 100))

    result = client.get_incident_detections(incident_id, limit)
    detections = result.get("items", [])

    return CommandResults(
        outputs_prefix="WithSecure.Detection",
        outputs_key_field="detectionId",
        outputs=detections,
        readable_output=tableToMarkdown(f"Detections for Incident {incident_id}", detections, headers=[
            "detectionId", "deviceId", "name", "detectionClass", "severity", "riskLevel",
            "exePath", "cmdl", "username", "createdTimestamp"
        ])
    )


def get_devices_command(client: Client, args: dict) -> CommandResults:
    """Get devices from WithSecure."""
    device_id = args.get("device_id")
    name = args.get("name")
    device_type = args.get("type")
    state = args.get("state")
    online = args.get("online")
    protection_status = args.get("protection_status")
    limit = arg_to_number(args.get("limit", 50))

    result = client.get_devices(device_id, name, device_type, state, online, protection_status, limit)
    devices = result.get("items", [])

    return CommandResults(
        outputs_prefix="WithSecure.Device",
        outputs_key_field="id",
        outputs=devices,
        readable_output=tableToMarkdown("WithSecure Devices", devices, headers=[
            "id", "name", "type", "state", "online", "protectionStatusOverview",
            "clientVersion", "os", "lastUser"
        ])
    )


def isolate_endpoint_command(client: Client, args: dict) -> CommandResults:
    """Isolate endpoints from network."""
    device_ids = argToList(args.get("device_ids"))
    message = args.get("message")

    if len(device_ids) > 5:
        raise DemistoException("Maximum 5 devices can be isolated at once.")

    result = client.isolate_endpoint(device_ids, message)
    multistatus = result.get("multistatus", [])

    outputs = []
    for item in multistatus:
        outputs.append({
            "deviceId": item.get("target"),
            "status": item.get("status"),
            "operationId": item.get("operationId"),
            "details": item.get("details")
        })

    return CommandResults(
        outputs_prefix="WithSecure.IsolationAction",
        outputs_key_field="deviceId",
        outputs=outputs,
        readable_output=tableToMarkdown("Endpoint Isolation Results", outputs, headers=[
            "deviceId", "status", "operationId", "details"
        ])
    )


def release_endpoint_command(client: Client, args: dict) -> CommandResults:
    """Release endpoints from network isolation."""
    device_ids = argToList(args.get("device_ids"))

    if len(device_ids) > 5:
        raise DemistoException("Maximum 5 devices can be released at once.")

    result = client.release_endpoint(device_ids)
    multistatus = result.get("multistatus", [])

    outputs = []
    for item in multistatus:
        outputs.append({
            "deviceId": item.get("target"),
            "status": item.get("status"),
            "operationId": item.get("operationId"),
            "details": item.get("details")
        })

    return CommandResults(
        outputs_prefix="WithSecure.IsolationAction",
        outputs_key_field="deviceId",
        outputs=outputs,
        readable_output=tableToMarkdown("Endpoint Release Results", outputs, headers=[
            "deviceId", "status", "operationId", "details"
        ])
    )


def scan_endpoint_command(client: Client, args: dict) -> CommandResults:
    """Trigger malware scan on endpoints."""
    device_ids = argToList(args.get("device_ids"))

    if len(device_ids) > 5:
        raise DemistoException("Maximum 5 devices can be scanned at once.")

    result = client.scan_endpoint(device_ids)
    multistatus = result.get("multistatus", [])

    outputs = []
    for item in multistatus:
        outputs.append({
            "deviceId": item.get("target"),
            "status": item.get("status"),
            "operationId": item.get("operationId"),
            "details": item.get("details")
        })

    return CommandResults(
        outputs_prefix="WithSecure.ScanAction",
        outputs_key_field="deviceId",
        outputs=outputs,
        readable_output=tableToMarkdown("Endpoint Scan Results", outputs, headers=[
            "deviceId", "status", "operationId", "details"
        ])
    )


def get_device_operations_command(client: Client, args: dict) -> CommandResults:
    """Get operations for a specific device."""
    device_id = args.get("device_id")

    result = client.get_device_operations(device_id)
    operations = result.get("items", [])

    return CommandResults(
        outputs_prefix="WithSecure.DeviceOperation",
        outputs_key_field="id",
        outputs=operations,
        readable_output=tableToMarkdown(f"Operations for Device {device_id}", operations, headers=[
            "id", "operationName", "status", "startedTimestamp", "lastUpdatedTimestamp", "expirationTimestamp"
        ])
    )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    base_url = params.get("url")
    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    first_fetch = parse_date(params.get("first_fetch", "3 months"))
    limit = arg_to_number(params.get("limit", 1000))

    verify_ssl = not params.get("insecure", False)

    proxy = params.get("proxy", False)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, verify=verify_ssl, client_id=client_id, client_secret=client_secret, proxy=proxy)

        if demisto.command() == "test-module":
            return_results(test_module(client))

        elif command == "with-secure-get-events":
            _, result = get_events_command(client, args)
            return_results(result)

        elif command == "fetch-events":
            events, next_run = fetch_events_command(client, first_fetch, limit)  # type: ignore
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        elif command == "with-secure-get-incidents":
            return_results(get_incidents_command(client, args))

        elif command == "with-secure-update-incident-status":
            return_results(update_incident_status_command(client, args))

        elif command == "with-secure-add-incident-comment":
            return_results(add_incident_comment_command(client, args))

        elif command == "with-secure-get-incident-detections":
            return_results(get_incident_detections_command(client, args))

        elif command == "with-secure-get-devices":
            return_results(get_devices_command(client, args))

        elif command == "with-secure-isolate-endpoint":
            return_results(isolate_endpoint_command(client, args))

        elif command == "with-secure-release-endpoint":
            return_results(release_endpoint_command(client, args))

        elif command == "with-secure-scan-endpoint":
            return_results(scan_endpoint_command(client, args))

        elif command == "with-secure-get-device-operations":
            return_results(get_device_operations_command(client, args))

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
