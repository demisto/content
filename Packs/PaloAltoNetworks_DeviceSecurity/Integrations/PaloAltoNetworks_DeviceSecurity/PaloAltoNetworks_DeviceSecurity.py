import json
import time
import base64
from datetime import UTC, datetime

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
from ContentClientApiModule import *

# IMPORTS


# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
# api list size limit
PAGELENGTH = 100
SEEN_IDS_LIMIT = 1000
SEEN_IDS_TRIM_COUNT = 750


class Client(ContentClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    """

    def __init__(
        self,
        base_url: str,
        first_fetch: str = "-1",
        max_fetch: int = 10,
        api_timeout: int = 60,
        verify: bool = True,
        proxy: bool = False,
        ok_codes: tuple = (),
        headers: dict | None = None,
    ) -> None:
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.api_timeout = api_timeout
        self.first_fetch = first_fetch
        self.max_fetch = min(max_fetch, PAGELENGTH)

    def _http_request(self, **kwargs) -> Any:  # type: ignore[override]
        try:
            params = kwargs.get("params", {})
            headers = kwargs.get("headers")

            if headers is None:
                headers = dict(self._headers) if self._headers else {}
            else:
                headers = dict(headers)

            headers.setdefault("User-Agent", "/")

            kwargs["params"] = params
            kwargs["headers"] = headers

            return super()._http_request(**kwargs)
        except DemistoException as error:
            error_message = str(error)
            if "[404]" in error_message:
                raise DemistoException(f"{error_message}\nResource or endpoint not found.")
            elif "[403]" in error_message:
                raise DemistoException(
                    f"{error_message}\nValidate your TSG ID and ensure the Client ID/Client Secret have the required permissions."
                )
            elif "[401]" in error_message:
                raise DemistoException(
                    f"{error_message}\nUnauthorized request. Validate Client ID and Client Secret, "
                    "and ensure the generated token is valid."
                )
            elif "[429]" in error_message:
                raise DemistoException(
                    f"{error_message}\nRate limit exceeded. Retry the request later or lower the request frequency."
                )
            elif "[500]" in error_message:
                raise DemistoException(f"{error_message}\nService temporary error. Retry the request in a few minutes.")
            else:
                raise error

    def get_device(self, device_id: str) -> dict:
        """
        Get a device from Device Security portal by device ID
        """
        return self._http_request(method="GET", url_suffix="/device", params={"deviceid": device_id}, timeout=self.api_timeout)

    def get_device_by_ip(self, ip: str) -> dict:
        """
        Get a device from Device Security portal by ip
        """
        return self._http_request(method="GET", url_suffix="/device/ip", params={"ip": ip}, timeout=self.api_timeout)

    def list_alerts(self, stime: str = "-1", offset: int = 0, pagelength: int = 100, sortdirection: str = "asc") -> list[dict]:
        """
        returns alerts inventory list
        """
        data = self._http_request(
            method="GET",
            url_suffix="/alert/list",
            params={
                "offset": offset,
                "pagelength": pagelength,
                "stime": stime,
                "type": "policy_alert",
                "resolved": "no",
                "sortfield": "date",
                "sortdirection": sortdirection,
            },
            timeout=self.api_timeout,
        )
        return data["items"]

    def list_vulns(self, stime: str = "-1", offset: int = 0, pagelength: int = 100) -> list[dict]:
        """
        returns vulnerability instances
        """
        data = self._http_request(
            method="GET",
            url_suffix="/vulnerability/list",
            params={
                "offset": offset,
                "pagelength": pagelength,
                "stime": stime,
                "type": "vulnerability",
                "status": "Confirmed",
                "groupby": "device",
            },
            timeout=self.api_timeout,
        )
        return data["items"]

    def list_devices(self, offset: int, pagelength: int) -> list[dict]:
        """
        returns a list of devices
        """
        data = self._http_request(
            method="GET",
            full_url=f"{self._base_url.replace('/v1', '/v2')}/device/list",
            params={
                "offset": offset,
                "pagelength": pagelength,
                "stime": datetime.fromtimestamp(int(time.time()) - 2592000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "sortdirection": "asc",
            },
            timeout=self.api_timeout,
        )
        return data["devices"]

    def resolve_alert(self, alert_id: str, reason: str, reason_type: str = "No Action Needed") -> dict:
        """
        Resolve a Device Security alert
        """
        return self._http_request(
            method="PUT",
            url_suffix="/alert/update",
            params={"id": alert_id},
            json_data={"resolved": "yes", "reason": reason, "reason_type": [reason_type]},
            timeout=self.api_timeout,
        )

    def resolve_vuln(self, vuln_id: str, full_name: str, reason: str) -> dict:
        """
        Resolve a Device Security vulnerability
        """
        return self._http_request(
            method="PUT",
            url_suffix="/vulnerability/update",
            json_data={"action": "mitigate", "full_name": full_name, "reason": reason, "ticketIdList": [vuln_id]},
            timeout=self.api_timeout,
        )


def get_scm_access_token(
    token_base_url: str, tsg_id: str, client_id: str, client_secret: str, verify_certificate: bool = True, proxy: bool = False
) -> str:
    try:
        integration_context = get_integration_context()
        access_token = integration_context.get("scm_access_token")
        expires_on = integration_context.get("scm_expires_on")

        if access_token and expires_on:
            try:
                expires_on_dt = datetime.fromisoformat(expires_on.replace("Z", "+00:00"))
                if expires_on_dt.tzinfo is None:
                    expires_on_dt = expires_on_dt.replace(tzinfo=UTC)

                if expires_on_dt > datetime.now(tz=UTC):
                    return access_token
            except ValueError:
                demisto.debug(f"Failed to parse cached scm_expires_on timestamp: {expires_on}. Requesting a new token.")

        auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        client = BaseClient(
            token_base_url,
            verify=verify_certificate,
            proxy=proxy,
            ok_codes=(200, 201, 202, 204),
            headers={"Authorization": f"Basic {auth}"},
        )

        token_data = client._http_request(
            method="POST",
            url_suffix="/oauth2/access_token",
            data={
                "grant_type": "client_credentials",
                "scope": f"tsg_id:{tsg_id}",
            },
        )

        access_token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 0)

        set_integration_context(
            {
                "scm_access_token": access_token,
                "scm_expires_on": (datetime.now(tz=UTC) + timedelta(seconds=int(expires_in))).isoformat(),
            }
        )

        return access_token
    except Exception as e:
        raise Exception(f"Failed to generate or validate SCM access token: {str(e)}")


def get_scm_ui_base_url() -> str:
    """Return SCM UI base URL."""
    return "https://stratacloudmanager.paloaltonetworks.com"


def get_scm_alert_url(alert_id: str) -> str:
    """Build the SCM alert details URL.

    Args:
        alert_id (str): Alert identifier.
    Returns:
        str: Full alert details URL.
    """
    return f"{get_scm_ui_base_url()}/insights/iot-security/alerts/security-alerts/alert-detail?id={alert_id}"


def get_scm_vuln_url(vuln: dict) -> str:
    """Build the SCM vulnerability details URL.

    Args:
        vuln (dict): Vulnerability object.
    Returns:
        str: Full vulnerability details URL.
    """
    vulnerability_name = vuln.get("vulnerability_name", "").replace(" ", "%20")
    device_id = vuln.get("deviceid", "")
    return (
        f"{get_scm_ui_base_url()}"
        f"/insights/iot-security/assets/assets/overview/{device_id}"
        f"?vulnerabilityname={vulnerability_name}"
    )


def trim_seen_ids(seen_ids: list[str]) -> list[str]:
    if len(seen_ids) > SEEN_IDS_LIMIT:
        return seen_ids[SEEN_IDS_TRIM_COUNT:]
    return seen_ids


def test_module(client: Client, is_fetch: bool, fetch_alerts: bool, fetch_vulns: bool) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client (Client): client to use
        is_fetch (bool): Whether to fetch incidents
        fetch_alerts (bool): Whether to fetch alerts
        fetch_vulns (bool): Whether to fetch vulnerabilities

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    if is_fetch:
        fetch_incidents(
            client,
            last_run=demisto.getLastRun(),
            fetch_alerts=fetch_alerts,
            fetch_vulns=fetch_vulns,
            is_test=True,
        )
    else:
        client.list_devices(0, 1)
    return "ok"


def device_security_get_device(client: Client, args: dict) -> CommandResults:
    """
    Returns a Device Security device

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        device

        CommandResults
    """
    device_id = args.get("id", "")
    if not device_id:
        return_error("id argument is required.")
    device_id = str(device_id)

    result = client.get_device(device_id)
    if not result:
        return CommandResults(readable_output="### No device found")

    readable_output = tableToMarkdown("Device Security Device", result, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="PaloAltoNetworksDeviceSecurity.Device",
        outputs_key_field="deviceid",
        outputs=result,
    )


def device_security_get_device_by_ip(client: Client, args: dict) -> CommandResults:
    """
    Returns a Device Security device

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        device

        CommandResults
    """
    device_ip = args.get("ip", "")
    if not device_ip:
        return_error("ip argument is required.")
    device_ip = str(device_ip)

    result = client.get_device_by_ip(device_ip)
    devices = result.get("devices", [])
    if not devices:
        return CommandResults(readable_output="### No devices found")

    readable_output = tableToMarkdown("Device Security Devices", devices, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="PaloAltoNetworksDeviceSecurity.Device",
        outputs_key_field="devices",
        outputs=devices,
    )


def device_security_list_devices(client: Client, args: dict) -> CommandResults:
    """
    Returns a list of Device Security devices

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        List of devices

        CommandResults
    """
    try:
        offset = int(args.get("offset", "0"))
        if offset < 0:
            return_error("Offset must be a non-negative integer.")

        pagelength = int(args.get("limit", client.max_fetch))
        if pagelength <= 0:
            return_error("Limit must be a positive integer.")
    except ValueError:
        return_error("Offset and limit must be integers.")

    result = client.list_devices(offset, pagelength)

    if not result:
        return CommandResults(readable_output="### No devices found")

    readable_output = tableToMarkdown("Device Security Devices", result, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="PaloAltoNetworksDeviceSecurity.DeviceList",
        outputs_key_field="deviceid",
        outputs=result,
    )


def device_security_list_alerts(client: Client, args: dict) -> CommandResults:
    """
    Returns a list of Device Security alerts (max: 100)

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        List of alerts

        CommandResults
    """
    try:
        start_time = arg_to_datetime(
            arg=args.get("start_time"),
            arg_name="start_time",
            required=False,
            is_utc=True,
        )
        stime = start_time.strftime("%Y-%m-%dT%H:%M:%SZ") if start_time else "-1"

        offset = int(args.get("offset", "0"))
        if offset < 0:
            return_error("Offset must be a non-negative integer.")
        pagelength = min(int(args.get("limit", client.max_fetch)), PAGELENGTH)
        if pagelength <= 0:
            return_error("Limit must be a positive integer.")
    except ValueError:
        return_error("Offset and limit must be integers.")

    result = client.list_alerts(stime, offset, pagelength, "desc")

    if not result:
        return CommandResults(readable_output="### No alerts found")

    readable_output = tableToMarkdown("Device Security Alerts", result, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="PaloAltoNetworksDeviceSecurity.Alerts",
        outputs_key_field="id",
        outputs=result,
    )


def device_security_list_vulns(client: Client, args: dict) -> CommandResults:
    """
    Returns a list of Device Security vulnerabilities (max: 100)

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        List of vulnerabilities

        CommandResults
    """
    try:
        start_time = arg_to_datetime(
            arg=args.get("start_time"),
            arg_name="start_time",
            required=False,
            is_utc=True,
        )
        stime = start_time.strftime("%Y-%m-%dT%H:%M:%SZ") if start_time else "-1"
        offset = int(args.get("offset", "0"))

        if offset < 0:
            return_error("Offset must be a non-negative integer.")

        pagelength = min(int(args.get("limit", client.max_fetch)), PAGELENGTH)

        if pagelength <= 0:
            return_error("Limit must be a positive integer.")
    except ValueError:
        return_error("Offset and limit must be integers.")

    result = client.list_vulns(stime, offset, pagelength)

    if not result:
        return CommandResults(readable_output="### No vulnerabilities found")

    readable_output = tableToMarkdown("Device Security Vulnerabilities", result, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="PaloAltoNetworksDeviceSecurity.Vulns",
        outputs_key_field="zb_ticketid",
        outputs=result,
    )


def device_security_resolve_alert(client: Client, args: dict) -> CommandResults:
    """
    Resolve a Device Security alert

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        None in CommandResults
    """
    alert_id = args.get("id", "")
    if not alert_id:
        return_error("id argument is required.")
    alert_id = str(alert_id)

    reason = str(args.get("reason", "Resolved by XSOAR"))
    reason_type = str(args.get("reason_type", "No Action Needed"))

    client.resolve_alert(alert_id, reason, reason_type)

    return CommandResults(readable_output=f"Alert {alert_id} was resolved successfully")


def device_security_resolve_vuln(client: Client, args: dict) -> CommandResults:
    """
    Resolve a Device Security vulnerability

    Args:
        client (Client): Device Security client.
        args (dict): all command arguments.

    Returns:
        None in CommandResults
    """
    vuln_id = args.get("id", "")
    if not vuln_id:
        return_error("id argument is required.")
    vuln_id = str(vuln_id)

    full_name = args.get("full_name", "")
    if not full_name:
        return_error("full_name argument is required.")
    full_name = str(full_name)

    reason = str(args.get("reason", "Resolved by XSOAR"))

    client.resolve_vuln(vuln_id, full_name, reason)

    return CommandResults(readable_output=f"Vulnerability {vuln_id} was resolved successfully")


def normalize_detected_date(detected_date: str | list | None) -> str | None:
    if isinstance(detected_date, str) or detected_date is None:
        return detected_date

    if detected_date:
        first_detected_date = detected_date[0]
        return first_detected_date if isinstance(first_detected_date, str) else None

    return None


def format_fetch_start_time(fetch_time: str) -> str:
    if fetch_time == "-1":
        return fetch_time

    fetch_time_dt = arg_to_datetime(fetch_time, arg_name="Fetch start time", is_utc=True, required=True)

    if fetch_time_dt is None:
        raise ValueError(f"Could not parse fetch time: {fetch_time}")

    return fetch_time_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_alert_incidents(
    client: Client, last_alerts_fetch: str | None, last_alerts_seen_ids: list[str] | None, max_fetch: int
) -> tuple[list[dict], str | None, list[str]]:
    stime = last_alerts_fetch or format_fetch_start_time(client.first_fetch)
    seen_ids = set(last_alerts_seen_ids or [])

    incidents: list[dict] = []
    new_last_fetch = last_alerts_fetch
    new_seen_ids: list[str] = list(seen_ids)  # preserve previously seen IDs
    offset = 0

    while len(incidents) < max_fetch:
        alerts = client.list_alerts(stime, offset=offset, pagelength=max_fetch)
        demisto.debug(f"[Fetch]- Number of incidents - alerts before filtering: {len(alerts)}")

        if not alerts:
            break

        for alert in alerts:
            alert_date = alert.get("date")
            alert_id = alert.get("zb_ticketid", "").replace("alert-", "")

            if not alert_date or not alert_id:
                continue

            if alert_date == last_alerts_fetch and alert_id in seen_ids:
                continue

            if len(incidents) >= max_fetch:
                break

            device_security_incident_url = get_scm_alert_url(alert_id)
            alert_raw_json = {
                **alert,
                "rawType": "Device Security Alert",
                "devicesecurityincidenturl": device_security_incident_url,
            }

            incidents.append(
                {
                    "name": alert.get("name", ""),
                    "rawType": "Device Security Alert",
                    "occurred": alert_date,
                    "rawJSON": json.dumps(alert_raw_json),
                    "details": alert.get("description", ""),
                    "CustomFields": {"devicesecurityincidenturl": device_security_incident_url},
                }
            )

            if new_last_fetch is None or alert_date > new_last_fetch:
                new_last_fetch = alert_date
                new_seen_ids = [alert_id]
            elif alert_date == new_last_fetch and alert_id not in new_seen_ids:
                new_seen_ids.append(alert_id)

        if len(alerts) < max_fetch or len(incidents) >= max_fetch:
            break

        offset += max_fetch

    return incidents, new_last_fetch, trim_seen_ids(new_seen_ids)


def fetch_vulnerability_incidents(
    client: Client, last_vulns_fetch: str | None, last_vulns_seen_ids: list[str] | None, max_fetch: int
) -> tuple[list[dict], str | None, list[str]]:
    stime = last_vulns_fetch or format_fetch_start_time(client.first_fetch)
    seen_ids = set(last_vulns_seen_ids or [])

    incidents: list[dict] = []
    new_last_fetch = last_vulns_fetch
    new_seen_ids: list[str] = list(seen_ids)  # preserve previously seen IDs
    offset = 0

    while len(incidents) < max_fetch:
        vulns = client.list_vulns(stime, offset=offset, pagelength=max_fetch)

        if not vulns:
            break

        for vuln in vulns:
            detected_date = normalize_detected_date(vuln.get("detected_date"))
            vuln_id = vuln.get("zb_ticketid", "")

            if not detected_date or not vuln_id:
                continue

            if detected_date == last_vulns_fetch and vuln_id in seen_ids:
                continue

            if len(incidents) >= max_fetch:
                break

            device_security_incident_url = get_scm_vuln_url(vuln)
            vuln_raw_json = {
                **vuln,
                "rawType": "Device Security Vulnerability",
                "devicesecurityincidenturl": device_security_incident_url,
            }

            incidents.append(
                {
                    "name": vuln.get("name", ""),
                    "rawType": "Device Security Vulnerability",
                    "occurred": detected_date,
                    "rawJSON": json.dumps(vuln_raw_json),
                    "details": (
                        f'Device {vuln.get("name", "")} at IP {vuln.get("ip", "")}: ' f'{vuln.get("vulnerability_name", "")}'
                    ),
                    "CustomFields": {"devicesecurityincidenturl": device_security_incident_url},
                }
            )

            if new_last_fetch is None or detected_date > new_last_fetch:
                new_last_fetch = detected_date
                new_seen_ids = [vuln_id]
            elif detected_date == new_last_fetch and vuln_id not in new_seen_ids:
                new_seen_ids.append(vuln_id)

        if len(vulns) < max_fetch or len(incidents) >= max_fetch:
            break

        offset += max_fetch

    return incidents, new_last_fetch, trim_seen_ids(new_seen_ids)


def fetch_incidents(
    client: Client, last_run: dict, fetch_alerts: bool, fetch_vulns: bool, is_test: bool = False
) -> tuple[dict | None, list[dict] | None]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): Device Security client
        last_run: last_run dict containing the timestamps of the latest incident we fetched from previous fetch

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    demisto.debug("[Fetch] PaloAltoNetworks_DeviceSecurity - Start fetching")
    demisto.debug(f"[Fetch] PaloAltoNetworks_DeviceSecurity - Last run: {json.dumps(last_run)}")
    # Get the last fetch time, if exists
    last_alerts_fetch = last_run.get("last_alerts_fetch")
    last_alerts_seen_ids = last_run.get("last_alerts_seen_ids", [])
    last_vulns_fetch = last_run.get("last_vulns_fetch")
    last_vulns_seen_ids = last_run.get("last_vulns_seen_ids", [])
    max_fetch = client.max_fetch

    incidents = []

    if fetch_alerts:
        alert_incidents, last_alerts_fetch, last_alerts_seen_ids = fetch_alert_incidents(
            client, last_alerts_fetch, last_alerts_seen_ids, max_fetch
        )
        incidents.extend(alert_incidents)

    if fetch_vulns:
        vuln_incidents, last_vulns_fetch, last_vulns_seen_ids = fetch_vulnerability_incidents(
            client, last_vulns_fetch, last_vulns_seen_ids, max_fetch
        )
        incidents.extend(vuln_incidents)

    next_run = {
        "last_alerts_fetch": last_alerts_fetch,
        "last_alerts_seen_ids": last_alerts_seen_ids,
        "last_vulns_fetch": last_vulns_fetch,
        "last_vulns_seen_ids": last_vulns_seen_ids,
    }
    demisto.debug(
        f"[Fetch] PaloAltoNetworks_DeviceSecurity - Number of incidents (alerts and vulnerability) "
        f"after filtering : {len(incidents)}"
    )
    demisto.debug(f"[Fetch] PaloAltoNetworks_DeviceSecurity - Next run after incidents fetching: {json.dumps(next_run)}")

    if is_test:
        return None, None

    return next_run, incidents


def parse_positive_int(value: Any, field_name: str) -> int:
    try:
        parsed_value = int(value)
    except (ValueError, TypeError) as e:
        raise ValueError(f"{field_name} needs to be an integer") from e

    if parsed_value <= 0:
        raise ValueError(f"{field_name} needs to be a positive integer")

    return parsed_value


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    command = demisto.command()

    try:
        params = demisto.params()
        args = demisto.args()

        is_fetch = argToBoolean(params.get("isFetch", False))
        tsg_id = params.get("tsg_id")
        client_id = params.get("client_id")
        client_secret = params.get("client_secret")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        proxy = argToBoolean(params.get("proxy", False))
        fetch_alerts = argToBoolean(params.get("fetch_alerts", True))
        fetch_vulns = argToBoolean(params.get("fetch_vulns", True))
        api_timeout = parse_positive_int(params.get("api_timeout", "60"), "API timeout")
        max_fetch = parse_positive_int(params.get("max_fetch", "10"), "Maximum number of incidents per fetch")

        first_fetch = "-1"
        try:
            first_fetch_dt = arg_to_datetime(
                arg=params.get("first_fetch"),
                arg_name="First fetch time",
                is_utc=True,
                required=False,
            )
        except ValueError as e:
            raise ValueError(f"First fetch time is in a wrong format. Error: {e!s}") from e

        if first_fetch_dt:
            first_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        token_base_url = "https://auth.apps.paloaltonetworks.com"
        base_url = "https://api.strata.paloaltonetworks.com/iot/pub/v1"

        access_token = get_scm_access_token(
            token_base_url,
            tsg_id,
            client_id,
            client_secret,
            verify_certificate,
            proxy,
        )
        headers = {"Authorization": f"Bearer {access_token}"}

        client = Client(
            base_url=base_url,
            api_timeout=api_timeout,
            first_fetch=first_fetch,
            max_fetch=max_fetch,
            verify=verify_certificate,
            proxy=proxy,
            ok_codes=(200,),
            headers=headers,
        )

        demisto.info(f"Command being called is {command}")

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, is_fetch, fetch_alerts, fetch_vulns))

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                fetch_alerts=fetch_alerts,
                fetch_vulns=fetch_vulns,
            )

            if next_run is not None:
                demisto.setLastRun(next_run)

            if incidents is not None:
                demisto.incidents(incidents)

        elif command == "device-security-get-device":
            return_results(device_security_get_device(client, args))

        elif command == "device-security-get-device-by-ip":
            return_results(device_security_get_device_by_ip(client, args))

        elif command == "device-security-list-devices":
            return_results(device_security_list_devices(client, args))

        elif command == "device-security-list-alerts":
            return_results(device_security_list_alerts(client, args))

        elif command == "device-security-list-vulns":
            return_results(device_security_list_vulns(client, args))

        elif command == "device-security-resolve-alert":
            return_results(device_security_resolve_alert(client, args))

        elif command == "device-security-resolve-vuln":
            return_results(device_security_resolve_vuln(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
