import json
import hashlib
import requests
import traceback
from typing import Any
from datetime import datetime, timedelta, UTC
from CommonServerPython import *
from CommonServerUserPython import *

"""  CONSTANTS """

ETD_LOG_TYPE = ["message"]

""" CLIENT """


class ETDClient(BaseClient):
    """Client for interacting with the Cisco Email Threat Defense (ETD) REST API."""

    def __init__(self, base_url: str, params: dict):
        """
        Initialize the ETD API client.
        Args:
            base_url: Cisco ETD API base URL.
            params: Integration configuration parameters.
        """
        self.params = params
        super().__init__(
            base_url=base_url,
            headers={},
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
        )
        token = self.get_access_token()
        self._headers.update(
            {
                "Authorization": f"Bearer {token}",
                "x-api-key": get_credential(params.get("api_key")),
                "Content-Type": "application/json",
            }
        )

    def get_access_token(self) -> str:
        """
        Authenticate with Cisco ETD and return an OAuth access token.
        Returns:OAuth access token.
        """
        api_key = get_credential(self.params.get("api_key"))
        client_secret = get_credential(self.params.get("client_secret"))
        headers = {"x-api-key": api_key}
        client_id = self.params.get("client_id") or ""
        res = self._http_request(
            method="POST",
            url_suffix="/v1/oauth/token",
            headers=headers,
            auth=(client_id, client_secret),
            timeout=30,
        )
        token = res.get("accessToken")
        if not token:
            raise DemistoException(f"Token not found: {res}")
        return token

    def request_log_export(self, start: str, end: str) -> dict:
        """
        Request download links for ETD message logs.
        Args:
            start: Start time in YYYY-MM-DDTHH format.
            end: End time in YYYY-MM-DDTHH format.
        Returns:API response containing download links.
        """
        body = {"timeRange": [start, end], "logTypes": ETD_LOG_TYPE}
        return self._http_request(method="POST", url_suffix="/v1/logs/downloadLinks", json_data=body, timeout=120)

    def get_links(self, response: dict) -> list:
        """
        Extract log download links from the ETD API response.
        Args:response: ETD log export response.
        Returns:List of download URLs.
        """
        data = response.get("data", {})
        return data.get("message", [])

    def download_logs(self, links: list) -> list:
        """
        Download and parse ETD message log files.
        Args:links: List of pre-signed download URLs.
        Returns: List of ETD message events.
        """
        events = []
        for link in links:
            try:
                response = requests.get(
                    link,
                    timeout=120,
                    verify=not self.params.get("insecure", False),
                    proxies=requests.utils.get_environ_proxies(link) if self.params.get("proxy") else {},
                )
                response.raise_for_status()
            except requests.exceptions.Timeout as exc:
                raise DemistoException(f"Timed out downloading ETD log file: {link}") from exc
            except requests.exceptions.RequestException as exc:
                raise DemistoException(f"Failed downloading ETD log file: {exc}") from exc
            res = response.text
            parse_errors = 0
            for line in res.splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if event.get("logType") != "message":
                        continue
                    events.append(event)
                except (json.JSONDecodeError, TypeError):
                    parse_errors += 1
                    continue
            if parse_errors:
                demisto.debug(f"Skipped {parse_errors} malformed ETD log record(s).")
        return events


""" UTIL """


def get_credential(param: dict[str, Any] | str | None) -> str:
    """
    Extract a credential value from an integration parameter.
    Args:
        param: Credential parameter.
    Returns: Credential string.
    """
    if isinstance(param, dict):
        return param.get("password") or param.get("credentials", {}).get("password") or ""
    return param or ""


def generate_intervals(start_dt: datetime, end_dt: datetime) -> list:
    """
    Split a time range into 3-hour intervals.
    Args:
        start_dt: Interval start time.
        end_dt: Interval end time.
    Returns: List of (start, end) datetime tuples.
    """
    intervals = []
    current = start_dt
    while current < end_dt:
        next_t = current + timedelta(hours=3)
        if next_t > end_dt:
            next_t = end_dt
        intervals.append((current, next_t))
        current = next_t
    return intervals


def get_event_time(event: dict) -> str | None:
    timestamp = event.get("message", {}).get("timestamp")
    if not timestamp:
        return None
    try:
        dt = arg_to_datetime(timestamp)
        if dt is None:
            return None
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def get_event_id(event: dict) -> str:
    """
    Generate a unique SHA256 identifier for an ETD event.
    Args:event: ETD event.
    Returns:Unique event identifier.
    """
    return hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()


""" FETCH INCIDENTS"""


def fetch_incidents(client: ETDClient, params: dict):
    """
    Fetch ETD message events and create XSOAR incidents.
    Args:
        client: ETD API client.
        params: Integration parameters.
    Returns: List of created incidents.
    """
    demisto.debug("[Fetch] ETD fetch-incidents started")
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    last_run = demisto.getLastRun() or {}
    last_fetch = last_run.get("last_fetch")
    last_ids = set(last_run.get("last_ids", []))
    if not last_fetch:
        first_fetch = params.get("first_fetch", "7 days")
        parsed_time = arg_to_datetime(first_fetch)
        if parsed_time is None:
            raise DemistoException("Invalid first_fetch value")
        parsed_time = parsed_time.astimezone(UTC)
        if not parsed_time:
            raise DemistoException(f"Invalid first fetch value: {first_fetch}")
        start_dt = parsed_time.astimezone(timezone.utc)
        # ETD API workaround
        if first_fetch.strip().lower() == "30 days":
            start_dt += timedelta(hours=1)
    else:
        start_dt = datetime.fromisoformat(last_fetch.replace("Z", "+00:00"))
    backlog_days = (now - start_dt).days
    # If backlog >= 6 days, process only 5 days
    if backlog_days >= 6:
        end_dt = start_dt + timedelta(days=5)
        if end_dt > now:
            end_dt = now
    else:
        end_dt = now
    demisto.info(f"[Fetch] Fetching ETD logs from " f"{start_dt.isoformat()} " f"to " f"{end_dt.isoformat()}")
    max_fetch = int(params.get("max_fetch", 500))
    incidents = []
    seen_ids = set()
    intervals = generate_intervals(start_dt, end_dt)
    demisto.info(f"[Fetch] Processing {len(intervals)} intervals")

    # Process Interval
    for start, end in intervals:
        start_time = start.strftime("%Y-%m-%dT%H")
        end_time = end.strftime("%Y-%m-%dT%H")
        try:
            demisto.debug(f"[Fetch]  Fetching interval " f"{start_time} -> {end_time}")
            response = client.request_log_export(start_time, end_time)
            links = client.get_links(response)
            if not links:
                demisto.debug(f"[Fetch]  No logs found for " f"{start_time} -> {end_time}")
                continue
            events = client.download_logs(links)
            demisto.debug(f"[Fetch] Downloaded {len(events)} events")
            for event in events:
                msg = event.get("message", {})
                event_id = get_event_id(event)
                event_time = get_event_time(event)
                if event_time is None:
                    demisto.debug("Skipping ETD event with missing timestamp.")
                    continue
                if event_id in seen_ids:
                    continue
                seen_ids.add(event_id)
                if last_fetch:
                    checkpoint = arg_to_datetime(last_fetch)
                    current_event_time = arg_to_datetime(event_time)
                    if checkpoint is None or current_event_time is None:
                        continue
                    checkpoint = checkpoint.astimezone(UTC)
                    current_event_time = current_event_time.astimezone(UTC)
                    if current_event_time < checkpoint:
                        continue
                    if current_event_time == checkpoint and event_id in last_ids:
                        continue
                sender = msg.get("fromAddresses", "unknown")
                verdict = (msg.get("verdict") or {}).get("verdict", "").lower()
                timestamp = event_time
                incident = {
                    "name": (f"[ETD] " f"{verdict.upper()} " f"Email - {sender}"),
                    "occurred": timestamp,
                    "rawJSON": json.dumps(event),
                    "severity": IncidentSeverity.MEDIUM,
                    "type": "ETD Malicious Email",
                    "CustomFields": {"etdmessageid": msg.get("id")},
                }
                incidents.append(incident)
                if len(incidents) >= max_fetch:
                    break
            if len(incidents) >= max_fetch:
                break
        except Exception as ex:
            demisto.error(f"[Fetch] Interval failed {start_time} -> {end_time}: {str(ex)}\n" f"{traceback.format_exc()}")
    incidents.sort(key=lambda x: str(x["occurred"]))
    if incidents:
        newest_time = incidents[-1]["occurred"]
        newest_ids = [get_event_id(json.loads(str(i["rawJSON"]))) for i in incidents if i["occurred"] == newest_time]
        demisto.setLastRun({"last_fetch": newest_time, "last_ids": newest_ids})
    else:
        demisto.debug("[Fetch] No new incidents found")
    demisto.info(f"[Fetch] Checkpoint saved: {demisto.getLastRun()}")
    demisto.info(f"[Fetch] Total incidents created: " f"{len(incidents)}")
    demisto.incidents(incidents)
    return incidents


def cisco_etd_move_message_command(client: ETDClient, args: dict) -> CommandResults:
    """
    Reclassifies and remediates an ETD message.
    Args:
        client: ETD API client.
        args: Command arguments.
    Returns: Command execution results.
    """
    message_id = args.get("message_id")
    verdict = args.get("verdict")
    folder = args.get("folder")
    body = {"folder": folder, "verdict": verdict, "ids": [message_id]}
    result = client._http_request(method="POST", url_suffix="/v1/messages/move", json_data=body, timeout=120)
    return CommandResults(
        readable_output=(f"ETD message updated\n\n" f"Message ID: {message_id}\n" f"Verdict: {verdict}\n" f"Folder: {folder}"),
        outputs_prefix="CiscoETD.Message",
        outputs=result,
        raw_response=result,
    )


""" TEST MODULE """


def test_module(client: ETDClient) -> str:
    """
    Verify connectivity to the Cisco ETD API.
    Args:
        client: ETD API client.
    Returns: "ok" if the connection succeeds.
    """
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    response = client.request_log_export((now - timedelta(hours=1)).strftime("%Y-%m-%dT%H"), now.strftime("%Y-%m-%dT%H"))
    links = client.get_links(response)
    if links:
        client.download_logs(links)
    return "ok"


""" MAIN"""


def main() -> None:
    """Execute the integration entry point."""
    params = demisto.params()
    command = demisto.command()
    client = ETDClient(base_url=params.get("etd_base_url"), params=params)
    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        elif command == "cisco-etd-move-message":
            return_results(cisco_etd_move_message_command(client, demisto.args()))
    except Exception as e:
        demisto.error(f"{str(e)}\n" f"{traceback.format_exc()}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
