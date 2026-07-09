import json
import traceback
from datetime import datetime, timedelta, timezone
from typing import List, Tuple
import hashlib
import requests
from ContentClientApiModule import *

"""  CONSTANTS """

ETD_LOG_TYPE = ["message"]

""" CLIENT """


class ETDClient(ContentClient):
    def __init__(self, base_url: str, params: dict):
        self.params = params
        super().__init__(
            base_url=base_url,
            headers={},
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False)
        )
        token = self.get_access_token()
        self._headers.update({
            "Authorization": f"Bearer {token}",
            "x-api-key": get_credential(params.get("api_key")),
            "Content-Type": "application/json",
        })

    def get_access_token(self) -> str:
        api_key = get_credential(
            self.params.get("api_key")
        )
        client_secret = get_credential(
            self.params.get("client_secret")
        )
        headers = {"x-api-key": api_key}
        res = self._http_request(
            method="POST",
            url_suffix="/v1/oauth/token",
            headers=headers,
            auth=(
                self.params.get("client_id"),
                client_secret
            ),
            timeout=30
        )
        token = res.get("accessToken")
        if not token:
            raise DemistoException(
                f"Token not found: {res}"
            )
        return token

    def request_log_export(self, start: str, end: str) -> dict:
        body = {
            "timeRange": [start, end],
            "logTypes": ETD_LOG_TYPE
        }
        return self._http_request(
            method="POST",
            url_suffix="/v1/logs/downloadLinks",
            json_data=body,
            timeout=120
        )

    # GET LINKS
    def get_links(self, response: dict) -> list:
        data = response.get("data", {})
        return data.get("message", [])

    # DOWNLOAD LOGS
    def download_logs(self, links: list) -> list:
        events = []
        for link in links:
            response = requests.get(link, timeout=120)
            if response.status_code != 200:
                raise DemistoException(f"Failed downloading ETD log file: {response.text}")
            res = response.text
            for line in res.splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    # ONLY MESSAGE LOGS
                    if event.get("logType") != "message":
                        continue
                    events.append(event)
                except Exception as e:
                    demisto.error(
                        f"Failed parsing ETD event: {str(e)}\n"
                        f"{traceback.format_exc()}"
                    )
                    continue
        return events


""" UTIL """


def get_credential(param: dict | str) -> str:
    if isinstance(param, dict):
        return (
            param.get("password")
            or param.get(
                "credentials",
                {}
            ).get("password")
        )
    return param


def generate_intervals(start_dt: datetime, end_dt: datetime) -> list:
    intervals = []
    current = start_dt
    while current < end_dt:
        next_t = current + timedelta(hours=3)
        if next_t > end_dt:
            next_t = end_dt
        intervals.append((current, next_t))
        current = next_t
    return intervals


def get_event_time(event: dict) -> str:
    timestamp = (
        event.get("message", {}).get("timestamp")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    try:
        dt = arg_to_datetime(timestamp).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )


def get_event_id(event: dict) -> str:
    return hashlib.sha256(
        json.dumps(event, sort_keys=True).encode()).hexdigest()


""" FETCH INCIDENTS"""


def fetch_incidents(client: ETDClient, params: dict) -> list:
    demisto.debug("ETD fetch-incidents started")
    now = datetime.now(timezone.utc).replace(
        minute=0,
        second=0,
        microsecond=0
    )
    last_run = demisto.getLastRun() or {}
    last_fetch = last_run.get("last_fetch")
    last_ids = set(
        last_run.get(
            "last_ids",
            []
        )
    )
    # Determine Fetch window
    if not last_fetch:
        start_dt = now - timedelta(hours=1)
    else:
        start_dt = arg_to_datetime(
            last_fetch
        ).astimezone(timezone.utc)
    end_dt = now
    demisto.info(
        f"Fetching ETD logs from "
        f"{start_dt.isoformat()} "
        f"to "
        f"{end_dt.isoformat()}"
    )
    max_fetch = int(params.get("max_fetch", 500))
    incidents = []
    seen_ids = set()
    intervals = generate_intervals(start_dt, end_dt)
    demisto.info(f"Processing {len(intervals)} intervals")
    # Process Interval
    for start, end in intervals:
        start_time = start.strftime("%Y-%m-%dT%H")
        end_time = end.strftime("%Y-%m-%dT%H")
        try:
            demisto.debug(f"Fetching interval "f"{start_time} -> {end_time}")
            response = client.request_log_export(start_time, end_time)
            links = client.get_links(response)
            if not links:
                demisto.debug(
                    f"No logs found for "
                    f"{start_time} -> {end_time}"
                )
                continue
            events = client.download_logs(links)
            demisto.debug(f"Downloaded {len(events)} events")
            for event in events:
                msg = event.get("message", {})
                event_id = get_event_id(event)
                event_time = get_event_time(event)
                if event_id in seen_ids:
                    continue
                seen_ids.add(event_id)
                if last_fetch:
                    checkpoint = arg_to_datetime(last_fetch).astimezone(timezone.utc)
                    current_event_time = arg_to_datetime(event_time).astimezone(timezone.utc)
                    if current_event_time < checkpoint:
                        continue
                    if (
                        current_event_time == checkpoint
                        and event_id in last_ids
                    ):
                        continue
                sender = msg.get("fromAddresses", "unknown")
                verdict = ((msg.get("verdict") or {}).get("verdict", "").lower())
                timestamp = event_time
                incident = {
                    "name": (f"[ETD] " f"{verdict.upper()} "f"Email - {sender}"),
                    "occurred": timestamp,
                    "rawJSON": json.dumps(event),
                    "severity": 3,
                    "type": "ETD Malicious Email",
                    "CustomFields": {"etdmessageid": msg.get("id")}
                }
                incidents.append(incident)
                if len(incidents) >= max_fetch:
                    break
            if len(incidents) >= max_fetch:
                break
        except Exception as ex:
            demisto.error(
                f"Interval failed {start_time} -> {end_time}: {str(ex)}\n"
                f"{traceback.format_exc()}"
            )
    incidents.sort(key=lambda x: x.get("occurred", ""))
    if incidents:
        newest_time = incidents[-1]["occurred"]
        newest_ids = [
            get_event_id(
                json.loads(i["rawJSON"])
            )
            for i in incidents
            if i["occurred"] == newest_time
        ]
        demisto.setLastRun({
            "last_fetch": newest_time,
            "last_ids": newest_ids
        })
    else:
        demisto.debug("No new incidents found")
    demisto.info(f"Checkpoint saved: {demisto.getLastRun()}")
    demisto.info(f"Total incidents created: "f"{len(incidents)}")
    demisto.incidents(incidents)
    return incidents


def etd_move_message_command(client: ETDClient, args: dict) -> CommandResults:
    message_id = args.get("message_id")
    verdict = args.get("verdict")
    folder = args.get("folder")
    body = {
        "folder": folder,
        "verdict": verdict,
        "ids": [message_id]
    }
    result = client._http_request(
        method="POST",
        url_suffix="/v1/messages/move",
        json_data=body,
        timeout=120
    )
    return CommandResults(
        readable_output=(
            f"ETD message updated\n\n"
            f"Message ID: {message_id}\n"
            f"Verdict: {verdict}\n"
            f"Folder: {folder}"
        ),
        outputs_prefix="CiscoETD.MessageUpdate",
        outputs=result
    )


""" TEST MODULE """


def test_module(client: ETDClient) -> str:
    now = datetime.now(timezone.utc).replace(
        minute=0,
        second=0,
        microsecond=0
    )
    response = client.request_log_export(
        (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H"),
        now.strftime("%Y-%m-%dT%H")
    )
    links = client.get_links(response)
    if links:
        client.download_logs(links)
    return "ok"



""" MAIN"""


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    client = ETDClient(
        base_url=params.get("etd_base_url"),
        params=params
    )
    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        elif command == "etd-move-message":
            return_results(
                etd_move_message_command(client, demisto.args())
            )
    except Exception as e:
        demisto.error(
            f"{str(e)}\n"
            f"{traceback.format_exc()}"
        )
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

register_module_line('ETDXsoarConnector', 'end', __line__())
