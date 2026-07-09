from typing import Any, Dict, List, Tuple, Union, Set
from datetime import datetime, timedelta, UTC
import hashlib
import json
import traceback
import requests
import demistomock as demisto
from CommonServerPython import *
from ContentClientApiModule import *

""" CONSTANTS """

ETD_LOG_TYPES = ["message", "audit", "connection"]
VENDOR = "Cisco"
PRODUCT = "ETD"

""" UTIT """


def get_credential(param: Union[dict, str]) -> str:
    if isinstance(param, dict):
        return param.get("password") or param.get(
            "credentials", {}
        ).get("password")
    return param


def generate_intervals(start_dt: datetime, end_dt: datetime) -> List[Tuple[datetime, datetime]]:
    intervals = []
    current = start_dt
    while current < end_dt:
        next_dt = current + timedelta(hours=3)
        if next_dt > end_dt:
            next_dt = end_dt
        intervals.append((current, next_dt))
        current = next_dt
    return intervals


def get_event_time(event: Dict[str, Any], log_type: str) -> str:
    if log_type == "message":
        time_stamp = event.get("message", {}).get("timestamp")
    else:
        time_stamp = event.get("timestamp")
    if time_stamp:
        try:
            dt = arg_to_datetime(time_stamp).astimezone(UTC)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_event_id(event: Dict[str, Any], log_type: str) -> str:
    if log_type == "message":
        return hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
    elif log_type == "connection":
        return event.get("connection_id", "")
    elif log_type == "audit":
        audit_identity = {
            "timestamp": event.get("timestamp"),
            "action": event.get("action"),
            "category": event.get("category"),
            "user": event.get("user"),
            "metadata": event.get("metadata")
        }
        return hashlib.sha256(
            json.dumps(
                audit_identity,
                sort_keys=True
            ).encode()
        ).hexdigest()
    return hashlib.sha256(
        json.dumps(
            event,
            sort_keys=True
        ).encode()
    ).hexdigest()


def deduplicate_events(events: List[Dict[str, Any]], last_fetch: str | None, last_ids: Set[str]) -> List[Dict[str, Any]]:
    unique_events = []
    seen = set()
    checkpoint = None
    if last_fetch:
        checkpoint = arg_to_datetime(last_fetch).astimezone(UTC)
    for event in events:
        event_id = event["_event_id"]
        # Remove duplicates within the same fetch
        if event_id in seen:
            continue
        seen.add(event_id)
        if checkpoint:
            event_time = arg_to_datetime(
                event["_time"]
            ).astimezone(UTC)
            # Skip events older than the checkpoint
            if event_time < checkpoint:
                continue
            # Skip events already processed at the checkpoint
            if (
                event_time == checkpoint
                and event_id in last_ids
            ):
                continue
        unique_events.append(event)
    return unique_events


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
        context = demisto.getIntegrationContext() or {}
        token = context.get("access_token")
        expiry = context.get("token_expiry")
        if token and expiry:
            if datetime.now(UTC).timestamp() < expiry:
                return token
        api_key = get_credential(self.params.get("api_key"))
        client_secret = get_credential(self.params.get("client_secret"))
        res = self._http_request(
            method="POST",
            url_suffix="/v1/oauth/token",
            headers={"x-api-key": api_key},
            auth=(self.params.get("client_id"), client_secret),
            timeout=30,
        )
        token = res.get("accessToken")
        if not token:
            raise DemistoException(f"Token not found: {res}")
        demisto.setIntegrationContext({
            "access_token": token,
            "token_expiry": (
                datetime.now(UTC) + timedelta(minutes=55)
            ).timestamp()
        })
        return token

    def request_log_export(self, start: str, end: str, event_types: list[str]) -> dict[str, Any]:
        body = {
            "timeRange": [start, end],
            "logTypes": event_types,
        }
        return self._http_request(
            method="POST",
            url_suffix="/v1/logs/downloadLinks",
            json_data=body,
            timeout=120,
        )

    def get_links(self, response: dict[str, Any], event_types: list[str]) -> list[tuple[str, str]]:
        data = response.get("data", {})
        links = []
        for log_type in event_types:
            chunk = data.get(log_type)
            if isinstance(chunk, list):
                links.extend([(log_type, link) for link in chunk])
        return links

    def download_logs(self, links: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        events = []
        for log_type, link in links:
            response = requests.get(link, timeout=120)
            if response.status_code != 200:
                raise DemistoException(f"Failed downloading ETD log file: {response.text}")
            res = response.text
            for line in res.splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    event["_source_log_type"] = log_type
                    event["_time"] = get_event_time(event, log_type)
                    event["_event_id"] = get_event_id(event, log_type)
                    events.append(event)
                except json.JSONDecodeError as e:
                    demisto.error(f"Failed to parse ETD event: {line}, error {str(e)}")
                    continue
        return events


""" FETCH INCIDENTS / INGEST LOGS """


def fetch_and_ingest_logs(client: ETDClient, params: Dict[str, Any]) -> None:
    demisto.debug("ETD fetch-events started")
    now = datetime.now(UTC).replace(
        minute=0,
        second=0,
        microsecond=0
    )
    max_fetch = int(params.get("max_fetch", 500))
    event_types = argToList(
        params.get("event_type")
    )
    if not event_types:
        event_types = ETD_LOG_TYPES
    last_run = demisto.getLastRun() or {}
    last_fetch = last_run.get("last_fetch")
    last_ids = set(last_run.get("last_ids", []))

    # Calculate fetch window
    if not last_fetch:
        start_dt = now - timedelta(hours=1)
    else:
        start_dt = arg_to_datetime(
            last_fetch
        ).astimezone(UTC)
    end_dt = now
    demisto.debug(f"Fetch Window: {start_dt} -> {end_dt}")
    intervals = generate_intervals(
        start_dt,
        end_dt
    )
    all_events = []

    # fetch every interval
    for start, end in intervals:
        start_time = start.strftime("%Y-%m-%dT%H")
        end_time = end.strftime("%Y-%m-%dT%H")
        demisto.debug(f"Fetching {start_time} -> {end_time}")
        try:
            response = client.request_log_export(
                start_time,
                end_time,
                event_types
            )
            links = client.get_links(
                response,
                event_types
            )
            if not links:
                continue
            interval_events = client.download_logs(links)
            # accumulate
            all_events.extend(interval_events)
            if len(all_events) >= max_fetch:
                demisto.debug(f"Reached max_fetch={max_fetch}, stopping fetch.")
                break
        except Exception as e:
            demisto.error(f"{e}\n{traceback.format_exc()}")
            break
    # nothing new
    if not all_events:
        demisto.debug("No new events")
        return
    # oldest first
    all_events.sort(key=lambda e: e["_time"])

    # remove duplicates
    all_events = deduplicate_events(
        all_events,
        last_fetch,
        last_ids
    )
    if not all_events:
        demisto.debug("No new events after deduplication")
        return
    if len(all_events) > max_fetch:
        all_events = all_events[:max_fetch]
        demisto.debug(f"Limited events to max_fetch={max_fetch}")
    # send once
    send_events_to_xsiam(events=all_events, vendor=VENDOR, product=PRODUCT)
    newest_time = all_events[-1]["_time"]
    newest_ids = [
        event["_event_id"]
        for event in all_events
        if event["_time"] == newest_time
    ]
    demisto.setLastRun({
        "last_fetch": newest_time,
        "last_ids": newest_ids
    })
    demisto.debug(f"Saved checkpoint {newest_time}")


def cisco_etd_get_events_command(client: ETDClient, args: Dict[str, Any]) -> CommandResults:
    limit = int(args.get("limit", 100))
    event_types = argToList(args.get("log_type"))
    if not event_types:
        event_types = ETD_LOG_TYPES
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    if not start_time or not end_time:
        raise DemistoException("start_time and end_time are required.")
    start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H").replace(tzinfo=UTC)
    end_dt = datetime.strptime(end_time, "%Y-%m-%dT%H").replace(tzinfo=UTC)
    intervals = generate_intervals(start_dt, end_dt)
    events = []
    for start, end in intervals:
        interval_start = start.strftime("%Y-%m-%dT%H")
        interval_end = end.strftime("%Y-%m-%dT%H")
        response = client.request_log_export(
            interval_start,
            interval_end,
            event_types
        )
        links = client.get_links(
            response,
            event_types
        )
        if not links:
            continue
        interval_events = client.download_logs(links)
        events.extend(interval_events)
        if len(events) >= limit:
            break
    events.sort(key=lambda e: e["_time"])
    events = deduplicate_events(
        events,
        None,
        set()
    )
    events = events[:limit]
    should_push = argToBoolean(
        args.get(
            "should_push_events",
            False
        )
    )
    if should_push:
        send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
    return CommandResults(
        readable_output=f"Fetched {len(events)} events.",
        outputs_prefix="CiscoETD.Events",
        outputs_key_field="_event_id",
        outputs=events,
    )


""" TEST MODULE """


def test_module(client: ETDClient) -> str:
    try:
        now = datetime.now(UTC).replace(
            minute=0,
            second=0,
            microsecond=0
        )
        args = {
            "start_time": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H"),
            "end_time": now.strftime("%Y-%m-%dT%H"),
            "log_type": "message,audit,connection",
            "limit": "1",
            "should_push_events": "false"
        }
        cisco_etd_get_events_command(client, args)
        return "ok"
    except Exception as e:
        demisto.error(
            f"[ERROR] Test failed: {str(e)}\n"
            f"{traceback.format_exc()}"
        )
        raise


""" MAIN """


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    client = ETDClient(base_url=params.get("etd_base_url"), params=params)
    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "cisco-etd-get-events":
            return_results(
                cisco_etd_get_events_command(
                    client,
                    demisto.args()
                )
            )
        elif command == "fetch-events":
            fetch_and_ingest_logs(client, params)
    except Exception as e:
        demisto.error(f"[ERROR] MAIN FAILED: {str(e)}\n" f"{traceback.format_exc()}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
