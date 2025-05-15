import hashlib

import incydr
from incydr.enums.file_events import EventSearchTerm

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

from typing import Any
from collections.abc import Iterable
from enum import Enum

DEFAULT_FILE_EVENTS_MAX_FETCH = 50000
DEFAULT_AUDIT_EVENTS_MAX_FETCH = 100000

DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%fZ"

MAX_FETCH_AUDIT_LOGS = 100000
MAX_AUDIT_LOGS_PAGE_SIZE = 10000

MAX_FETCH_FILE_EVENTS = 50000
MAX_FILE_EVENTS_PAGE_SIZE = 10000
FILE_EVENTS_LOOK_BACK = timedelta(seconds=45)
# The time filter in Code 42 is only accurate up to the first 23 characters (first 3 microsecond digits)
# i.e., a query for incidents inserted after "2025-01-01 00:00:00.123456Z" is the same as "2025-01-01 00:00:00.123000Z"
CODE42_DATETIME_ACCURACY = 23

VENDOR = "code42"
PRODUCT = "code42"


class FileEventLastRun(str, Enum):
    TIME = "file-event-time"  # saves the last time of previous fetch of file-events
    FETCHED_IDS = "file-event-ids"  # saved a list of IDs of previous fetch which are is the latest time


class AuditLogLastRun(str, Enum):
    TIME = "audit-log-time"  # saves the last time of previous fetch of audit-logs
    FETCHED_IDS = "audit-log-ids"  # saved a list of IDs of previous fetch which are is the latest time


class EventType(str, Enum):
    FILE = "file"
    AUDIT = "audit"


class Client:
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool):
        self.client_id = client_id
        self.client_secret = client_secret
        self.code42_client = incydr.Client(base_url, api_client_id=client_id, api_client_secret=client_secret)
        self.code42_client.session.verify = verify

    def get_audit_logs(
        self,
        start_time: datetime | str,
        end_time: datetime | timedelta | str | None = None,
        limit: int = MAX_FETCH_AUDIT_LOGS,
        page_size: int = MAX_AUDIT_LOGS_PAGE_SIZE,
    ):
        """
        Get audit logs

        Args:
            start_time: from which start time to get logs
            end_time: until which time to get logs
            limit: maximum events to retrieve
            page_size: the page size per single request
        """
        demisto.debug(f"Audit logs: {start_time=}, {end_time=}, {limit=}")
        audit_logs = []

        for audit_log in self.code42_client.audit_log.v1.iter_all(
            start_time=start_time,
            end_time=end_time,
            page_size=page_size,  # iterates all the pages
        ):
            encoded_audit_log = json.dumps(audit_log, sort_keys=True).encode()
            audit_log["id"] = hashlib.sha256(encoded_audit_log).hexdigest()
            audit_log["_time"] = dateparser.parse(audit_log["timestamp"])
            audit_log["eventType"] = EventType.AUDIT
            audit_logs.append(audit_log)

        audit_logs = sorted(
            audit_logs,
            key=lambda _log: _log["_time"],  # type: ignore[arg-type, return-value]
        )
        return audit_logs[:limit]

    def get_file_events(
        self,
        start_time: datetime | str | timedelta,
        end_time: datetime | str | timedelta | None = None,
        limit: int = MAX_FETCH_FILE_EVENTS,
        page_size: int = MAX_FILE_EVENTS_PAGE_SIZE,
    ) -> List[dict[str, Any]]:
        """
        Get file events

        Args:
            start_time: from which start time to get events
            end_time: until which time to get events
            limit: maximum events to retrieve
            page_size: the page size per single request
        """
        demisto.debug(f"File Events: {start_time=}, {end_time=}, {limit=}")
        query = incydr.EventQuery(
            start_date=start_time,
            end_date=end_time,
            page_size=page_size,
            sort_dir="asc",
            sort_key=EventSearchTerm.EVENT_INSERTED,
        )
        for filter in query.groups[0].filters:
            filter.term = EventSearchTerm.EVENT_INSERTED

        response = self.code42_client.file_events.v2.search(query)
        if response.total_count == 0:
            return []
        file_events = response.file_events
        while query.page_token is not None and len(file_events) < limit:
            response = self.code42_client.file_events.v2.search(query)
            if current_events := response.file_events:
                file_events.extend(current_events)

        sorted_file_events = sorted(file_events, key=lambda x: x.event.inserted)[:limit]

        for event in sorted_file_events:
            event.eventType = EventType.FILE
            event._time = event.event.inserted

        return [event.dict() for event in sorted_file_events]


def dedup_fetched_events(events: List[dict], last_run_fetched_event_ids: Iterable[str], keys_list_to_id: List[str]) -> List[dict]:
    """
    Dedup events, removes events which were already fetched.

    Args:
        events (list[dict]): the events to deduplicate
        last_run_fetched_event_ids (Iterable[dict]): a list of already fetched IDs from previous run
        keys_list_to_id (list): a list of keys to retrieve the ID from the event
    """
    new_events = []

    for event in events:
        event_id = dict_safe_get(event, keys=keys_list_to_id)
        if event_id not in last_run_fetched_event_ids:
            new_events.append(event)

    return new_events


def get_event_ids(events: List[Dict[str, Any]], keys_to_id: List[str]) -> List[str]:
    return [dict_safe_get(event, keys=keys_to_id) for event in events]


def get_latest_file_event_ids_and_time(
    events: List[dict], pre_fetch_look_back: Optional[datetime] = None
) -> tuple[dict[str, str], str]:
    """
    Get the latest event IDs and get latest time

    Args:
        events: list of events
        keys_to_id: a list of nested keys to get into the event ID
    """
    latest_time_event = max(event["_time"] for event in events)

    next_fetch_from = datetime.fromisoformat(
        min(latest_time_event, pre_fetch_look_back or latest_time_event).strftime("%Y-%m-%dT%H:%M:%S.%f")[
            :CODE42_DATETIME_ACCURACY
        ]
        + "000+00:00"
    )

    latest_event_ids = {
        dict_safe_get(event, keys=["event", "id"]): event["_time"].isoformat()
        for event in events
        if event["_time"] >= next_fetch_from
    }

    demisto.debug(f"Next file events fetch from {next_fetch_from}")
    return latest_event_ids, next_fetch_from.strftime(DATE_FORMAT)


def get_latest_audit_logs_ids_and_time(events: List[dict]) -> tuple[List[str], str]:
    """
    Get the latest event IDs and get latest time

    Args:
        events: list of events
        keys_to_id: a list of nested keys to get into the event ID
    """
    latest_time_event = datetime.fromisoformat(
        max([event["_time"] for event in events]).strftime("%Y-%m-%dT%H:%M:%S.%f")[:CODE42_DATETIME_ACCURACY] + "000+00:00"
    )

    latest_event_ids: List = [dict_safe_get(event, keys=["id"]) for event in events if event["_time"] >= latest_time_event]
    demisto.debug(f"Latest Audit Log event IDs occurred after {latest_time_event}")
    return latest_event_ids, latest_time_event.strftime(DATE_FORMAT)


def datetime_to_date_string(events: List[Dict[str, Any]]):
    """
    Recursively convert all datetime fields inside an event to date-strings

    Args:
        events: list of events
    """

    def _datetime_to_date_string(_event: Dict[str, Any]):
        for key in _event:
            if isinstance(_event[key], datetime):
                _event[key] = _event[key].strftime(DATE_FORMAT)
            elif isinstance(_event[key], dict):
                _datetime_to_date_string(_event[key])
            elif isinstance(_event[key], list):
                for k in _event[key]:
                    if isinstance(k, dict):
                        _datetime_to_date_string(k)

    for event in events:
        _datetime_to_date_string(event)


def test_module(client: Client, event_types_to_fetch) -> str:
    """
    Tests that it is possible to retrieve file events and audit logs and credentials are valid
    """
    if "File" in event_types_to_fetch:
        client.get_file_events(timedelta(minutes=1), limit=1)
    if "Audit" in event_types_to_fetch:
        client.get_audit_logs(datetime.now() - timedelta(minutes=1), limit=1)
    return "ok"


def fetch_file_events(client: Client, last_run: dict, max_fetch_file_events: int):
    """
    Fetches file events

    Args:
        client: Code42EventCollector client
        last_run: Last run object
        max_fetch_file_events: the maximum number of file events to return
    """
    demisto.debug(f"last run before getting {EventType.FILE} logs: {last_run}")
    new_last_run = last_run.copy()
    file_event_time = cast(
        datetime,
        dateparser.parse(last_run[FileEventLastRun.TIME])
        if FileEventLastRun.TIME in last_run
        else (datetime.now() - timedelta(minutes=1)),
    )

    fetched_events = last_run.get(FileEventLastRun.FETCHED_IDS, {})
    pre_fetch_look_back = datetime.now(tz=timezone.utc) - FILE_EVENTS_LOOK_BACK
    file_events = client.get_file_events(file_event_time, limit=max_fetch_file_events + len(fetched_events))
    dedup_file_events = dedup_fetched_events(
        file_events, last_run_fetched_event_ids=fetched_events, keys_list_to_id=["event", "id"]
    )
    if file_events:
        latest_file_event_ids, latest_file_event_time = get_latest_file_event_ids_and_time(
            file_events + format_last_run_dupes(fetched_events), pre_fetch_look_back=pre_fetch_look_back
        )
        datetime_to_date_string(dedup_file_events)
        new_last_run.update(
            {
                FileEventLastRun.TIME.value: latest_file_event_time,
                FileEventLastRun.FETCHED_IDS.value: latest_file_event_ids,
            }
        )

    demisto.debug(f"updated last run of {EventType.FILE} events to {new_last_run}")
    return dedup_file_events, new_last_run


def fetch_audit_logs(client: Client, last_run: dict, max_fetch_audit_events: int) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    """
    Fetch audit logs

    Args:
        client: Code42EventCollector client
        last_run: Last run object
        max_fetch_audit_events: the maximum number of audit logs to return
    """
    demisto.debug(f"last run before getting {EventType.AUDIT} logs: {last_run}")
    new_last_run = last_run.copy()
    audit_log_time = (
        dateparser.parse(last_run[AuditLogLastRun.TIME])
        if AuditLogLastRun.TIME in last_run
        else (datetime.now() - timedelta(minutes=1))
    )
    last_fetched_audit_log_ids = set(last_run.get(AuditLogLastRun.FETCHED_IDS, []))
    audit_logs = client.get_audit_logs(audit_log_time, limit=max_fetch_audit_events)  # type: ignore[arg-type]
    audit_logs = dedup_fetched_events(audit_logs, last_run_fetched_event_ids=last_fetched_audit_log_ids, keys_list_to_id=["id"])

    if audit_logs:
        latest_audit_log_ids, latest_audit_log_time = get_latest_audit_logs_ids_and_time(audit_logs)
        datetime_to_date_string(audit_logs)
        new_last_run.update(
            {
                AuditLogLastRun.TIME.value: latest_audit_log_time,
                AuditLogLastRun.FETCHED_IDS.value: latest_audit_log_ids,
            }
        )

    demisto.debug(f"updated last run of {EventType.AUDIT} logs to {new_last_run}")
    return audit_logs, new_last_run


def format_last_run_dupes(dupes: dict) -> list[dict]:
    return [{"event": {"id": dupe_id}, "_time": datetime.fromisoformat(dupe_time)} for dupe_id, dupe_time in dupes.items()]


def fetch_events(
    client: Client, last_run: dict, max_fetch_file_events: int, max_fetch_audit_events: int, event_types_to_fetch: List[str]
):
    """
    Fetch audit-logs & file-events
    """
    if "File" in event_types_to_fetch:
        file_events, file_events_last_run = fetch_file_events(
            client, last_run=last_run, max_fetch_file_events=max_fetch_file_events
        )

        last_run.update(file_events_last_run)
        futures = send_events_to_xsiam(file_events, multiple_threads=True, vendor=VENDOR, product=PRODUCT)
        if futures:
            tuple(concurrent.futures.as_completed(futures))  # wait for all the alerts to be sent XSIAM
        demisto.updateModuleHealth({f"{EventType.FILE} events sent": len(file_events)})
    if "Audit" in event_types_to_fetch:
        audit_logs, audit_logs_last_run = fetch_audit_logs(
            client, last_run=last_run, max_fetch_audit_events=max_fetch_audit_events
        )
        for log in audit_logs:
            log.pop("id", None)

        last_run.update(audit_logs_last_run)
        futures = send_events_to_xsiam(audit_logs, multiple_threads=True, vendor=VENDOR, product=PRODUCT)
        if futures:
            tuple(concurrent.futures.as_completed(futures))  # wait for all the alerts to be sent XSIAM
        demisto.updateModuleHealth({f"{EventType.AUDIT} events sent": len(audit_logs)})
    demisto.setLastRun(last_run)


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get events command, used mainly for debugging
    """
    start_date = args["start_date"]
    end_date = args.get("end_date")
    limit = arg_to_number(args.get("limit")) or 100
    event_type = args["event_type"]

    if event_type == "audit":
        events = client.get_audit_logs(start_date, end_time=end_date, limit=limit)
        readable_output = tableToMarkdown(
            "Audit Logs",
            events,
            headers=["actorId", "actorName", "timestamp", "type"],
            headerTransform=pascalToSpace,
            removeNull=True,
        )
    else:
        events = client.get_file_events(start_date, end_time=end_date, limit=limit)
        for event in events:
            event["Id"] = event["event"]["id"]
        readable_output = tableToMarkdown("File Events", events, headers=["id", "_time"], removeNull=True)

    return CommandResults(
        outputs_prefix="Code42EventCollector.Events", outputs=events, raw_response=events, readable_output=readable_output
    )


def main() -> None:
    params = demisto.params()
    client_id: str = params.get("credentials", {}).get("identifier", "")
    client_secret: str = params.get("credentials", {}).get("password", "")
    base_url: str = params.get("url", "").rstrip("/")
    verify_certificate = not params.get("insecure", False)
    max_fetch_file_events = arg_to_number(params.get("max_file_events_per_fetch")) or DEFAULT_FILE_EVENTS_MAX_FETCH
    max_fetch_audit_events = arg_to_number(params.get("max_audit_events_per_fetch")) or DEFAULT_AUDIT_EVENTS_MAX_FETCH
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", ["File"]))
    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
        )
        if command == "test-module":
            return_results(test_module(client, event_types_to_fetch))
        elif command == "fetch-events":
            fetch_events(
                client,
                last_run=demisto.getLastRun(),
                max_fetch_file_events=max_fetch_file_events,
                max_fetch_audit_events=max_fetch_audit_events,
                event_types_to_fetch=event_types_to_fetch,
            )
        elif command == "code42-get-events":
            return_results(get_events_command(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
