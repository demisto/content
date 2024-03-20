import incydr
from incydr import EventQuery

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
from enum import Enum


# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_FILE_EVENTS_MAX_FETCH = 50000
DEFAULT_AUDIT_EVENTS_MAX_FETCH = 100000


''' CONSTANTS '''

MAX_FETCH_AUDIT_LOGS = 100000
MAX_AUDIT_LOGS_PAGE_SIZE = 10000


MAX_FETCH_FILE_EVENTS = 50000
MAX_FILE_EVENTS_PAGE_SIZE = 10000


VENDOR = "code42"
PRODUCT = "code42"


class FileEventLastRun(str, Enum):
    TIME = "file-event-time"  # saves the last time of previous fetch of file-events
    FETCHED_IDS = "file-event-ids"  # saved a list of IDs of previous fetch which are is the latest time


class EventType(str, Enum):
    FILE = "file-event"
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
        page_size: int = MAX_AUDIT_LOGS_PAGE_SIZE
    ) -> List[Dict]:
        """
        Get audit logs

        Args:
            start_time: from which start time to get logs
            end_time: until which time to get logs
            limit: maximum events to retrieve
            page_size: the page size per single request
        """
        audit_logs = []
        page = 0
        while len(audit_logs) < limit:
            audit_event_page = self.code42_client.audit_log.v1.get_page(page, start_time=start_time, end_time=end_time)
            events = audit_event_page.events
            if len(events) < page_size:
                break
            audit_logs.extend(audit_event_page.events)

        audit_logs = sorted(
            audit_logs, key=lambda _log: dateparser.parse(_log["timestamp"])  # type: ignore[arg-type, return-value]
        )
        audit_logs = audit_logs[:limit]
        for audit_log in audit_logs:
            audit_log["_time"] = audit_log["timestamp"]

        return audit_logs

    def get_file_events(
        self,
        start_time: datetime | str | timedelta,
        end_time: datetime | str | timedelta | None = None,
        limit: int = MAX_FETCH_FILE_EVENTS,
        page_size: int = MAX_FILE_EVENTS_PAGE_SIZE
    ) -> List[Dict[str, Any]]:
        """
        Get file events

        Args:
            start_time: from which start time to get events
            end_time: until which time to get events
            limit: maximum events to retrieve
            page_size: the page size per single request
        """
        query = EventQuery(start_date=start_time, end_date=end_time, srtDir="asc", pgSize=page_size)
        response = self.code42_client.file_events.v2.search(
            query
        )

        file_events = response.file_events
        if not file_events:
            return []
        while query.page_token is not None or len(file_events) < limit:
            file_events.extend(self.code42_client.file_events.v2.search(query))

        file_events = file_events[:limit]

        for event in file_events:
            event["type"] = EventType.FILE
            event["_time"] = event["event"]["inserted"]

        return file_events


''' HELPER FUNCTIONS '''


def dedup_fetched_events(
    events: List[dict],
    last_run_fetched_event_ids: Set[str],
    keys_list_to_id: List[str]
) -> List[dict]:
    """
    Dedup events, removes events which were already fetched.
    """
    un_fetched_events = []

    for event in events:
        event_id = dict_safe_get(event, keys=keys_list_to_id)
        if event_id not in last_run_fetched_event_ids:
            demisto.debug(f'event {event["type"]} with ID {event_id} has not been fetched.')
            un_fetched_events.append(event)
        else:
            demisto.debug(f'event {event["type"]} with ID {event_id} for has been fetched')

    un_fetched_event_ids = {dict_safe_get(event, keys=keys_list_to_id) for event in un_fetched_events}
    demisto.debug(f'{un_fetched_event_ids=}')
    
    return un_fetched_events


# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    client.get_file_events(timedelta(minutes=1), page_size=1)
    client.get_audit_logs(datetime.now() - timedelta(minutes=1), page_size=1)
    return "ok"


def fetch_events(client: Client, last_run: Dict, max_fetch_file_events: int, max_fetch_audit_events: int) -> List[Dict[str, Any], Dict[str, Any]]:
    if FileEventLastRun.TIME not in last_run:
        file_event_time = datetime.now() - timedelta(minutes=1)
    else:
        file_event_time = last_run[FileEventLastRun.TIME]

    file_events = client.get_file_events(file_event_time, limit=max_fetch_file_events)







def get_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get events command, used mainly for debugging
    """
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    limit = arg_to_number(args.get("limit")) or 100
    event_type = args.get("event_type")

    if event_type == "audit":
        events = client.get_audit_logs(start_date, end_time=end_date, limit=limit)
        readable_output = tableToMarkdown(
            "Audit Logs",
            events,
            headers=["actorId", "actorName", "timestamp", "type"],
            headerTransform=pascalToSpace, removeNull=True
        )
    else:
        events = client.get_file_events(start_date, end_time=end_date, limit=limit)
        for event in events:
            event["id"] = event["event"]["id"]
            event["inserted"] = event["event"]["inserted"]
        readable_output = tableToMarkdown(
            "File Events",
            events,
            headers=["id", "inserted"],
            headerTransform=lambda x: x.upper(),
            removeNull=True
        )

    return CommandResults(
        outputs_prefix="Code42EventCollector.Events",
        outputs=events,
        raw_response=events,
        readable_output=readable_output
    )


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    max_fetch_file_events = arg_to_number(params.get("max_file_events_per_fetch")) or DEFAULT_FILE_EVENTS_MAX_FETCH
    max_fetch_audit_events = params.get("max_audit_events_per_fetch") or DEFAULT_AUDIT_EVENTS_MAX_FETCH

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            events, last_run = fetch_events(
                client,
                last_run=demisto.getLastRun(),
                max_fetch_file_events=max_fetch_file_events,
                max_fetch_audit_events=max_fetch_audit_events
            )
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_run)
        elif command == "code42-get-events":
            return_results(get_events_command(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
