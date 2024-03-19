import incydr
from incydr import EventQuery

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any


# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_FILE_EVENTS_MAX_FETCH = 50000
DEFAULT_AUDIT_EVENTS_MAX_FETCH = 100000


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_FETCH_AUDIT_LOGS = 100000
MAX_AUDIT_LOGS_PAGE_SIZE = 10000


MAX_FETCH_FILE_EVENTS = 50000
MAX_FILE_EVENTS_PAGE_SIZE = 10000

''' CLIENT CLASS '''


class Client:

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.code42_client = incydr.Client(base_url, api_client_id=client_id, api_client_secret=client_secret)
        self.code42_client.session.verify = verify

    def get_audit_logs(
        self, start_time: datetime | str | timedelta, end_time: datetime | timedelta | str | None = None, limit: int = MAX_FETCH_AUDIT_LOGS, page_size: int = MAX_AUDIT_LOGS_PAGE_SIZE
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

    def get_file_events(self, start_time: datetime | str | timedelta, end_time: datetime | str | timedelta | None = None, limit: int = MAX_FETCH_FILE_EVENTS, page_size: int = MAX_FILE_EVENTS_PAGE_SIZE) -> List[Dict[str, Any]]:
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
            event["_time"] = event["event"]["inserted"]

        return file_events



''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    client.get_file_events(timedelta(minutes=1), page_size=1)
    client.get_audit_logs(timedelta(minutes=1), page_size=1)
    return "ok"



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
            events, last_run = fetch_events(client, first_fetch=max_fetch_audit_events, last_run=demisto.getLastRun(), max_fetch=max_fetch_file_events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent event {[event.get("id") for event in events]} IDs to XSIAM')
            demisto.setLastRun(last_run)
        elif command == "cybelangel-get-events":
            return_results(get_events_command(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
