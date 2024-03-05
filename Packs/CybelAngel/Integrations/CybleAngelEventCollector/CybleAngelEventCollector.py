import dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from enum import Enum

# Disable insecure warnings
urllib3.disable_warnings()


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
DEFAULT_MAX_FETCH = 5000
VENDOR = "cybelangel"
PRODUCT = "platform"


class LastRun(str, Enum):
    LATEST_REPORT_TIME = "latest_report_time"
    LATEST_FETCHED_REPORTS = "latest_fetched_reports"


class Client(BaseClient):

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, method: str, url_suffix: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        response = self._http_request(
            method, url_suffix=url_suffix, headers=headers, params=params, resp_type="response", ok_codes=(401, 200)
        )
        if response.status_code == 200:
            return response.json()

        token = self.get_access_token(create_new_token=True)
        headers["Authorization"] = f'Bearer {token}'

        return self._http_request(method, url_suffix=url_suffix, headers=headers, params=params)

    def get_reports(self, start_date: str, end_date: str, limit: int = DEFAULT_MAX_FETCH) -> List[dict[str, Any]]:
        params = {
            "start-date": start_date,
            "end-date": end_date
        }
        reports = self.http_request(method='GET', url_suffix="/api/v2/reports", params=params).get("reports") or []
        # sort the reports by their date as their order is returned randomly
        reports = sorted(reports, key=lambda report: dateparser.parse(report["created_at"]))
        return reports[:limit]

    def get_access_token(self, create_new_token: bool = False) -> str:
        """
       Obtains access and refresh token from CybleAngel server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

        Returns:
            str: the access token.
       """
        integration_context = get_integration_context()
        current_access_token = integration_context.get('access_token')
        if current_access_token and not create_new_token:
            return current_access_token
        new_access_token = self.get_token_request()
        integration_context = {
            'access_token': new_access_token,
        }
        demisto.debug(f'updating access token at {datetime.now()}')
        set_integration_context(context=integration_context)
        return new_access_token

    def get_token_request(self) -> str:
        """
        Sends request to retrieve token.

       Returns:
           tuple[str, str]: token and its expiration date
        """

        token_response = self._http_request(
            'POST',
            full_url='https://auth.cybelangel.com/oauth/token',
            json_data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": "https://platform.cybelangel.com/",
                "grant_type": "client_credentials"
            }
        )
        return token_response.get("access_token", "")


def dedup_fetched_events(
    events: List[dict],
    last_run_fetched_event_ids: Set[str],
) -> List[dict]:

    un_fetched_events = []

    for event in events:
        event_id = event.get("id")
        if event_id not in last_run_fetched_event_ids:
            demisto.debug(f'event with ID {event_id} has not been fetched.')
            un_fetched_events.append(event)
        else:
            demisto.debug(f'event with ID {event_id} for has been fetched')

    demisto.debug(f'{un_fetched_events=}')
    return un_fetched_events


def test_module(client: Client) -> str:
    client.get_reports(
        start_date=(datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT),
        end_date=datetime.now().strftime(DATE_FORMAT)
    )
    return "ok"


def fetch_events(client: Client, last_run: dict, max_fetch: int) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    last_run_time, last_fetched_report_ids = last_run.get(
        LastRun.LATEST_REPORT_TIME), last_run.get(LastRun.LATEST_FETCHED_REPORTS)
    if not last_run_time:
        last_run_time = (datetime.now() - timedelta(days=1065)).strftime(DATE_FORMAT)

    reports = client.get_reports(start_date=last_run_time, end_date=datetime.now().strftime(DATE_FORMAT), limit=max_fetch)
    reports = dedup_fetched_events(reports, last_run_fetched_event_ids=last_fetched_report_ids or set())

    for report in reports:
        report["_time"] = report["created_at"]

    latest_report_time = reports[-1]["created_at"] if reports else None
    demisto.debug(f'latest-report-time: {latest_report_time}')
    last_fetched_report_ids = [report for report in reports if report["created_at"] == latest_report_time]
    demisto.debug(f'latest-fetched-report-ids {last_fetched_report_ids}')

    last_run.update(
        {
            LastRun.LATEST_REPORT_TIME: latest_report_time or last_run_time,
            LastRun.LATEST_FETCHED_REPORTS: last_fetched_report_ids or last_fetched_report_ids
        }
    )
    return reports, last_run


def get_events(client: Client, args: dict[str, Any]) -> CommandResults:
    pass


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            events, last_run = fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent event {[event.get("id") for event in events]} IDs to xsiam')
            demisto.setLastRun(last_run)
        elif command == "cybleangel-get-events":
            return_results(get_events(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
