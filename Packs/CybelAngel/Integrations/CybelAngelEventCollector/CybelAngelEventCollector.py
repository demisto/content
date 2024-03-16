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
DEFAULT_FIRST_FETCH = "30 days"


class LastRun(str, Enum):
    LATEST_REPORT_TIME = "latest_report_time"
    LATEST_FETCHED_REPORTS_IDS = "latest_fetched_reports_ids"


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

        demisto.debug(f'Running http-request with URL {url_suffix} and {params=}')

        response = self._http_request(
            method, url_suffix=url_suffix, headers=headers, params=params, resp_type="response", ok_codes=(401, 200)
        )
        if response.status_code == 200:
            return response.json()
        else:
            demisto.debug('Access token has expired, retrieving new access token')

        token = self.get_access_token(create_new_token=True)
        headers["Authorization"] = f'Bearer {token}'

        return self._http_request(method, url_suffix=url_suffix, headers=headers, params=params)

    def get_reports(self, start_date: str, end_date: str, limit: int = DEFAULT_MAX_FETCH) -> List[dict[str, Any]]:
        """
        Get manual reports from Cybel Angel Collector.

        Note:
            The order of the events returned is random, hence need to sort them out to return the oldest events first.
        """
        params = {
            "start-date": start_date,
            "end-date": end_date
        }
        reports = self.http_request(method='GET', url_suffix="/api/v2/reports", params=params).get("reports") or []
        for report in reports:
            if updated_at := report.get("updated_at"):
                _time_field = updated_at
            else:
                _time_field = report["created_at"]

            report["_time"] = _time_field

        reports = sorted(
            reports, key=lambda _report: dateparser.parse(_report["_time"])  # type: ignore[arg-type, return-value]
        )
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
        url = 'https://auth.cybelangel.com/oauth/token'

        token_response = self._http_request(
            'POST',
            full_url=url,
            json_data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": "https://platform.cybelangel.com/",
                "grant_type": "client_credentials"
            }
        )
        if access_token := token_response.get("access_token"):
            return access_token
        raise RuntimeError(f"Could not retrieve token from {url}, access-token returned is empty")


def dedup_fetched_events(
    events: List[dict],
    last_run_fetched_event_ids: Set[str],
) -> List[dict]:
    """
    Dedup events, removes events which were already fetched.
    """
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


def get_latest_event_time_and_ids(reports: List[Dict[str, Any]]) -> tuple[str, List[str]]:
    """
    Returns the latest event time and all the events that were fetched in the latest event time
    """
    latest_report_time = reports[-1]["_time"]
    return latest_report_time, [report["id"] for report in reports if report["_time"] == latest_report_time]


def test_module(client: Client) -> str:
    """
    Tests that the authentication to the api is ok.
    """
    client.get_reports(
        start_date=(datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT),
        end_date=datetime.now().strftime(DATE_FORMAT)
    )
    return "ok"


def fetch_events(client: Client, first_fetch: str, last_run: dict, max_fetch: int) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    """
    Fetches reports from Cybel Angel

    Args:
        client: Cybel Angel client
        first_fetch: since when to start to takes reports
        last_run: the last run object
        max_fetch: maximum number of reports

    Fetch logic:
    1. Get the latest report time from last fetch or start from fetch in case its a the first time fetching
    2. get all the reports since the last fetch or first fetch
    3. remove any reports which where already fetched
    4. if there are no reports after dedup, keep the last run the same and return
    5. if there are reports after dedup, update the last run to the latest report time, save all the report IDs which
       occurred in the last event time
    6. return all the fetched events

    """
    last_run_time = last_run.get(LastRun.LATEST_REPORT_TIME)
    if not last_run_time:
        last_run_time = dateparser.parse(first_fetch).strftime(DATE_FORMAT)  # type: ignore[union-attr]
        if not last_run_time:
            demisto.error(f'First fetch {first_fetch} is not valid')
            raise ValueError(f'First fetch {first_fetch} not valid')
    else:
        last_run_time = dateparser.parse(last_run_time).strftime(DATE_FORMAT)  # type: ignore[union-attr]
    now = datetime.now()
    reports = client.get_reports(start_date=last_run_time, end_date=now.strftime(DATE_FORMAT), limit=max_fetch)
    reports = dedup_fetched_events(reports, last_run_fetched_event_ids=last_run.get(LastRun.LATEST_FETCHED_REPORTS_IDS) or set())
    if not reports:
        demisto.debug(f'No reports found when last run is {last_run}')
        return [], {
            LastRun.LATEST_REPORT_TIME: last_run_time,
            LastRun.LATEST_FETCHED_REPORTS_IDS: last_run.get(LastRun.LATEST_FETCHED_REPORTS_IDS)
        }

    latest_report_time, latest_fetched_report_ids = get_latest_event_time_and_ids(reports)
    demisto.debug(f'latest-report-time: {latest_report_time}')
    demisto.debug(f'latest-fetched-report-ids {latest_fetched_report_ids}')

    last_run.update(
        {
            LastRun.LATEST_REPORT_TIME: latest_report_time,
            LastRun.LATEST_FETCHED_REPORTS_IDS: latest_fetched_report_ids
        }
    )
    return reports, last_run


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get events from Cybel Angel, used mainly for debugging purposes
    """
    if end := args.get("end-date"):
        end_date = dateparser.parse(end).strftime(DATE_FORMAT)  # type: ignore[union-attr]
    else:
        end_date = datetime.now().strftime(DATE_FORMAT)

    reports = client.get_reports(
        dateparser.parse(args["start-date"]).strftime(DATE_FORMAT),  # type: ignore[union-attr]
        end_date=end_date,
        limit=arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    )

    return CommandResults(
        outputs_prefix="CybleAngel.Events",
        outputs_key_field="id",
        outputs=reports,
        raw_response=reports,
        readable_output=tableToMarkdown("Reports", reports, headers=["id", "created_at", "updated_at"], removeNull=True)
    )


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH

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
            events, last_run = fetch_events(client, first_fetch=first_fetch, last_run=demisto.getLastRun(), max_fetch=max_fetch)
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
