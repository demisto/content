import dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
DEFAULT_MAX_FETCH = 5000
VENDOR = "cybelangel"
PRODUCT = "platform"


class Client(BaseClient):

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, method: str, url_suffix: str, params: Dict[str, Any] | None = None):
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

        token = self.get_token_request()
        headers["Authorization"] = f'Bearer {token}'

        return self._http_request(method, url_suffix=url_suffix, headers=headers, params=params)

    def get_reports(self, start_date: str, end_date: str, limit: int = DEFAULT_MAX_FETCH) -> List[Dict[str, Any]]:
        params = {
            "start-date": start_date,
            "end-date": end_date
        }
        reports = self.http_request(method='GET', url_suffix="/api/v2/reports", params=params).get("reports") or []
        return reports[:limit]

    def get_access_token(self) -> str:
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

        Returns:
            str: the access token.
       """
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        token_initiate_time = integration_context.get('token_initiate_time')
        token_expiration_seconds = integration_context.get('token_expiration_seconds')

        if access_token and not is_token_expired(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token
        return self.get_access_token()

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
        access_token, token_expiration_seconds = token_response.get('access_token'), token_response.get('expires_in')
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.debug(f'updating access token')
        set_integration_context(context=integration_context)

        return access_token


def is_token_expired(token_initiate_time: float, token_expiration_seconds: float) -> bool:
    """
    Check whether a token has expired. a token considered expired if it has been reached to its expiration date in
    seconds minus a minute.

    for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

    300.0001 - 240 < 120 - 60

    Args:
        token_initiate_time (float): the time in which the token was initiated in seconds.
        token_expiration_seconds (float): the time in which the token should be expired in seconds.

    Returns:
        bool: True if token has expired, False if not.
    """
    return time.time() - token_initiate_time >= token_expiration_seconds - 60


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


def get_latest_fetched_event_ids(events: List[dict]) -> Tuple[str, List[str]]:

    if not events:
        return "", []

    latest_event_time = max(events, key=lambda event: dateparser.parse(event["created_at"]).strftime(DATE_FORMAT))["created_at"]
    demisto.debug(f'Latest event time: {latest_event_time}')

    latest_occurred_event_ids = set()

    for event in events:
        if event["created_at"] == latest_event_time:
            event_id = event.get("id")
            demisto.info(f'adding event with ID {event_id} to latest occurred event IDs')
            latest_occurred_event_ids.add(event_id)

    return latest_event_time, list(latest_occurred_event_ids)


def test_module(client: Client) -> str:
    client.get_reports(
        start_date=(datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT),
        end_date=datetime.now().strftime(DATE_FORMAT)
    )
    return "ok"


def fetch_events(client: Client, last_run: Dict, max_fetch: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    last_run_time, last_fetched_report_ids = last_run.get("time"), last_run.get("fetched_report_ids")
    reports = client.get_reports(start_date=last_run_time, end_date=datetime.now().strftime(DATE_FORMAT), limit=max_fetch)
    reports = dedup_fetched_events(reports, last_run_fetched_event_ids=last_fetched_report_ids)

    for report in reports:
        report["_time"] = report["created_at"]

    latest_report_time, last_fetched_report_ids = get_latest_fetched_event_ids(reports)
    last_run.update({"time": latest_report_time or last_run_time, "fetched_report_ids": last_fetched_report_ids})
    return reports, last_run



def get_events(client: Client, args: Dict[str, Any]) -> CommandResults:
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
            events, last_fetch = fetch_events(client, last_run=demisto.getLastRun(), max_fetch=max_fetch)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent event {[event.get("id") for event in events]} IDs to xsiam')
            demisto.setLastRun(last_fetch)
        elif command == "cyble-angel-get-events":
            return_results(get_events(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
