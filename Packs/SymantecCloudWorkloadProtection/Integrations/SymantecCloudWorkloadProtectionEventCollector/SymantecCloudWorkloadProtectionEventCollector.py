import demistomock as demisto
from CommonServerPython import *
from collections.abc import Callable
from typing import TypedDict
from math import ceil

# Disable insecure warnings

''' CONSTANTS '''

API_LIMIT = 10_000
AUTH_CONTEXT_KEY = 'API_Auth'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
VENDOR = 'symantec'
PRODUCT = 'cwp'

''' TYPING '''


class LastRun(TypedDict):
    last_date: str
    last_synchronous_ids: list[str]


class LastRuns(TypedDict):
    alerts: LastRun
    events: LastRun


''' CLIENT CLASS '''


class Client(BaseClient):

    credentials: dict = {}
    max_fetch: int = 0

    def _http_request(
        self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
        params=None, data=None, files=None, timeout=None, ok_codes=(200,), **kwargs
    ):
        demisto.debug(f'http_request to {url_suffix!r} with {data=}')
        res: requests.Response = super()._http_request(
            method, url_suffix, full_url, headers, auth, json_data, params, data,
            files, timeout, 'response', ok_codes + (401,), **kwargs
        )
        if res.status_code == 401:
            demisto.debug('Token expired, 401 status code received.')
            self.update_authorization(self.get_new_token())
            res: requests.Response = super()._http_request(
                method, url_suffix, full_url, headers, auth, json_data, params,
                data, files, timeout, 'response', ok_codes, **kwargs
            )
        try:
            return res.json()
        except requests.JSONDecodeError as e:
            raise DemistoException(f'Failed to parse response: {res.content}', e, res)

    def update_authorization(self, auth: str):
        if not self._headers:
            self._headers = {}
        self._headers['Authorization'] = auth

    def get_new_token(self) -> str:
        res = self._http_request(
            'POST',
            '/dcs-service/dcscloud/v1/oauth/tokens',
            json_data=self.credentials
        )
        auth = f'{res["token_type"]} {res["access_token"]}'  # type: ignore
        demisto.setIntegrationContext(
            demisto.getIntegrationContext()
            | {AUTH_CONTEXT_KEY: auth}
        )
        demisto.debug(f'New access token generated: {auth[:-200]}...')
        return auth

    @classmethod
    def from_params(
        cls, url: str, credentials: dict, customer_id: str,
        domain_id: str, max_events_per_fetch: str, insecure: bool,
        proxy: bool, **_
    ):
        client = cls(
            base_url=url.removesuffix('/'),
            verify=(not insecure),
            proxy=proxy,
            headers={
                'content-type': 'application/json',
                'x-epmp-customer-id': customer_id,
                'x-epmp-domain-id': domain_id,
            },
        )
        client.credentials = {
            'client_id': credentials['identifier'],
            'client_secret': credentials['password'],
        }
        client.max_fetch = arg_to_number(max_events_per_fetch) or 0
        client.update_authorization(
            demisto.getIntegrationContext().get(AUTH_CONTEXT_KEY)
            or client.get_new_token()
        )
        demisto.debug('client created')
        return client

    def test_credentials(self):
        data = {
            'pageSize': 1,
            'pageNumber': 0,
            'startDate': (datetime.now() - timedelta(days=30)).strftime(DATE_FORMAT),
            'endDate': datetime.now().strftime(DATE_FORMAT)
        }
        demisto.debug('Testing event endpoint...')
        self._event_request(data=data)
        demisto.debug('Testing alert endpoint...')
        self._alert_request(data=data)

    def _pagination_fetch(self, request_func: Callable[[dict], dict], last_date: str) -> list[dict]:

        def unpack_and_validate_res(result=None, total=None, **kwargs) -> tuple[list, int]:
            if not (isinstance(result, list) and isinstance(total, int)):
                raise DemistoException(f'Unexpected response from Symantec API: {kwargs}')
            return result, total

        objects = []
        end_date = datetime.now().strftime(DATE_FORMAT)
        pages = ceil(self.max_fetch / API_LIMIT)  # The minimum amount of calls needed
        page_size = ceil(self.max_fetch / pages)  # The minimum amount of objects needed per call
        demisto.debug(f'paginating with {pages=}, {page_size=}, {end_date=}')
        for page in range(pages):
            res = request_func(
                {
                    'pageSize': page_size,
                    'pageNumber': page,
                    'startDate': last_date,
                    'endDate': end_date,
                    'order': 'ASCENDING',
                }
            )
            result, total = unpack_and_validate_res(**res)
            demisto.debug(f'Got results: result[0]={(result or [None])[0]}, {len(result)=}, {total=}')
            objects += result
            if total < page_size:
                break
        del objects[self.max_fetch:]
        return objects

    def _manage_duplicates(self, objects: list[dict], last_synchronous_ids: list) -> tuple[list, LastRun]:
        ids = set(last_synchronous_ids)
        objects = [x for x in objects if x['uuid'] not in ids]
        last_date: str = dict_safe_get(objects, (-1, 'time'))  # type: ignore
        last_synchronous_ids = [i['uuid'] for i in objects if i['time'] == last_date]
        demisto.debug(f'New LastRun: {last_date=}, {last_synchronous_ids=}')
        return objects, LastRun(last_date=last_date, last_synchronous_ids=last_synchronous_ids)

    def _fetch_objects(
        self, request_func: Callable[[dict], dict], last_date: str | None = None, last_synchronous_ids: list | None = None
    ) -> tuple[list, LastRun]:
        last_date = last_date or (datetime.now() - timedelta(minutes=1)).strftime(DATE_FORMAT)
        objects = self._pagination_fetch(request_func, last_date)
        return self._manage_duplicates(objects, last_synchronous_ids or [])

    def _event_request(self, data: dict) -> dict:
        return self._http_request(
            'POST',
            '/dcs-service/dcscloud/v1/event/query',
            json_data=data
        )

    def _alert_request(self, data: dict) -> dict:
        data['eventTypeToQuery'] = 16
        return self._http_request(
            'POST',
            '/dcs-service/sccs/v1/events/search',
            json_data=data
        )

    def fetch_events(self, args: LastRun) -> tuple[list, LastRun]:
        return self._fetch_objects(self._event_request, **args)

    def fetch_alerts(self, args: LastRun) -> tuple[list, LastRun]:
        return self._fetch_objects(self._alert_request, **args)


def test_module(client: Client) -> str:
    client.test_credentials()
    return 'ok'


''' MAIN FUNCTION '''


def add_time_to_objects(objects: list[dict]):
    """
    Adds the _time key to the objects (events/alerts).
    Args:
        objects: list[dict] - list of objects to add the "_time" key to.
    """
    for obj in objects:
        obj['_time'] = obj.get('time')


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client.from_params(**demisto.params())

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-events':

            last_run: LastRuns = demisto.getLastRun() or LastRuns(events={}, alerts={})  # type: ignore

            events, events_last_run = client.fetch_events(last_run['events'])
            alerts, alerts_last_run = client.fetch_alerts(last_run['alerts'])

            events += alerts
            add_time_to_objects(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            demisto.setLastRun(LastRuns(events=events_last_run, alerts=alerts_last_run))

        # TEMP
        elif command == 'symantec-fetch-events-test':
            args = demisto.args()
            res = client._event_request({
                'pageSize': arg_to_number(args['page_size']),
                'pageNumber': arg_to_number(args['page_number']),
                'startDate': args['start_date'],
                'endDate': datetime.now().strftime(DATE_FORMAT),
                'order': args['order'],
            })
            return_results(CommandResults(readable_output=json.dumps(res, indent=4)))

        # TEMP
        elif command == 'symantec-fetch-alerts-test':
            args = demisto.args()
            res = client._alert_request({
                'pageSize': arg_to_number(args['page_size']),
                'pageNumber': arg_to_number(args['page_number']),
                'startDate': args['start_date'],
                'endDate': datetime.now().strftime(DATE_FORMAT),
                'order': args['order'],
            })
            return_results(CommandResults(readable_output=json.dumps(res, indent=4)))

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
