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


class LastRunTypes(TypedDict):
    alerts: LastRun
    events: LastRun


''' CLIENT CLASS '''


class Client(BaseClient):

    credentials: dict = {}
    max_fetch: int = 0

    def _http_request(
        self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
        params=None, data=None, files=None, timeout=None, ok_codes=None, **kwargs
    ):
        res: requests.Response = super()._http_request(
            method, url_suffix, full_url, headers, auth, json_data, params, data,
            files, timeout, 'response', (ok_codes or (200,)) + (401,), **kwargs
        )
        if res.status_code == 401:
            self.get_new_token()
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
            data=self.credentials
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
            'client_secret': credentials['password']
        }
        client.max_fetch = arg_to_number(max_events_per_fetch) or 0
        client.update_authorization(
            demisto.getIntegrationContext().get(AUTH_CONTEXT_KEY)
            or client.get_new_token()
        )
        return client

    def test_credentials(self):
        data = {
            'pageSize': 1,
            'pageNumber': 0,
            'startDate': (datetime.now() - timedelta(days=30)).strftime(DATE_FORMAT),
            'endDate': datetime.now().strftime(DATE_FORMAT)
        }
        self._event_request(data=data)
        self._alert_request(data=data)

    def _pagination_fetch(self, request_func: Callable, last_date: str) -> list[dict]:
        objects = []
        end_date = datetime.now().strftime(DATE_FORMAT)
        pages = ceil(self.max_fetch / API_LIMIT)  # The minimum amount of calls needed
        page_size = ceil(self.max_fetch / pages)  # The minimum needed per call
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
            objects += res.get('result') or []
            if res.get('total') < page_size:
                break
        del objects[:self.max_fetch]
        return objects

    def _manage_duplicates(self, objects: list[dict], last_synchronous_ids: list, last_date: str) -> tuple[list, list]:
        ids = set(last_synchronous_ids)
        objects = list(filter((lambda x: x['uuid'] not in ids), objects))
        last_synchronous_ids = [i['uuid'] for i in objects if i['time'] == last_date]
        return objects, last_synchronous_ids

    def _fetch_objects(
        self, request_func: Callable, last_date: str | None = None, last_synchronous_ids: list | None = None
    ) -> tuple[list, str, list]:
        last_date = last_date or (datetime.now() - timedelta(minutes=1)).strftime(DATE_FORMAT)
        last_synchronous_ids = last_synchronous_ids or []
        objects = self._pagination_fetch(request_func, last_date)
        new_last_date: str = dict_safe_get(objects, (-1, 'time'))  # type: ignore
        objects, new_last_synchronous_ids = self._manage_duplicates(objects, last_synchronous_ids, new_last_date)
        return objects, new_last_date, new_last_synchronous_ids

    def _event_request(self, data: dict):
        return self._http_request(
            'POST',
            '/dcs-service/dcscloud/v1/event/query',
            data=data
        )

    def _alert_request(self, data: dict):
        data['eventTypeToQuery'] = 16
        return self._http_request(
            'POST',
            '/dcs-service/sccs/v1/events/search',
            data=data
        )

    def fetch_events(self, args: LastRun) -> tuple[list, str, list]:
        return self._fetch_objects(self._event_request, **args)

    def fetch_alerts(self, args: LastRun) -> tuple[list, str, list]:
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


def _fetch_objects(fetch_func: Callable[[LastRun], tuple[list, str, list]], args: LastRun) -> LastRun:
    objects, last_date, last_synchronous_ids = fetch_func(args)
    add_time_to_objects(objects)
    send_events_to_xsiam(
        objects,
        vendor=VENDOR,
        product=PRODUCT
    )
    return LastRun(
        last_date=last_date,
        last_synchronous_ids=last_synchronous_ids
    )


def fetch_events(client: Client, args: LastRun) -> LastRun:
    return _fetch_objects(client.fetch_events, args)


def fetch_alerts(client: Client, args: LastRun) -> LastRun:
    return _fetch_objects(client.fetch_alerts, args)


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

            last_run: LastRunTypes = demisto.getLastRun() or {'events': {}, 'alerts': {}}  # type: ignore
            next_run = LastRunTypes(
                events=fetch_events(client, last_run['events']),
                alerts=fetch_alerts(client, last_run['alerts'])
            )
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
