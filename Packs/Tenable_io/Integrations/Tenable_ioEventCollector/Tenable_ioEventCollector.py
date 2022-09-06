import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'tenable'
PRODUCT = 'io'

DATE_FORMAT = '%Y-%m-%d'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

        This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
        Handles the token retrieval.

        :param base_url (str): Saas Security server url.
        :param client_id (str): client ID.
        :param client_secret (str): client secret.
        :param verify (bool): specifies whether to verify the SSL certificate or not.
        :param proxy (bool): specifies if to use XSOAR proxy settings.
        """

    def __init__(self, base_url: str, access_key: str, secret_key: str, verify: bool, proxy: bool, headers: dict, **kwargs):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, **kwargs)

    def get_audit_logs_request(self, from_date: str, to_date: str, actor_id: str, target_id: str, limit: int):
        """

        Args:
            limit:
            from_date: date to fetch audit logs from.
            to_date: date which until to fetch audit logs.
            actor_id: fetch audit logs with matching actor id.
            target_id:fetch audit logs with matching target id.

        Returns:
            audit logs fetched from the API.
        """
        query = ''
        params = {}
        if from_date:
            query += f'f=date.gt:{from_date}'
            params.update({'f=date.gt': from_date})
        if to_date:
            query += f'f=date.lt:{to_date}'
            params.update({'f=date.lt': to_date})
        if actor_id:
            query += f'f=actor_id.match:{actor_id}'
            params.update({'f=actor_id.match': actor_id})
        if target_id:
            query += f'f=target_id.match:{target_id}'
            params.update({'f=target_id.match': target_id})
        if limit:
            params.update({'limit': limit})
        return super()._http_request(url_suffix='/audit-log/v1/events', params=params, headers=self.headers)



    def get_audit_fetch_events(self, last_run: dict, limit: int, first_fetch: str):
        last_fetch = last_run.get('last_fetch')
        last_id_fetched = last_run.get('last_id')
        found_last_fetched = False
        if not last_fetch and first_fetch:
            start_date = first_fetch.strftime(DATE_FORMAT)

        audit_logs = []
        audit_logs_from_api = self.get_audit_logs_request(start_date)
        for log in audit_logs_from_api:
            if not last_id_fetched or not found_last_fetched:
                if log.get('id') == last_id_fetched:
                    found_last_fetched = True
                continue




    def get_audit_fetch_events(self, last_run, limit, first_fetch):
        marker = last_run.get('marker')
        query = ''
        since = None
        events = []
        fetched_events_count = 0
        if not marker and first_fetch:
            since = first_fetch.strftime(DATE_FORMAT)[:-4] + 'Z'
        query_params = assign_params(marker=marker, since=since)

        while fetched_events_count < limit:
            demisto.debug(f'Fetching new events, {query_params=}')
            raw_response = self._http_request(
                method='GET',
                url_suffix='logs',
                params=query_params,
            )

            new_fetched_events = raw_response.get('page', {}).get('items', [])
            events.extend(new_fetched_events)
            marker = raw_response.get('page', {}).get('pageMarker', marker)
            query_params = {'marker': marker}
            if len(new_fetched_events) < 1000:
                break
            fetched_events_count += len(new_fetched_events)

        new_last_run = {'marker': marker}
        demisto.info(f'Done fetching {len(events)} events, Setting {new_last_run=}.')
        return events, new_last_run


''' COMMAND FUNCTIONS '''


def test_module(client: Client, limit=1000, first_fetch=None) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    if (limit % 1000 != 0) or (limit > 10000):
        raise Exception('Limit parameter should be multiple of 1000 and not greater than 10,000.')

    client.get_logs(since=first_fetch)
    return 'ok'


def fetch_audit_logs_command(client: Client, first_fetch, last_run: dict, limit=1000) -> Tuple[list, dict]:
    if (limit % 1000 != 0) or (limit > 10000):
        raise Exception('Limit parameter should be multiple of 1000 and not greater than 10,000.')

    last_fetch = last_run.get('last_fetch')
    if not last_fetch and first_fetch:
        start_date = first_fetch.strftime(DATE_FORMAT)

    events, new_last_run = client.get_logs_fetch_events(last_run, limit, first_fetch)
    return events, new_last_run


def get_events_command(client: Client, args: Dict[str, Any]) -> Tuple[list, CommandResults]:
    marker = args.get('marker')
    since = arg_to_datetime(args.get('since'))
    until = arg_to_datetime(args.get('until'))

    raw_response, events, new_marker = client.get_logs(marker, since, until)

    results = CommandResults(
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            name='Event Logs',
            t=events,
            metadata=f'Marker: {new_marker}' if new_marker else None,
        )
    )
    return events, results


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    access_key = params.get('access_key', {}).get('password')
    secret_key = params.get('secret_key', {}).get('password')
    base_url = 'https://cloud.tenable.com'
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    limit = arg_to_number(params.get('limit'))
    first_fetch = arg_to_datetime(params.get('first_fetch'))

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}'}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client, limit, first_fetch))

        elif command in ('sta-get-events', 'fetch-events'):

            if command == 'sta-get-events':
                events, results = get_events_command(client, demisto.args())
                return_results(results)

            else:  # command == 'fetch-events':
                last_run = demisto.getLastRun()
                events, last_run = fetch_events_command(client, first_fetch, last_run, limit)
                demisto.setLastRun(last_run)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    params.get('vendor', 'safenet'),
                    params.get('product', 'trusted_access')
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
