import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from typing import Any

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()  # pylint: disable=no-member


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_logs(self, marker=None, since=None, until=None):
        since = since.strftime(DATE_FORMAT)[:-4] + 'Z' if since else None
        until = until.strftime(DATE_FORMAT)[:-4] + 'Z' if until else None
        query_params = assign_params(marker=marker, since=since, until=until)

        raw_response = self._http_request(
            method='GET',
            url_suffix='logs',
            params=query_params,
        )

        events = raw_response.get('page', {}).get('items')
        marker = raw_response.get('page', {}).get('pageMarker')

        return raw_response, events, marker

    def get_logs_fetch_events(self, last_run, limit, first_fetch):
        marker = last_run.get('marker')
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


def fetch_events_command(client: Client, first_fetch, last_run: dict, limit=1000) -> tuple[list, dict]:
    if (limit % 1000 != 0) or (limit > 10000):
        raise Exception('Limit parameter should be multiple of 1000 and not greater than 10,000.')

    events, new_last_run = client.get_logs_fetch_events(last_run, limit, first_fetch)
    return events, new_last_run


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list, CommandResults]:
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

    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(urljoin(params['url'], 'api/v1/tenants/'), demisto.params()['tenant_code'])
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    limit = arg_to_number(params.get('limit'))
    first_fetch = arg_to_datetime(params.get('first_fetch'))

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'accept': 'application/json',
            'Object-Id-Format': 'base64',
            'Content-Type': 'application/json',
            'apikey': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            ok_codes=(200, 201, 204))

        if command == 'test-module':
            return_results(test_module(client, limit, first_fetch))

        elif command == 'sta-get-events':
            events, results = get_events_command(client, demisto.args())
            return_results(results)
            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    params.get('vendor', 'safenet'),
                    params.get('product', 'trusted_access')
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(client, first_fetch, last_run, limit)

            send_events_to_xsiam(
                events,
                params.get('vendor', 'safenet'),
                params.get('product', 'trusted_access')
            )
            demisto.setLastRun(last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
