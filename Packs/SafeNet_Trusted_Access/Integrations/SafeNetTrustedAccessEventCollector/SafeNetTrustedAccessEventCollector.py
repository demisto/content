import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import requests
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    # Sends request to API Endpoint URL using _http_request() method.
    def http_request(self, method, url_suffix, data=None, headers=None, json_data=None, params=None, full_url=None,
                     resp_type='response'):

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            data=data,
            headers=headers,
            resp_type=resp_type,
            json_data=json_data,
            params=params,
            full_url=full_url
        )

    def get_logs(self, last_run=None):
        query_params = {}

        return self.http_request(
            method='GET',
            url_suffix='logs',
            params=query_params,
        ).json()['page']['items']


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_events_command(client: Client, last_run: dict) -> CommandResults:

    result = client.get_logs(last_run)
    return result


def get_events_command(client: Client, args: Dict[str, Any]) -> Tuple[list, dict]:

    events = client.get_logs()

    return CommandResults(
        raw_response=events,
        readable_output=tableToMarkdown(
            'Event Logs',
            events,
        )
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()

    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(urljoin(params['url'], 'api/v1/tenants/'), demisto.params()['tenant_code'])
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

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
            return_results(test_module(client))

        elif command in ('sta-get-events', 'fetch-events'):

            if command == 'sta-get-events':
                events, results = get_events_command(client, demisto.args())
                return_results(results)

            else:  # command == 'fetch-events':
                last_run = demisto.getLastRun()
                events, last_run = fetch_events_command(client, last_run)
                demisto.setLastRun(last_run)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    params.get('vendor', 'safenet'),
                    params.get('product', 'safenet')
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
