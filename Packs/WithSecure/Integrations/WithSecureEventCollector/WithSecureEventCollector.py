"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MAX_FETCH_LIMIT = 1000
VENDOR = 'WithSecure'
PRODUCT = 'Endpoint Protection'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    def __init__(self, base_url, verify, proxy, client_id, client_secret):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self) -> tuple[str, int]:
        """Get the access token from the WithSecure API.

        Returns:
            tuple[str,int]: The token and its expiration time in seconds received from the API.
        """

        response = self._http_request(
            method="POST",
            url_suffix='as/token.oauth2',
            auth=(self.client_id, self.client_secret),
            data={"grant_type": "client_credentials"},
            error_handler=access_token_error_handler
        )

        return response.get("access_token"), response.get("expires_in")

    def get_access_token(self):
        """Return the token stored in integration context or returned from the API call.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Returns:
            str: Authentication token.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate()
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,
        }
        set_integration_context(integration_context)

        return token

    def get_events_api_call(self, fetch_from, limit, next_anchor=None):
        params = {
            "serverTimestampStart": fetch_from,
            "limit": limit
        }
        if next_anchor:
            params['anchor'] = next_anchor
        return self._http_request(
            method="GET",
            url_suffix='security-events/v1/security-events',
            headers={"Authorization": f"Bearer {self.get_access_token()}"},
            params=params
        )


''' HELPER FUNCTIONS '''


def access_token_error_handler(response: requests.Response):
    """
    Error Handler for WithSecure access_token
    Args:
        response (response): WithSecure Token url response
    Raise:
         DemistoException
    """
    if response.status_code == 401:
        raise DemistoException('Authorization Error: The provided credentials for WithSecure are '
                               'invalid. Please provide a valid Client ID and Client Secret.')
    elif response.status_code >= 400:
        raise DemistoException('Error: something went wrong, please try again.')


def parse_date(dt):
    date_time = dateparser.parse(dt, settings={'TIMEZONE': 'UTC'})
    return date_time.strftime(DATE_FORMAT)


def parse_events(events, last_fetch):
    last_fetch_timestamp = date_to_timestamp(last_fetch, DATE_FORMAT)
    last_event_time = None
    for event in events:
        event['_time'] = parse_date(event.get('clientTimestamp'))
        event_time = date_to_timestamp(parse_date(event.get('serverTimestamp')), DATE_FORMAT)
        if last_fetch_timestamp < event_time:
            last_fetch_timestamp = event_time
            last_event_time = event.get('serverTimestamp')

    return parse_date(last_event_time), events


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

    client.get_access_token()
    return 'ok'


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    fetch_from = parse_date(args.get('fetch_from') or demisto.params().get('first_fetch', '3 months'))
    limit = args.get('limit') or MAX_FETCH_LIMIT
    events = []
    next_anchor = 'first'
    while next_anchor and len(events) < limit:
        req_limit = min(MAX_FETCH_LIMIT, limit - len(events))
        res = client.get_events_api_call(fetch_from, req_limit, next_anchor if next_anchor != 'first' else None)
        events.extend(res.get('items'))
        next_anchor = res.get('nextAnchor')

    events = events if len(events) < limit else events[:limit]
    hr = tableToMarkdown(name='With Secure Events', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events_command(client, first_fetch, limit):
    last_run = demisto.getLastRun()
    fetch_from = last_run.get('fetch_from') or first_fetch
    events = []
    next_anchor = 'first'

    while next_anchor and len(events) < limit:
        req_limit = min(MAX_FETCH_LIMIT, limit - len(events))
        res = client.get_events_api_call(fetch_from, req_limit, next_anchor if next_anchor != 'first' else None)
        events.extend(res.get('items'))
        next_anchor = res.get('nextAnchor')

    last_fetch, parsed_events = parse_events(events if len(events) < limit else events[:limit], fetch_from)
    demisto.setLastRun({'fetch_from': last_fetch})
    return parsed_events


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    first_fetch = parse_date(params.get('first_fetch', '3 months'))
    limit = params.get('limit', 1000)

    verify_ssl = not params.get('insecure', False)

    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_ssl,
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy)

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif command == 'with-secure-get-events':
            events, result = get_events_command(client, args)
            return_results(result)

        elif command == 'fetch-events':
            events = fetch_events_command(client, first_fetch, limit)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
