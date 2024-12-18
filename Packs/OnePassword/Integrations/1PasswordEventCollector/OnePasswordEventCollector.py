import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
EVENT_TYPE_FEATURE = {
    'item usage actions': 'itemusages',
    'audit events': 'auditevents',
    'sign in attempts': 'signinattempts',
    'sign-in attempts': 'signinattempts',
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the 1Password Events API"""

    def introspect(self) -> dict:
        """Performs an introspect API call to check authentication status and the features (scopes) that the token can access,
        including one or more of: 'auditevents', 'itemusage', and 'signinattempts'.

        Returns:
            dict: The response JSON.

        Raises:
            DemistoException: If API call responds with an HTTP error status code.
        """
        return self._http_request(method='GET', url_suffix='/auth/introspect', raise_on_status=True)


''' HELPER FUNCTIONS '''


def get_unauthorized_event_types(auth_introspection_response: dict[str, Any], event_types: list[str]) -> set[str]:
    """Checks if the bearer token has no access to any of the configured event types.

    Args:
        auth_introspection_response (dict): Response JSON from Client.introspect call.
        event_types (list): List of event types from the integration configuration params.

    Returns:
        set[str]: Set of unauthorized event types that the token does not have access to.
    """
    authorized_features = set(auth_introspection_response['features'])
    unauthorized_event_types = set()
    for event_type in event_types:
        feature = EVENT_TYPE_FEATURE.get(event_type.lower())
        if feature in authorized_features:
            continue
        unauthorized_event_types.add(event_type)

    return unauthorized_event_types

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)


''' COMMAND FUNCTIONS '''


def test_module(client: Client, event_types: list[str]) -> str:
    """Tests connectivity and authentication with 1Password Events API and verifies that the token has access to the
    configured event types.

    Args:
        client (Client): 1Password Events API client.
        event_types (list): List of event types from the integration configuration params.

    Returns:
        str: 'ok' if test passed, anything else will fail the test.

    Raises:
        DemistoException: If API call responds with an unhandled HTTP error status code or token does not have access to the
        configured event types.
    """
    try:
        response = client.introspect()

        unauthorized_event_types = get_unauthorized_event_types(response, event_types)
        if unauthorized_event_types:
            return f'The API token does not have access to the event types: {", ".join(unauthorized_event_types)}'

        return 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    # args = demisto.args()

    # required
    base_url = urljoin(params['url'], '/api/v2')
    token = params['credentials']['password']
    event_types = argToList(params['event_types'])

    # optional
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command!r}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
            proxy=proxy
        )

        if command == 'test-module':
            result = test_module(client, event_types)
            return_results(result)

        if command == '1password-get-events':
            return_results(CommandResults(readable_output='Testing'))

        else:
            raise NotImplementedError(f'Unknown command {command!r}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command!r} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
