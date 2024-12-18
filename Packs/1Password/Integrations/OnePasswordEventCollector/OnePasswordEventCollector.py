import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from http import HTTPStatus

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

        Raises:
            DemistoException: If API responds with an HTTP error status code.

        Returns:
            dict: The response JSON from the 'Auth introspect' endpoint.
        """
        return self._http_request(method='GET', url_suffix='/auth/introspect', raise_on_status=True)

    def get_events(
        self,
        event_type: str,
        limit: int | None = None,
        start_time: str | None = None,
        pagination_cursor: str | None = None,
    ):
        """Gets events from 1Password based on the specified event type

        Args:
            event_type (str): Type of 1Password event.
            limit (int): The maximum number of records in response; must be ≤ 1000 otherwise API raises HTTP 400 [Bad Request].
            start_time (str | None): ISO8601 format timestamp (e.g. 2023-03-15T16:32:50-03:00).
            pagination_cursor (str | None): Pagination Cursor from previous API response.

        Raises:
            ValueError: If unknown event type or missing cursor and start time.
            DemistoException: If API responds with an HTTP error status code.

        Returns:
            dict: The response JSON from the event endpoint.
        """
        feature = EVENT_TYPE_FEATURE.get(event_type.lower())
        if not feature:
            raise ValueError(f'Invalid or unsupported 1Password event type: {event_type}.')

        if not (pagination_cursor or start_time):
            raise ValueError("Either a 'pagination_cursor' or a 'start_time' need to be specified.")

        if pagination_cursor:
            body = {'cursor': pagination_cursor}
        else:
            body = assign_params(limit=limit, start_time=start_time)

        return self._http_request(method='POST', url_suffix=f'/{feature}', data=body, raise_on_status=True)


''' HELPER FUNCTIONS '''


def get_unauthorized_event_types(auth_introspection_response: dict[str, Any], event_types: list[str]) -> list[str]:
    """Checks if the bearer token has no access to any of the configured event types.

    Args:
        auth_introspection_response (dict): Response JSON from Client.introspect call.
        event_types (list): List of event types from the integration configuration params.

    Returns:
        list[str]: List of unauthorized event types that the token does not have access to.
    """
    authorized_features = auth_introspection_response['features']
    return [
        event_type for event_type in event_types
        if EVENT_TYPE_FEATURE.get(event_type.lower()) not in authorized_features
    ]


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, event_types: list[str]) -> str:
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

        if unauthorized_event_types := get_unauthorized_event_types(response, event_types):
            return f'The API token does not have access to the event types: {", ".join(unauthorized_event_types)}'

        return 'ok'

    except DemistoException as e:
        error_status_code = e.res.status_code if isinstance(e.res, requests.Response) else None

        if error_status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
            return 'Authorization Error: Make sure the API server URL and token are correctly set'

        if error_status_code == HTTPStatus.NOT_FOUND:
            return 'Endpoint Not Found: Make sure the API server URL is correctly set'

        # Some other unknown / unexpected error
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
            result = test_module_command(client, event_types)
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
