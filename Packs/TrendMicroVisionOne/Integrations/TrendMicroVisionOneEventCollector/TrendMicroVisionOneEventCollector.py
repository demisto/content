import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_MAX_LIMIT = 1000
''' CLIENT CLASS '''


class Client(BaseClient):

    API_VERSION = 'v3.0'
    def __init__(self, base_url: str, api_key: str, proxy: bool, verify: bool):
        self.base_url = base_url
        self.api_key = api_key

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def http_request(
        self,
        url_suffix: str | None = None,
        method: str = 'GET',
        params: Dict | None = None,
        headers: Dict | None = None,
        next_link: str | None = None
    ) -> Any:
        """
        Implements a generic http request to Trend Micro Vision One api.

        Args:
            url_suffix (str): The URL suffix for the api endpoint.
            method (str): the method of the api endpoint.
            params (dict): query parameters for the api request.
            headers (dict): any custom headers for the api request.
            next_link (str): the next link for the api request (used mainly for pagination)
        """
        request_headers = headers or {
            "Authorization": f"Bearer {self.api_key}"
        }

        url = next_link or f"{self.base_url}{url_suffix}"
        demisto.debug(f'Sending the http request with {url=}, {params=}')

        return self._http_request(
                method=method,
                full_url=url,
                params=params,
                headers=request_headers,
            )

    def get_events(
        self,
        url_suffix: str,
        method: str = 'GET',
        params: Dict | None = None,
        headers: Dict | None = None,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[Dict]:
        """
        Implements a generic method with pagination to retrieve logs from trend micro vision one.

        Args:
            url_suffix (str): the URL suffix for the api endpoint.
            method (str): the method of the api endpoint.
            params (dict): query parameters for the api request.
            headers (dict): any custom headers for the api request.
            limit (str): the maximum number of events to retrieve.

        Returns:
            List[Dict]: a list of the requested logs.
        """
        events = []

        response = self.http_request(url_suffix=url_suffix, method=method, params=params, headers=headers)
        current_items = response.get('items') or []
        demisto.debug(f'Received {current_items=} with {url_suffix=}')
        events.extend(current_items)

        while (next_link := response.get('nextLink')) and len(events) < limit:
            response = self.http_request(method=method, params=params, headers=headers, next_link=next_link)
            current_items = response.get('items') or []
            demisto.debug(f'Received {current_items=} with {next_link=}')
            events.extend(current_items)

        return events[:limit]

    def get_workbench_logs(
        self,
        start_datetime: str,
        end_datetime: str | None = None,
        order_by: str | None = None,
        limit: int = DEFAULT_MAX_LIMIT
    ):
        """
        Implements a generic method with pagination to retrieve logs from trend micro vision one.

        Args:
            start_datetime (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start
                                  of the data retrieval time range.
            end_datetime (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end
                                of the data retrieval time range.
            order_by (str): Parameter to be used for sorting records. Records are returned in descending
                            order by default.
            limit (str): the maximum number of workbench events to retrieve.

        Returns:
            List[Dict]: The workbench events that were found.
        """
        # will retrieve all the events that are more or equal to start_datetime, does not support miliseconds
        params = {'startDateTime': start_datetime}

        if end_datetime:
            params['endDateTime'] = end_datetime
        if order_by:
            params['orderBy'] = order_by

        return self.get_events(
            url_suffix=f'/{self.API_VERSION}/workbench/alerts',
            params=params,
            limit=limit
        )


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
