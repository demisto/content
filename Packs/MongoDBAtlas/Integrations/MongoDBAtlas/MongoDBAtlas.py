import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''

class Client(BaseClient):
    """
    Client class to interact with the service API
    """
    
    def search_events():
        pass

    

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
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

def get_events(client: Client, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get('limit', 50)
    from_date = args.get('from_date')
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)

def fetch_events(client: Client, last_run: dict[str, int],
                 first_fetch_time, alert_status: str | None, max_events_per_fetch: int
                 ) -> tuple[Dict, List[Dict]]:
    pass

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    
    base_url = urljoin(demisto.params()['url'], '/api/v1')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
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
