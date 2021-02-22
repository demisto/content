from typing import Any, Callable, Dict, List, Tuple, Optional

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this FeedHelloWorld implementation, no special attributes defined
    """

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        res = self._http_request('GET',
                                 url_suffix='',
                                 full_url=self._base_url,
                                 resp_type='text',
                                 )

        result = []

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split('\n')

            for indicator in indicators:
                if auto_detect_indicator_type(indicator):
                    result.append({
                        'value': indicator,
                        'type': auto_detect_indicator_type(indicator),
                        'FeedURL': self._base_url
                    })

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')
        return result


def test_module(client: Client) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    # INTEGRATION FEED DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error

    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value,
            'type': type_,
        }

        # create indicator object for each value
        for key, val in item.items():
            raw_data.update({key: val})
        indicator_obj = {
            'value': value,
            'type': type_,
            'service': 'FeedHelloWorld',
            'fields': {},
            'rawJSON': raw_data
        }

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    indicators = fetch_indicators(client, tlp_color, limit)
    human_readable = tableToMarkdown('Indicators from FeedHelloWorld:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    tlp_color = params.get('tlp_color')
    indicators = fetch_indicators(client, tlp_color)
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # get the service API url
    base_url = params.get('url')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_outputs(*test_module(client))

        elif command == 'FeedHelloWorld-get-indicators':
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_outputs(*get_indicators_command(client, params, args))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified Feed Fetch Interval
            indicators = fetch_indicators_command(client, demisto.params())
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
