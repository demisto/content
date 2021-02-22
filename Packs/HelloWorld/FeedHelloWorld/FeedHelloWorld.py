from typing import Any, Callable, Dict, List, Tuple, Optional

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'FeedHelloWorld'


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


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """

    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]
    for item in iterator:
        value = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value,
            'type': type_,
        }
        for key, val in item.items():
            raw_data.update({key: val})
        indicator_obj = {
            'value': value,
            'type': type_,
            'service': 'FeedHelloWorld',
            'fields': {},
            'rawJSON': raw_data
        }

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
    indicators = fetch_indicators(client, limit)
    human_readable = tableToMarkdown('Indicators from Talos Feed:', indicators,
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
    indicators = fetch_indicators(client)
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    base_url = params.get('url')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        commands: Dict[
            str, Callable[[Client, Dict[str, str], Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]
        ] = {
            'test-module': test_module,
            'FeedHelloWorld-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.params(), demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, demisto.params())
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception:
        err_msg = (f'Error in {INTEGRATION_NAME} Integration.\n\n'
                   'Verify that the server URL parameter is correct and that you'
                   ' have access to the server from your host.\n')
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
