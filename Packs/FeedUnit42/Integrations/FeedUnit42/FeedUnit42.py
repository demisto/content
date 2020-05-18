from typing import List, Dict, Tuple, Any, Callable

import requests

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

UNIT42_TYPES_TO_DEMISTO_TYPES = {
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'domain': FeedIndicatorType.Domain,
    'domain-name': FeedIndicatorType.Domain,
    'url': FeedIndicatorType.URL,
    'md5': FeedIndicatorType.File,
    'sha-1': FeedIndicatorType.File,
    'sha-256': FeedIndicatorType.File,
    'file:hashes': FeedIndicatorType.File,
}


class Client(BaseClient):

    def __init__(self, url, collection, api_key, verify):
        """
        Implements class for Unit 42 feed.
        :param url: unit42 url.
        :param collection: unit42 collection.
        :param api_key: unit42 API Key.
        :param verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        """
        super().__init__(base_url=f'{url}playbooks/collections/{collection}/objects/', verify=verify,
                         proxy=handle_proxy(), headers={'Authorization': f'Token {api_key}'})

    def get_indicators(self) -> dict:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        return self._http_request('GET', url_suffix='', full_url=self._base_url, ok_codes=(200, 201, 206))


def parse_response(response: dict) -> list:
    """Parse the objects retrieved from the feed.

    Returns:
        A list of indicators, containing the indicators.
    """
    objects = response.get('objects', [])
    indicators_objects = [item for item in objects if item.get('type') == 'indicator']  # retrieve only indicators

    indicators = []
    if indicators_objects:
        for indicator_object in indicators_objects:
            pattern = indicator_object.get('pattern')
            for key in UNIT42_TYPES_TO_DEMISTO_TYPES.keys():
                if key in pattern:  # retrieve only Demisto indicator types
                    indicators.append({
                        "value": indicator_object.get('name'),
                        "type": UNIT42_TYPES_TO_DEMISTO_TYPES[key],
                        "rawJSON": indicator_object,
                    })

    return indicators


def test_module(client: Client) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    response = client.get_indicators()
    _ = parse_response(response)
    return 'ok', {}, {}


def fetch_indicators(client: Client) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    response = client.get_indicators()
    indicators = parse_response(response)
    return indicators


def get_indicators_command(client: Client, args: Dict[str, str]) -> Tuple[Any, Dict[Any, Any], Dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Demisto Outputs.
    """
    limit = int(args.get('limit', '10'))
    response = client.get_indicators()
    indicators = parse_response(response)
    limited_indicators = indicators[:limit]

    human_readable = tableToMarkdown('Unit42 Indicators:', t=limited_indicators, headers=['type', 'value'])
    entry_context = {'Unit42(val.value && val.value == obj.value)': limited_indicators}

    return human_readable, entry_context, response


def main():
    """
    PARSE AND VALIDATE FEED PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    url = 'https://stix2.unit42.org/'
    collection = '5ac266d8-de48-3d6b-83f1-c4e4047d6e44'
    api_key = str(params.get('api_key', ''))
    verify = not params.get('insecure', False)

    command = demisto.command()
    demisto.info(f'Command being called in Unit42 feed is: {command}')

    try:
        client = Client(url, collection, api_key, verify)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[Any, Dict[Any, Any], Dict[Any, Any]]]] = {
            'unit42-get-indicators': get_indicators_command,
        }

        if demisto.command() == 'test-module':
            md_, ec_, raw = test_module(client)
            return_outputs(md_, ec_, raw)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            md_, ec_, raw = commands[command](client, args)
            return_outputs(md_, ec_, raw)

    except Exception as err:
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
