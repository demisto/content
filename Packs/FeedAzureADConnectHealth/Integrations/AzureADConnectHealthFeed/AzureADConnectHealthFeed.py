import demistomock as demisto
from CommonServerPython import *

from typing import Any, Callable, Dict, List, Tuple, Optional

import urllib3
from bs4 import BeautifulSoup
import re

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'Microsoft Azure AD Connect Health Feed'
PATTERN = re.compile(r"(https?:/{2}|\*\*\.|\*\.)([\w-]+\.)+\w{2,3}")   # guardrails-disable-line


class Client(BaseClient):
    """
    Client to use in the Microsoft Azure Feed integration. Overrides BaseClient.
    """

    def __init__(self, base_url: str, verify: bool = False, proxy: bool = False):
        """
        Implements class for Microsoft Azure feeds.
        :param url: the Azure endpoint URL
        :verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        """
        super().__init__(base_url, verify=verify, proxy=proxy)

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        r = self._http_request('GET', url_suffix='', full_url=self._base_url, resp_type='text')

        soup = BeautifulSoup(r, 'html.parser')

        global PATTERN
        scraped_indicators = list(set([PATTERN.match(cell.text).group(0) for cell in soup.select(  # type: ignore # noqa
            "tbody tr td code") if PATTERN.match(cell.text)]))
        for indicator in scraped_indicators:
            result.append({
                'value': indicator,
                'type': FeedIndicatorType.DomainGlob if '*' in indicator else FeedIndicatorType.URL,
                'FeedURL': self._base_url
            })

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


def fetch_indicators(client: Client, feed_tags: List = [], tlp_color: Optional[str] = '', limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        feed_tags (list): tags to assign fetched indicators
        tlp_color (str): Traffic Light Protocol color
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
        type_ = item.get('type', FeedIndicatorType.Domain)
        raw_data = {
            'value': value,
            'type': type_,
        }
        for key, val in item.items():
            raw_data.update({key: val})
        indicator_obj = {
            'value': value,
            'type': type_,
            'service': 'Azure AD Connect Health Feed',
            'rawJSON': raw_data,
            'fields': {}
        }
        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags
        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = feed_tags

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
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = demisto.params().get('tlp_color')
    limit = int(args.get('limit', '10'))
    indicators = fetch_indicators(client, feed_tags, tlp_color, limit)
    human_readable = tableToMarkdown('Indicators from Microsoft Azure Feed:', indicators,
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
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = demisto.params().get('tlp_color')
    indicators = fetch_indicators(client, feed_tags, tlp_color)
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
    demisto.info(f'Command being called in {INTEGRATION_NAME} is {command}')

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
            'azure-ad-health-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.params(), demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, demisto.params())
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
