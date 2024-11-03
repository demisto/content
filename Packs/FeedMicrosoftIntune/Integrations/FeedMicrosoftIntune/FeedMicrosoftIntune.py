import demistomock as demisto
from CommonServerPython import *
from typing import Any
from collections.abc import Callable

import urllib3
import re
from bs4 import BeautifulSoup

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'Microsoft Intune Feed'


class Client(BaseClient):
    """
    Client to use in the Microsoft Intune Feed integration. Overrides BaseClient.
    """

    def __init__(self, base_url: str, verify: bool = False, proxy: bool = False, tlp_color: str | None = None):
        """
        Implements class for Microsoft Intune feeds.
        :param url: the Intune endpoint URL
        :verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param proxy: boolean, if *false* feed HTTPS server certificate will not use proxies. Default: *false*
        :param tlp_color: Traffic Light Protocol color.
        """
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.tlp_color = tlp_color

    def build_iterator(self) -> list:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []  # type: list
        domains = []  # type: list
        ipv4s = []  # type: list
        ipv4cidrs = []  # type: list
        r = self._http_request('GET', url_suffix='', full_url=self._base_url, resp_type='text')

        soup = BeautifulSoup(r, 'html.parser')

        table_rows = soup.select("tbody tr")
        for row in table_rows:
            found_domains = [string.strip() for string in row.strings if re.search(
                r'(microsoft\.(com|net))|'
                r'microsoftonline\.com|'
                r'officeconfig\.msocdn\.com|'
                r'config\.office\.com|'
                r'graph\.windows\.net',
                string)]
            if found_domains:
                domains += found_domains
                for string in row.strings:
                    string = string.strip()
                    if re.match(ipv4cidrRegex, string):
                        ipv4cidrs.append(string)
                    elif re.match(ipv4Regex, string):
                        ipv4s.append(string)

        for domain in domains:
            result.append({
                "value": domain,
                'type': FeedIndicatorType.DomainGlob if '*' in domain else FeedIndicatorType.Domain,
                "FeedURL": self._base_url
            })
        for ipv4 in ipv4s:
            result.append({
                "value": ipv4,
                'type': FeedIndicatorType.IP,
                "FeedURL": self._base_url
            })
        for cidr in ipv4cidrs:
            result.append({
                "value": cidr,
                'type': FeedIndicatorType.CIDR,
                "FeedURL": self._base_url
            })

        return result


def test_module(client: Client, *_) -> tuple[str, dict[Any, Any], dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, feed_tags: list = [], limit: int = -1) -> list[dict]:
    """Retrieves indicators from the feed

    Args:
        client (Client): Client object with request
        feed_tags (list): tags to assign fetched indicators
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
            "value": value,
            "type": type_,
            "rawJSON": raw_data,
            'fields': {}
        }
        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags
        if client.tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = client.tlp_color

        indicators.append(indicator_obj)
    return indicators


def get_indicators_command(client: Client,
                           params: dict[str, str],
                           args: dict[str, str]
                           ) -> tuple[str, dict[Any, Any], dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()

    Returns:
        Outputs.
    """
    feed_tags = argToList(params.get('feedTags', ''))
    limit = int(args.get('limit', '10'))
    indicators = fetch_indicators(client, feed_tags, limit)
    human_readable = tableToMarkdown('Indicators from Microsoft Intune Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators_command(client: Client, params: dict[str, str]) -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request
        params: demisto.params()

    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, feed_tags)
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    base_url = params.get('url')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    tlp_color = params.get('tlp_color')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
            tlp_color=tlp_color
        )

        commands: dict[
            str, Callable[[Client, dict[str, str], dict[str, str]], tuple[str, dict[Any, Any], dict[Any, Any]]]
        ] = {
            'test-module': test_module,
            'intune-get-indicators': get_indicators_command
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
