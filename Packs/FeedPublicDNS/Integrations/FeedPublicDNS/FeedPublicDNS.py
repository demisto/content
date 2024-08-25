import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

from typing import Any
from netaddr import IPAddress
import urllib3


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_NAME = 'Public DNS Feed'


class Client:
    def __init__(self, feed_url: str, tags: Optional[list] = None,
                 tlp_color: Optional[str] = None, insecure: bool = False):
        self._feed_url: str = feed_url
        self._verify: bool = insecure
        self._proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        self.Tags = [] if tags is None else tags
        self.Tlp_color = tlp_color

    def build_iterator(self) -> list:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        feed_url = self._feed_url
        try:
            response = requests.get(
                url=feed_url,
                verify=self._verify,
                proxies=self._proxies,
            )
            response.raise_for_status()
            data = response.text
            indicators = data.split('\n')
        except requests.exceptions.SSLError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                            f'Check your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                            f'Check your Server URL parameter.\n\n{err}')
        except requests.exceptions.HTTPError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n')

        return indicators


def test_module(client: Client) -> tuple[str, dict[Any, Any], dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, limit: int = -1, enrichment_excluded: bool = False) -> list[dict]:
    """Retrieves indicators from the feed
    Args:
        client: Client object with request
        limit: limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()

    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        type_ = FeedIndicatorType.IP

        ip = IPAddress(item)
        if ip.version == 6:
            type_ = FeedIndicatorType.IPv6

        indicator_obj = {
            'value': item,
            'type': type_,
            'rawJSON': {'value': item, 'type': type_},
            'fields': {'tags': client.Tags},
        }

        if enrichment_excluded:
            indicator_obj['enrichmentExcluded'] = enrichment_excluded

        if client.Tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = client.Tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client) -> tuple[str, dict[Any, Any], dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
    Returns:
        Outputs.
    """

    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    enrichment_excluded = demisto.params().get('enrichmentExcluded', False)
    indicators = fetch_indicators(client, limit, enrichment_excluded=enrichment_excluded)
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME}:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {'Indicator': indicators}, {'raw_response': indicators}


def fetch_indicators_command(client: Client, enrichment_excluded: bool = False) -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
    Returns:
        Indicators.
    """
    indicators = fetch_indicators(client, enrichment_excluded=enrichment_excluded)
    return indicators


def main():  # pragma: no cover
    params = demisto.params()
    url = params.get('url', 'https://public-dns.info/nameservers-all.txt')
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    use_ssl = not params.get('insecure', False)
    enrichment_excluded = params.get('enrichmentExcluded', False)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url, tags, tlp_color, use_ssl)
        commands: dict = {
            'test-module': test_module,
            'public-dns-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, enrichment_excluded=enrichment_excluded)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
