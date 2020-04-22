import demistomock as demisto
from CommonServerPython import *
from typing import Dict, List, Tuple, Any, Callable

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

    def __init__(self, base_url: str, verify: bool = False, proxy: bool = False):
        """
        Implements class for Microsoft Intune feeds.
        :param url: the Intune endpoint URL
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

        def subs(text):
            patterns = (('comp', 'com p'), ('comm', 'com m'), ('comf', 'com f'), ('\*\.', ''), ('\n', ''))
            for e in patterns:
                text = re.sub(e[0], e[1], text)
            return text

        try:
            scraped_domains = sum([subs(cell.text).rstrip().split() for cell in soup.select(
                "tbody tr td") if re.findall(r'microsoft\.(com|net)', cell.text)], [])
            for domain in scraped_domains:
                result.append({
                    "value": domain,
                    'type': FeedIndicatorType.DomainGlob if '*' in domain else FeedIndicatorType.Domain,
                    "FeedURL": self._base_url
                })

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


def fetch_indicators(client: Client, limit: int = -1) -> List[Dict]:
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
        value = item.get('value')
        type_ = item.get('type', FeedIndicatorType.Domain)
        raw_data = {
            'value': value,
            'type': type_,
        }
        for key, val in item.items():
            raw_data.update({key: val})
        indicators.append({
            "value": value,
            "type": type_,
            "rawJSON": raw_data,
        })
    return indicators


def get_indicators_command(client: Client, args: Dict[str, str]) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators = fetch_indicators(client, limit)
    human_readable = tableToMarkdown('Indicators from Microsoft Intune Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators_command(client: Client) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

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
    insecure = params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'intune-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
