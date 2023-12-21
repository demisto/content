register_module_line('FortiGuard', 'start', __line__())
### pack version: 1.0.0

import requests
import ast
import gzip
import io
import json
from typing import Optional, Pattern, Dict, Any, Tuple, Union, List, Callable

''' CONSTANTS '''
API_KEY = demisto.params().get('credentials', {}).get('password')
''' CLIENT CLASS '''


class Client(BaseClient):

    def fetch_iocs_inbody(self):

        handle_proxy()

        url = "https://premiumapi.fortinet.com/v1/cti/feed/csv?cc=all"

        headers = {
        'Accept': 'application/json',
        'Token': API_KEY,
        }

        response = requests.request("GET", url, headers=headers)

        return response



    def fetch_iocs_compressed(self, feed_url):

        handle_proxy()

        feed_data = requests.get(feed_url)

        return feed_data


    def get_url_rating(self, urltorate):

        handle_proxy()

        url = "https://premiumapi.fortinet.com/v1/rate?url="+urltorate

        headers = {
        'Accept': 'application/json',
        'Token': API_KEY,
        }
        response = requests.request("GET", url, headers=headers)

        return response

''' HELPER FUNCTIONS '''

def __decompress_zip_file(feed_data):

    compressed_file = io.BytesIO(feed_data.content)

    feed_gzip = gzip.GzipFile(fileobj=compressed_file)

    feed_text = feed_gzip.read()

    feed_text = feed_text.decode('utf-8')  # convert from byte to str

    feed_gzip.close()

    return feed_text



''' COMMAND FUNCTIONS '''
def fetch_indicators_command(client: Client, params: dict[str, Any]):
    indicators = get_indicators_command(client, demisto.args()).split('\n')
    results = []
    feedtags = params.get('feedTags')
    for indicator in indicators:
        #demisto.debug(f'indicator log:' f' {indicator}\n')
        type_ = auto_detect_indicator_type(indicator)
        #demisto.debug(f'indicator type log:' f' {type_}\n')
        indicator_obj = {
            "value": indicator,
            "type": type_,
            "CustomFields": {"Source": "FortiGuard ThreatIntel"},
            "fields": {"tags": feedtags},
            "rawJSON": {"value": indicator, "type": type_},
        }
        results.append(indicator_obj)
    demisto.debug(f'indicators obj log:' f' {indicators}\n')
    return results

def get_url_rating_command(client: Client, args: Dict[str, Any]):

    url = args.get('url')

    url_data = client.get_url_rating(url).json()

    readable_output = tableToMarkdown('Url', url_data)

    command_results: List[CommandResults] = []

    command_results.append(CommandResults(
        readable_output=readable_output,
        outputs_prefix='FortiGuard.Url',
        outputs_key_field='url',
        outputs=url_data,
    ))
    return command_results


def get_indicators_command(client: Client, params: dict[str, Any]):
    response = client.fetch_iocs_inbody().text
    # Downloading feed data
    feed_url = ast.literal_eval(response)[0]['data']
    # Decompress feed data
    feed_data = client.fetch_iocs_compressed(feed_url=feed_url)
    return __decompress_zip_file(feed_data)

def test_module(client: Client, params: dict[str, Any]) -> str:
    try:
        result = json.loads(client.fetch_iocs_inbody().text)
        if "data" in result[0]:
            return 'ok'
        else:
            return str(result)

    except DemistoException as e:
        raise e

''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
    'test-module': test_module,
    'fortiguard-get-indicators': get_indicators_command,
    'url': get_url_rating_command,
    }

    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('integrationReliability') or DBotScoreReliability.C


    demisto.debug(f'Command being called is {command}')
    try:
        headers = {}

        client = Client(
            base_url = "",
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client, params)
            return_results(result)

        elif command == 'fortiguard-get-indicators':
            demisto.results(fileResult('FortiGuard Indicators',get_indicators_command(client, demisto.args())))

        elif command == 'url':
            # demisto.results(fileResult('FortiGuard Indicators',get_indicators_command(client, demisto.args())))
            return_results(get_url_rating_command(client, demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, demisto.args())
            for iter_ in batch(indicators, batch_size=2000):
                try:
                    demisto.createIndicators(iter_)
                except Exception:
                    # find problematic indicator
                    for indicator in iter_:
                        try:
                            demisto.createIndicators([indicator])
                        except Exception as err:
                            demisto.debug(f'createIndicators Error: failed to create the following indicator:'
                                            f' {indicator}\n {err}')
                    raise

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        return_error(err)

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('FortiGuard', 'end', __line__())