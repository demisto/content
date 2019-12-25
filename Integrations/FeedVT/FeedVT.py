from CommonServerPython import *

''' IMPORTS '''
from typing import List, Dict, Union
import jmespath
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'VirusTotalFeed'
_VT_NOTIFICATIONS = 'https://www.virustotal.com/intelligence/hunting/notifications-feed/'


class Client:
    def __init__(self, api_key: str, url: str = '', fields: Union[List, str] = None, insecure: bool = False,
                 indicator_type: str = None, **_):
        """
        Implements class for miners of VirusTotal notifications JSON feed.

        :param url: URL of the VirusTotal notification feed.
        :param api_key: VirusTotal authentication API key
        :param fields: list of attributes to include in the indicator value. If *None* all attributes will be extracted.
        :param insecure: if *False* feed HTTPS server certificate will be verified
        :param indicator_type: the indicator type to extract
        """
        self.indicator_type = indicator_type
        self.extractor = 'notifications'
        self.fields = argToList(fields)

        # Request related attributes
        self.url = url or _VT_NOTIFICATIONS
        self.verify = not insecure
        self.api_key = api_key

        # Hidden params
        self.source_name = 'VirusTotal'

    def build_iterator(self) -> List:
        r = requests.get(
            url=self.url,
            verify=self.verify,
            params={'apikey': self.api_key}
        )

        try:
            r.raise_for_status()
            data = r.json()
            result = jmespath.search(expression=self.extractor, data=data)
            return result

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')


def batch(sequence, batch_size=1):
    sequence_length = len(sequence)
    for i in range(0, sequence_length, batch_size):
        yield sequence[i:min(i + batch_size, sequence_length)]


def test_module(client) -> str:
    client.build_iterator()
    return 'ok'


def fetch_indicators_command(client: Client, update_context: bool = False, limit: int = None) -> Union[Dict, List]:
    """
    Fetches the indicators from VirusTotal notifications client.

    :param client: Client with VirusTotal notifications JSON Feed
    :param update_context: if *True* will also update the context with the indicators
    :param limit: limits the number of context indicators to output
    """
    indicators = []
    for item in client.build_iterator():
        # find the right indicator type
        for indicator_type in ['md5', 'sha256', 'sha1']:
            if indicator_type in item:
                indicator_value = item.get(indicator_type)
                indicator = {'value': indicator_value, 'type': client.indicator_type or indicator_type}

                attributes = {'source_name': client.source_name}
                attributes.update({f: item.get(f) for f in client.fields or item.keys() if f is not indicator_type})
                attributes.update(indicator)
                indicator['rawJSON'] = attributes

                indicators.append(indicator)
                break

    if update_context:
        context_output = {
            f"{INTEGRATION_NAME}.Indicator": jmespath.search(expression='[].rawJSON', data=indicators)[:limit or 50]
        }
        return context_output

    return indicators


def main():
    # handle proxy settings
    handle_proxy()

    client = Client(**demisto.params())
    indicator_type = demisto.params().get('indicator_type')
    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            return_outputs(test_module(client))

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, indicator_type)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif demisto.command() == 'get-indicators':
            # dummy command for testing
            limit = demisto.args().get('limit', 50)
            indicators = fetch_indicators_command(client, update_context=True, limit=limit)
            return_outputs('', indicators)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
