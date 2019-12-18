from CommonServerPython import *

''' IMPORTS '''
from typing import List, Dict, Union
import jmespath
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'JsonFeed'


class Client:
    def __init__(self, url: str, credentials: Dict[str, str] = None, extractor: str = '@', indicator: str = 'indicator',
                 source_name: str = 'json', fields: Union[List, str] = None, insecure: bool = True, cert_file: str = None,
                 key_file: str = None, headers: str = None):
        """
        Implements class for miners of JSON feeds over http/https.

        :param url: URL of the feed.
        :param credentials:
            username: username for BasicAuth authentication
            password: password for BasicAuth authentication
        :param extractor: JMESPath expression for extracting the indicators from
        :param indicator: the JSON attribute to use as indicator. Default: indicator
        :param source_name: feed source name
        :param fields: list of JSON attributes to include in the indicator value.
        If None no additional attributes will be extracted.
        :param insecure: if *true* feed HTTPS server certificate will be verified

        Hidden parameters:
        :param: cert_file: client certificate
        :param: key_file: private key of the client certificate
        :param: headers: Header parameters are optional to specify a user-agent or an api-token
        Example: headers = {'user-agent': 'my-app/0.0.1'} or Authorization: Bearer
        (curl -H "Authorization: Bearer " "https://api-url.com/api/v1/iocs?first_seen_since=2016-1-1")

         Example:
            Example config in YAML::
                url: https://ip-ranges.amazonaws.com/ip-ranges.json
                extractor: "prefixes[?service=='AMAZON']"
                prefix: aws
                indicator: ip_prefix
                headers: {'Authorization': '12345668900', 'user-agent': 'my-app/0.0.1'}
                fields:
                    - region
                    - service
        """
        self.url = url
        self.verify = insecure
        self.auth = (credentials.get('username'), credentials.get('password'))
        self.extractor = extractor
        self.indicator = indicator
        self.source_name = source_name
        self.fields = argToList(fields)

        # Hidden
        self.headers = headers
        self.cert = (cert_file, key_file)

    def build_iterator(self) -> List:
        r = requests.get(**vars(self))

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


def fetch_indicators_command(client: Client, indicator_type: str) -> List[Dict]:
    iterator = client.build_iterator()

    indicators = []
    for item in iterator:
        indicator_value = item.get(client.indicator)

        fields = client.fields
        if not fields:
            fields = item.keys()
            fields.remove(client.indicator)

        attributes = {'source_name': client.source_name}
        for field in fields:
            if field in item:
                attributes[field] = item[field]

        indicator = {'value': indicator_value, 'type': indicator_type}

        attributes.update(indicator)
        indicator['rawJSON'] = attributes

        indicators.append(indicator)
    return indicators


def main():
    # handle parameters (remove None values)
    params = {param: value for param, value in demisto.params().items() if value is not None}

    # handle proxy settings
    handle_proxy()

    client = Client(**params)

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            readable_output, outputs, raw_response = test_module(client)
            return_outputs(readable_output, outputs, raw_response)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params.get('indicator_type'))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
