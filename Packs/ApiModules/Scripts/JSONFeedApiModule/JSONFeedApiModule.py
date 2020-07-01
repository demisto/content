from CommonServerPython import *

''' IMPORTS '''
import urllib3
import jmespath
from typing import List, Dict, Union, Optional

# disable insecure warnings
urllib3.disable_warnings()


class Client:
    def __init__(self, url: str = '', credentials: dict = None,
                 feed_name_to_config: Dict[str, dict] = None, source_name: str = 'JSON',
                 extractor: str = '', indicator: str = 'indicator',
                 insecure: bool = False, cert_file: str = None, key_file: str = None, headers: dict = None, **_):
        """
        Implements class for miners of JSON feeds over http/https.
        :param url: URL of the feed.
        :param credentials: username and password used for basic authentication.
         Can be also used as API key header and value by specifying _header in the username field.
        :param extractor: JMESPath expression for extracting the indicators from
        :param indicator: the JSON attribute to use as indicator. Default: indicator
        :param source_name: feed source name
        If None no additional attributes will be extracted.
        :param insecure: if *False* feed HTTPS server certificate will be verified
        Hidden parameters:
        :param: cert_file: client certificate
        :param: key_file: private key of the client certificate
        :param: headers: Header parameters are optional to specify a user-agent or an api-token
        Example: headers = {'user-agent': 'my-app/0.0.1'} or Authorization: Bearer
        (curl -H "Authorization: Bearer " "https://api-url.com/api/v1/iocs?first_seen_since=2016-1-1")
         Example:
            Example feed config:
            'AMAZON': {
                'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'extractor': "prefixes[?service=='AMAZON']",
                'indicator': 'ip_prefix',
            }
        """

        self.source_name = source_name or 'JSON'
        if feed_name_to_config:
            self.feed_name_to_config = feed_name_to_config
        else:
            self.feed_name_to_config = {
                self.source_name: {
                    'url': url,
                    'indicator': indicator or 'indicator',
                    'extractor': extractor or '@',
                }}

        # Request related attributes
        self.url = url
        self.verify = not insecure
        self.auth: Optional[tuple] = None
        self.headers = headers

        if credentials:
            username = credentials.get('identifier', '')
            if username.startswith('_header:'):
                header_name = username.split(':')[1]
                header_value = credentials.get('password', '')
                if not self.headers:
                    self.headers = {}
                self.headers[header_name] = header_value
            else:
                password = credentials.get('password', '')
                if username is not None and password is not None:
                    self.auth = (username, password)

        self.cert = (cert_file, key_file) if cert_file and key_file else None

    def build_iterator(self, **kwargs) -> List:
        results = []
        for feed_name, feed in self.feed_name_to_config.items():
            r = requests.get(
                url=feed.get('url', self.url),
                verify=self.verify,
                auth=self.auth,
                cert=self.cert,
                headers=self.headers,
                **kwargs
            )

            try:
                r.raise_for_status()
                data = r.json()
                result = jmespath.search(expression=feed.get('extractor'), data=data)
                results.append({feed_name: result})

            except ValueError as VE:
                raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')

        return results


def test_module(client, params) -> str:
    client.build_iterator()
    return 'ok'


def fetch_indicators_command(client: Client, indicator_type: str, feedTags: list, auto_detect: bool, **kwargs)\
        -> Union[Dict, List[Dict]]:
    """
    Fetches the indicators from client.
    :param client: Client of a JSON Feed
    :param indicator_type: the default indicator type
    :param feedTags: the indicator tags
    """
    indicators = []
    for result in client.build_iterator(**kwargs):
        for service_name, items in result.items():
            feed_config = client.feed_name_to_config.get(service_name, {})
            indicator_field = feed_config.get('indicator') if feed_config.get('indicator') else 'indicator'
            indicator_type = feed_config.get('indicator_type', indicator_type)
            for item in items:
                mapping = feed_config.get('mapping')

                if isinstance(item, str):
                    item = {indicator_field: item}
                indicator_value = item.get(indicator_field)

                current_indicator_type = determine_indicator_type(indicator_type, auto_detect, indicator_value)
                if not current_indicator_type:
                    continue

                indicator = {'value': indicator_value, 'type': current_indicator_type, 'fields': {'tags': feedTags}}

                attributes = {'source_name': service_name, 'value': indicator_value,
                              'type': current_indicator_type}

                attributes.update(extract_all_fields_from_indicator(item, indicator_field))

                if mapping:
                    for map_key in mapping:
                        if map_key in attributes:
                            indicator['fields'][mapping[map_key]] = attributes.get(map_key)  # type: ignore

                indicator['rawJSON'] = item

                indicators.append(indicator)

    return indicators


def determine_indicator_type(indicator_type, auto_detect, value):
    """
    Detect the indicator type of the given value.
    Args:
        indicator_type: (str) Given indicator type.
        auto_detect: (bool) True whether auto detection of the indicator type is wanted.
        value: (str) The value which we'd like to get indicator type of.
    Returns:
        Str which stands for the indicator type after detection.
    """
    if auto_detect:
        indicator_type = auto_detect_indicator_type(value)
    return indicator_type


def extract_all_fields_from_indicator(indicator, indicator_key):
    """Flattens the JSON object to create one dictionary of values

    Args:
        indicator(dict): JSON object that holds indicator full data.
        indicator_key(str): The key that holds the indicator value.

    Returns:
        dict. A dictionary of the fields in the JSON object.
    """
    fields = {}  # type: dict

    def insert_value_to_fields(key, value):
        if key in fields:
            if not isinstance(fields[key], list):
                fields[key] = [fields[key]]
            fields[key].append(value)
        else:
            fields[key] = value

    def extract(json_element):
        if isinstance(json_element, dict):
            for key, value in json_element.items():
                if value and isinstance(value, dict):
                    extract(value)
                elif key != indicator_key:
                    insert_value_to_fields(key, value)

        elif json_element and indicator_key not in json_element:
            for key, value in json_element:
                insert_value_to_fields(key, value)

    extract(indicator)
    return fields


def feed_main(params, feed_name, prefix):
    handle_proxy()

    client = Client(**params)
    indicator_type = params.get('indicator_type')
    feedTags = argToList(params.get('feedTags'))
    command = demisto.command()
    if prefix and not prefix.endswith('-'):
        prefix += '-'
    if command != 'fetch-indicators':
        demisto.info(f'Command being called is {demisto.command()}')
    try:
        if command == 'test-module':
            return_outputs(test_module(client, params))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params.get('indicator_type'), feedTags,
                                                  params.get('auto_detect_type'))
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == f'{prefix}get-indicators':
            # dummy command for testing
            limit = int(demisto.args().get('limit', 10))
            auto_detect = params.get('auto_detect_type')
            indicators = fetch_indicators_command(client, indicator_type, feedTags, auto_detect)[:limit]
            hr = tableToMarkdown('Indicators', indicators, headers=['value', 'type', 'rawJSON'])
            return_outputs(hr, {}, indicators)

    except Exception as err:
        err_msg = f'Error in {feed_name} integration [{err}]'
        return_error(err_msg)
