from CommonServerPython import *

''' IMPORTS '''
import urllib3
import jmespath
from typing import List, Dict, Union, Optional, Callable

# disable insecure warnings
urllib3.disable_warnings()


class Client:
    def __init__(self, url: str = '', credentials: dict = None,
                 feed_name_to_config: Dict[str, dict] = None, source_name: str = 'JSON',
                 extractor: str = '', indicator: str = 'indicator',
                 insecure: bool = False, cert_file: str = None, key_file: str = None, headers: dict = None,
                 tlp_color: Optional[str] = None, **_):
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
        :param tlp_color: Traffic Light Protocol color.

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
        self.tlp_color = tlp_color

    def build_iterator(self, feed: dict, **kwargs) -> List:
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

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')

        return result


def test_module(client: Client, limit) -> str:
    for feed_name, feed in client.feed_name_to_config.items():
        custom_build_iterator = feed.get('custom_build_iterator')
        if custom_build_iterator:
            custom_build_iterator(client, feed, limit)
        else:
            client.build_iterator(feed)
    return 'ok'


def fetch_indicators_command(client: Client, indicator_type: str, feedTags: list, auto_detect: bool,
                             limit: int = 0, **kwargs) -> Union[Dict, List[Dict]]:
    """
    Fetches the indicators from client.
    :param client: Client of a JSON Feed
    :param indicator_type: the default indicator type
    :param feedTags: the indicator tags
    :param auto_detect: a boolean indicates if we should automatically detect the indicator_type
    :param limit: given only when get-indicators command is running. function will return number indicators as the limit
    """
    indicators: List[dict] = []
    feeds_results = {}
    for feed_name, feed in client.feed_name_to_config.items():
        custom_build_iterator = feed.get('custom_build_iterator')
        if custom_build_iterator:
            indicators_from_feed = custom_build_iterator(client, feed, limit, **kwargs)
            if not isinstance(indicators_from_feed, list):
                raise Exception("Custom function to handle with pagination must return a list type")
            feeds_results[feed_name] = indicators_from_feed
        else:
            feeds_results[feed_name] = client.build_iterator(feed, **kwargs)

    for service_name, items in feeds_results.items():
        feed_config = client.feed_name_to_config.get(service_name, {})
        indicator_field = str(feed_config.get('indicator') if feed_config.get('indicator') else 'indicator')
        indicator_type = str(feed_config.get('indicator_type', indicator_type))
        use_prefix_flat = bool(feed_config.get('flat_json_with_prefix', False))
        mapping_function = feed_config.get('mapping_function', indicator_mapping)
        handle_indicator_function = feed_config.get('handle_indicator_function', handle_indicator)

        for item in items:
            if isinstance(item, str):
                item = {indicator_field: item}

            handle_indicator_function(client, item, feed_config, service_name, indicator_type, indicator_field,
                                      use_prefix_flat, feedTags, auto_detect, indicators, mapping_function)

            if limit and len(indicators) % limit == 0:  # We have a limitation only when get-indicators command is
                # called, and then we return for each service_name "limit" of indicators
                break
    return indicators


def indicator_mapping(mapping: Dict, indicator: Dict, attributes: Dict):
    for map_key in mapping:
        if map_key in attributes:
            fields = mapping[map_key].split(".")
            if len(fields) > 1:
                if indicator['fields'].get(fields[0]):
                    indicator['fields'][fields[0]][0].update({fields[1]: attributes.get(map_key)})
                else:
                    indicator['fields'][fields[0]] = [{fields[1]: attributes.get(map_key)}]
            else:
                indicator['fields'][mapping[map_key]] = attributes.get(map_key)  # type: ignore


def handle_indicator(client: Client, item: Dict, feed_config: Dict, service_name: str,
                     indicator_type: str, indicator_field: str, use_prefix_flat: bool,
                     feedTags: list, auto_detect: bool, indicator_list: list,
                     mapping_function: Callable = indicator_mapping) -> None:

    mapping = feed_config.get('mapping')
    take_value_from_flatten = False
    indicator_value = item.get(indicator_field)
    if not indicator_value:
        take_value_from_flatten = True
    current_indicator_type = determine_indicator_type(indicator_type, auto_detect, indicator_value)

    if not current_indicator_type:
        return

    indicator = {
        'type': current_indicator_type,
        'fields': {
            'tags': feedTags,
        }
    }

    if client.tlp_color:
        indicator['fields']['trafficlightprotocol'] = client.tlp_color

    attributes = {'source_name': service_name, 'type': current_indicator_type}
    attributes.update(extract_all_fields_from_indicator(item, indicator_field,
                                                        flat_with_prefix=use_prefix_flat))

    if take_value_from_flatten:
        indicator_value = attributes.get(indicator_field)
    indicator['value'] = indicator_value
    attributes['value'] = indicator_value

    if mapping:
        mapping_function(mapping, indicator, attributes)

    indicator['rawJSON'] = item

    indicator_list.append(indicator)


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


def extract_all_fields_from_indicator(indicator: Dict, indicator_key: str, flat_with_prefix: bool = False) -> Dict:
    """Flattens the JSON object to create one dictionary of values
    Args:
        indicator(dict): JSON object that holds indicator full data.
        indicator_key(str): The key that holds the indicator value.
        flat_with_prefix(bool): Indicates whether should add the inner json path as part of the keys in the flatten json
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

    def extract(json_element, prefix_field="", use_prefix=False):
        if isinstance(json_element, dict):
            for key, value in json_element.items():
                if value and isinstance(value, dict):
                    if use_prefix:
                        extract(value, prefix_field=f"{prefix_field}_{key}" if prefix_field else key,
                                use_prefix=use_prefix)
                    else:
                        extract(value)
                elif key != indicator_key:
                    if use_prefix:
                        insert_value_to_fields(f"{prefix_field}_{key}" if prefix_field else key, value)
                    else:
                        insert_value_to_fields(key, value)
        elif json_element and indicator_key not in json_element:
            for key, value in json_element:
                insert_value_to_fields(key, value)

    extract(indicator, use_prefix=flat_with_prefix)

    return fields


def feed_main(params, feed_name, prefix):
    handle_proxy()
    client = Client(**params)
    indicator_type = params.get('indicator_type')
    auto_detect = params.get('auto_detect_type')

    feedTags = argToList(params.get('feedTags'))
    limit = int(demisto.args().get('limit', 10))
    command = demisto.command()
    if prefix and not prefix.endswith('-'):
        prefix += '-'
    if command != 'fetch-indicators':
        demisto.info(f'Command being called is {demisto.command()}')
    try:
        if command == 'test-module':
            return_results(test_module(client, limit))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, indicator_type, feedTags, auto_detect)
            if not len(indicators):
                demisto.createIndicators(indicators)
            else:
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)

        elif command == f'{prefix}get-indicators':
            # dummy command for testing
            indicators = fetch_indicators_command(client, indicator_type, feedTags, auto_detect, limit)
            hr = tableToMarkdown('Indicators', indicators, headers=['value', 'type', 'rawJSON'])
            return_results(CommandResults(readable_output=hr, raw_response=indicators))

    except Exception as err:
        err_msg = f'Error in {feed_name} integration [{err}]'
        return_error(err_msg)
