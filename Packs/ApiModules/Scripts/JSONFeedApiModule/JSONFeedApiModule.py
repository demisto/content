# pylint: disable=E9010
from CommonServerPython import *

''' IMPORTS '''
import urllib3
import jmespath
from typing import List, Dict, Union, Optional, Callable, Tuple

# disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
THRESHOLD_IN_SECONDS = 43200        # 12 hours in seconds


class Client:
    def __init__(self, url: str = '', credentials: dict = None,
                 feed_name_to_config: Dict[str, dict] = None, source_name: str = 'JSON',
                 extractor: str = '', indicator: str = 'indicator',
                 insecure: bool = False, cert_file: str = None, key_file: str = None, headers: Union[dict, str] = None,
                 tlp_color: Optional[str] = None, data: Union[str, dict] = None, **_):
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
        :param: headers: Header parameters are optional to specify a user-agent or an api-token.
            Support also a multiline string where each line contains a header of the format 'Name: Value'
            Example: headers = {'user-agent': 'my-app/0.0.1'} or "Authorization: Bearer"
            (curl -H "Authorization: Bearer " "https://api-url.com/api/v1/iocs?first_seen_since=2016-1-1")
        :param tlp_color: Traffic Light Protocol color.
        :param data: Data to post. If not specified will do a GET request. May also be passed as dict as
            supported by requests. If passed as a string will set content-type to
            application/x-www-form-urlencoded if not specified in the headers.

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
        self.auth: Optional[tuple[str, str]] = None
        self.headers = self.parse_headers(headers)

        if credentials:
            username = credentials.get('identifier', '')
            if username.startswith('_header:'):
                header_name = username.split(':')[1]
                header_value = credentials.get('password', '')
                self.headers[header_name] = header_value
            else:
                password = credentials.get('password', '')
                if username is not None and password is not None:
                    self.auth = (username, password)

        self.cert = (cert_file, key_file) if cert_file and key_file else None
        self.tlp_color = tlp_color
        self.post_data = data

        if isinstance(self.post_data, str):
            content_type_header = 'Content-Type'
            if content_type_header.lower() not in [k.lower() for k in self.headers]:
                self.headers[content_type_header] = 'application/x-www-form-urlencoded'

    @staticmethod
    def parse_headers(headers: Optional[Union[dict, str]]) -> dict:
        """Parse headers if passed as a string. Support a multiline string where each line contains a header
        of the format 'Name: Value'

        Args:
            headers (Optional[Union[dict, str]]): either dict or string to parse

        Returns:
            dict: returns a headers dict or None
        """
        if not headers:
            return {}
        if isinstance(headers, str):
            res = {}
            for line in headers.splitlines():
                if line.strip():  # ignore empty lines
                    key_val = line.split(':', 1)
                    res[key_val[0].strip()] = key_val[1].strip()
            return res
        else:
            return headers

    def build_iterator(self, feed: dict, feed_name: str, **kwargs) -> Tuple[List, bool]:
        url = feed.get('url', self.url)

        if is_demisto_version_ge('6.5.0'):
            prefix_feed_name = get_formatted_feed_name(feed_name)  # Support for AWS feed

            # Set the If-None-Match and If-Modified-Since headers
            # if we have etag or last_modified values in the context, with server version higher than 6.5.0.
            last_run = demisto.getLastRun()
            etag = last_run.get(prefix_feed_name, {}).get('etag') or last_run.get(feed_name, {}).get('etag')
            last_modified = last_run.get(prefix_feed_name, {}).get('last_modified') or last_run.get(feed_name, {}).get('last_modified')  # noqa: E501
            last_updated = last_run.get(prefix_feed_name, {}).get('last_updated') or last_run.get(feed_name, {}).get('last_updated')  # noqa: E501
            # To avoid issues with indicators expiring, if 'last_updated' is over X hours old,
            # we'll refresh the indicators to ensure their expiration time is updated.
            # For further details, refer to : https://confluence-dc.paloaltonetworks.com/display/DemistoContent/Json+Api+Module
            if last_updated and has_passed_time_threshold(timestamp_str=last_updated, seconds_threshold=THRESHOLD_IN_SECONDS):
                last_modified = None
                etag = None
                demisto.debug("Since it's been a long time with no update, to make sure we are keeping the indicators alive, \
                    we will refetch them from scratch")

            if etag:
                self.headers['If-None-Match'] = etag

            if last_modified:
                self.headers['If-Modified-Since'] = last_modified

        result: List[Dict] = []
        if not self.post_data:
            r = requests.get(
                url=url,
                verify=self.verify,
                auth=self.auth,
                cert=self.cert,
                headers=self.headers,
                **kwargs
            )
        else:
            r = requests.post(
                url=url,
                data=self.post_data,
                verify=self.verify,
                auth=self.auth,
                cert=self.cert,
                headers=self.headers,
                **kwargs
            )

        try:
            r.raise_for_status()
            if r.content:
                demisto.debug(f'JSON: found content for {feed_name}')
                data = r.json()
                result = jmespath.search(expression=feed.get('extractor'), data=data) or []
                if not result:
                    demisto.debug(f'No results found - retrieved data is: {data}')

        except ValueError as VE:
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {VE}')
        if is_demisto_version_ge('6.5.0'):
            return result, get_no_update_value(r, feed_name)
        return result, True


def get_no_update_value(response: requests.Response, feed_name: str) -> bool:
    """
    detect if the feed response has been modified according to the headers etag and last_modified.
    For more information, see this:
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag
    Args:
        response: (requests.Response) The feed response.
        feed_name: (str) the name of the feed.
    Returns:
        boolean with the value for noUpdate argument.
        The value should be False if the response was modified.
    """
    # HTTP status code 304 (Not Modified) set noUpdate to True.
    if response.status_code == 304:
        demisto.debug('No new indicators fetched, createIndicators will be executed with noUpdate=True.')
        return True

    etag = response.headers.get('ETag')
    last_modified = response.headers.get('Last-Modified')
    current_time = datetime.utcnow()
    # Save the current time as the last updated time. This will be used to indicate the last time the feed was updated in XSOAR.
    last_updated = current_time.strftime(DATE_FORMAT)

    if not etag and not last_modified:
        demisto.debug('Last-Modified and Etag headers are not exists, '
                      'createIndicators will be executed with noUpdate=False.')
        return False

    last_run = demisto.getLastRun()
    last_run[feed_name] = {
        'last_modified': last_modified,
        'etag': etag,
        'last_updated': last_updated
    }
    demisto.setLastRun(last_run)
    demisto.debug(f'JSON: The new last run is: {last_run}')
    demisto.debug('New indicators fetched - the Last-Modified value has been updated,'
                  ' createIndicators will be executed with noUpdate=False.')
    return False


def get_formatted_feed_name(feed_name: str):
    """support for AWS Feed config name, that contains $$ in the name.
        example: AMAZON$$CIDR
    Args:
        feed_name (str): The feed config name
    """
    prefix_feed_name = ''
    if '$$' in feed_name:
        prefix_feed_name = feed_name.split('$$')[0]
        return prefix_feed_name

    return feed_name


def test_module(client: Client, limit) -> str:  # pragma: no cover
    for feed_name, feed in client.feed_name_to_config.items():
        custom_build_iterator = feed.get('custom_build_iterator')
        if custom_build_iterator:
            custom_build_iterator(client, feed, limit)
        else:
            client.build_iterator(feed, feed_name)
    return 'ok'


def fetch_indicators_command(client: Client, indicator_type: str, feedTags: list, auto_detect: bool,
                             create_relationships: bool = False, limit: int = 0, remove_ports: bool = False,
                             enrichment_excluded: bool = False, **kwargs) -> Tuple[List[dict], bool]:
    """
    Fetches the indicators from client.
    :param client: Client of a JSON Feed
    :param indicator_type: the default indicator type
    :param feedTags: the indicator tags
    :param auto_detect: a boolean indicates if we should automatically detect the indicator_type
    :param limit: given only when get-indicators command is running. function will return number indicators as the limit
    :param create_relationships: whether to add connected indicators
    """
    indicators: List[dict] = []
    feeds_results = {}
    no_update = False
    for feed_name, feed in client.feed_name_to_config.items():
        custom_build_iterator = feed.get('custom_build_iterator')
        if custom_build_iterator:
            indicators_from_feed = custom_build_iterator(client, feed, limit, **kwargs)
            if not isinstance(indicators_from_feed, list):
                raise Exception("Custom function to handle with pagination must return a list type")
            feeds_results[feed_name] = indicators_from_feed
        else:
            feeds_results[feed_name], no_update = client.build_iterator(feed, feed_name, **kwargs)

    indicators_values: Set[str] = set()
    indicators_values_indexes = {}

    for service_name, items in feeds_results.items():
        feed_config = client.feed_name_to_config.get(service_name, {})
        indicator_field = str(feed_config.get('indicator') if feed_config.get('indicator') else 'indicator')
        indicator_type = str(feed_config.get('indicator_type', indicator_type))
        use_prefix_flat = bool(feed_config.get('flat_json_with_prefix', False))
        mapping_function = feed_config.get('mapping_function', indicator_mapping)
        handle_indicator_function = feed_config.get('handle_indicator_function', handle_indicator)
        create_relationships_function = feed_config.get('create_relations_function')
        service_name = get_formatted_feed_name(service_name)

        for item in items:
            if isinstance(item, str):
                item = {indicator_field: item}

            indicator_value = item.get(indicator_field)
            if indicator_value is None:
                continue
            if indicator_value not in indicators_values:
                indicators_values_indexes[indicator_value] = len(indicators_values)
                indicators_values.add(indicator_value)
            else:
                service = indicators[indicators_values_indexes[indicator_value]].get('rawJSON', {}).get('service', '')
                if service and service_name not in service.split(','):
                    service_name += f', {service}'
                indicators[indicators_values_indexes[indicator_value]]['rawJSON']['service'] = service_name
                continue

            indicators.extend(
                handle_indicator_function(client, item, feed_config, service_name, indicator_type, indicator_field,
                                          use_prefix_flat, feedTags, auto_detect, mapping_function,
                                          create_relationships, create_relationships_function, remove_ports,
                                          enrichment_excluded=enrichment_excluded,
                                          ))

            if limit and len(indicators) >= limit:  # We have a limitation only when get-indicators command is
                # called, and then we return for each service_name "limit" of indicators
                break
    return indicators, no_update


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
                     feedTags: list, auto_detect: bool, mapping_function: Callable = indicator_mapping,
                     create_relationships: bool = False, relationships_func: Callable | None = None,
                     remove_ports: bool = False,
                     enrichment_excluded: bool = False) -> List[dict]:
    indicator_list = []
    mapping = feed_config.get('mapping')
    take_value_from_flatten = False
    indicator_value = item.get(indicator_field)
    if not indicator_value:
        take_value_from_flatten = True
    current_indicator_type = determine_indicator_type(indicator_type, auto_detect, indicator_value)

    if not current_indicator_type:
        demisto.debug(f'Could not determine indicator type for value: {indicator_value} from field: {indicator_field}.'
                      f' Skipping item: {item}')
        return []

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

    if create_relationships and relationships_func and feed_config.get('relation_name'):
        indicator['relationships'] = relationships_func(feed_config, mapping, attributes)

    if feed_config.get('rawjson_include_indicator_type'):
        item['_indicator_type'] = current_indicator_type

    if remove_ports and indicator['type'] == 'IP' and indicator['value']:
        indicator['value'] = indicator['value'].split(':')[0]

    indicator['rawJSON'] = item

    if enrichment_excluded:
        indicator['enrichmentExcluded'] = enrichment_excluded

    indicator_list.append(indicator)

    return indicator_list


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


def feed_main(params, feed_name, prefix):  # pragma: no cover
    handle_proxy()
    client = Client(**params)
    indicator_type = params.get('indicator_type')
    auto_detect = params.get('auto_detect_type')
    feedTags = argToList(params.get('feedTags'))
    limit = int(demisto.args().get('limit', 10))
    enrichment_excluded = (params.get('enrichmentExcluded', False)
                           or (params.get('tlp_color') == 'RED' and is_xsiam_or_xsoar_saas()))
    command = demisto.command()
    if prefix and not prefix.endswith('-'):
        prefix += '-'
    if command != 'fetch-indicators':
        demisto.info(f'Command being called is {demisto.command()}')
    try:
        if command == 'test-module':
            return_results(test_module(client, limit))

        elif command == 'fetch-indicators':
            remove_ports = argToBoolean(params.get('remove_ports', False))
            create_relationships = params.get('create_relationships')
            indicators, no_update = fetch_indicators_command(client,
                                                             indicator_type,
                                                             feedTags,
                                                             auto_detect,
                                                             create_relationships,
                                                             remove_ports=remove_ports,
                                                             enrichment_excluded=enrichment_excluded)
            demisto.debug(f"Received {len(indicators)} indicators, no_update={no_update}")

            # check if the version is higher than 6.5.0 so we can use noUpdate parameter
            if is_demisto_version_ge('6.5.0'):
                if not indicators:
                    demisto.createIndicators(indicators, noUpdate=no_update)
                else:
                    for b in batch(indicators, batch_size=2000):
                        demisto.createIndicators(b, noUpdate=no_update)

            else:
                # call createIndicators without noUpdate arg
                if not indicators:
                    demisto.createIndicators(indicators)
                else:
                    for b in batch(indicators, batch_size=2000):
                        demisto.createIndicators(b)

        elif command == f'{prefix}get-indicators':
            remove_ports = argToBoolean(demisto.args().get('remove_ports', False))
            create_relationships = params.get('create_relationships')
            indicators, _ = fetch_indicators_command(client, indicator_type, feedTags, auto_detect,
                                                     create_relationships, limit, remove_ports)

            hr = tableToMarkdown(f'Indicators ({len(indicators)}):', indicators, headers=['value', 'type', 'rawJSON'])
            if not indicators:
                hr = 'No indicators found.'

            return_results(CommandResults(readable_output=hr, raw_response=indicators))

    except Exception as err:
        err_msg = f'Error in {feed_name} integration [{err}]'
        return_error(err_msg)
