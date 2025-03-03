import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import csv
import gzip
import urllib3
from typing import Optional, Pattern, Dict, Any, Tuple, Union, List

# disable insecure warnings
urllib3.disable_warnings()

# Globals
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
THRESHOLD_IN_SECONDS = 43200    # 12 hours in seconds


class Client(BaseClient):
    def __init__(self, url: str, feed_url_to_config: Optional[Dict[str, dict]] = None, fieldnames: str = '',
                 insecure: bool = False, credentials: dict = None, ignore_regex: str = None, encoding: str = 'latin-1',
                 delimiter: str = ',', doublequote: bool = True, escapechar: Union[str, None] = None,
                 quotechar: str = '"', skipinitialspace: bool = False, polling_timeout: int = 20, proxy: bool = False,
                 feedTags: Optional[str] = None, tlp_color: Optional[str] = None, value_field: str = 'value', **kwargs):
        """
        :param url: URL of the feed.
        :param feed_url_to_config: for each URL, a configuration of the feed that contains
         If *null* the values in the first row of the file are used as names. Default: *null*
         Example:
         feed_url_to_config = {
            'https://ipstack.com':
            {
                'fieldnames': ['value'],
                'indicator_type': 'IP',
                'mapping': {
                    'Date': 'date' / 'Date': ('date', r'(regex_string)', 'The date is {}')
                }
            }
         }
         For the mapping you can use either:
            1. 'indicator_field': 'value_from_feed'
            2. 'indicator_field': ('value_from_feed', regex_string_extractor, string_formatter)
                * regex_string_extractor will extract the first match from the value_from_feed,
                Use None to get the full value of the field.
                * string_formatter will format the data in your preferred way, Use None to get the extracted field.
            3. 'indicator_field': ('value_from_feed', 'field_mapper_function')
                * field_mapper_function will accept as an argument 'value_from_feed' and return the data
                in your preferred way.
        :param fieldnames: list of field names in the file. If *null* the values in the first row of the file are
            used as names. Default: *null*
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param credentials: username and password used for basic authentication.
        Can be also used as API key header and value by specifying _header in the username field.
        :param ignore_regex: python regular expression for lines that should be ignored. Default: *null*
        :param encoding: Encoding of the feed, latin-1 by default.
        :param delimiter: see `csv Python module
            <https://docs.python.org/3/library/csv.html#dialects-and-formatting-parameters>`. Default: ,
        :param doublequote: see `csv Python module
            <https://docs.python.org/3/library/csv.html#dialects-and-formatting-parameters>`. Default: true
        :param escapechar: see `csv Python module
            <https://docs.python.org/3/library/csv.html#dialects-and-formatting-parameters>`. Default null
        :param quotechar: see `csv Python module
            <https://docs.python.org/3/library/csv.html#dialects-and-formatting-parameters>`. Default "
        :param skipinitialspace: see `csv Python module
            <https://docs.python.org/3/library/csv.html#dialects-and-formatting-parameters>`. Default False
        :param polling_timeout: timeout of the polling request in seconds. Default: 20
        :param proxy: Sets whether use proxy when sending requests
        :param tlp_color: Traffic Light Protocol color.
        """
        self.tags: List[str] = argToList(feedTags)
        self.tlp_color = tlp_color
        self.value_field = value_field
        if not credentials:
            credentials = {}

        auth: Optional[tuple] = None
        self.headers = {}

        username = credentials.get('identifier', '')
        if username.startswith('_header:'):
            header_name = username.split(':')[1]
            header_value = credentials.get('password', '')
            self.headers[header_name] = header_value
        else:
            password = credentials.get('password', '')
            auth = None
            if username and password:
                auth = (username, password)

        super().__init__(base_url=url, proxy=proxy, verify=not insecure, auth=auth)

        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            return_error('Please provide an integer value for "Request Timeout"')
        self.encoding = encoding
        self.ignore_regex: Optional[Pattern] = None
        if ignore_regex is not None:
            self.ignore_regex = re.compile(ignore_regex)
        self.feed_url_to_config: Optional[Dict[str, dict]] = feed_url_to_config
        self.fieldnames = argToList(fieldnames)
        self.dialect: Dict[str, Any] = {
            'delimiter': delimiter,
            'doublequote': doublequote,
            'escapechar': escapechar,
            'quotechar': quotechar,
            'skipinitialspace': skipinitialspace
        }

    def _build_request(self, url):
        r = requests.Request(
            'GET',
            url,
            auth=self._auth
        )

        return r.prepare()

    def build_iterator(self, **kwargs):
        results = []
        urls = self._base_url
        if not isinstance(urls, list):
            urls = [urls]
        for url in urls:
            _session = requests.Session()

            prepreq = self._build_request(url)

            # this is to honour the proxy environment variables
            kwargs.update(_session.merge_environment_settings(
                prepreq.url,
                {}, None, None, None  # defaults
            ))
            kwargs['stream'] = True
            kwargs['verify'] = self._verify
            kwargs['timeout'] = self.polling_timeout

            if is_demisto_version_ge('6.5.0'):
                # Set the If-None-Match and If-Modified-Since headers if we have etag or
                # last_modified values in the context.
                last_run = demisto.getLastRun()
                etag = last_run.get(url, {}).get('etag')
                last_modified = last_run.get(url, {}).get('last_modified')
                last_updated = last_run.get(url, {}).get('last_updated')
                # To avoid issues with indicators expiring, if 'last_updated' is over X hours old,
                # we'll refresh the indicators to ensure their expiration time is updated.
                # For further details, refer to : https://confluence-dc.paloaltonetworks.com/display/DemistoContent/Json+Api+Module     # noqa: E501
                if last_updated and has_passed_time_threshold(timestamp_str=last_updated, seconds_threshold=THRESHOLD_IN_SECONDS):
                    last_modified = None
                    etag = None
                    demisto.debug("Since it's been a long time with no update, to make sure we are keeping the indicators alive, \
                        we will refetch them from scratch")

                if etag:
                    self.headers['If-None-Match'] = etag

                if last_modified:
                    self.headers['If-Modified-Since'] = last_modified

            # set request headers
            if 'headers' in kwargs:
                self.headers.update(kwargs['headers'])
                del kwargs['headers']

            if self.headers:
                prepreq.headers.update(self.headers)

            try:
                r = _session.send(prepreq, **kwargs)
            except requests.exceptions.ConnectTimeout as exception:
                err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                          ' is incorrect or that the Server is not accessible from your host.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.SSLError as exception:
                # in case the "Trust any certificate" is already checked
                if not self._verify:
                    raise
                err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                          ' the integration configuration.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ProxyError as exception:
                err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                          ' selected, try clearing the checkbox.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ConnectionError as exception:
                # Get originating Exception in Exception chain
                error_class = str(exception.__class__)
                err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
                err_msg = 'Verify that the server URL parameter' \
                          ' is correct and that you have access to the server from your host.' \
                          '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                    .format(err_type, exception.errno, exception.strerror)
                raise DemistoException(err_msg, exception)
            try:
                r.raise_for_status()
            except Exception:
                return_error(f'Exception in request: {r.status_code} {r.content.decode("utf-8")}')
                raise

            response = self.get_feed_content_divided_to_lines(url, r)
            if self.feed_url_to_config:
                fieldnames = self.feed_url_to_config.get(url, {}).get('fieldnames', [])
                skip_first_line = self.feed_url_to_config.get(url, {}).get('skip_first_line', False)
            else:
                fieldnames = self.fieldnames
                skip_first_line = False
            if self.ignore_regex is not None:
                response = filter(  # type: ignore
                    lambda x: self.ignore_regex.match(x) is None,  # type: ignore
                    response
                )

            csvreader = csv.DictReader(
                response,
                fieldnames=fieldnames,
                **self.dialect
            )

            if skip_first_line:
                next(csvreader)
            no_update = get_no_update_value(r, url) if is_demisto_version_ge('6.5.0') else True
            results.append({url: {'result': csvreader, 'no_update': no_update}})

        return results

    def get_feed_content_divided_to_lines(self, url, raw_response):
        """Fetch feed data and divides its content to lines

        Args:
            url: Current feed's url.
            raw_response: The raw response from the feed's url.

        Returns:
            List. List of lines from the feed content.
        """
        if self.feed_url_to_config and self.feed_url_to_config.get(url).get('is_zipped_file'):  # type: ignore
            response_content = gzip.decompress(raw_response.content)
        else:
            response_content = raw_response.content

        return response_content.decode(self.encoding).split('\n')


def get_no_update_value(response: requests.models.Response, url: str) -> bool:
    """
    detect if the feed response has been modified according to the headers etag and last_modified.
    For more information, see this:
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag
    Args:
        response: (requests.Response) The feed response.
        url: (str) The feed URL (service).
    Returns:
        boolean with the value for noUpdate argument.
        The value should be False if the response was modified.
    """
    if response.status_code == 304:
        demisto.debug('No new indicators fetched, createIndicators will be executed with noUpdate=True.')
        return True

    etag = response.headers.get('ETag')
    last_modified = response.headers.get('Last-Modified')
    current_time = datetime.utcnow()
    # Save the current time as the last updated time. This will be used to indicate the last time the feed was updated in XSOAR.
    last_updated = current_time.strftime(DATE_FORMAT)

    if not etag and not last_modified:
        demisto.debug('Last-Modified and Etag headers are not exists,'
                      'createIndicators will be executed with noUpdate=False.')
        return False

    last_run = demisto.getLastRun()
    last_run[url] = {'last_modified': last_modified, 'etag': etag, 'last_updated': last_updated}
    demisto.setLastRun(last_run)

    demisto.debug('New indicators fetched - the Last-Modified value has been updated,'
                  ' createIndicators will be executed with noUpdate=False.')
    return False


def determine_indicator_type(indicator_type, default_indicator_type, auto_detect, value):
    """
    Detect the indicator type of the given value.
    Args:
        indicator_type: (str) Indicator type given in the config.
        default_indicator_type: Indicator type which was inserted as a param of the integration by user.
        auto_detect: (bool) True whether auto detection of the indicator type is wanted.
        value: (str) The value which we'd like to get indicator type of.
    Returns:
        Str which stands for the indicator type after detection.
    """
    if auto_detect:
        indicator_type = auto_detect_indicator_type(value)
    if not indicator_type:
        indicator_type = default_indicator_type
    return indicator_type


def module_test_command(client: Client, args):
    client.build_iterator()
    return 'ok', {}, {}


def date_format_parsing(date_string):
    """
    formats a datestring to the ISO-8601 format which the server expects to recieve
    :param date_string: Date represented as a tring
    :return: ISO-8601 date string
    """
    formatted_date = dateparser.parse(date_string, settings={'TIMEZONE': 'UTC'})
    assert formatted_date is not None, f"failed parsing {date_string}"
    return formatted_date.strftime(DATE_FORMAT)


def create_fields_mapping(raw_json: Dict[str, Any], mapping: Dict[str, Union[Tuple, str]]):
    fields_mapping = {}  # type: dict

    for key, field in mapping.items():
        regex_extractor = None
        formatter_string = None
        field_mapper_function = None

        # case 'value_from_feed', regex_string_extractor, string_formatter
        if isinstance(field, tuple) and len(field) == 3:
            field, regex_extractor, formatter_string = field

        # case 'value_from_feed', 'field_mapper_function'
        elif isinstance(field, tuple) and len(field) == 2:
            field, field_mapper_function = field

        if not raw_json.get(field):  # type: ignore
            continue

        if not regex_extractor:
            field_value = raw_json[field]  # type: ignore
        else:
            try:
                field_value = re.match(regex_extractor, raw_json[field]).group(1)  # type: ignore
            except Exception:
                field_value = raw_json[field]  # type: ignore

        field_value = formatter_string.format(field_value) if formatter_string else field_value
        field_value = field_mapper_function(field_value) if field_mapper_function else field_value
        fields_mapping[key] = field_value

        if key in ['firstseenbysource', 'lastseenbysource']:
            fields_mapping[key] = date_format_parsing(fields_mapping[key])

    return fields_mapping


def fetch_indicators_command(client: Client, default_indicator_type: str, auto_detect: Optional[bool], limit: int = 0,
                             create_relationships: bool = False, enrichment_excluded: bool = False, **kwargs):
    iterator = client.build_iterator(**kwargs)
    relationships_of_indicator = []
    indicators = []
    config = client.feed_url_to_config or {}

    # set noUpdate flag in createIndicators command True only when all the results from all the urls are True.
    no_update = all(next(iter(item.values())).get('no_update', False) for item in iterator)

    for url_to_reader in iterator:
        for url, reader in url_to_reader.items():
            mapping = config.get(url, {}).get('mapping', {})
            for item in reader.get('result', []):
                raw_json = dict(item)
                fields_mapping = create_fields_mapping(raw_json, mapping) if mapping else {}
                value = item.get(client.value_field) or fields_mapping.get('Value')
                if not value and len(item) > 1:
                    value = next(iter(item.values()))
                if value:
                    raw_json['value'] = value
                    conf_indicator_type = config.get(url, {}).get('indicator_type')
                    indicator_type = determine_indicator_type(conf_indicator_type, default_indicator_type, auto_detect,
                                                              value)
                    raw_json['type'] = indicator_type
                    # if relationships param is True and also the url returns relationships
                    if create_relationships \
                            and config.get(url, {}).get('relationship_name') \
                            and fields_mapping.get('relationship_entity_b'):
                        relationships_lst = EntityRelationship(
                            name=config.get(url, {}).get('relationship_name'),
                            entity_a=value,
                            entity_a_type=indicator_type,
                            entity_b=fields_mapping.get('relationship_entity_b'),
                            entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                config.get(url, {}).get('relationship_entity_b_type')),
                        )
                        relationships_of_indicator = [relationships_lst.to_indicator()]

                    indicator = {
                        'value': value,
                        'type': indicator_type,
                        'rawJSON': raw_json,
                        'fields': fields_mapping,
                        'relationships': relationships_of_indicator,
                    }
                    indicator['fields']['tags'] = client.tags

                    if client.tlp_color:
                        indicator['fields']['trafficlightprotocol'] = client.tlp_color

                    if enrichment_excluded:
                        indicator['enrichmentExcluded'] = enrichment_excluded

                    indicators.append(indicator)
                    # exit the loop if we have more indicators than the limit
                    if limit and len(indicators) >= limit:
                        return indicators, no_update

    return indicators, no_update


def get_indicators_command(client, args: dict, tags: Optional[List[str]] = None):
    if tags is None:
        tags = []
    itype = args.get('indicator_type', demisto.params().get('indicator_type'))
    try:
        limit = int(args.get('limit', 50))
    except ValueError:
        raise ValueError('The limit argument must be a number.')
    auto_detect = demisto.params().get('auto_detect_type')
    relationships = demisto.params().get('create_relationships', False)
    enrichment_excluded = (demisto.params().get('enrichmentExcluded', False)
                           or (demisto.params().get('tlp_color') == 'RED' and is_xsiam_or_xsoar_saas()))
    indicators_list, _ = fetch_indicators_command(client, itype, auto_detect, limit, relationships, enrichment_excluded)
    entry_result = indicators_list[:limit]
    hr = tableToMarkdown('Indicators', entry_result, headers=['value', 'type', 'fields'])
    return hr, {}, indicators_list


def feed_main(feed_name, params=None, prefix=''):   # pragma: no cover
    if not params:
        params = {k: v for k, v in demisto.params().items() if v is not None}
    handle_proxy()
    client = Client(**params)
    command = demisto.command()
    if command != 'fetch-indicators':
        demisto.info('Command being called is {}'.format(command))
    if prefix and not prefix.endswith('-'):
        prefix += '-'
    # Switch case
    commands: dict = {
        'test-module': module_test_command,
        f'{prefix}get-indicators': get_indicators_command
    }
    try:
        if command == 'fetch-indicators':
            indicators, no_update = fetch_indicators_command(
                client,
                params.get('indicator_type'),
                params.get('auto_detect_type'),
                params.get('limit'),
                params.get('create_relationships'),
                params.get('enrichmentExcluded', False),
            )

            # check if the version is higher than 6.5.0 so we can use noUpdate parameter
            if is_demisto_version_ge('6.5.0'):
                if not indicators:
                    demisto.createIndicators(indicators, noUpdate=no_update)  # type: ignore
                else:
                    # we submit the indicators in batches
                    for b in batch(indicators, batch_size=2000):
                        demisto.createIndicators(b, noUpdate=no_update)  # type: ignore
            else:
                # call createIndicators without noUpdate arg
                if not indicators:
                    demisto.createIndicators(indicators)  # type: ignore
                else:
                    for b in batch(indicators, batch_size=2000):  # type: ignore
                        demisto.createIndicators(b)

        else:
            args = demisto.args()
            args['feed_name'] = feed_name
            readable_output, outputs, raw_response = commands[command](client, args)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {feed_name} Integration - Encountered an issue with createIndicators' if \
            'failed to create' in str(e) else f'Error in {feed_name} Integration [{e}]'
        return_error(err_msg)
