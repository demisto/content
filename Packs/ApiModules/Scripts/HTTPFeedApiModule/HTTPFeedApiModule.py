import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import requests
from dateutil.parser import parse
from typing import Optional, Pattern, List

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS '''
TAGS = 'feedTags'
TLP_COLOR = 'trafficlightprotocol'


class Client(BaseClient):
    def __init__(self, url: str, feed_name: str = 'http', insecure: bool = False, credentials: dict = None,
                 ignore_regex: str = None, encoding: str = None, indicator_type: str = '',
                 indicator: str = '', fields: str = '{}', feed_url_to_config: dict = None, polling_timeout: int = 20,
                 headers: dict = None, proxy: bool = False, custom_fields_mapping: dict = None, **kwargs):
        """Implements class for miners of plain text feeds over HTTP.
        **Config parameters**
        :param: url: URL of the feed.
        :param: polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :param feed_name: The name of the feed.
        :param: custom_fields_mapping: Dict, the "fields" to be used in the indicator - where the keys
        are the *current* keys of the fields returned feed data and the *values* are the *indicator fields in Demisto*.
        :param: headers: dict, Optional list of headers to send in the request.
        :param: ignore_regex: Python regular expression for lines that should be
            ignored. Default: *null*
        :param: insecure: boolean, if *false* feed HTTPS server certificate is
            verified. Default: *false*
        :param credentials: username and password used for basic authentication.
                            Can be also used as API key header and value by specifying _header in the username field.
        :param: encoding: encoding of the feed, if not UTF-8. See
            ``str.decode`` for options. Default: *null*, meaning do
            nothing, (Assumes UTF-8).
        :param: indicator_type: Default indicator type
        :param: indicator: an *extraction dictionary* to extract the indicator from
            the line. If *null*, the text until the first whitespace or newline
            character is used as indicator. Default: *null*
        :param: fields: a dictionary of *extraction dictionaries* to extract
            additional attributes from each line. Default: {}
        :param: feed_url_to_config: For each service, a dictionary to process indicators by.
        For example, ASN feed:
        'https://www.spamhaus.org/drop/asndrop.txt': {
            'indicator_type': ASN,
            'indicator': { (Regex to extract the indicator by, if empty - the whole line is extracted)
                'regex': r'^AS[0-9]+',
            },
            'fields': [{ (See Extraction dictionary below)
                'asndrop_country': {
                    'regex': '^.*;\\W([a-zA-Z]+)\\W+',
                    'transform: r'\1'
                }
            }]
        }
        :param: proxy: Use proxy in requests.
        **Extraction dictionary**
            Extraction dictionaries contain the following keys:
            :regex: Python regular expression for searching the text.
            :transform: template to generate the final value from the result
                of the regular expression. Default: the entire match of the regex
                is used as extracted value.
            See Python `re <https://docs.python.org/2/library/re.html>`_ module for
            details about Python regular expressions and templates.
        Example:
            Example config in YAML where extraction dictionaries are used to
            extract the indicator and additional fields::
                url: https://www.dshield.org/block.txt
                ignore_regex: "[#S].*"
                indicator:
                    regex: '^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\t([0-9]
                    {1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})'
                    transform: '\\1-\\2'
                fields:
                    dshield_nattacks:
                        regex: '^.*\\t.*\\t[0-9]+\\t([0-9]+)'
                        transform: '\\1'
                    dshield_name:
                        regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t([^\\t]+)'
                        transform: '\\1'
                    dshield_country:
                        regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t([A-Z]+)'
                        transform: '\\1'
                    dshield_email:
                        regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t[A-Z]+\\t(\\S+)'
                        transform: '\\1'
            Example config in YAML where the text in each line until the first
            whitespace is used as indicator::
                url: https://ransomwaretracker.abuse.ch/downloads/CW_C2_URLBL.txt
                ignore_regex: '^#'
        """
        super().__init__(base_url=url, verify=not insecure, proxy=proxy)
        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            raise ValueError('Please provide an integer value for "Request Timeout"')

        self.headers = headers
        self.encoding = encoding
        self.feed_name = feed_name
        if not credentials:
            credentials = {}
        self.username = None
        self.password = None

        username = credentials.get('identifier', '')
        if username.startswith('_header:'):
            if not self.headers:
                self.headers = {}
            header_field = username.split(':')
            if len(header_field) < 2:
                raise ValueError('An incorrect value was provided for an API key header.'
                                 ' The correct value is "_header:<header_name>"')
            header_name: str = header_field[1]
            header_value: str = credentials.get('password', '')
            self.headers[header_name] = header_value
        else:
            self.username = username
            self.password = credentials.get('password', None)

        self.indicator_type = indicator_type
        if feed_url_to_config:
            self.feed_url_to_config = feed_url_to_config
        else:
            self.feed_url_to_config = {url: self.get_feed_config(fields, indicator)}
        self.ignore_regex: Optional[Pattern] = None
        if ignore_regex is not None:
            self.ignore_regex = re.compile(ignore_regex)

        if custom_fields_mapping is None:
            custom_fields_mapping = {}
        self.custom_fields_mapping = custom_fields_mapping

    def get_feed_config(self, fields_json: str = '', indicator_json: str = ''):
        """
        Get the feed configuration from the indicator and field JSON strings.
        :param fields_json: JSON string of fields to extract, for example:
            {
                'fieldname': {
                    'regex': regex,
                    'transform': r'\1'
                }
            },
            {
                'asndrop_org': {
                    'regex': regex,
                    'transform': r'\1'
                }
            }
        :param indicator_json: JSON string of the indicator to extract, for example:
            {'regex': regex}
        :return: The feed configuration.
        """
        config = {}
        if indicator_json:
            indicator = json.loads(indicator_json)
            if 'regex' in indicator:
                indicator['regex'] = re.compile(indicator['regex'])
            else:
                raise ValueError(f'{self.feed_name} - indicator stanza should have a regex')
            if 'transform' not in indicator:
                if indicator['regex'].groups > 0:
                    LOG(f'{self.feed_name} - no transform string for indicator but pattern contains groups')
                indicator['transform'] = r'\g<0>'

            config['indicator'] = indicator
        if fields_json:
            fields = json.loads(fields_json)
            config['fields'] = []
            for f, fattrs in fields.items():
                if 'regex' in fattrs:
                    fattrs['regex'] = re.compile(fattrs['regex'])
                else:
                    raise ValueError(f'{self.feed_name} - {f} field does not have a regex')
                if 'transform' not in fattrs:
                    if fattrs['regex'].groups > 0:
                        LOG(f'{self.feed_name} - no transform string for field {f} but pattern contains groups')
                    fattrs['transform'] = r'\g<0>'
                config['fields'].append({
                    f: fattrs
                })

        return config

    def build_iterator(self, **kwargs):
        """
        For each URL (service), send an HTTP request to get indicators and return them after filtering by Regex
        :param kwargs: Arguments to send to the HTTP API endpoint
        :return: List of indicators
        """
        kwargs['stream'] = True
        kwargs['verify'] = self._verify
        kwargs['timeout'] = self.polling_timeout

        if self.headers is not None:
            kwargs['headers'] = self.headers

        if self.username is not None and self.password is not None:
            kwargs['auth'] = (self.username, self.password)
        try:
            urls = self._base_url
            url_to_response_list: List[dict] = []
            if not isinstance(urls, list):
                urls = [urls]
            for url in urls:
                r = requests.get(
                    url,
                    **kwargs
                )
                try:
                    r.raise_for_status()
                except Exception:
                    LOG(f'{self.feed_name!r} - exception in request:'
                        f' {r.status_code!r} {r.content!r}')
                    raise
                url_to_response_list.append({url: r})
        except requests.exceptions.SSLError as exception:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise DemistoException(err_msg, exception)
        except requests.ConnectionError:
            raise requests.ConnectionError('Failed to establish a new connection. Please make sure your URL is valid.')

        results = []
        for url_to_response in url_to_response_list:
            for url, lines in url_to_response.items():
                result = lines.iter_lines()
                if self.encoding is not None:
                    result = map(
                        lambda x: x.decode(self.encoding).encode('utf_8'),
                        result
                    )
                else:
                    result = map(
                        lambda x: x.decode('utf_8'),
                        result
                    )
                if self.ignore_regex is not None:
                    result = filter(
                        lambda x: self.ignore_regex.match(x) is None,  # type: ignore[union-attr]
                        result
                    )
                results.append({url: result})
        return results

    def custom_fields_creator(self, attributes: dict):
        created_custom_fields = {}
        for attribute in attributes.keys():
            if attribute in self.custom_fields_mapping.keys() or attribute in [TAGS, TLP_COLOR]:
                if attribute in [TAGS, TLP_COLOR]:
                    created_custom_fields[attribute] = attributes[attribute]
                else:
                    created_custom_fields[self.custom_fields_mapping[attribute]] = attributes[attribute]

        return created_custom_fields


def datestring_to_millisecond_timestamp(datestring):
    date = parse(str(datestring))
    return int(date.timestamp() * 1000)


def get_indicator_fields(line, url, feed_tags: list, tlp_color: Optional[str], client: Client):
    """
    Extract indicators according to the feed type
    :param line: The current line in the feed
    :param url: The feed URL
    :param client: The client
    :param feed_tags: The indicator tags.
    :param tlp_color: Traffic Light Protocol color.
    :return: The indicator
    """
    attributes = None
    value: str = ''
    indicator = None
    fields_to_extract = []
    feed_config = client.feed_url_to_config.get(url, {})
    if feed_config:
        if 'indicator' in feed_config:
            indicator = feed_config['indicator']
            if 'regex' in indicator:
                indicator['regex'] = re.compile(indicator['regex'])
            if 'transform' not in indicator:
                indicator['transform'] = r'\g<0>'

    if 'fields' in feed_config:
        fields = feed_config['fields']
        for field in fields:
            for f, fattrs in field.items():
                field = {f: {}}
                if 'regex' in fattrs:
                    field[f]['regex'] = re.compile(fattrs['regex'])
                if 'transform' not in fattrs:
                    field[f]['transform'] = r'\g<0>'
                else:
                    field[f]['transform'] = fattrs['transform']
                fields_to_extract.append(field)

    line = line.strip()
    if line:
        extracted_indicator = line.split()[0]
        if indicator:
            extracted_indicator = indicator['regex'].search(line)
            if extracted_indicator is None:
                return attributes, value
            if 'transform' in indicator:
                extracted_indicator = extracted_indicator.expand(indicator['transform'])
        attributes = {}
        for field in fields_to_extract:
            for f, fattrs in field.items():
                m = fattrs['regex'].search(line)

                if m is None:
                    continue

                attributes[f] = m.expand(fattrs['transform'])

                try:
                    i = int(attributes[f])
                except Exception:
                    pass
                else:
                    attributes[f] = i
        attributes['value'] = value = extracted_indicator
        attributes['type'] = feed_config.get('indicator_type', client.indicator_type)
        attributes['tags'] = feed_tags

        if tlp_color:
            attributes['trafficlightprotocol'] = tlp_color

    return attributes, value


def fetch_indicators_command(client, feed_tags, tlp_color, itype, auto_detect, **kwargs):
    iterators = client.build_iterator(**kwargs)
    indicators = []
    for iterator in iterators:
        for url, lines in iterator.items():
            for line in lines:
                attributes, value = get_indicator_fields(line, url, feed_tags, tlp_color, client)
                if value:
                    if 'lastseenbysource' in attributes.keys():
                        attributes['lastseenbysource'] = datestring_to_millisecond_timestamp(
                            attributes['lastseenbysource'])

                    if 'firstseenbysource' in attributes.keys():
                        attributes['firstseenbysource'] = datestring_to_millisecond_timestamp(
                            attributes['firstseenbysource'])
                    indicator_type = determine_indicator_type(
                        client.feed_url_to_config.get(url, {}).get('indicator_type'), itype, auto_detect, value)
                    indicator_data = {
                        "value": value,
                        "type": indicator_type,
                        "rawJSON": attributes,
                    }

                    if len(client.custom_fields_mapping.keys()) > 0 or TAGS in attributes.keys():
                        custom_fields = client.custom_fields_creator(attributes)
                        indicator_data["fields"] = custom_fields

                    indicators.append(indicator_data)
    return indicators


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


def get_indicators_command(client: Client, args):
    itype = args.get('indicator_type', client.indicator_type)
    limit = int(args.get('limit'))
    feed_tags = args.get('feedTags')
    tlp_color = args.get('tlp_color')
    auto_detect = demisto.params().get('auto_detect_type')
    indicators_list = fetch_indicators_command(client, feed_tags, tlp_color, itype, auto_detect)[:limit]
    entry_result = camelize(indicators_list)
    hr = tableToMarkdown('Indicators', entry_result, headers=['Value', 'Type', 'Rawjson'])
    return hr, {}, indicators_list


def test_module(client: Client, args):
    if not client.feed_url_to_config:
        indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
        if not FeedIndicatorType.is_valid_type(indicator_type):
            indicator_types = []
            for key, val in vars(FeedIndicatorType).items():
                if not key.startswith('__') and type(val) == str:
                    indicator_types.append(val)
            supported_values = ', '.join(indicator_types)
            raise ValueError(f'Indicator type of {indicator_type} is not supported. Supported values are:'
                             f' {supported_values}')
    client.build_iterator()
    return 'ok', {}, {}


def feed_main(feed_name, params=None, prefix=''):
    if not params:
        params = assign_params(**demisto.params())
    if 'feed_name' not in params:
        params['feed_name'] = feed_name
    feed_tags = argToList(demisto.params().get('feedTags'))
    tlp_color = demisto.params().get('tlp_color')
    client = Client(**params)
    command = demisto.command()
    if command != 'fetch-indicators':
        demisto.info('Command being called is {}'.format(command))
    if prefix and not prefix.endswith('-'):
        prefix += '-'
    # Switch case
    commands: dict = {
        'test-module': test_module,
        f'{prefix}get-indicators': get_indicators_command
    }
    try:
        if command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, feed_tags, tlp_color, params.get('indicator_type'),
                                                  params.get('auto_detect_type'))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            args = demisto.args()
            args['feed_name'] = feed_name
            if feed_tags:
                args['feedTags'] = feed_tags
            if tlp_color:
                args['tlp_color'] = tlp_color
            readable_output, outputs, raw_response = commands[command](client, args)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {feed_name} integration [{e}]'
        return_error(err_msg, error=e)
