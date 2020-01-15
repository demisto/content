import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import requests
from typing import Optional, Pattern, List

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, url: str, feed_name: str = 'http', insecure: bool = False, credentials: dict = None,
                 ignore_regex: str = None, encoding: str = None, indicator_type: str = '',
                 feed_types: dict = None, polling_timeout: int = 20,
                 user_agent: str = None, proxy: bool = False, **kwargs):
        """Implements class for miners of plain text feeds over HTTP.
        **Config parameters**
        :param: url: URL of the feed.
        :param: polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :param: user_agent: string, value for the User-Agent header in HTTP
            request. If ``MineMeld``, MineMeld/<version> is used.
            Default: python ``requests`` default.
        :param: ignore_regex: Python regular expression for lines that should be
            ignored. Default: *null*
        :param: verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :param: encoding: encoding of the feed, if not UTF-8. See
            ``str.decode`` for options. Default: *null*, meaning do
            nothing, (Assumes UTF-8).
        :param: feed_types: For each sub-feed, a dictionary to process indicators by.
        For example, ASN feed:
        'https://www.spamhaus.org/drop/asndrop.txt': {
            'indicator_type': ASN,
            'regex': r'^AS[0-9]+',
            'fields': {
                'asndrop_country': {
                    'regex': '^.*;\\W([a-zA-Z]+)\\W+',
                    'transform: r'\1'
                }
            }
        }
        :param: indicator_type: Default indicator type
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
        Args:
            name (str): node name, should be unique inside the graph
            chassis (object): parent chassis instance
            config (dict): node config.
        """
        super().__init__(base_url=url, verify=not insecure, proxy=proxy)
        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            raise ValueError('Please provide an integer value for "Request Timeout"')
        self.user_agent = user_agent
        self.encoding = encoding
        self.feed_name = feed_name
        if not credentials:
            credentials = {}
        self.username = credentials.get('identifier', None)
        self.password = credentials.get('password', None)
        self.indicator_type = indicator_type
        self.feed_types = feed_types if feed_types else {}
        self.ignore_regex: Optional[Pattern] = None
        if ignore_regex is not None:
            self.ignore_regex = re.compile(ignore_regex)

    def build_iterator(self, **kwargs):
        """
        For each URL (sub-feed), send an HTTP request to get indicators and return them after filtering by Regex
        :param kwargs: Arguments to send to the HTTP API endpoint
        :return: List of indicators
        """
        kwargs['stream'] = True
        kwargs['verify'] = self._verify
        kwargs['timeout'] = self.polling_timeout

        if self.user_agent is not None:
            kwargs['headers'] = {
                'User-Agent': self.user_agent
            }

        if self.username is not None and self.password is not None:
            kwargs['auth'] = (self.username, self.password)
        try:
            urls = self._base_url
            rs: List[dict] = []
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
                    LOG(f'{self.feed_name} - exception in request:'  # type: ignore[str-bytes-safe]
                        f' {r.status_code} {r.content}')
                    raise
                rs.append({url: r})
        except requests.ConnectionError:
            raise requests.ConnectionError('Failed to establish a new connection. Please make sure your URL is valid.')

        results = []
        for url_to_response in rs:
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


def get_indicator_fields(line, url, client: Client):
    """
    Extract indicators according to the feed type
    :param line: The current line in the feed
    :param url: The feed URL
    :param client: The client
    :return: The indicator
    """
    attributes = None
    value = None
    indicator = None
    fields_to_extract = []
    feed_type = client.feed_types.get(url, {})
    if feed_type:
        if 'indicator' in feed_type:
            indicator = feed_type['indicator']
            if 'regex' in indicator:
                indicator['regex'] = re.compile(indicator['regex'])
            if 'transform' not in indicator:
                indicator['transform'] = r'\g<0>'
    else:
        indicator = None

    if 'fields' in feed_type:
        fields = feed_type['fields']
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
        attributes['type'] = feed_type['indicator_type']
    return attributes, value


def fetch_indicators_command(client, itype, **kwargs):
    iterators = client.build_iterator(**kwargs)
    indicators = []
    for iterator in iterators:
        for url, lines in iterator.items():
            for line in lines:
                attributes, value = get_indicator_fields(line, url, client)
                if value:
                    indicators.append({
                        "value": value,
                        "type": client.feed_types.get(url, {}).get('indicator_type', itype),
                        "rawJSON": attributes,
                    })
    return indicators


def get_indicators_command(client: Client, args):
    itype = args.get('indicator_type', client.indicator_type)
    limit = int(args.get('limit'))
    indicators_list = fetch_indicators_command(client, itype)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators', entry_result, headers=['Value', 'Type', 'Rawjson'])
    feed_name = args.get('feed_name', 'HTTP')
    return hr, {f'{feed_name}.Indicator': entry_result}, indicators_list


def test_module(client, args):
    client.build_iterator()
    return 'ok', {}, {}


def feed_main(feed_name, params):
    params['feed_name'] = feed_name
    client = Client(**params)
    command = demisto.command()
    if command != 'fetch-indicators':
        demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands: dict = {
        'test-module': test_module,
        'get-indicators': get_indicators_command
    }
    try:
        if command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params.get('indicator_type'))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            args = demisto.args()
            args['feed_name'] = feed_name
            readable_output, outputs, raw_response = commands[command](client, args)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {feed_name} feed [{e}]'  # FEED_NAME should be in the integration code
        return_error(err_msg)
