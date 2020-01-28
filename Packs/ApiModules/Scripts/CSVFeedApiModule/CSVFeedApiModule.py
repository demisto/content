import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import csv
from typing import Optional, Pattern, Dict, Any

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, url: str, feed_url_to_config: Optional[Dict[str, dict]] = None, fieldnames: str = '',
                 insecure: bool = False, credentials: dict = None, ignore_regex: str = None, encoding: str = 'latin-1',
                 delimiter: str = ',', doublequote: bool = True, escapechar: str = '', api_key: bool = False,
                 quotechar: str = '"', skipinitialspace: bool = False, polling_timeout: int = 20, proxy: bool = False,
                 **kwargs):
        """
        :param url: URL of the feed.
        :param feed_url_to_config: for each URL, a list of field names in the file.
         If *null* the values in the first row of the file are used as names. Default: *null*
         Example:
         url_to_fieldnames = {
            'https://ipstack.com': ['indicator']
         }
        :param fieldnames: list of field names in the file. If *null* the values in the first row of the file are
            used as names. Default: *null*
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param credentials: username and password used for basic authentication
        :param ignore_regex: python regular expression for lines that should be ignored. Default: *null*
        :param encoding: Encoding of the feed, latin-1 by default.
        :param delimiter: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default: ,
        :param doublequote: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default: true
        :param escapechar: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default null
        :param quotechar: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default "
        :param skipinitialspace: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default False
        :param polling_timeout: timeout of the polling request in seconds. Default: 20
        :param proxy: Sets whether use proxy when sending requests
        """
        if not credentials:
            credentials = {}

        auth: Optional[tuple] = None
        self.headers = {}

        if api_key:
            header_name = credentials.get('identifier', None)
            header_value = credentials.get('password', None)
            self.headers[header_name] = header_value
        else:
            username = credentials.get('identifier', None)
            password = credentials.get('password', None)
            auth = None
            if username is not None and password is not None:
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

            if self.headers:
                if 'headers' in kwargs:
                    kwargs['headers'].update(self.headers)
                else:
                    kwargs['headers'] = self.headers

            try:
                r = _session.send(prepreq, **kwargs)
            except requests.ConnectionError:
                raise requests.ConnectionError('Failed to establish a new connection.'
                                               ' Please make sure your URL is valid.')
            try:
                r.raise_for_status()
            except Exception:
                return_error('Exception in request: {} {}'.format(r.status_code, r.content))
                raise

            response = r.content.decode(self.encoding).split('\n')
            if self.feed_url_to_config:
                fieldnames = self.feed_url_to_config.get(url, {}).get('fieldnames', [])
            else:
                fieldnames = self.fieldnames
            if self.ignore_regex is not None:
                response = filter(
                    lambda x: self.ignore_regex.match(x) is None,  # type: ignore[union-attr]
                    response
                )

            csvreader = csv.DictReader(
                response,
                fieldnames=fieldnames,
                **self.dialect
            )

            results.append({url: csvreader})

        return results


def module_test_command(client: Client, args):
    if not client.feed_url_to_config:
        indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
        if not FeedIndicatorType.is_valid_type(indicator_type):
            supported_values = ', '.join((
                FeedIndicatorType.Account,
                FeedIndicatorType.CVE,
                FeedIndicatorType.Domain,
                FeedIndicatorType.Email,
                FeedIndicatorType.File,
                FeedIndicatorType.MD5,
                FeedIndicatorType.SHA1,
                FeedIndicatorType.SHA256,
                FeedIndicatorType.Host,
                FeedIndicatorType.IP,
                FeedIndicatorType.CIDR,
                FeedIndicatorType.IPv6,
                FeedIndicatorType.IPv6CIDR,
                FeedIndicatorType.Registry,
                FeedIndicatorType.SSDeep,
                FeedIndicatorType.URL
            ))
            raise ValueError(f'Indicator type of {indicator_type} is not supported. Supported values are:'
                             f' {supported_values}')
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators_command(client: Client, default_indicator_type: str, **kwargs):
    iterator = client.build_iterator(**kwargs)
    indicators = []

    for url_to_reader in iterator:
        for url, reader in url_to_reader.items():
            for item in reader:
                raw_json = dict(item)
                value = item.get('indicator')
                if not value and len(item) == 1:
                    value = next(iter(item.values()))
                else:
                    del raw_json['indicator']
                if value:
                    raw_json['value'] = value
                    if client.feed_url_to_config:
                        indicator_type = client.feed_url_to_config.get(url, {}).get('indicator_type')
                    else:
                        indicator_type = default_indicator_type
                    raw_json['type'] = indicator_type
                    indicators.append({
                        'value': value,
                        'type': indicator_type,
                        'rawJSON': raw_json,
                    })
    return indicators


def get_indicators_command(client, args):
    itype = args.get('indicator_type', demisto.params().get('indicator_type'))
    limit = int(args.get('limit'))
    indicators_list = fetch_indicators_command(client, itype)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators', entry_result, headers=['value', 'type', 'rawJSON'])
    feed_name_context = args.get('feed_name', 'CSV').replace(' ', '')
    return hr, {f'{feed_name_context}.Indicator': entry_result}, indicators_list


def feed_main(feed_name, params=None, prefix=''):
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
            indicators = fetch_indicators_command(client, params.get('indicator_type'))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore
        else:
            args = demisto.args()
            args['feed_name'] = feed_name
            readable_output, outputs, raw_response = commands[command](client, args)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {feed_name} Integration - Encountered an issue with createIndicators' if \
            'failed to create' in str(e) else f'Error in {feed_name} Integration [{e}]'
        return_error(err_msg)
