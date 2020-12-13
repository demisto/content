import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from dataclasses import dataclass


### GENERATED CODE ###
# This code was inserted in place of an API module.


''' IMPORTS '''
import csv
import gzip
import urllib3
from dateutil.parser import parse
from typing import Optional, Pattern, Dict, Any, Tuple, Union, List

# disable insecure warnings
urllib3.disable_warnings()

# Globals


class Client(BaseClient):
    def __init__(self, url: str, feed_url_to_config: Optional[Dict[str, dict]] = None, fieldnames: str = '',
                 insecure: bool = False, credentials: dict = None, ignore_regex: str = None, encoding: str = 'latin-1',
                 delimiter: str = ',', doublequote: bool = True, escapechar: str = '',
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
        :param fieldnames: list of field names in the file. If *null* the values in the first row of the file are
            used as names. Default: *null*
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param credentials: username and password used for basic authentication.
        Can be also used as API key header and value by specifying _header in the username field.
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

            response = self.get_feed_content_divided_to_lines(url, r)
            if self.feed_url_to_config:
                fieldnames = self.feed_url_to_config.get(url, {}).get('fieldnames', [])
            else:
                fieldnames = self.fieldnames
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

            results.append({url: csvreader})

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
    formatted_date = parse(date_string).isoformat()
    if "+" in formatted_date:
        formatted_date = formatted_date.split('+')[0]

    if "." in formatted_date:
        formatted_date = formatted_date.split('.')[0]

    if not formatted_date.endswith('Z'):
        formatted_date = formatted_date + 'Z'

    return formatted_date


def create_fields_mapping(raw_json: Dict[str, Any], mapping: Dict[str, Union[Tuple, str]]):
    fields_mapping = {}  # type: dict

    for key, field in mapping.items():
        regex_extractor = None
        formatter_string = None

        if isinstance(field, tuple):
            field, regex_extractor, formatter_string = field

        if not raw_json.get(field):  # type: ignore
            continue

        if not regex_extractor:
            field_value = raw_json[field]  # type: ignore
        else:
            try:
                field_value = re.match(regex_extractor, raw_json[field]).group(1)  # type: ignore
            except Exception:
                field_value = raw_json[field]  # type: ignore

        fields_mapping[key] = formatter_string.format(field_value) if formatter_string else field_value

        if key in ['firstseenbysource', 'lastseenbysource']:
            fields_mapping[key] = date_format_parsing(fields_mapping[key])

    return fields_mapping


def fetch_indicators_command(client: Client, default_indicator_type: str, auto_detect: bool, limit: int = 0, **kwargs):
    iterator = client.build_iterator(**kwargs)
    indicators = []
    config = client.feed_url_to_config or {}
    for url_to_reader in iterator:
        for url, reader in url_to_reader.items():
            mapping = config.get(url, {}).get('mapping', {})
            for item in reader:
                raw_json = dict(item)
                value = item.get(client.value_field)
                if not value and len(item) > 1:
                    value = next(iter(item.values()))
                if value:
                    raw_json['value'] = value
                    conf_indicator_type = config.get(url, {}).get('indicator_type')
                    indicator_type = determine_indicator_type(conf_indicator_type, default_indicator_type, auto_detect,
                                                              value)
                    raw_json['type'] = indicator_type
                    indicator = {
                        'value': value,
                        'type': indicator_type,
                        'rawJSON': raw_json,
                        'fields': create_fields_mapping(raw_json, mapping) if mapping else {}
                    }
                    indicator['fields']['tags'] = client.tags

                    if client.tlp_color:
                        indicator['fields']['trafficlightprotocol'] = client.tlp_color

                    indicators.append(indicator)
                    # exit the loop if we have more indicators than the limit
                    if limit and len(indicators) >= limit:
                        return indicators

    return indicators


def get_indicators_command(client, args: dict, tags: Optional[List[str]] = None):
    if tags is None:
        tags = []
    itype = args.get('indicator_type', demisto.params().get('indicator_type'))
    try:
        limit = int(args.get('limit', 50))
    except ValueError:
        raise ValueError('The limit argument must be a number.')
    auto_detect = demisto.params().get('auto_detect_type')
    indicators_list = fetch_indicators_command(client, itype, auto_detect, limit)
    entry_result = indicators_list[:limit]
    hr = tableToMarkdown('Indicators', entry_result, headers=['value', 'type', 'fields'])
    return hr, {}, indicators_list


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
            indicators = fetch_indicators_command(
                client,
                params.get('indicator_type'),
                params.get('auto_detect_type'),
                params.get('limit'),
            )
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


# disable insecure warningsø
urllib3.disable_warnings()

''' CONSTANTS '''
SERVER_URL = 'https://www.bitcoinabuse.com/api/'
API_KEY = demisto.params().get('api_key', '')
FEED_ENDPOINT_PREFIX = 'download/'
REPORT_ADDRESS_ENDPOINT_PREFIX = 'reports/create'
abuse_type_name_to_id: Dict[str, int] = {
    'ransomware': 1,
    'darknet market': 2,
    'bitcoin tumbler': 3,
    'blackmail scam': 4,
    'sextortio': 5,
    'other': 99
}
OTHER_ABUSE_TYPE_ID = 99
REPORT_ADDRESS_SUFFIX = '/reports/create'


@dataclass
class _ReportAddressParams:
    """
    contains all the parameters required for reporting address post http request
    Fields:
        api_token: the api token to connect to Bitcoin Abuse API
        address: the address of the abuser
        abuse_type_id: an id which indicates which type of abuse was made
        abuse_type_other: incase abuse_type_id was other, holds information describing the abuse type
        abuser: information about the abuser (email, name, ...)
        description: description of the abuse (may include email sent, etc)
    """
    api_token: str
    address: str
    abuse_type_id: int
    abuse_type_other: Optional[str]
    abuser: str
    description: str


@dataclass
class _DownloadParams:
    """
    contains all the parameters required for downloading csv get http request
    Fields:
        api_token: the api token to connect to Bitcoin Abuse API
    """
    api_token: str


class BitcoinAbuseClient(BaseClient):

    def report_address(self, report_address_params: _ReportAddressParams) -> str:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            report_address_params: _ReportAddressParams contains all the required parameters for report address http post request
        Returns:
            Returns if post request was successful.
        """
        return self._http_request(
            method='POST',
            url_suffix=REPORT_ADDRESS_SUFFIX,
            params=vars(report_address_params)
        )

    def download_csv(self, download_params: _DownloadParams, time_period: str) -> str:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            download_params: _DownloadParams contains all the required parameters for download get http request
            time_period: str the time period to receive in the csv from Bitcoin Abuse API.
                         Allowed options are 1d, 30d, or forever
        Returns:
            Returns response representing the csv file of text if get request was successful.
        """
        url_suffix = FEED_ENDPOINT_PREFIX + time_period
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=vars(download_params),
            resp_type='text'
        )


def test_module(client: BitcoinAbuseClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :param client: BitcoinAbuseClient the client to use for the api request

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    params = demisto.params()

    time_period = params.get('fetchInterval')

    download_params = _DownloadParams(API_KEY)
    client.download_csv(download_params, time_period)
    return "ok"  # TODO TOM: implement test module


def fetch_indicators() -> None:
    """
    Wrapper which calls to CSVFeedApiModule for fetching indicators from the feed to the Indicators tab.
    """
    params = {k: v for k, v in demisto.params().items() if v is not None}

    fetch_interval = params.get('fetchInterval')

    feed_url_to_config = {
        f'{SERVER_URL}{FEED_ENDPOINT_PREFIX}{fetch_interval}?api_token={API_KEY}': {
            'fieldnames': ['id', 'address', 'abuse_type_id', 'abuse_type_other', 'abuser',
                           'description', 'from_country', 'from_country_code', 'created_at'],
            'indicator_type': 'Cryptocurrency Address',
            'mapping': {
                'address': 'value',
                'from_country': 'Country Name',
                'created_at': 'Creation Date',
                'description': 'Bitcoin Abuse Description',
                'abuse_type': 'todo '  # TODO TOM
            }
        }
    }

    params['url'] = f'{SERVER_URL}{FEED_ENDPOINT_PREFIX}{fetch_interval}?api_token={API_KEY}'
    params['feed_url_to_config'] = feed_url_to_config
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Bitcoin Abuse Feed', params, 'bitcoin')


def report_address_command(client: BitcoinAbuseClient) -> str:
    """
    Reports a bitcoin abuse to Bitcoin Abuse integration

    :param client: BitcoinAbuseClient  used to post abuse to the api
    :return: 'ok' if http request was successful
    """
    args = demisto.args()

    def is_valid_abuse_type(abuse_id, abuse_info):
        valid_other_abuse_id = abuse_id == OTHER_ABUSE_TYPE_ID and abuse_info is not None
        valid_rest_abuse_id = abuse_id is not None and abuse_id is not None
        return valid_rest_abuse_id or valid_other_abuse_id

    abuse_type_id = abuse_type_name_to_id.get(args.get('abuse_type', ''))
    abuse_type_other = args.get('abuse_type_other')

    if not is_valid_abuse_type(abuse_type_id, abuse_type_other):
        raise DemistoException("TODO WHAT TO WRITE")  # TODO TOM WHICH ERROR TO RAISE?

    report_address_params = _ReportAddressParams(
        api_token=API_KEY,
        address=args.get('address', ''),
        abuse_type_id=abuse_type_id,
        abuse_type_other=abuse_type_other,
        abuser=args.get('abuser', ''),
        description=args.get('description', '')
    )
    return client.report_address(report_address_params)


def main() -> None:
    command = demisto.command()

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    client = BitcoinAbuseClient(
        base_url=SERVER_URL,
        verify=verify_certificate,
        proxy=proxy)
    try:

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-indicators':
            fetch_indicators()

        elif command == 'bitcoin-report-address':
            return_results(report_address_command(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
