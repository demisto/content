import demistomock as demisto
from CommonServerPython import *
from typing import Dict, Tuple, List
from CommonServerUserPython import *
# IMPORTS
import requests
import ipaddress
import csv


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
INTEGRATION_NAME = 'Recorded Future'

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SOURCE_NAME = 'recordedfuture.masterrisklist'
BASE_URL = 'https://api.recordedfuture.com/v2/'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, indicator_types: str, api_token: str, api_type: str, risk_rule: str = None, fusion_path: str = None, insecure: bool = False,
                 ignore_regex: str = None, polling_timeout: int = 20, proxy: bool = False, path: str = None, **kwargs):
        """
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param credentials: username and password used for basic authentication
        :param ignore_regex: python regular expression for lines that should be ignored. Default: *null*
        :param polling_timeout: timeout of the polling request in seconds. Default: 20
        :param proxy: Sets whether use proxy when sending requests
        :param kwargs:
        """

        super().__init__(BASE_URL, proxy=proxy, verify=not insecure)

        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            return_error('Please provide an integer value for "Request Timeout"')

        self.risk_rule = risk_rule
        self.ignore_regex = ignore_regex
        self.fusion_path = fusion_path
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)  # type: ignore

        self.dialect = {
            'delimiter': ',',
            'doublequote': True,
            'escapechar': '',
            'quotechar': '"',
            'skipinitialspace': False
        }

        self.api_token = api_token
        self.api_type = api_type
        self.indicator_types = indicator_types
        self.path = path

    def _build_request(self, indicator_type):

        if self.api_type == 'connectApi':
            if self.risk_rule is None:
                url = BASE_URL + str(indicator_type) + '/risklist'
            else:
                url = BASE_URL + str(indicator_type) + '/risklist?list=' + self.risk_rule
            params = {'output_format': 'csv/splunk'}
            headers = {'X-RFToken': self.api_token, 'X-RF-User-Agent': 'Demisto',
                       'content-type': 'application/json'}

            r = requests.Request(
                'GET',
                url,
                headers=headers,
                params=params
            )
            return r.prepare()

        if self.api_type == 'fusion':
            if self.path is None:
                suffix = '/public/risklists/default_' + str(indicator_type) + '_risklist.csv'
            else:
                suffix = self.path

            suffix = suffix.replace('/', '%2F')
            params = {'output_format': 'csv/splunk'}
            headers = {'X-RFToken': self.api_token, 'X-RF-User-Agent': 'Demisto',
                       'content-type': 'application/json'}
            r = requests.Request('GET',
                                 BASE_URL + 'fusion/files/?path=' + suffix,
                                 headers=headers,
                                 params=params)

            return r.prepare()

    def build_iterator(self, indicator_type):
        """Retrieves all entries from the feed.
        Args:

        Returns:
        A list of objects, containing the indicators.
        """
        _session = requests.Session()

        prepreq = self._build_request(indicator_type)
        # this is to honour the proxy environment variables
        rkwargs = _session.merge_environment_settings(
            prepreq.url,
            {}, None, None, None  # defaults
        )
        rkwargs['stream'] = True
        rkwargs['verify'] = self._verify
        rkwargs['timeout'] = self.polling_timeout

        try:
            r = _session.send(prepreq, **rkwargs)
        except requests.ConnectionError:
            raise requests.ConnectionError('Failed to establish a new connection. Please make sure your URL is valid.')
        try:
            r.raise_for_status()
        except Exception:
            return_error('{} - exception in request: {} {}'.format(SOURCE_NAME, r.status_code, r.content))
            raise

        response = r.content.decode('latin-1').split('\n')
        if self.ignore_regex is not None:
            response = filter(
                lambda x: self.ignore_regex.match(x) is None,
                response
            )

        csvreader = csv.DictReader(
            response,
            **self.dialect
        )

        return csvreader


# simple function to iterate list in batches
def batch(iterable, batch_size=1):
    current_batch = []
    for item in iterable:
        current_batch.append(item)
        if len(current_batch) == batch_size:
            yield current_batch
            current_batch = []
    if current_batch:
        yield current_batch


def test_module(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """

    client.build_iterator('ip')
    return 'ok', {}, {}


def get_ip_type(indicator):
    """Checks the indicator type
    Args:
        indicator: IP
    Returns:
        The IP type per the indicators defined in Demisto
    """
    is_CIDR = False
    try:
        address_type = ipaddress.ip_address(indicator)
    except Exception:
        try:
            address_type = ipaddress.ip_network(indicator)
            is_CIDR = True
        except Exception:
            demisto.debug(F'{INTEGRATION_NAME} - Invalid ip range: {indicator}')
            return {}
    if address_type.version == 4:
        type_ = 'CIDR' if is_CIDR else 'IP'
    elif address_type.version == 6:
        type_ = 'IPv6CIDR' if is_CIDR else 'IPv6'
    else:
        LOG(F'{INTEGRATION_NAME} - Unknown IP version: {address_type.version}')
        return {}
    return type_


def get_indicator_type(indicator_type, item):
    """Checks the indicator type
    Args:
        indicator_type: IP, URL, domain or hash
        item: the indicator row from the csv response
    Returns:
        The indicator type per the indicators defined in Demisto
    """

    if indicator_type == 'ip':
        return get_ip_type(item.get('Name'))
    elif indicator_type == 'hash':
        return item.get('Algorithm')
    else:
        return indicator_type


def fetch_indicators_command(client):
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client: Client object with request
    Returns:
        Indicators.
    """
    indicators = []
    for indicator_type in client.indicator_types:
        iterator = client.build_iterator(indicator_type)
        for item in iterator:
            raw_json = dict(item)
            raw_json['value'] = value = item.get('Name')
            raw_json['type'] = get_indicator_type(indicator_type, item)
            indicators.append({
                "value": value,
                "type": raw_json['type'],
                "rawJSON": raw_json,
            })
    return indicators


def get_indicators_command(client, args):
    """Retrieves indicators from the feed to the war-room.
        Args:
            client: Client object with request
            args: demisto.args()
        Returns:
            Outputs.
        """
    # indicator_types = args.get('indicator_types', demisto.params().get('indicator_types'))
    limit = int(args.get('limit'))
    indicators_list = fetch_indicators_command(client)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators from RecordedFuture Feed:', entry_result, headers=['Value', 'Type'])
    return hr, {'RecordedFutureFeed.Indicator': entry_result}, indicators_list


def get_risk_rules_command(client: Client, args):
    indicator_type = args.get('indicator_type')
    result = client._http_request(
        method='GET',
        url_suffix=indicator_type + '/riskrules',
        params={'output_format': 'csv/splunk'},
        headers={'X-RFToken': client.api_token, 'X-RF-User-Agent': 'Demisto',
                 'content-type': 'application/json'}
    )
    entry_result = []
    for entry in result['data']['results']:
        entry_result.append({
            'Name': entry.get('name'),
            'Description': entry.get('description'),
            'Criticality Label': entry.get('criticalityLabel')
        })
    headers = ['Name', 'Description', 'Criticality Label']
    hr = tableToMarkdown(f'Available risk rules for {indicator_type}:', entry_result, headers)
    return hr, {'RecordedFutureFeed.RiskRule': entry_result}, result


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    handle_proxy()
    client = Client(**params)
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands = {
        'test-module': test_module,
        'get-indicators': get_indicators_command,
        'get-risk-rules': get_risk_rules_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
