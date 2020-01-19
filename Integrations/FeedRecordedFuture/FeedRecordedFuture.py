import demistomock as demisto
from CommonServerPython import *
from typing import Tuple
from CommonServerUserPython import *
# IMPORTS
import requests
import ipaddress
import csv

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
INTEGRATION_NAME = 'Recorded Future'

# CONSTANTS
SOURCE_NAME = 'recordedfuture.masterrisklist'
BASE_URL = 'https://api.recordedfuture.com/v2/'
PARAMS = {'output_format': 'csv/splunk'}
HEADERS = {'X-RF-User-Agent': 'Demisto',
           'content-type': 'application/json'}
HASH_DT = {
    'MD5': 'File.MD5(val.MD5 && obj.MD5 == val.MD5)',
    'SHA256': 'File.SHA256(val.SHA256 && obj.SHA256 == val.SHA256)',
    'SHA1': 'File.SHA1(val.SHA1 && obj.SHA1 == val.SHA1)'
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, indicator_type: str, api_token: str, sub_feed: str, risk_rule: str = None,
                 fusion_file_path: str = None, insecure: bool = False,
                 polling_timeout: int = 20, proxy: bool = False, **kwargs):
        """
        Attributes:
             indicator_type: string, the indicator type of the feed.
             api_token: string, the api token for RecordedFuture.
             sub_feed: list, the sub feeds from RecordedFuture.
             risk_rule: string, an optional argument to the 'ConnectApi' sub feed request.
             fusion_file_path: string, an optional argument to the 'Fusion' sub feed request.
             insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
             polling_timeout: timeout of the polling request in seconds. Default: 20
             proxy: Sets whether use proxy when sending requests
             kwargs:
        """

        super().__init__(BASE_URL, proxy=proxy, verify=not insecure)

        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            return_error('Please provide an integer value for "Request Timeout"')

        self.risk_rule = risk_rule
        self.fusion_file_path = fusion_file_path
        self.api_token = HEADERS['X-RFToken'] = api_token
        self.sub_feed = sub_feed
        self.indicator_type = indicator_type

    def _build_request(self, sub_feed, indicator_type):
        if sub_feed == 'connectApi':
            if self.risk_rule is None:
                url = BASE_URL + indicator_type + '/risklist'
            else:
                url = BASE_URL + indicator_type + '/risklist?list=' + self.risk_rule

            r = requests.Request(
                'GET',
                url,
                headers=HEADERS,
                params=PARAMS
            )
            return r.prepare()

        if sub_feed == 'fusion':
            url = BASE_URL + 'fusion/files/?path='
            if self.fusion_file_path is None:
                fusion_path = '/public/risklists/default_' + indicator_type + '_risklist.csv'
            else:
                fusion_path = self.fusion_file_path

            fusion_path = fusion_path.replace('/', '%2F')
            r = requests.Request('GET',
                                 url + fusion_path,
                                 headers=HEADERS,
                                 params=PARAMS)
            return r.prepare()

    def build_iterator(self, sub_feed, indicator_type):
        """Retrieves all entries from the feed.
        Args:

        Returns:
        csv iterator
        """
        _session = requests.Session()
        prepreq = self._build_request(sub_feed, indicator_type)
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

        csvreader = csv.DictReader(response)

        return csvreader


# # simple function to iterate list in batches
def old_batch(iterable, batch_size=1):
    current_batch = []
    for item in iterable:
        current_batch.append(item)
        if len(current_batch) == batch_size:
            yield current_batch
            current_batch = []
    if current_batch:
        yield current_batch


def test_module(client: Client, args: dict) -> Tuple[str, dict, dict]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """

    client.build_iterator('connectApi', 'ip')
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
        return 'File ' + item.get('Algorithm')
    elif indicator_type == 'domain':
        return 'Domain'
    elif indicator_type == 'url':
        return 'URL'


def fetch_indicators_command(client, indicator_type):
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client: Client object with request
    Returns:
        Indicators.
    """
    indicators = []
    indicator_context = []
    for feed in client.sub_feed:
        iterator = client.build_iterator(feed, indicator_type)
        for item in iterator:
            raw_json = dict(item)
            raw_json['value'] = value = item.get('Name')
            raw_json['type'] = demisto_indicator_type = get_indicator_type(indicator_type, item)
            indicators.append({
                "value": value,
                "type": raw_json['type'],
                "rawJSON": raw_json,
            })

            indicator_context.append(get_indicator_context(demisto_indicator_type, value))

    return indicators, indicator_context


def get_indicator_context(indicator_type, value):
    if indicator_type == 'IP':
        return {'Address': value}

    elif indicator_type == 'Domain':
        return {'Name': value}

    elif indicator_type == 'File SHA-256':
        return {'SHA256': value}

    elif indicator_type == 'File MD5':
        return {'MD5': value}

    elif indicator_type == 'File SHA-1':
        return {'SHA1': value}

    elif indicator_type == 'URL':
        return {'Data': value}


def split_hash_context(entry_result):
    sha256_context = []
    md5_context = []
    sha1_context = []

    for entry in entry_result:
        if entry['Type'] == 'MD5':
            md5_context.append(entry['Value'])
        elif entry['Type'] == 'SHA-1':
            sha1_context.append(entry['Value'])
        else:
            sha256_context.append(entry['Value'])

    return sha256_context, md5_context, sha1_context


def get_indicators_command(client, args) -> Tuple[str, dict, dict]:
    """Retrieves indicators from the feed to the war-room.
        Args:
            client: Client object with request
            args: demisto.args()
        Returns:
            Outputs.
        """
    indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
    limit = int(args.get('limit'))
    indicators_list, indicator_context = fetch_indicators_command(client, indicator_type)
    entry_result = camelize(indicators_list[:limit])
    indicator_context = indicator_context[:limit]
    hr = tableToMarkdown('Indicators from RecordedFuture Feed:', entry_result, headers=['Value', 'Type'])
    if indicator_type == 'hash':
        sha256_context, md5_context, sha1_context = split_hash_context(entry_result)
        result_dict = {'RecordedFutureFeed.Indicator': entry_result,
                       HASH_DT['MD5']: md5_context,
                       HASH_DT['SHA256']: sha256_context,
                       HASH_DT['SHA1']: sha1_context}

    else:
        result_dict = {'RecordedFutureFeed.Indicator': entry_result,
                       outputPaths[indicator_type]: indicator_context}

    return hr, result_dict, indicators_list


def get_risk_rules_command(client: Client, args) -> Tuple[str, dict, dict]:
    indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
    result = client._http_request(
        method='GET',
        url_suffix=indicator_type + '/riskrules',
        params=PARAMS,
        headers=HEADERS
    )
    entry_result = []
    for entry in result['data']['results']:
        entry_result.append({
            'Name': entry.get('name'),
            'Description': entry.get('description'),
            'Criticality': entry.get('criticalityLabel')
        })
    headers = ['Name', 'Description', 'Criticality']
    hr = tableToMarkdown(f'Available risk rules for {indicator_type}:', entry_result, headers)
    return hr, {'RecordedFutureFeed.RiskRule': entry_result}, result


def main():
    handle_proxy()
    client = Client(**demisto.params())
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
            indicators, _ = fetch_indicators_command(client, {})
            # we submit the indicators in batches
            for b in old_batch(indicators, batch_size=2000):  # TODO change to commonserverpython batch
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, client.indicator_type)  # type:ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
