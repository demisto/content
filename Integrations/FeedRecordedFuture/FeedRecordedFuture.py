import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS
import csv
import requests
import urllib.parse
from typing import Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
INTEGRATION_NAME = 'Recorded Future'

# CONSTANTS


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    SOURCE_NAME = 'recordedfuture.masterrisklist'
    BASE_URL = 'https://api.recordedfuture.com/v2/'
    PARAMS = {'output_format': 'csv/splunk'}
    HEADERS = {'X-RF-User-Agent': 'Demisto',
               'content-type': 'application/json'}

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
        """

        super().__init__(self.BASE_URL, proxy=proxy, verify=not insecure)
        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            return_error('Please provide an integer value for "Request Timeout"')

        self.risk_rule = risk_rule
        self.fusion_file_path = fusion_file_path
        self.api_token = self.HEADERS['X-RFToken'] = api_token
        self.sub_feed = sub_feed
        self.indicator_type = indicator_type

    def _build_request(self, sub_feed, indicator_type):
        """Builds the request for the Recorded Future feed.
        Args:
            sub_feed (str): The sub feed from recorded future. Can be 'connectApi' or 'fusion'
            indicator_type (str) The indicator type. Can be 'domain', 'ip', 'hash' or 'url'

        Returns:
            requests.PreparedRequest: The prepared request which will be sent to the server
        """
        if sub_feed == 'connectApi':
            if self.risk_rule is None:
                url = self.BASE_URL + indicator_type + '/risklist'
            else:
                url = self.BASE_URL + indicator_type + '/risklist?list=' + self.risk_rule

            response = requests.Request(
                'GET',
                url,
                headers=self.HEADERS,
                params=self.PARAMS
            )

        elif sub_feed == 'fusion':
            url = self.BASE_URL + 'fusion/files/?path='
            if self.fusion_file_path is None:
                fusion_path = '/public/risklists/default_' + indicator_type + '_risklist.csv'
            else:
                fusion_path = self.fusion_file_path

            fusion_path = urllib.parse.quote_plus(fusion_path)
            response = requests.Request('GET',
                                        url + fusion_path,
                                        headers=self.HEADERS,
                                        params=self.PARAMS)
        return response.prepare()

    def build_iterator(self, sub_feed, indicator_type):
        """Retrieves all entries from the feed.
        Args:
            sub_feed (str): The sub feed from recorded future. Can be 'connectApi' or 'fusion'
            indicator_type (str) The indicator type. Can be 'domain', 'ip', 'hash' or 'url'

        Returns:
            csv.DictReader: Iterates the csv returned from the api request
        """
        _session = requests.Session()
        prepared_request = self._build_request(sub_feed, indicator_type)
        # this is to honour the proxy environment variables
        rkwargs = _session.merge_environment_settings(
            prepared_request.url,
            {}, None, None, None  # defaults
        )
        rkwargs['stream'] = True
        rkwargs['verify'] = self._verify
        rkwargs['timeout'] = self.polling_timeout

        try:
            response = _session.send(prepared_request, **rkwargs)
        except requests.ConnectionError as e:
            raise requests.ConnectionError(f'Failed to establish a new connection: {str(e)}')
        try:
            response.raise_for_status()
        except Exception:
            return_error(
                '{} - exception in request: {} {}'.format(self.SOURCE_NAME, response.status_code, response.content))
            raise

        data = response.text.split('\n')

        csvreader = csv.DictReader(data)

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
        client(Client): Recorded Future Feed client.
        args(dict): demisto.args()
    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.build_iterator('connectApi', 'ip')
    return 'ok', {}, {}


def get_indicator_type(indicator_type, item):
    """Returns the indicator type in Demisto
    Args:
        indicator_type: ip, url, domain or hash
        item: the indicator row from the csv response
    Returns:
        The indicator type per the indicators defined in Demisto
    """

    if indicator_type == 'ip':
        return FeedIndicatorType.ip_to_indicator_type(item.get('Name'))
    elif indicator_type == 'hash':
        return FeedIndicatorType.File
    elif indicator_type == 'domain':
        return FeedIndicatorType.Domain
    elif indicator_type == 'url':
        return FeedIndicatorType.URL


def fetch_indicators_command(client, indicator_type):
    """Fetches indicators from the Recorded Future feeds to the indicators tab.
    Args:
        client(Client): Recorded Future Feed client.
        indicator_type(str): The indicator type
    Returns:
        list. List of indicators from the feed
    """
    indicators = []
    for feed in client.sub_feed:
        iterator = client.build_iterator(feed, indicator_type)
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


def get_indicators_command(client, args) -> Tuple[str, dict, dict]:
    """Retrieves indicators from the Recorded Future feed to the war-room.
        Args:
            client(Client): Recorded Future Feed client.
            args(dict): demisto.args()
        Returns:
            str, dict, list. the markdown table, context JSON and list of indicators
        """
    indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
    limit = int(args.get('limit'))
    indicators_list = fetch_indicators_command(client, indicator_type)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators from RecordedFuture Feed:', entry_result, headers=['Value', 'Type'])

    return hr, {}, indicators_list


def get_risk_rules_command(client: Client, args) -> Tuple[str, dict, dict]:
    """Retrieves all risk rules available from Recorded Future to the war-room.
        Args:
            client(Client): Recorded Future Feed client.
            args(dict): demisto.args()
        Returns:
            str, dict, list. the markdown table, context JSON and list of risk rules
        """
    indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
    result = client._http_request(
        method='GET',
        url_suffix=indicator_type + '/riskrules',
        params=client.PARAMS,
        headers=client.HEADERS
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
    client = Client(**demisto.params())
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands = {
        'test-module': test_module,
        'recordedFuture-get-indicators': get_indicators_command,
        'recordedFuture-get-risk-rules': get_risk_rules_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, client.indicator_type)
            # we submit the indicators in batches
            for b in old_batch(indicators, batch_size=2000):  # TODO change to commonserverpython batch
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())  # type:ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
