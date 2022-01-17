import gzip
import json

from CommonServerPython import *
# IMPORTS
import urllib3
import csv
import requests
import traceback
import urllib.parse
from typing import Tuple, Optional, List, Dict

# Disable insecure warnings
urllib3.disable_warnings()
BATCH_SIZE = 2000
INTEGRATION_NAME = 'Recorded Future'

# taken from recorded future docs
RF_CRITICALITY_LABELS = {
    'Very_Malicious': 90,
    'Malicious': 65,
    'Suspicious': 25,
    'Unusual': 5
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    SOURCE_NAME = 'recordedfuture.masterrisklist'
    BASE_URL = 'https://api.recordedfuture.com/v2/'
    PARAMS = {'output_format': 'csv/splunk',
              'download': 1}  # for faster download
    headers = {'X-RF-User-Agent': 'Demisto',
               'content-type': 'application/json'}

    def __init__(self, indicator_type: str, api_token: str, services: list, risk_rule: str = None,
                 fusion_file_path: str = None, insecure: bool = False,
                 polling_timeout: int = 20, proxy: bool = False, threshold: int = 65,
                 tags: Optional[list] = None, tlp_color: Optional[str] = None):
        """
        Attributes:
             indicator_type: string, the indicator type of the feed.
             api_token: string, the api token for RecordedFuture.
             services: list, the services from RecordedFuture.
             risk_rule: string, an optional argument to the 'ConnectApi' service request.
             fusion_file_path: string, an optional argument to the 'Fusion' service request.
             insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
             polling_timeout: timeout of the polling request in seconds. Default: 20
             proxy: Sets whether use proxy when sending requests
             threshold: The minimum score from the feed in order to to determine whether the indicator is malicious.
             tags: A list of tags to add to indicators
             :param tlp_color: Traffic Light Protocol color
        """
        if tags is None:
            tags = []
        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            return_error('Please provide an integer value for "Request Timeout"')

        self.risk_rule = argToList(risk_rule)
        self.fusion_file_path = fusion_file_path if fusion_file_path != "" else None
        self.api_token = self.headers['X-RFToken'] = api_token
        self.services = services
        self.indicator_type = indicator_type
        self.threshold = int(threshold)
        self.tags = tags
        self.tlp_color = tlp_color
        super().__init__(self.BASE_URL, proxy=proxy, verify=not insecure)

    def _build_request(self, service, indicator_type, risk_rule: Optional[str] = None) -> requests.PreparedRequest:
        """Builds the request for the Recorded Future feed.
        Args:
            service (str): The service from recorded future. Can be 'connectApi' or 'fusion'
            indicator_type (str) The indicator type. Can be 'domain', 'ip', 'hash' or 'url'
            risk_rule(str): A risk rule that limits the fetched indicators

        Returns:
            requests.PreparedRequest: The prepared request which will be sent to the server
        """
        if service == 'connectApi':
            if risk_rule:
                url = self.BASE_URL + indicator_type + '/risklist?list=' + risk_rule
            else:
                url = self.BASE_URL + indicator_type + '/risklist'

            params = self.PARAMS
            params['gzip'] = True

            response = requests.Request(
                'GET',
                url,
                headers=self.headers,
                params=params
            )

        elif service == 'fusion':
            url = self.BASE_URL + 'fusion/files/?path='
            if self.fusion_file_path is None:
                fusion_path = '/public/risklists/default_' + indicator_type + '_risklist.csv'
            else:
                fusion_path = self.fusion_file_path

            fusion_path = urllib.parse.quote_plus(fusion_path)
            response = requests.Request('GET',
                                        url + fusion_path,
                                        headers=self.headers,
                                        params=self.PARAMS)
        else:
            raise DemistoException(f'Service unknown: {service}')
        return response.prepare()

    def build_iterator(self, service, indicator_type, risk_rule: Optional[str] = None):
        """Retrieves all entries from the feed.
        Args:
            service (str): The service from recorded future. Can be 'connectApi' or 'fusion'
            indicator_type (str): The indicator type. Can be 'domain', 'ip', 'hash' or 'url'
            risk_rule (str): A risk rule that limits the fetched indicators

        Returns:
            list of feed dictionaries.
        """
        _session = requests.Session()
        prepared_request = self._build_request(service, indicator_type, risk_rule)
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
        except requests.exceptions.HTTPError:
            if "Insufficient credits" in response.text:
                return_error("'Insufficient Credits' error was returned from Recorded Future. \n"
                             "Try increasing the integration's fetch interval in order to decrease the amount of API"
                             " requests made to Recorded Future. ")
            else:
                return_error(
                    '{} - exception in request: {} {}'.format(self.SOURCE_NAME, response.status_code, response.content))

        if service == 'connectApi':
            response_content = gzip.decompress(response.content)
            response_content = response_content.decode('utf-8')
            with open("response.txt", "w") as f:
                f.write(response_content)
        else:
            with open("response.txt", "w") as f:
                f.write(response.text)

    def get_batches_from_file(self, limit):

        file_stream = open("response.txt", 'rt')
        columns = file_stream.readline()  # get the headers from the csv file.
        columns = columns.replace("\"", "").strip().split(",")  # '"a","b"\n' -> ["a", "b"]

        batch_size = limit if limit else BATCH_SIZE
        while True:

            feed_batch = [feed for _, feed in zip(range(batch_size + 1), file_stream) if feed]

            if not feed_batch:
                file_stream.close()
                os.remove("response.txt")
                return

            yield csv.DictReader(feed_batch, fieldnames=columns)

    def calculate_indicator_score(self, risk_from_feed):
        """Calculates the Dbot score of an indicator based on its Risk value from the feed.
        Args:
            risk_from_feed (str): The indicator's risk value from the feed
        Returns:
            int. The indicator's Dbot score
        """
        dbot_score = 0
        risk_from_feed = int(risk_from_feed)
        if risk_from_feed >= self.threshold or risk_from_feed >= 65:
            dbot_score = 3
        elif risk_from_feed >= 5:
            dbot_score = 2

        return dbot_score

    def run_parameters_validations(self):
        """Checks validation of the risk_rule and fusion_file_path parameters
        Returns:
            None in success, Error otherwise
        """
        if self.risk_rule:
            if 'connectApi' not in self.services:
                return_error("You entered a risk rule but the 'connectApi' service is not chosen. "
                             "Add the 'connectApi' service to the list or remove the risk rule.")
            else:
                for risk_rule in self.risk_rule:
                    if not is_valid_risk_rule(self, risk_rule):
                        return_error(f"The given risk rule: {risk_rule} does not exist,"
                                     f"please make sure you entered it correctly. \n"
                                     f"To see all available risk rules run the '!rf-get-risk-rules' command.")

        if self.fusion_file_path is not None:
            if 'fusion' not in self.services:
                return_error("You entered a fusion file path but the 'fusion' service is not chosen. "
                             "Add the 'fusion' service to the list or remove the fusion file path.")

    def get_risk_rules(self, indicator_type: Optional[str] = None) -> dict:
        if indicator_type is None:
            indicator_type = self.indicator_type
        return self._http_request(
            method='GET',
            url_suffix=indicator_type + '/riskrules',
            params=self.PARAMS,
            headers=self.headers
        )


def is_valid_risk_rule(client: Client, risk_rule):
    """Checks if the risk rule is valid by requesting from RF a list of all available rules.
    Returns:
        bool. Whether the risk rule is valid or not
    """
    risk_rule_response: dict = client.get_risk_rules()
    risk_rules_list = [single_risk_rule['name'] for single_risk_rule in risk_rule_response['data']['results']]
    if risk_rule in risk_rules_list:
        return True
    else:
        return False


def test_module(client: Client, *args) -> Tuple[str, dict, dict]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client(Client): Recorded Future Feed client.
        args(dict): demisto.args()
    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.run_parameters_validations()

    for service in client.services:
        # if there are risk rules, select the first one for test
        risk_rule = client.risk_rule[0] if client.risk_rule else None
        client.build_iterator(service, client.indicator_type, risk_rule)
        client.get_batches_from_file(limit=1)
    return 'ok', {}, {}


def get_indicator_type(indicator_type, item):
    """Returns the indicator type in Demisto
    Args:
        indicator_type (str): ip, url, domain or hash
        item (dict): the indicator row from the csv response
    Returns:
        str. The indicator type per the indicators defined in Demisto
    """

    if indicator_type == 'ip':
        return ip_to_indicator_type(item.get('Name'))
    elif indicator_type == 'hash':
        return FeedIndicatorType.File
    elif indicator_type == 'domain':
        # If * is in the domain it is of type DomainGlob
        if '*' in item.get('Name', ''):
            return FeedIndicatorType.DomainGlob
        return FeedIndicatorType.Domain
    elif indicator_type == 'url':
        return FeedIndicatorType.URL


def ip_to_indicator_type(ip):
    """Returns the indicator type of the input IP.
    :type ip: ``str``
    :param ip: IP address to get it's indicator type.
    :rtype: ``str``
    :return:: Indicator type from FeedIndicatorType, or None if invalid IP address.
    """
    ip = str(ip)
    if re.match(ipv4cidrRegex, ip):
        return FeedIndicatorType.CIDR

    elif re.match(ipv4Regex, ip):
        return FeedIndicatorType.IP

    elif re.match(ipv6cidrRegex, ip):
        return FeedIndicatorType.IPv6CIDR

    elif re.match(ipv6Regex, ip):
        return FeedIndicatorType.IPv6

    else:
        return None


def calculate_recorded_future_criticality_label(risk_from_feed):
    risk_from_feed = int(risk_from_feed)
    if risk_from_feed >= RF_CRITICALITY_LABELS['Very_Malicious']:
        return 'Very Malicious'
    elif risk_from_feed >= RF_CRITICALITY_LABELS['Malicious']:
        return 'Malicious'
    elif risk_from_feed >= RF_CRITICALITY_LABELS['Suspicious']:
        return 'Suspicious'
    elif risk_from_feed >= RF_CRITICALITY_LABELS['Unusual']:
        return 'Unusual'
    else:
        return 'No current evidence of risk'


def format_risk_string(risk_string):
    """Formats the risk string returned from the feed
    Args:
        risk_string(str): The risk string from the feed, in 'X/X' format
    Returns:
        str. The formatted string
    """
    splitted_risk_string = risk_string.split('/')
    return f'{splitted_risk_string[0]} of {splitted_risk_string[1]} Risk Rules Triggered'


def fetch_and_create_indicators(client, risk_rule: Optional[str] = None):
    """Fetches indicators from the Recorded Future feeds,
    and from each fetched indicator creates an indicator in XSOAR.

    Args:
        client(Client): Recorded Future Feed client.
        risk_rule(str): A risk rule that limits the fetched indicators

    Returns: None.

    """
    for indicators in fetch_indicators_command(client, client.indicator_type, risk_rule):
        demisto.createIndicators(indicators)


def fetch_indicators_command(client, indicator_type, risk_rule: Optional[str] = None, limit: Optional[int] = None):
    """Fetches indicators from the Recorded Future feeds.
    Args:
        client(Client): Recorded Future Feed client
        indicator_type(str): The indicator type
        risk_rule(str): A risk rule that limits the fetched indicators
        limit(int): Optional. The number of the indicators to fetch
    Returns:
        list. List of indicators from the feed
    """
    indicators_value_set: Set[str] = set()
    for service in client.services:
        client.build_iterator(service, indicator_type, risk_rule)
        feed_batches = client.get_batches_from_file(limit)
        for feed_dicts in feed_batches:
            indicators = []
            for item in feed_dicts:
                raw_json = dict(item)
                raw_json['value'] = value = item.get('Name')
                if value in indicators_value_set:
                    continue
                indicators_value_set.add(value)
                raw_json['type'] = get_indicator_type(indicator_type, item)
                score = 0
                risk = item.get('Risk')
                if isinstance(risk, str) and risk.isdigit():
                    raw_json['score'] = score = client.calculate_indicator_score(risk)
                    raw_json['Criticality Label'] = calculate_recorded_future_criticality_label(risk)
                lower_case_evidence_details_keys = []
                evidence_details_value = item.get('EvidenceDetails', '{}')
                if evidence_details_value:
                    evidence_details = json.loads(evidence_details_value).get('EvidenceDetails', [])
                    if evidence_details:
                        raw_json['EvidenceDetails'] = evidence_details
                        for rule in evidence_details:
                            rule = dict((key.lower(), value) for key, value in rule.items())
                            lower_case_evidence_details_keys.append(rule)
                risk_string = item.get('RiskString')
                if isinstance(risk_string, str):
                    raw_json['RiskString'] = format_risk_string(risk_string)
                indicator_obj = {
                    'value': value,
                    'type': raw_json['type'],
                    'rawJSON': raw_json,
                    'fields': {
                        'recordedfutureevidencedetails': lower_case_evidence_details_keys,
                        'tags': client.tags,
                    },
                    'score': score
                }
                if client.tlp_color:
                    indicator_obj['fields']['trafficlightprotocol'] = client.tlp_color

                indicators.append(indicator_obj)

            yield indicators


def get_indicators_command(client, args) -> Tuple[str, Dict[Any, Any], List[Dict]]:
    """Retrieves indicators from the Recorded Future feed to the war-room.
        Args:
            client(Client): Recorded Future Feed client.
            args(dict): demisto.args()
        Returns:
            str, dict, list. the markdown table, context JSON and list of indicators
        """
    indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
    limit = int(args.get('limit'))

    human_readable: str = ''
    entry_results: List[Dict]
    indicators_list: List[Dict]

    if client.risk_rule:
        entry_results = []
        for risk_rule in client.risk_rule:
            indicators_list = []
            for indicators in fetch_indicators_command(client, indicator_type, risk_rule, limit):
                indicators_list.extend(indicators)

                if limit and len(indicators_list) >= limit:
                    break

            entry_result = camelize(indicators_list)
            entry_results.extend(entry_result)
            hr = tableToMarkdown(f'Indicators from RecordedFuture Feed for {risk_rule} risk rule:', entry_result,
                                 headers=['Value', 'Type'], removeNull=True)
            human_readable += f'\n{hr}'

    else:  # there are no risk rules
        indicators_list = []
        risk_rule = None
        for indicators in fetch_indicators_command(client, indicator_type, risk_rule, limit):
            indicators_list.extend(indicators)

            if limit and len(indicators_list) >= limit:
                break

        entry_results = camelize(indicators_list)
        human_readable = tableToMarkdown('Indicators from RecordedFuture Feed:', entry_results,
                                         headers=['Value', 'Type'], removeNull=True)

    return human_readable, {}, entry_results


def get_risk_rules_command(client: Client, args) -> Tuple[str, dict, dict]:
    """Retrieves all risk rules available from Recorded Future to the war-room.
        Args:
            client(Client): Recorded Future Feed client.
            args(dict): demisto.args()
        Returns:
            str, dict, list. the markdown table, context JSON and list of risk rules
        """
    indicator_type = args.get('indicator_type', demisto.params().get('indicator_type'))
    result = client.get_risk_rules(indicator_type)
    entry_result = []
    for entry in result['data']['results']:
        entry_result.append({
            'Name': entry.get('name'),
            'Description': entry.get('description'),
            'Criticality': entry.get('criticalityLabel')
        })
    headers = ['Name', 'Description', 'Criticality']
    hr = tableToMarkdown(f'Available risk rules for {indicator_type}:', entry_result, headers)
    return hr, {'RecordedFutureFeed.RiskRule(val.Name == obj.Name)': entry_result}, result


def main():
    params = demisto.params()
    client = Client(params.get('indicator_type'), params.get('api_token'), params.get('services'),
                    params.get('risk_rule'), params.get('fusion_file_path'), params.get('insecure'),
                    params.get('polling_timeout'), params.get('proxy'), params.get('threshold'),
                    argToList(params.get('feedTags'), params.get('tlp_color'))
                    )
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    # Switch case
    commands = {
        'test-module': test_module,
        'rf-feed-get-indicators': get_indicators_command,
        'rf-feed-get-risk-rules': get_risk_rules_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            if client.risk_rule:
                for risk_rule in client.risk_rule:
                    fetch_and_create_indicators(client, risk_rule)
            else:  # there are no risk rules
                fetch_and_create_indicators(client)

        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())  # type:ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}] \n Traceback: {traceback.format_exc()}'
        return_error(err_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
