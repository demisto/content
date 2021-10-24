# IMPORTS

# import json

# import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
from typing import Any, Dict, List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class pXScoring():
    """
    Class to handle all current and future scoring for PerimeterX objects
    """

    def add_score_to_ip_list(self, ip_address: str, risk_score: int, thresholds: Dict[str, Any]):
        """
        Create the DBotScore structure first using the Common.DBotScore class.

        :type ip_address: ``str``
        :param ip_address: IP Address to be used as the indicator for this entry

        :type risk_score: ``int``
        :param risk_score: PerimeterX provided risk score for the IP Address

        :return: Updated List of Common IP Addresses with this entry appended
        :rtype: ``List[Common.IP]``
        """

        # create the DBotScore object and populate it with the needed values
        dbot_score = Common.DBotScore(
            indicator=ip_address,
            indicator_type=DBotScoreType.IP,
            integration_name='PerimeterX',
            score=self.dbotscore_from_risk(risk_score, thresholds),
            malicious_description='Something random from PerimeterX for now enjoy!'
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=ip_address,
            # asn=ip_data.get('asn'),
            dbot_score=dbot_score
        )

        self.ip_standard_list.append(ip_standard_context)

    def __init__(self):
        """
        Init the pXScoring Object

        :return: Empty List of Common IP Addresses
        :rtype: ``List[Common.IP]``
        """

        self.ip_standard_list: List[Common.IP] = []

    def dbotscore_from_risk(self, risk_score: int, thresholds: Dict[str, Any]) -> int:
        """
        Create the DBotScore structure first using the Common.DBotScore class.

        :type risk_score: ``int``
        :param risk_score: PerimeterX provided risk score for the IP Address

        :return: Returns the relevant DBotScore value for the provided PerimeterX risk score
        :rtype: ``int``
        """

        if risk_score > thresholds['bad_threshold']:
            dbot_score = Common.DBotScore.BAD  # bad

        elif risk_score > thresholds['suspicious_threshold']:
            dbot_score = Common.DBotScore.SUSPICIOUS  # suspicious

        elif risk_score > thresholds['good_threshold']:
            dbot_score = Common.DBotScore.GOOD  # good

        else:
            dbot_score = Common.DBotScore.NONE  # unknown

        return dbot_score


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def test_api_connection(self) -> Dict[str, Any]:
        """
        Makes a call to the status API path to confirm the proper URL and Authorization token were provided
        """
        
        api_key = demisto.params().get('apikey')

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        return self._http_request(
            method='GET',
            url_suffix='?search=ip:1.1.1.1&tops=path',
            headers=headers
        )

    def post_investigate_by_ip(self, ip_type: str, ip_address: str) -> Dict[str, Any]:
        """
        Query the PerimeterX API to get the relevant details regarding the provided IP within a particular customer's own data

        :type ip_address: ``str``
        :param ip_address: IP Address to be used as the indicator for this entry

        :type ip_type: ``str``
        :param ip_type: The type of IP address we will be querying (true_ip or socket_ip)

        :return: The JSON response body from the PerimeterX API
        :rtype: ``Dict[str, Any]``
        """

        api_key = demisto.params().get('apikey')

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        request_params: Dict[str, Any] = {}

        #if ip_type:
        #    request_params['ip_type'] = ip_type

        if ip_address:
            request_params['ip_address'] = f'search=ip:{ip_address}'

        return self._http_request(
            method='GET',
            url_suffix = f'?{request_params["ip_address"]}&tops=user-agent,path,socket_ip_classification',
            headers=headers
        )

    def post_investigate_by_name(self, name_type: str, name: str) -> Dict[str, Any]:
        """
        THIS IS NOT CURRENTLY IMPLEMENTED
        Query the PerimeterX API to get the relevant details regarding the provided name within a particular customer's own data

        :type name: ``str``
        :param name: name to be used as the indicator for this entry

        :type name_type: ``str``
        :param name_type: The type of name we will be querying (domain or param)

        :return: The JSON response body from the PerimeterX API
        :rtype: ``Dict[str, Any]``
        """

        request_params: Dict[str, Any] = {}

        if name_type:
            request_params['name_type'] = name_type

        if name:
            request_params['name'] = name

        return self._http_request(
            method='POST',
            url_suffix='',
            json_data=request_params
        )


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: PerimeterX client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.test_api_connection()
    if result['message'] == 'ok':
        return 'ok'
    else:
        return 'Test failed because something wasn\'t right'


def perimeterx_get_investigate_details(client: Client, args: Dict[str, Any], thresholds: Dict[str, Any]) -> CommandResults:
    """
    Collect the required details to query the PerimeterX API to get the relevant details regarding the provided
    search term within a particular customer's own data

    :type search_term: ``str``
    :param search_term: This is the entry that we'll be querying for against the PerimeterX API

    :type search_type: ``str``
    :param search_type: The type of query that will be run against the PerimeterX API

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    # Check for the field to query for
    search_type = args.get('search_type', None)
    if not search_type:
        raise ValueError('No search_type specified')

    # Check to make sure we have a query term
    search_term = args.get('search_term', None)
    if not search_term:
        raise ValueError('No search_term specified')

    # Check for an IP based investigation
    supported_ip_search_types = ['true_ip', 'socket_ip']

    # risk_score=result['maxRiskScore']

    if search_type in supported_ip_search_types:
        """
        Run an IP based search if the search type is one supported by the IP types
        """
        result = client.post_investigate_by_ip(ip_type=search_type, ip_address=search_term)

        pXScore = pXScoring()
        
        pXScore.add_score_to_ip_list(ip_address=search_term, risk_score=result['max_risk_score'], thresholds=thresholds)

        return CommandResults(
            outputs_prefix='PerimeterX',
            outputs_key_field='',
            outputs=result,
            indicators=pXScore.ip_standard_list
        )

    elif search_type == 'name':
        """
        THIS IS NOT CURRENTLY IMPLEMENTED
        Run a name based search if the search type is name
        """
        result = client.post_investigate_by_name(name_type=search_type, name=search_term)

    else:
        """
        Generate an error because the search type is not supported
        """
        raise ValueError('Invalid search_type provided')

    readable_output = f'{result}'

    return CommandResults(
        outputs_prefix='PerimeterX',
        outputs_key_field='',
        outputs=result
    )


def ip(client: Client, args: Dict[str, Any], thresholds: Dict[str, Any]):
    """
    Collect the details to run an IP Reputation query against the PerimeterX API

    :type ip: ``str``
    :param ip: Results will be provided for this particular IP

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    # Check to make sure we have a query term
    ip_address = args.get('ip', None)
    if not ip_address:
        raise ValueError('No IP Address specified')

    result = client.post_investigate_by_ip(ip_type='true_ip', ip_address=ip_address)

    pXScore = pXScoring()

    pXScore.add_score_to_ip_list(ip_address=ip_address, risk_score=result['max_risk_score'], thresholds=thresholds)

    readable_output = f'{pXScore.ip_standard_list}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='PerimeterX',
        outputs_key_field='',
        outputs=result,
        indicators=pXScore.ip_standard_list
    )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    api_key = demisto.params().get('apikey')

    # get the service API url
    # '/investigate?search=ip:1.1.1.1&tops=path' + api_key
    base_url = urljoin(demisto.params()['url'], '/v1/bot-defender/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # get the DBot Thresholds
    thresholds = {
        "good_threshold": int(demisto.params().get('dbotGoodThreshold')),
        "suspicious_threshold": int(demisto.params().get('dbotSuspiciousThreshold')),
        "bad_threshold": int(demisto.params().get('dbotBadThreshold')),
        "unknown_threshold": 0
    }

    LOG(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        #elif demisto.command() == 'perimeterx-get-investigate-details':
        #    return_results(perimeterx_get_investigate_details(client=client, args=demisto.args(), thresholds=thresholds))

        elif demisto.command() == 'ip':
            return_results(ip(client=client, args=demisto.args(), thresholds=thresholds))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()




