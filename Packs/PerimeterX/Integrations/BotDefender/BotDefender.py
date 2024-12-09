
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class pXScoring:
    """
    Class to handle all current and future scoring for PerimeterX objects
    """

    @staticmethod
    def dbotscore_from_risk(risk_score: int, thresholds: dict[str, Any]) -> int:
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

    @staticmethod
    def get_ip_score(ip_address: str, risk_score: int, thresholds: dict[str, Any]):
        """
        Create the DBotScore structure first using the Common.DBotScore class.

        :type ip_address: ``str``
        :param ip_address: IP Address to be used as the indicator for this entry

        :type risk_score: ``int``
        :param risk_score: PerimeterX provided risk sco1re for the IP Address

        :return: Updated List of Common IP Addresses with this entry appended
        :rtype: ``List[Common.IP]``
        """

        # create the DBotScore object and populate it with the needed values
        dbot_score = Common.DBotScore(
            indicator=ip_address,
            indicator_type=DBotScoreType.IP,
            integration_name='PerimeterX',
            score=pXScoring.dbotscore_from_risk(risk_score, thresholds),
            malicious_description='High risk score indicates high probability that the requests from the IP are '
                                  'malicious ',
            reliability=demisto.params().get('integrationReliability')
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        return Common.IP(
            ip=ip_address,
            # asn=ip_data.get('asn'),
            dbot_score=dbot_score
        )


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def test_api_connection(self, api_key: str) -> dict[str, Any]:
        """
        Makes a call to the status API path to confirm the proper URL and Authorization token were provided
        """

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        return self._http_request(
            method='GET',
            full_url=f'{self._base_url}?search=ip:1.1.1.1&tops=path',
            headers=headers
        )

    def post_investigate_by_ip(self, ip_type: str, ip_address: str, api_key: str) -> dict[str, Any]:
        """
        Query the PerimeterX API to get the relevant details regarding the provided IP within a particular customer's own data

        :type ip_address: ``str``
        :param ip_address: IP Address to be used as the indicator for this entry

        :type ip_type: ``str``
        :param ip_type: The type of IP address we will be querying (true_ip or socket_ip)

        :return: The JSON response body from the PerimeterX API
        :rtype: ``Dict[str, Any]``
        """
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        request_params: dict[str, Any] = {}

        if ip_type:
            request_params['ip_type'] = ip_type

        if ip_address:
            request_params['ip_address'] = f'search=ip:{ip_address}'

        return self._http_request(
            method='GET',
            full_url=f'{self._base_url}?{request_params["ip_address"]}&tops=user-agent,path,socket_ip_classification',
            headers=headers
        )

    def post_investigate_by_name(self, name_type: str, name: str) -> dict[str, Any]:
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

        request_params: dict[str, Any] = {}

        if name_type:
            request_params['name_type'] = name_type

        if name:
            request_params['name'] = name

        return self._http_request(
            method='POST',
            full_url=self._base_url,
            json_data=request_params
        )


def test_module(client: Client, api_key):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: PerimeterX client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        result = client.test_api_connection(api_key)
        if result['success']:
            return 'ok'
        else:
            return 'Connection to api failed: ' + result['errors']
    except DemistoException as de:
        return 'Connection to api failed with exception: ' + de.message


def perimeterx_get_investigate_details(client: Client, args: dict[str, Any],
                                       thresholds: dict[str, Any], api_key: str) -> CommandResults:
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

    if search_type in supported_ip_search_types:
        """
        Run an IP based search if the search type is one supported by the IP types
        """
        result = client.post_investigate_by_ip(ip_type=search_type, ip_address=search_term, api_key=api_key)

        indicator = pXScoring.get_ip_score(ip_address=search_term, risk_score=result['max_risk_score'],
                                           thresholds=thresholds)

        return CommandResults(
            outputs_prefix='PerimeterX',
            outputs_key_field='',
            outputs=result,
            indicator=indicator
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

    return CommandResults(
        outputs_prefix='PerimeterX',
        outputs_key_field='',
        outputs=result
    )


def ip(client: Client, args, thresholds: dict[str, Any], api_key):
    """
    Collect the details to run an IP Reputation query against the PerimeterX API

    :type ip: ``str``
    :param ip: Results will be provided for list of IPs

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    # Check to make sure we have a query term
    ip_list = argToList(args.get('ip'))
    results = []
    for ip_address in ip_list:
        result = client.post_investigate_by_ip(ip_type='true_ip', ip_address=ip_address, api_key=api_key)

        indicator = pXScoring.get_ip_score(ip_address=ip_address, risk_score=result['max_risk_score'],
                                           thresholds=thresholds)
        readable_output = f'{indicator}'
        cr = CommandResults(
            readable_output=readable_output,
            outputs_prefix='PerimeterX',
            outputs_key_field='',
            outputs=result,
            indicator=indicator
        )
        results.append(cr)

    return results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = params.get('apikey')

    # get the service API url
    base_url = urljoin(params['url'], '/v1/bot-defender/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # get the DBot Thresholds
    thresholds = {
        "good_threshold": int(params.get('dbotGoodThreshold')),
        "suspicious_threshold": int(params.get('dbotSuspiciousThreshold')),
        "bad_threshold": int(params.get('dbotBadThreshold')),
        "unknown_threshold": 0
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')
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

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, api_key)
            demisto.results(result)

        elif command == 'ip':
            return_results(ip(client, demisto.args(), thresholds=thresholds, api_key=api_key))

        elif command == 'perimeterx_get_investigate_details':
            return_results(perimeterx_get_investigate_details(client=client, args=demisto.args(), thresholds=thresholds,
                                                              api_key=api_key))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
