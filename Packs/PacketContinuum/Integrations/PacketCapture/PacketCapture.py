import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

"""
Packet Continuum Integration for Cortex XSOAR.
"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API

    Implements http calls to server capture server and returns relevant data.
    """

    def __init__(self, base_url):
        demisto.debug(base_url)
        super().__init__(base_url, verify=True)

    def get_status(self, url: str) -> Dict[str, str]:
        """ Get server status
        Args:
                url (str): string with DNS/IP address of system, status endpoint, and rest token
        Return:
            dict: status information of server
        """

        return self._http_request(
            method='GET',
            url_suffix=url
        )

    def basic_search(self, url: str, postData: Dict[str, Any]) -> Dict[str, str]:
        """ Make search call to server
        Args:
            url (str): kql search endpoint
            postData (Dict[str, Any]): endpoint mandatory values
        Return:
            dict: kql search results based on user query
        """

        return self._http_request(
            method='POST',
            url_suffix=url,
            json_data=postData
        )


''' HELPER FUNCTIONS '''


def IncidentToTimeWindow(incidentTime: str, delta: timedelta):
    """
    Builds time window based on incident timcestamp for search
    Args:
        incidentTime (str): timestamp of incident
        delta (datetime.timedelta): how many days before and after incident timestamp to include in search
    Returns:
        tuple of str: time window to initiate search
    """

    timeConversion = datetime.strptime(incidentTime, DATE_FORMAT)

    leftBracket = timeConversion - delta
    rightBracket = timeConversion + delta

    return (leftBracket, rightBracket)


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: Dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication

    When ok is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.

    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.

    Returns:
        str: ok if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        pc_get_status(client, params)
    except DemistoException as e:
        raise e

    return 'ok'


def pc_get_status(client: Client, params: Dict[str, Any]) -> CommandResults:
    """
    Return server status and health

    Args:
        client (Client): demisto api http class

        params (Dict[str, Any]): required parameters

    Returns:
        CommandResults object with status information
    """

    result = client.get_status("/v3/fmping?rest_token=" + params['api_token'])

    return CommandResults(
        outputs_prefix='status',
        outputs_key_field='',
        outputs=result)


def pc_kql_or_bpf_search(client: Client, params: Dict[str, Any], args: Dict[str, Any]) -> CommandResults:
    """
    Run a serch using kql syntax

    Args:
        client (Client): demisto api http class

        params (Dict[str, Any]): required parameters

        args (Dict[str, Any]):
    Returns:
        CommandResults object with search results
    """

    timeDelta = int(args['incident_delta'])
    timeTuple = IncidentToTimeWindow(args['incident_time'], timedelta(days=timeDelta))

    postData = {
        'rest_token': params['api_token'],
        'search_name': args['search_name'],
        'search_filter': args['search_filter'],
        'begin_time': timeTuple[0].strftime(DATE_FORMAT),
        'end_time': timeTuple[1].strftime(DATE_FORMAT),
        'max_packets': args['max_packets']
    }

    demisto.debug(f"rest_token is {params['api_token']}")
    demisto.debug(f"search_name is {args['search_name']}")
    demisto.debug(f"search_filter is {args['search_filter']}")
    demisto.debug(f"begin_time {timeTuple[0]}")
    demisto.debug(f"end_time {timeTuple[1]}")

    result = client.basic_search("/v3/fmsearch", postData)

    return CommandResults(
        outputs_prefix='kqlsearch',
        outputs_key_field='',
        outputs=result)


''' MAIN FUNCTION '''


def main() -> None:
    try:
        client = Client(base_url='https://' + demisto.params()['ip_management'] + ':41395')
        if demisto.command() == 'test-module':
            return_results(test_module(client, demisto.params()))
        elif demisto.command() == 'pc-get-status':
            result = pc_get_status(client, demisto.params())
            return_results(result)
        elif demisto.command() == 'pc-kql-search':
            result = pc_kql_or_bpf_search(client, demisto.params(), demisto.args())
            return_results(result)
        elif demisto.command() == 'pc-bpf-search':
            result = pc_kql_or_bpf_search(client, demisto.params(), demisto.args())
            return_results(result)
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
