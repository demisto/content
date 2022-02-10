import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import requests
import traceback
from typing import List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


ENDPOINTS = {
    'document': '/rest/document'
}
# BASE_URL= "https://api.intelgraph.idefense.com/"

class Client(BaseClient):
    def __init__(self, input_url:str, api_key:str, verify_certificate: bool, proxy: bool, endpoint="/rest/document"):
        base_url = urljoin(input_url, endpoint)
        headers = {
            "Content-Type": "application/json",
            'auth-token': api_key
        }
        super(Client, self).__init__(base_url=base_url, headers=headers)

    def document_download(self, url_suffix: str, data: dict = {}) -> dict:
        return self._http_request(method="GET", url_suffix=url_suffix, params=data)


def test_module(client: Client) -> str:                                                                         # type: ignore
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.document_download(url_suffix='/v0')
        return 'ok'
    except Exception as e:
        if 'Error in API call [403]' in e.args[0]:
            return_results(f"This API token doesn't have permission for accessing Document API!.\n Error: {str(e)}")
            demisto.debug(e.args[0])
        else:
            raise DemistoException(f"Error in API call - check the input parameters and the API Key. Error: {e}.")


def getThreatReport_command(client: Client, args: dict, reliability: DBotScoreReliability):
    result = client.document_download(url_suffix='/v0', data = {'page_size': 4})
    reports = _extract_results(result)
    return reports



def _extract_results(res: dict) -> List[dict]:

    if not res.get('total_size'):
        return []

    results_array = res.get('results', [])
    if not len(results_array):
        return []

    return_data = {}
    shortened_result = []
    demisto.debug("############## line no 72 ###############")
    for result in results_array:
        res_dict = {
            'abstract': result['abstract'],
            'title': result['title']
        }
        demisto.debug("############## line no 78 ###############")
        shortened_result.append(res_dict)
        demisto.debug(shortened_result)
    demisto.debug("############## line no 81 ###############")
    return {"ACTI_Report": shortened_result}

def main():
    params = demisto.params()
    # a = {
    #     'bodyexecutivebrief':'This section is realated to body of the report',
    #     'name':'This is name section',
    #     'type':'This is type section'
    # }
    # execute_command('createThreatIntelReport',a)
    api_key = params.get('api_token')
    if isinstance(api_key, dict):
        api_key = api_key.get('password')

    reliability = params.get('integrationReliability', 'B - Usually reliable')
    base_url = urljoin(params.get('url', ''))
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('use_proxy', False)

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        Exception("Accenture CTI error: Please provide a valid value for the Source Reliability parameter")

    commands = {
        'acti-getThreatIntelReport' : getThreatReport_command
    }

    try:
        command = demisto.command()
        client = Client(base_url, api_key, verify_certificate, proxy, endpoint=ENDPOINTS['document'])
        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
        # elif command == 'acti-getThreatIntelReport':
            # execute_command('createThreatIntelReport',a)
            return_results(commands[command](client, demisto.args(), reliability))
            

    except Exception as e:
        if 'Error in API call [403]' in e.args[0]:
            return_error(f"This API token doesn't have permission for accessing document API!.\n Error: {str(e)}")
        else:
            demisto.error(traceback.format_exc())
            return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()