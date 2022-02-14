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
ATTACHMENT_LINK='https://intelgraph.idefense.com/rest/files/download'

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


def _calculate_dbot_score(severity: int) -> int:
    """
    Calculates Dbot score according to table:
    Dbot Score   | severity
     0           | 0
     1           | 1,2
     2           | 3,4
     3           | 5,6,7
    Args:
        severity: value from 1 to 5, determined by iDefense threat indicator

    Returns:
        Calculated score
    """
    dbot_score = Common.DBotScore.NONE

    if severity > 4:
        dbot_score = Common.DBotScore.BAD
    elif severity > 2:
        dbot_score = Common.DBotScore.SUSPICIOUS
    elif severity > 0:
        dbot_score = Common.DBotScore.GOOD

    return dbot_score


def getThreatReport_command(client: Client, args: dict , reliability: DBotScoreReliability):
    try:
        result={}
        ia_ir_url: str = str(args.get('url'))
        ia_ir_uuid = ia_ir_url.split('/')[-1]
        result = client.document_download(url_suffix=f'/v0/{ia_ir_uuid}')
        context = _ia_ir_extract(result, reliability)
        return CommandResults(raw_response=result,outputs=context,readable_output=f"Report with UUID: {ia_ir_uuid} has been fetched")
        
    except Exception as e:
        if 'Failed to parse json object from response' in e.args[0]:
            return CommandResults(indicator=None, raw_response={},
                                  readable_output=f"No report was found for UUID: {ia_ir_uuid} !!")
        else:
            raise e


def _ia_ir_extract(Res: dict, reliability: DBotScoreReliability):
    """
    """
    threat_types = Res.get('threat_types','')
    threattypes=''
    if threat_types:
            for threat_type in threat_types:
                threattypes= threattypes+'\n- '+threat_type
    context = {
        "Report": {
                'created_on' : Res.get('created_on','NA'),
                'display_text' : Res.get('display_text','NA'),
                'dynamic_properties' : Res.get('dynamic_properties','NA'),
                'index_timestamp' : Res.get('index_timestamp','NA'),
                'key' : Res.get('key','NA'),
                'last_modified' : Res.get('last_modified','NA'),
                'last_published' : Res.get('last_published','NA'),
                'links' : Res.get('links','NA'),
                'threat_types' : threattypes,
                'title' : Res.get('title','NA'),
                'type' : Res.get('type','NA'),
                'uuid' : Res.get('uuid','NA'),
                'analysis' : Res.get('analysis','NA'),
                'sources_external' : Res.get('sources_external','NA')
            },
            "DBotScore": {
                "Indicator": Res.get('display_text','NA'),
                "Reliability": reliability,
                "Type": "Report",
                "Vendor": "ACTI Threat Intelligence Report"
            }
        }
    type_of_report = Res.get('type','NA')
    if 'intelligence_report' in type_of_report:
        context['Report']['conclusion'] = Res.get('conclusion','NA')
        context['Report']['summary'] = Res.get('summary','NA')
        context['DBotScore']['Score'] = Res.get('NA')  # Intelligence alerts shouldn't contain severity
    else:
        severity_dbot_score = Res.get('severity','NA')
        if severity_dbot_score != 'NA':
            severity_dbot_score = _calculate_dbot_score(severity_dbot_score)
        context['Report']['mitigation'] = Res.get('mitigation','NA')
        context['Report']['severity'] = Res.get('severity','NA')
        context['Report']['abstract'] = Res.get('abstract','NA')
        attachment_links = Res.get('attachment_links','')
        fqlink: str = ''
        if attachment_links:
            for link in attachment_links:
                fqlink= fqlink+'\n- '+(ATTACHMENT_LINK+link)
        else:
            fqlink = 'NA'
        context['Report']['attachment_links'] = fqlink
        context['DBotScore']['Score'] = severity_dbot_score
    
    return context

def main():
    params = demisto.params()
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
            return_results(commands[command](client, demisto.args(), reliability))
            

    except Exception as e:
        if 'Error in API call [403]' in e.args[0]:
            return_error(f"This API token doesn't have permission for accessing document API!.\n Error: {str(e)}")
        else:
            demisto.error(traceback.format_exc())
            return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()