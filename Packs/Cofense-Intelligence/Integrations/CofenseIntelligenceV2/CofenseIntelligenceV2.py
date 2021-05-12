"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
import base64


from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
VENDOR_NAME = "Cofense Intelligence v2"

SEVERITY_SCORE = {'None': 0, 'Minor': 1, 'Moderate': 2, 'Major': 3}
VERDICT = {0: 'Unknown', 1: 'Good', 2: 'Suspicious', 3: 'Bad'}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}

    def threat_search_call(self, ip=None, file=None, email=None, url=None, string=None):
        params = {}
        if ip:
            params['ip'] = ip
        elif email:
            params['watchListEmail'] = email
        elif file:
            params['allMD5'] = file
        elif url:
            params['urlSearch'] = url
        elif string:
            params['extractedString'] = string
        return self._http_request(method='POST', url_suffix='/threat/search', params=params)

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

def create_threat_md_row(threat, severity_level=None):
    threat_row= {'Threat ID': threat.get('id', ''),
                     'Threat Types': '\n'.join(
                         [m.get('description', '') for m in threat.get('malwareFamilySet', [])]),
                     'Executive Summary': threat.get('executiveSummary', ''),
                     'Campaign': threat.get('label', ''),
                     'Last Published': epochToTimestamp(threat.get('lastPublished'))}
    if severity_level:
        threat_row['Verdict'] = VERDICT.get(severity_level)
    return threat_row

def threats_analysis(threats, indicator):
    threshold = demisto.params().get('url_threshold')
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    md_data = []
    indicator_found = False
    dbot_score = adjusted_score = 0
    for threat in threats:
        severity_level = 0
        for block in threat.get('blockSet'):
            if block.get('impact'):
                threat_score = SEVERITY_SCORE.get(block.get('impact'))
                adjusted_score = 3 if threshold_score <= threat_score else threat_score
                if block.get('data') == indicator:
                    dbot_score = severity_level = adjusted_score
                    indicator_found = True
                    break
            severity_level = max(severity_level, adjusted_score)

        md_data.append(create_threat_md_row(threat, severity_level))

        if not indicator_found:
            dbot_score = max(dbot_score, severity_level)

    return md_data, dbot_score


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        client.threat_search_call()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure user name and password are correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client

def search_url_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    url = args.get('url', None)
    if not url:
        raise ValueError('url not specified')
    result = client.threat_search_call(url=url)
    threats = result.get('data', {}).get('threats', [])

    md_data, dbot_score = threats_analysis(threats, indicator=url)

    dbot_score_obj = Common.DBotScore(indicator=url, indicator_type=DBotScoreType.URL,
                                      integration_name="Cofense-Intelligence-v2", score=dbot_score, reliability=demisto.params().get('integration_reliability'))
    url_indicator = Common.URL(url=url, dbot_score=dbot_score_obj)

    return CommandResults(
        outputs_prefix='CofenseIntelligence.Threat',
        outputs_key_field='id',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(f'Cofense URL Reputation for url {url}', md_data),
        indicator=url_indicator,

    )




def check_ip_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ip = args.get('ip', None)
    if not ip:
        raise ValueError('ip not specified')
    # Call the Client function and get the raw response
    result = client.threat_search_call(ip=ip)
    threats = result.get('data',{}).get('threats',[])
    indicatorFnd = False
    threshold = demisto.params().get('ip_threshold')
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    dbot_score = 0
    dbot_score_obj = Common.DBotScore(indicator=ip, indicator_type=DBotScoreType.IP,
                                      integration_name="Cofense-Intelligence-v2", score=dbot_score,reliability=demisto.params().get('integration_reliability'))
    adjusted_score = 0
    ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score_obj)
    severityLevel = 0
    md_data=[]
    for threat in threats:
        ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score_obj)
        severityLevel = 0
        for block in threat.get('blockSet'):
            if block.get('data') == ip and block.get('ipDetail'):
                ip_indicator.asn = block.get('ipDetail').get('asn')
                ip_indicator.geo_latitude = block.get("ipDetail").get("latitude")
                ip_indicator.geo_longitude = block.get("ipDetail").get("longitude")
                ip_indicator.geo_country = block.get("ipDetail").get("countryIsoCode")

            if block.get('impact'):
                threat_score = SEVERITY_SCORE.get(block.get('impact'))
                adjusted_score = 3 if threshold_score <= threat_score else threat_score
                if block.get('ipDetail') and block.get('ipDetail').get('ip') == ip:
                    severity_level = adjusted_score
                    dbot_score = severityLevel
                    indicatorFnd = True
                    break
            severityLevel = max(severityLevel, adjusted_score)
        threat_md_row=create_threat_md_row(threat,severity_level)
        threat_md_row['ASN']=ip_indicator.asn
        threat_md_row['Country'] = ip_indicator.geo_country
        md_data.append(threat_md_row)
    if not indicatorFnd:
        dbot_score = max(dbot_score, severityLevel)

    dbot_score_obj = Common.DBotScore(indicator=ip, indicator_type=DBotScoreType.IP,
                                      integration_name="Cofense-Intelligence-v2", score=dbot_score,reliability=demisto.params().get('integration_reliability'))
    ip_indicator.dbot_score=dbot_score_obj

    return CommandResults(
        outputs_prefix='CofenseIntelligence.Threat',
        outputs_key_field='IP',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(f'Cofense IP Reputation for IP {ip}', md_data),
        indicator=ip_indicator,
    )


def check_email_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    email = args.get('email', None)
    if not email:
        raise ValueError('email not specified')
    # Call the Client function and get the raw response
    result = client.threat_search_call(email=email)
    threats = result.get('data', {}).get('threats', [])

    md_data, dbot_score = threats_analysis(threats, indicator=email)

    dbot_score_obj = Common.DBotScore(indicator=email, indicator_type=DBotScoreType.EMAIL,
                                      integration_name="Cofense-Intelligence-v2", score=dbot_score,reliability=demisto.params().get('integration_reliability'))

    email_indicator = Common.EMAIL(address=email, dbot_score=dbot_score_obj)
    return CommandResults(
        outputs_prefix='CofenseIntelligence.Threat',
        outputs=threats,
        outputs_key_field='id',
        raw_response=result,
        readable_output=tableToMarkdown(f'Cofense email Reputation for email {email}', md_data),
        indicator=email_indicator,
    )

def check_md5_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    file = args.get('file', None)
    if not file:
        raise ValueError('file not specified')
    # Call the Client function and get the raw response
    result = client.threat_search_call(file=file)
    threats = result.get('data', {}).get('threats', [])
    threshold = demisto.params().get('url_threshold')
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    md_data = []
    dbot_score = adjusted_score = 0
    for threat in threats:
        severity_level = 0
        block_set=threat.get('blockSet')
        for i in range(len(block_set)):
            if block_set[i].get('impact'):
                threat_score = SEVERITY_SCORE.get(block_set[i].get('impact'))
                adjusted_score = 3 if threshold_score <= threat_score else threat_score
            severity_level = max(severity_level, adjusted_score)
        threat_md_row = {'Threat ID': threat.get('id', ''),
                         'Threat Types': '\n'.join(
                             [m.get('description', '') for m in threat.get('malwareFamilySet', [])]),
                         'Verdict': VERDICT.get(severity_level),
                         'Executive Summary': threat.get('executiveSummary', ''),
                         'Campaign': threat.get('label', ''),
                         'Last Published': epochToTimestamp(threat.get('lastPublished'))}
        md_data.append(threat_md_row)
        dbot_score = max(dbot_score, severity_level)
    dbot_score_obj = Common.DBotScore(indicator=file, indicator_type=DBotScoreType.FILE,
                                      integration_name="Cofense-Intelligence-v2", score=dbot_score,reliability=demisto.params().get('integration_reliability'))

    file_indicator = Common.File(md5=file,dbot_score=dbot_score_obj)
    return CommandResults(
        outputs_prefix='CofenseIntelligence.Threat',
        outputs_key_field='id',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(f'Cofense file Reputation for file {file}', md_data),
        indicator=file_indicator)

def extracted_string(client: Client, args: Dict[str, Any]) -> CommandResults:
    string = args.get('str', None)
    if not string:
        raise ValueError('string not specified')
    limit = args.get('limit', None)
    if not limit:
        limit = 10
    # Call the Client function and get the raw response
    result = client.threat_search_call(string=string)
    threats = result.get('data', {}).get('threats', [])
    threshold = demisto.params().get('url_threshold')
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')
    md_data = []
    count_threats=0
    if threats:
        for threat in threats:
            if threat.get('hasReport'):
                count_threats+=1
                md_data.append(create_threat_md_row(threat))
                if count_threats==limit:
                    break
    return CommandResults(
        outputs_prefix='CofenseIntelligence',
        outputs_key_field='id',
        outputs={'CofenseIntelligence': {"String": string, "NumOfThreats": count_threats}},
        raw_response=result,
        readable_output=tableToMarkdown(f'There are {count_threats} threats regarding your string search\n', md_data))



''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication

    username = demisto.params().get('credentials', {}).get('identifier', None)
    password = demisto.params().get('credentials', {}).get('password', None)
    # get the service API url
    base_url = demisto.params()['url']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {
            "Authorization": f"Basic {base64.b64encode(':'.join([username, password]).encode()).decode().strip()}"
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        command = demisto.command()
        args = demisto.args()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement
        elif command == "url":
            return_results(search_url_command(client, args))
        elif command == "cofense-search":
            return_results(extracted_string(client, args))
        elif command == "email":
            return_results(check_email_command(client, args))
        elif command == "file":
            return_results(check_md5_command(client, args))
        elif command == "ip":
            return_results(check_ip_command(client, args))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
