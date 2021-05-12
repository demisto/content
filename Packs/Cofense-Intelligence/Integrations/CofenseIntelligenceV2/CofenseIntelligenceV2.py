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
INTEGRATION_NAME = "CofenseIntelligenceV2"
OUTPUT_PREFIX = 'CofenseIntelligence.Threat'
RELIABILITY = 'integration_reliability'

SEVERITY_SCORE = {'None': 0, 'Minor': 1, 'Moderate': 2, 'Major': 3}
VERDICT = {0: 'Unknown', 1: 'Good', 2: 'Suspicious', 3: 'Bad'}

EMAIL_REGEX = r'[^@]+@[^@]+\.[^@]+'


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

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


def create_threat_md_row(threat: Dict, severity_level: int=None):
    threat_row = {"Threat ID": threat.get("id", ""),
                  "Threat Types": "\n".join(
                      [m.get("description", "") for m in threat.get("malwareFamilySet", [])]),
                  "Executive Summary": threat.get("executiveSummary", ""),
                  "Campaign": threat.get("label", ""),
                  "Last Published": epochToTimestamp(threat.get("lastPublished"))}
    if severity_level:
        threat_row["Verdict"] = VERDICT.get(severity_level)
    return threat_row


def threats_analysis(threats: List, indicator: str, threshold: str):
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(
            f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

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
        client.threat_search_call()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure user name and password are correctly set'
        else:
            raise e
    return message


def search_url_command(client: Client, args: Dict[str, Any], params) -> CommandResults:
    url = args.get('url')
    if not url:
        raise ValueError('url not specified')
    result = client.threat_search_call(url=url)

    threats = result.get('data', {}).get('threats', [])
    md_data, dbot_score = threats_analysis(threats, indicator=url, threshold=params.get('url_threshold'))
    result = client.threat_search_call(url=url)

    dbot_score_obj = Common.DBotScore(indicator=url, indicator_type=DBotScoreType.URL,
                                      integration_name=INTEGRATION_NAME, score=dbot_score,
                                      reliability=params.get(RELIABILITY))
    url_indicator = Common.URL(url=url, dbot_score=dbot_score_obj)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field='id',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(name=f'Cofense URL Reputation for url {url}', t=md_data,
                                        headers=['Threat ID', 'Threat Types', 'Verdict', 'Executive Summary',
                                                 'Campaign', 'Last Published']),
        indicator=url_indicator,

    )


def check_ip_command(client: Client, args: Dict[str, Any], params) -> CommandResults:
    ip = args.get('ip')
    if not ip:
        raise ValueError('IP not specified')
    try:
        socket.inet_aton(ip)
        # legal
    except socket.error:
        raise ValueError('Invalid IP')

    # Call the Client function and get the raw response
    result = client.threat_search_call(ip=ip)
    threats = result.get('data', {}).get('threats', [])
    indicator_found = False
    threshold = params.get('ip_threshold')
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(
            f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    dbot_score = 0
    dbot_score_obj = Common.DBotScore(indicator=ip, indicator_type=DBotScoreType.IP,
                                      integration_name=INTEGRATION_NAME, score=dbot_score,
                                      reliability=params.get(RELIABILITY))
    adjusted_score = 0
    ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score_obj)
    severity_level = 0
    md_data = []
    for threat in threats:
        severity_level = 0
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
                    ip_indicator.malware_family = block.get('malwareFamily', {}).get('familyName')
                    severity_level = adjusted_score
                    dbot_score = severity_level
                    indicator_found = True
                    break
            severity_level = max(severity_level, adjusted_score)
        threat_md_row = create_threat_md_row(threat, severity_level)
        threat_md_row["ASN"] = ip_indicator.asn
        threat_md_row["Country"] = ip_indicator.geo_country
        md_data.append(threat_md_row)
    if not indicator_found:
        dbot_score = max(dbot_score, severity_level)

    dbot_score_obj = Common.DBotScore(indicator=ip, indicator_type=DBotScoreType.IP,
                                      integration_name=INTEGRATION_NAME, score=dbot_score,
                                      reliability=params.get(RELIABILITY))
    ip_indicator.dbot_score = dbot_score_obj

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field='IP',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(name=f'Cofense IP Reputation for IP {ip}', t=md_data,
                                        headers=['Threat ID', 'Threat Types', 'Verdict', 'Executive Summary',
                                                 'Campaign', 'Last Published', 'ASN', 'Country']),
        indicator=ip_indicator,

    )


def check_email_command(client: Client, args: Dict[str, Any], params) -> CommandResults:
    email = args.get('email')
    if not email:
        raise ValueError('Email not specified')
    if not re.fullmatch(EMAIL_REGEX, email):
        raise ValueError('Invalid email')

    # Call the Client function and get the raw response
    result = client.threat_search_call(email=email)
    threats = result.get('data', {}).get('threats', [])

    md_data, dbot_score = threats_analysis(threats, indicator=email, threshold=params.get('email_threshold'))

    dbot_score_obj = Common.DBotScore(indicator=email, indicator_type=DBotScoreType.EMAIL,
                                      integration_name=INTEGRATION_NAME, score=dbot_score,
                                      reliability=params.get(RELIABILITY))

    email_indicator = Common.EMAIL(address=email, dbot_score=dbot_score_obj, domain=email.split('@')[1])
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs=threats,
        outputs_key_field='id',
        raw_response=result,
        readable_output=tableToMarkdown(name=f'Cofense email Reputation for email {email}', t=md_data,
                                        headers=['Threat ID', 'Threat Types', 'Verdict', 'Executive Summary',
                                                 'Campaign', 'Last Published']),
        indicator=email_indicator,
    )


def check_md5_command(client: Client, args: Dict[str, Any], params) -> CommandResults:
    file = args.get('file', None)
    if not file:
        raise ValueError('file not specified')
    # Call the Client function and get the raw response
    result = client.threat_search_call(file=file)
    threats = result.get('data', {}).get('threats', [])
    threshold = params.get('file_threshold')
    threshold_score = SEVERITY_SCORE.get(threshold)
    if not threshold_score:
        raise Exception(
            f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    md_data = []
    dbot_score = adjusted_score = 0

    file_indicator = Common.File(md5=file, dbot_score=None)
    for threat in threats:
        severity_level = 0
        block_set = threat.get('blockSet')
        for block in block_set:
            if block.get('impact'):
                threat_score = SEVERITY_SCORE.get(block.get('impact'))
                adjusted_score = 3 if threshold_score <= threat_score else threat_score
            severity_level = max(severity_level, adjusted_score)

        for es in threat.get('executableSet'):
            if es.get('md5Hex') == file:
                file_indicator.sha512 = es.get('sha512Hex')
                file_indicator.sha1 = es.get('sha1Hex')
                file_indicator.sha256 = es.get('sha256Hex')
                file_indicator.name = es.get('fileName')
                file_indicator.malware_family = es.get('malwareFamily', {}).get('familyName')
                file_indicator.extension = es.get('fileNameExtension')
                break

        threat_md_row = create_threat_md_row(threat, severity_level)
        md_data.append(threat_md_row)
        dbot_score = max(dbot_score, severity_level)

    dbot_score_obj = Common.DBotScore(indicator=file, indicator_type=DBotScoreType.FILE,
                                      integration_name=INTEGRATION_NAME, score=dbot_score,
                                      reliability=params.get(RELIABILITY))

    file_indicator.dbot_score = dbot_score_obj

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field='id',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(name=f'Cofense file Reputation for file {file}', t=md_data,
                                        headers=['Threat ID', 'Threat Types', 'Verdict', 'Executive Summary',
                                                 'Campaign', 'Last Published']),
        indicator=file_indicator)


def extracted_string(client: Client, args: Dict[str, Any]) -> CommandResults:
    string = args.get('str')
    if not string:
        raise ValueError('string not specified')
    limit = args.get('limit')
    if not limit:
        limit = 10
    # Call the Client function and get the raw response
    result = client.threat_search_call(string=string)
    threats = result.get('data', {}).get('threats', [])

    md_data = []
    count_threats = 0
    if threats:
        for threat in threats:
            if threat.get('hasReport'):
                count_threats += 1
                md_data.append(create_threat_md_row(threat))
                if count_threats == limit:
                    break

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field='id',
        outputs={'CofenseIntelligence': {"String": string, "NumOfThreats": count_threats}},
        raw_response=result,
        readable_output=tableToMarkdown(name=f'There are {count_threats} threats regarding your string search\n',
                                        t=md_data,
                                        headers=['Threat ID', 'Threat Types', 'Executive Summary',
                                                 'Campaign', 'Last Published']))


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')
    # get the service API url
    base_url = demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
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
        params = demisto.params()
        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif command == "url":
            return_results(search_url_command(client, args, params))
        elif command == "cofense-search":
            return_results(extracted_string(client, args))
        elif command == "email":
            return_results(check_email_command(client, args, params))
        elif command == "file":
            return_results(check_md5_command(client, args, params))
        elif command == "ip":
            return_results(check_ip_command(client, args, params))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
