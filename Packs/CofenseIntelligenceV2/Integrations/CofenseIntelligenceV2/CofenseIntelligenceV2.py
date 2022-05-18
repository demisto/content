import base64

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
VENDOR_NAME = "Cofense Intelligence v2"
INTEGRATION_NAME = "CofenseIntelligenceV2"
OUTPUT_PREFIX = 'CofenseIntelligence'
RELIABILITY = 'integration_reliability'

DBOT_TO_VERDICT = {0: 'Unknown', 1: 'Benign', 2: 'Suspicious', 3: 'Malicious'}

EMAIL_REGEX = r'[^@]+@[^@]+\.[^@]+'
BRAND = "Cofense Intelligence"


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, headers, verify, proxy, score_mapping, create_relationships=True):

        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)
        self.create_relationships = create_relationships
        self.severity_score = self.score_mapping(score_mapping)

    @staticmethod
    def score_mapping(score_mapping):
        """
        Updating the SEVERITY_SCORE according to the score_mapping provided by user.
        :param score_mapping: custom score mapping provided by user.

        """
        severity_score = {'None': 0, 'Minor': 1, 'Moderate': 2, 'Major': 3}
        if score_mapping:
            mappings = [mapping.strip() for mapping in score_mapping.split(",") if mapping.strip()]
            for mapping in mappings:
                if mapping:
                    attr = [score.strip() for score in mapping.split(":") if score.strip()]
                    if len(attr) == 2 and attr[0] in severity_score.keys():
                        severity_score[attr[0]] = int(attr[1])

        return severity_score

    def threat_search_call(self, days_back=90, ip=None, file=None, email=None, url=None, string=None, domain=None):
        """Performs the API call to the threats-search endpoint with the requested query param
            Args:
                - days_back (string): search for data not older then 'days_back' days
                - ip (string): search for threats associated with this ip address
                - file (string): search for threats associated with this file hash
                - email (string): search for threats associated with this email address
                - url (string): search for threats associated with this url
                - string (string): search for threats related to  this string
            return:
             Json: The response returned from the API call
        """
        params = {'beginTimestamp': get_n_days_back_epoch(int(days_back))}
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

        elif domain:
            params['domain'] = domain

        return self._http_request(method='POST', url_suffix='/apiv1/threat/search', params=params)

    def search_cofense(self, params: Dict) -> Dict:
        """Performs the API call to the threats-search endpoint with the requested query param
            Args:
                - params (dict): Query Parameters to be passed.
            return:
             Json: The response returned from the API call
        """
        return self._http_request(method='POST', url_suffix='/apiv1/threat/search', params=params)


def remove_false_vendors_detections_from_threat(threats):
    """remove from report vendor detections fields that are equal to false as they are not relevant
        Args:
            - threats (Array): threats reports from cofense raw response
    """
    for threat in threats:
        for exe in threat.get('executableSet', []):
            detections = []
            for detection in exe.get('vendorDetections', []):
                if detection.get('detected'):
                    detections.append(detection)
            exe['vendorDetections'] = detections


def get_n_days_back_epoch(days_back: int):
    today = datetime.now()
    d = timedelta(days=days_back)
    return int((today - d).timestamp())


def create_threat_md_row(threat: Dict, severity_level: int = None):
    """ generate dict representing a single row in the human readable markdown format
            Args:
                - threat (Dict): threat data from cofense raw response
                - sevirity_level (int): threat severity level fot dbot score
            return:
             Dict: single row in the human  readable markdown format
    """

    threat_row = {"Threat ID": threat.get("id", ""),
                  "Threat Type": threat.get("threatType", ""),
                  "Executive Summary": threat.get("executiveSummary", ""),
                  "Campaign": threat.get("label", ""),
                  "Malware Family Description": "\n".join(
                      [m.get("description", "") for m in threat.get("malwareFamilySet", [])]),
                  "Last Published": epochToTimestamp(threat.get("lastPublished")),
                  "Threat Report": f"[{threat.get('reportURL', '')}]({threat.get('reportURL', '')})"}

    if severity_level:
        threat_row["Verdict"] = DBOT_TO_VERDICT.get(severity_level)

    return threat_row


def create_hr_for_cofense_search(threat: Dict):
    """ generate dict representing a single row in the human readable markdown format
            Args:
                - threat (Dict): threat data from cofense raw response

            return:
             Dict: single row in the human  readable markdown format
    """

    threat_row = {"Threat ID": threat.get("id", ""),
                  "Threat Type": threat.get("threatType", ""),
                  "Executive Summary": threat.get("executiveSummary", ""),
                  "Campaign": threat.get("label", ""),
                  "Malware Family": "\n".join(
                      [m.get("familyName", "") for m in threat.get("malwareFamilySet", [])]),
                  "Malware File": "\n".join(
                      [m.get("fileName", "") for m in threat.get("executableSet", [])]),
                  "Malware Subject": "\n".join(
                      [m.get("subject", "") for m in threat.get("subjectSet", [])]),
                  "Malware Family Description": "\n".join(
                      [m.get("description", "") for m in threat.get("malwareFamilySet", [])]),
                  "Last Published": epochToTimestamp(threat.get("lastPublished")),
                  "Threat Report": f"[{threat.get('reportURL', '')}]({threat.get('reportURL', '')})"}

    return threat_row


def threats_analysis(severity_score: dict, threats: List, indicator: str, threshold: str):
    """ process raw response data and generate dbot score and human readable results
            Args:
                - severity_score(dict): severity score mapping
                - threats (list): threats data from cofense raw response
                - indicator (string): threat severity level for dbot score calculation
                - threshold (string): threshold for threat's severity
            return:
             Dict: represents human readable markdown table
             int: dbot score
    """

    threshold_score = severity_score.get(threshold)
    if threshold_score is None:
        raise Exception(
            f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    md_data = []
    indicator_found = False
    dbot_score = adjusted_score = 0

    for threat in threats:
        severity_level = 0
        for block in threat.get('blockSet'):

            if block.get('impact'):
                threat_score: int = severity_score.get(block.get('impact'), 0)
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


def ip_threats_analysis(severity_score, threats: List, ip: str, threshold: str, dbot_score_obj):
    """ process raw response data and generate dbot score ,human readable results, ip indicator object
            Args:
                - threats (list): threats data from cofense raw response
                - indicator (string): threat severity level for dbot score calculation
                - threshold (string): threshold for threat's severity
            return:
             Dict: represents human readable markdown table
             int: dbot score
             ip indicator : indicator object with the data collected from the threats
    """
    threshold_score = severity_score.get(threshold)
    if threshold_score is None:
        raise Exception(
            f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    md_data = []
    indicator_found = False
    dbot_score = adjusted_score = severity_level = 0
    ip_indicator = Common.IP(ip=ip, dbot_score=dbot_score_obj)
    for threat in threats:
        severity_level = 0
        for block in threat.get('blockSet'):
            if block.get('impact'):
                threat_score = severity_score.get(block.get('impact'), 0)
                adjusted_score = 3 if threshold_score <= threat_score else threat_score
                if block.get('ipDetail') and block.get('ipDetail').get('ip') == ip:
                    ip_indicator.asn = block.get('ipDetail').get('asn')
                    ip_indicator.geo_latitude = block.get("ipDetail").get("latitude")
                    ip_indicator.geo_longitude = block.get("ipDetail").get("longitude")
                    ip_indicator.geo_country = block.get("ipDetail").get("countryIsoCode")
                    ip_indicator.malware_family = block.get('malwareFamily', {}).get('familyName')
                    severity_level = adjusted_score
                    dbot_score = severity_level
                    indicator_found = True
                    # if the searched ip is found - will take its severity
                    break
            severity_level = max(severity_level, adjusted_score)
        threat_md_row = create_threat_md_row(threat, severity_level)
        threat_md_row["ASN"] = ip_indicator.asn
        threat_md_row["Country"] = ip_indicator.geo_country
        md_data.append(threat_md_row)
    if not indicator_found:
        dbot_score = max(dbot_score, severity_level)

    return md_data, dbot_score, ip_indicator


def file_threats_analysis(severity_score, threats: List, file: str, threshold: str, dbot_score_obj):
    """ process raw response data and generate dbot score ,human readable results, file indicator object
            Args:
                - threats (list): threats data from cofense raw response
                - indicator (string): threat severity level for dbot score calculation
                - threshold (string): threshold for threat's severity
            return:
             Dict: represents human readable markdown table
             int: dbot score
             file indicator : indicator object with the data collected from the threats
    """

    threshold_score = severity_score.get(threshold)
    if threshold_score is None:
        raise Exception(
            f'Cofense error: Invalid threshold value: {threshold}. Valid values are: None, Minor, Moderate or Major')

    md_data = []
    dbot_score = adjusted_score = 0

    file_indicator = Common.File(md5=file, dbot_score=dbot_score_obj)
    for threat in threats:
        severity_level = 0
        block_set = threat.get('blockSet')
        for block in block_set:
            if block.get('impact'):
                threat_score: int = severity_score.get(block.get('impact'), 0)
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

    return md_data, dbot_score, file_indicator


def check_indicator_type(indicator_value) -> str:
    """
    Infer the type of the indicator.

    :type indicator_value: ``str``
    :param indicator_value: The indicator whose type we want to check. (required)

    :return: The type of the indicator.
    :rtype: ``str``
    """
    domainRegex = r'/.+\/\/|www.|\..+/g'

    if re.match(domainRegex, indicator_value):
        return FeedIndicatorType.Domain
    else:
        return auto_detect_indicator_type(indicator_value)


def create_relationship(client: Client, indicator: str, threats: List, entity_a_type: str) -> List:
    """
    Create relationships between indicators as part of enrichment.

    :param entity_a_type:
    :type client: ``Client``
    :param client: client instance that is responsible for connecting with cofense API

    :type indicator: ``str``
    :param indicator: indicator value

    :type threats: ``List``
    :param threats: threats data from cofense raw response

    :return: relationships between indicators
    :rtype: ``List``
    """
    relationships = []
    if client.create_relationships:
        for threat in threats:
            for block in threat.get('blockSet'):
                relationships.append(
                    EntityRelationship(name='related-to',
                                       entity_a=indicator,
                                       entity_a_type=entity_a_type,
                                       entity_b=block.get('data'),
                                       entity_b_type=check_indicator_type(block.get('data')),
                                       brand=BRAND))
            for exec_set in threat.get('executableSet'):
                relationships.append(
                    EntityRelationship(name='related-to',
                                       entity_a=indicator,
                                       entity_a_type=entity_a_type,
                                       entity_b=exec_set.get('md5Hex'),
                                       entity_b_type=FeedIndicatorType.File,
                                       brand=BRAND))
    return relationships


def connectivity_testing(client: Client) -> str:
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
        client.threat_search_call()
        message = 'ok'
    except DemistoException as e:
        if e.res is not None:
            if e.res.status_code in [401, 403]:
                message = 'Authorization Error: make sure Token name and password are correctly set'

            elif e.res.status_code == 404:
                message = 'Not Found: make sure server URL is correct'

        else:
            raise e

    return message


def search_url_command(client: Client, args: Dict[str, Any], params) -> List[CommandResults]:
    """ Performs the api call to cofense threts-search endpoint to get all threats associated with the given url,
     analyze the response and generates the command result object for the url command
            Args:
                - client (Client): client instance that is responsible for connecting with cofense API
                - args (Dict): the command args- url
                - params (Dict): The integartion params such as threshold, reliability
            return:
             CommandResults: results of the url command including outputs, raw response, readable output
    """

    urls = argToList(args.get('url'))
    days_back = args.get('days_back') if args.get('days_back') else params.get('days_back')
    if not urls:
        raise ValueError('URL not specified')
    results_list = []
    for url in urls:
        result = client.threat_search_call(url=url, days_back=days_back)
        threats = result.get('data', {}).get('threats', [])
        remove_false_vendors_detections_from_threat(threats)
        outputs = {'Data': url, 'Threats': threats}
        md_data, dbot_score = threats_analysis(client.severity_score, threats, indicator=url,
                                               threshold=params.get('url_threshold'))

        dbot_score_obj = Common.DBotScore(indicator=url, indicator_type=DBotScoreType.URL,
                                          integration_name=INTEGRATION_NAME, score=dbot_score,
                                          reliability=params.get(RELIABILITY))
        relationships = create_relationship(client, url, threats, FeedIndicatorType.URL)
        url_indicator = Common.URL(url=url, dbot_score=dbot_score_obj, relationships=relationships)

        command_results = CommandResults(
            outputs_prefix=f'{OUTPUT_PREFIX}.URL',
            outputs_key_field='Data',
            outputs=outputs,
            raw_response=result,
            readable_output=tableToMarkdown(name=f'Cofense URL Reputation for url {url}', t=md_data,
                                            headers=['Threat ID', 'Threat Type', 'Verdict', 'Executive Summary',
                                                     'Campaign', 'Malware Family Description', 'Last Published',
                                                     'Threat Report']),
            indicator=url_indicator,
            relationships=relationships)
        results_list.append(command_results)
    return results_list


def check_ip_command(client: Client, args: Dict[str, Any], params) -> List[CommandResults]:
    """ Performs the api call to cofense threts-search endpoint to get all threats associated with the given ip,
     analyze the response and generates the command result object for the ip command
            Args:
                - client (Client): client instance that is responsible for connecting with cofense API
                - args (Dict): the command args- ip
                - params (Dict): The integration params such as threshold, reliability
            return:
             CommandResults: results of the ip command including outputs, raw response, readable output
    """

    ips = argToList(args.get('ip'))
    days_back = args.get('days_back') if args.get('days_back') else params.get('days_back')
    if not ips:
        raise ValueError('IP not specified')
    results_list = []
    for ip in ips:
        try:
            # verify ip is valid
            socket.inet_aton(ip)

        except socket.error:
            raise ValueError(f'Invalid IP: {ip}')

        # Call the Client function and get the raw response
        result = client.threat_search_call(ip=ip, days_back=days_back)
        threats = result.get('data', {}).get('threats', [])
        remove_false_vendors_detections_from_threat(threats)
        outputs = {'Data': ip, 'Threats': threats}
        dbot_score_obj = Common.DBotScore(indicator=ip, indicator_type=DBotScoreType.IP,
                                          integration_name=INTEGRATION_NAME, score=0,
                                          reliability=params.get(RELIABILITY))
        md_data, dbot_score, ip_indicator = ip_threats_analysis(client.severity_score, threats=threats, ip=ip,
                                                                threshold=params.get("ip_threshold"),
                                                                dbot_score_obj=dbot_score_obj)
        relationships = create_relationship(client, ip, threats, FeedIndicatorType.IP)
        dbot_score_obj.score = dbot_score
        ip_indicator.dbot_score = dbot_score_obj
        ip_indicator.relationships = relationships

        command_results = CommandResults(
            outputs_prefix=f'{OUTPUT_PREFIX}.IP',
            outputs_key_field='Data',
            outputs=outputs,
            raw_response=result,
            readable_output=tableToMarkdown(name=f'Cofense IP Reputation for IP {ip}', t=md_data,
                                            headers=['Threat ID', 'Threat Type', 'Verdict', 'Executive Summary',
                                                     'Campaign', 'Malware Family Description', 'Last Published', 'ASN',
                                                     'Country', 'Threat Report']),
            indicator=ip_indicator, relationships=relationships)
        results_list.append(command_results)
    return results_list


def check_email_command(client: Client, args: Dict[str, Any], params) -> List[CommandResults]:
    """ Performs the api call to cofense threts-search endpoint to get all threats associated with the given email,
     analyze the response and generates the command result object for the email command
            Args:
                - client (Client): client instance that is responsible for connecting with cofense API
                - args (Dict): the command args- email
                - params (Dict): The integration params such as threshold, reliability
            return:
             CommandResults: results of the email command including outputs, raw response, readable output
    """

    emails = argToList(args.get('email'))
    days_back = args.get('days_back') if args.get('days_back') else params.get('days_back')
    if not emails:
        raise ValueError('Email not specified')
    results_list = []
    for email in emails:
        if not re.fullmatch(EMAIL_REGEX, email):
            raise ValueError(f'Invalid email address: {email}')

        # Call the Client function and get the raw response
        result = client.threat_search_call(email=email, days_back=days_back)
        threats = result.get('data', {}).get('threats', [])
        remove_false_vendors_detections_from_threat(threats)
        outputs = {'Data': email, 'Threats': threats}
        md_data, dbot_score = threats_analysis(client.severity_score, threats, indicator=email,
                                               threshold=params.get('email_threshold'))

        dbot_score_obj = Common.DBotScore(indicator=email, indicator_type=DBotScoreType.EMAIL,
                                          integration_name=INTEGRATION_NAME, score=dbot_score,
                                          reliability=params.get(RELIABILITY))
        relationships = create_relationship(client, email, threats, FeedIndicatorType.Email)
        email_indicator = Common.EMAIL(address=email, dbot_score=dbot_score_obj, domain=email.split('@')[1],
                                       relationships=relationships)
        command_results = CommandResults(
            outputs_prefix=f'{OUTPUT_PREFIX}.Email',
            outputs=outputs,
            outputs_key_field='Data',
            raw_response=result,
            readable_output=tableToMarkdown(name=f'Cofense email Reputation for email {email}', t=md_data,
                                            headers=['Threat ID', 'Threat Type', 'Verdict', 'Executive Summary',
                                                     'Campaign', 'Malware Family Description', 'Last Published',
                                                     'Threat Report']),
            indicator=email_indicator,
            relationships=relationships
        )
        results_list.append(command_results)
    return results_list


def check_md5_command(client: Client, args: Dict[str, Any], params) -> List[CommandResults]:
    """ Performs the api call to cofense threts-search endpoint to get all threats associated with the given file hash,
     analyze the response and generates the command result object for the file command
            Args:
                - client (Client): client instance that is responsible for connecting with cofense API
                - args (Dict): the command args- file
                - params (Dict): The integration params such as threshold, reliability
            return:
             CommandResults: results of the file command including outputs, raw response, readable output
    """
    files = argToList(args.get('file', None))
    days_back = args.get('days_back') if args.get('days_back') else params.get('days_back')
    if not files:
        raise ValueError('File not specified')
    results_list = []
    for file in files:
        # Call the Client function and get the raw response
        result = client.threat_search_call(file=file, days_back=days_back)
        threats = result.get('data', {}).get('threats', [])
        remove_false_vendors_detections_from_threat(threats)
        outputs = {'Data': file, 'Threats': threats}
        dbot_score_obj = Common.DBotScore(indicator=file, indicator_type=DBotScoreType.FILE,
                                          integration_name=INTEGRATION_NAME, score=0,
                                          reliability=params.get(RELIABILITY))
        md_data, dbot_score, file_indicator = file_threats_analysis(client.severity_score, threats=threats, file=file,
                                                                    threshold=params.get('file_threshold'),
                                                                    dbot_score_obj=dbot_score_obj)
        relationships = create_relationship(client, file, threats, FeedIndicatorType.File)
        file_indicator.relationships = relationships
        file_indicator.dbot_score = dbot_score_obj
        dbot_score_obj.score = dbot_score
        command_results = CommandResults(
            outputs_prefix=f'{OUTPUT_PREFIX}.File',
            outputs_key_field='Data',
            outputs=outputs,
            raw_response=result,
            readable_output=tableToMarkdown(name=f'Cofense file Reputation for file {file}', t=md_data,
                                            headers=['Threat ID', 'Threat Type', 'Verdict', 'Executive Summary',
                                                     'Campaign', 'Malware Family Description', 'Last Published',
                                                     'Threat Report']),
            indicator=file_indicator,
            relationships=relationships)
        results_list.append(command_results)
    return results_list


def extracted_string(client: Client, args: Dict[str, Any], params) -> CommandResults:
    """ Performs the api call to cofense threts-search endpoint to get all threats associated with the given string,
     analyze the response and generates the command result object for the cofense-search command
            Args:
                - client (Client): client instance that is responsible for connecting with cofense API
                - args (Dict): the command args- string
                - params (Dict): The integartion params such as threshold, reliability
            return:
             CommandResults: results of the cofense-search command including outputs, raw response, readable output
    """
    string = args.get('str')

    limit = arg_to_number(args.get('limit'))
    if not limit:
        limit = 10
    malware_family = args.get('malware_family')
    malware_file = args.get('malware_file')
    malware_subject = args.get('malware_subject')
    url = args.get('url')
    days_back = args.get('days_back') if args.get('days_back') else params.get('days_back')
    begin_time_stamp = get_n_days_back_epoch(int(days_back))  # type:ignore
    params = assign_params(extractedString=string, malwareFamily=malware_family, malwareFile=malware_file,
                           malwareSubject=malware_subject, urlSearch=url,
                           beginTimestamp=begin_time_stamp)
    # Call the Client function and get the raw response
    result = client.search_cofense(params=params)
    threats = result.get('data', {}).get('threats', [])
    md_data = []
    count_threats = 0

    if threats:
        for threat in threats:
            if threat.get('hasReport'):
                count_threats += 1
                md_data.append(create_hr_for_cofense_search(threat))
                if count_threats == limit:
                    break
    remove_false_vendors_detections_from_threat(threats)
    return CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.Threats',
        outputs_key_field='id',
        outputs=threats,
        raw_response=result,
        readable_output=tableToMarkdown(name=f'There are {count_threats} threats regarding your string search\n',
                                        t=md_data,
                                        headers=['Threat ID', 'Threat Type', 'Executive Summary',
                                                 'Campaign', 'Malware Family', 'Malware File', 'Malware Subject',
                                                 'Malware Family Description', 'Last Published',
                                                 'Threat Report']))


def check_domain_command(client: Client, args: Dict[str, Any], params) -> List[CommandResults]:
    """ Performs the api call to cofense threts-search endpoint to get all threats associated with the given domain,
     analyze the response and generates the command result object for the domain command
            Args:
                - client (Client): client instance that is responsible for connecting with cofense API
                - args (Dict): the command args- domain
                - params (Dict): The integartion params such as threshold, reliability
            return:
             CommandResults: results of the url command including outputs, raw response, readable output
    """

    domains = argToList(args.get('domain'))
    days_back = args.get('days_back') if args.get('days_back') else params.get('days_back')
    if not domains:
        raise ValueError('Domain not specified')
    results_list = []
    for domain in domains:
        result = client.threat_search_call(domain=domain, days_back=days_back)
        threats = result.get('data', {}).get('threats', [])
        remove_false_vendors_detections_from_threat(threats)
        outputs = {'Data': domain, 'Threats': threats}
        md_data, dbot_score = threats_analysis(client.severity_score, threats, indicator=domain,
                                               threshold=params.get('domain_threshold'))
        dbot_score_obj = Common.DBotScore(indicator=domain, indicator_type=DBotScoreType.DOMAIN,
                                          integration_name=INTEGRATION_NAME, score=dbot_score,
                                          reliability=params.get(RELIABILITY))
        relationships = create_relationship(client, domain, threats, FeedIndicatorType.Domain)
        domain_indicator = Common.Domain(domain=domain, dbot_score=dbot_score_obj, relationships=relationships)

        command_results = CommandResults(
            outputs_prefix=f'{OUTPUT_PREFIX}.Domain',
            outputs_key_field='Data',
            outputs=outputs,
            raw_response=result,
            readable_output=tableToMarkdown(name=f'Cofense Domain Reputation for domain {domain}', t=md_data,
                                            headers=['Threat ID', 'Threat Type', 'Verdict', 'Executive Summary',
                                                     'Campaign', 'Malware Family Description', 'Last Published',
                                                     'Threat Report']),
            indicator=domain_indicator,
            relationships=relationships)
        results_list.append(command_results)
    return results_list


def main() -> None:
    """main function, parses params and runs command functions

    return:
     command results: results returned from the command that is being called
    """
    params = demisto.params()
    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    create_relationships = argToBoolean(params.get('create_relationships', True))
    score_mapping = params.get('scoreMapping', "None:0, Minor:1, Moderate:2, Major:3")
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {
            "Authorization": f"Basic {base64.b64encode(':'.join([username, password]).encode()).decode().strip()}"
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            score_mapping=score_mapping,
            create_relationships=create_relationships
        )

        command = demisto.command()
        args = demisto.args()

        if demisto.command() == 'test-module':
            return_results(connectivity_testing(client))

        elif command == "url":
            return_results(search_url_command(client, args, params))

        elif command == "cofense-search":
            return_results(extracted_string(client, args, params))

        elif command == "email":
            return_results(check_email_command(client, args, params))

        elif command == "file":
            return_results(check_md5_command(client, args, params))

        elif command == "ip":
            return_results(check_ip_command(client, args, params))

        elif command == "domain":
            return_results(check_domain_command(client, args, params))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
