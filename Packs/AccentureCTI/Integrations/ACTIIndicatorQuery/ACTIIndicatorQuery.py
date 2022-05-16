from typing import Union
from CommonServerPython import *
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
IDEFENSE_URL_TEMPLATE = "https://intelgraph.idefense.com/#/node/{0}/view/{1}"
ATTACHMENT_LINK = 'https://intelgraph.idefense.com/rest/files/download'
IA_URL = 'https://intelgraph.idefense.com/#/node/intelligence_alert/view/'
IR_URL = 'https://intelgraph.idefense.com/#/node/intelligence_report/view/'
ENDPOINTS = {
    'threatindicator': '/rest/threatindicator',
    'document': '/rest/document',
    'fundamental': '/rest/fundamental/v0'
}


class Client(BaseClient):
    def __init__(self, input_url: str, api_key: str, verify_certificate: bool, proxy: bool, endpoint="/rest/threatindicator/v0"):
        base_url = urljoin(input_url, endpoint)
        PACK_VERSION = get_pack_version()
        DEMISTO_VERSION = demisto.demistoVersion()
        DEMISTO_VERSION = f'{DEMISTO_VERSION["version"]}.{DEMISTO_VERSION["buildNumber"]}'
        headers = {
            "Content-Type": "application/json",
            'auth-token': api_key,
            "User-Agent": f"AccentureCTI Pack/{PACK_VERSION} Palo Alto XSOAR/{DEMISTO_VERSION}"
        }
        super(Client, self).__init__(base_url=base_url,
                                     verify=verify_certificate,
                                     headers=headers,
                                     proxy=proxy)

    def threat_indicator_search(self, url_suffix: str, data: dict = {}) -> dict:
        return self._http_request(method='GET', url_suffix=url_suffix, params=data)


def _validate_args(indicator_type: str, values: list) -> None:
    """
    Args:
        indicator_type: IP or URL
        values: list of values
    Returns: Raise error if value do not match to his corresponding regex
    """
    for value in values:
        if indicator_type == 'IP':
            if not re.match(ipv4Regex, value):
                raise DemistoException("Received wrong IP value. Please check values again.")
        elif indicator_type == 'URL':
            if not re.match(urlRegex, value):
                raise DemistoException("Received wrong URL value. Please check values again.")


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


def _extract_analysis_info(res: dict, dbot_score_type: str, reliability: DBotScoreReliability) -> List[dict]:
    """
    Extract context data from http-response and create corresponding DBotScore.
    If response is empty, return empty context and a none for DBotScore object
    Args:
        res: response from http request
        indicator_value: value of indicator given as calling the command
        dbot_score_type: DBotScoreType
    Returns:
        analysis_info: dictionary contains the indicator details returned
        dbot: DBotScore regarding the specific indicator
    """

    analysis_results = []
    if res.get('total_size'):
        results_array = res.get('results', [])
        if len(results_array):
            for result_content in results_array:
                indicator_value = result_content.get('key', '')
                dbot_score: int = _calculate_dbot_score(result_content.get('severity', 0))
                desc = 'Match found in iDefense database'
                dbot = Common.DBotScore(indicator_value, dbot_score_type, 'iDefense', dbot_score, desc, reliability)
                last_published = result_content.get('last_published', '')
                last_published_format = parse_date_string(last_published, DATE_FORMAT)
                last_seen = result_content.get('last_seen', '')
                if last_seen:
                    last_seen_format = parse_date_string(last_seen, DATE_FORMAT)
                else:
                    last_seen_format = 'no Last Seen details available'
                analysis_info = {
                    'Name': result_content.get('display_text', ''),
                    'DbotReputation': dbot_score,
                    'Confidence': result_content.get('confidence', 0),
                    'ThreatTypes': result_content.get('threat_types', ''),
                    'TypeOfUse': result_content.get('last_seen_as', ''),
                    'LastPublished': str(last_published_format),
                    'LastSeen': str(last_seen_format)
                }
                analysis_results.append({'analysis_info': analysis_info, 'dbot': dbot})

    return analysis_results


def _check_returned_results(res: dict) -> List[str]:
    """
    Checks which indicator value founded on iDefense database.
    Args:
        res: api response
    Returns: list of indicator values that returned from api request
    """
    returned_values = []
    if res.get('total_size'):
        results_array = res.get('results', [])
        if len(results_array):
            for result_content in results_array:
                returned_values.append(result_content.get('key', ''))
    return returned_values


def _check_no_match_values(all_inputs: list, res: list) -> List[str]:
    """
    Args:
        all_inputs: all indicator values received from the user
        res: list of all indicator values that returned from api request
    Returns: Which indicator has no match on iDefense database
    """
    complete_values = []

    for val in all_inputs:
        if val not in res:
            complete_values.append(val)

    return complete_values


def test_module(client: Client) -> str:
    """
    Perform basic request to check if the connection to service was successful
    Args:
        client: iDefense client
    Returns:
        'ok' if the response is ok, else will raise an error
    """

    try:
        client.threat_indicator_search(url_suffix='/v0')
        return 'ok'
    except Exception as e:
        raise DemistoException(f"Error in API call - check the input parameters and the API Key. Error: {e}.")


def iair_to_context(analysis_info: dict):
    ia, ir = [], []
    alerts = analysis_info.get('Intelligence Alerts', [])
    reports = analysis_info.get('Intelligence Reports', [])
    if type(alerts) is dict:
        alerts = list(analysis_info.get('Intelligence Alerts', []).values())
        for alert in alerts:
            ia.append(alert.split("/")[-1])
    if type(reports) is dict:
        reports = list(analysis_info.get('Intelligence Reports', []).values())
        for report in reports:
            ir.append(report.split("/")[-1])

    context = {
        "intelligence_alerts": ia,
        "intelligence_reports": ir
    }
    return context


def ip_command(client: Client, args: dict, reliability: DBotScoreReliability, doc_search_client: Client) -> List[CommandResults]:
    """
    Args:
        client: iDefense client
        args: arguments obtained with the command representing the indicator value to search
        reliability: reliability of the source
    Returns: CommandResults containing the indicator, the response and a readable output
    """
    ips: list = argToList(args.get('ip'))
    _validate_args("IP", ips)
    res = client.threat_indicator_search(url_suffix='/v0/ip', data={'key.values': ips})
    analysis_results = _extract_analysis_info(res, DBotScoreType.IP, reliability)
    returned_ips = _check_returned_results(res)
    no_match_values = _check_no_match_values(ips, returned_ips)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info: dict = analysis_result.get('analysis_info', {})
        analysis_info = _enrich_analysis_result_with_intelligence(analysis_info, doc_search_client)
        dbot = analysis_result.get('dbot')
        context = iair_to_context(analysis_info)
        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.IP(analysis_info.get('Name', ''), dbot)
        command_results.append(CommandResults(indicator=indicator,
                                              outputs=context,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        desc = "No results were found on iDefense database"
        dbot = Common.DBotScore(val, DBotScoreType.IP, 'iDefense', 0, desc)
        indicator = Common.IP(val, dbot)
        readable_output = f"No results were found for ip {val}"
        command_results.append(CommandResults(indicator=indicator, readable_output=readable_output))

    return command_results


def url_command(client: Client, args: dict, reliability: DBotScoreReliability, doc_search_client: Client) -> List[CommandResults]:
    urls: list = argToList(args.get('url'))
    _validate_args("URL", urls)

    res = client.threat_indicator_search(url_suffix='/v0/url', data={'key.values': urls})
    analysis_results = _extract_analysis_info(res, DBotScoreType.URL, reliability)
    returned_urls = _check_returned_results(res)
    no_match_values = _check_no_match_values(urls, returned_urls)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info: dict = analysis_result.get('analysis_info', {})
        analysis_info = _enrich_analysis_result_with_intelligence(analysis_info, doc_search_client)
        dbot = analysis_result.get('dbot')
        context = iair_to_context(analysis_info)
        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.URL(analysis_info.get('Name', ''), dbot)
        command_results.append(CommandResults(indicator=indicator,
                                              outputs=context,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        desc = "No results were found"
        dbot = Common.DBotScore(val, DBotScoreType.URL, 'iDefense', 0, desc, reliability)
        indicator = Common.URL(val, dbot)
        readable_output = f"No results were found for url {val}"
        command_results.append(CommandResults(indicator=indicator, readable_output=readable_output))

    return command_results


def domain_command(client: Client, args: dict, reliability: DBotScoreReliability, doc_search_client: Client) -> List[CommandResults]:  # noqa

    domains: list = argToList(args.get('domain'))

    res = client.threat_indicator_search(url_suffix='/v0/domain', data={'key.values': domains})
    analysis_results = _extract_analysis_info(res, DBotScoreType.DOMAIN, reliability)
    returned_domains = _check_returned_results(res)
    no_match_values = _check_no_match_values(domains, returned_domains)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info: dict = analysis_result.get('analysis_info', {})
        analysis_info = _enrich_analysis_result_with_intelligence(analysis_info, doc_search_client)
        dbot = analysis_result.get('dbot')
        context = iair_to_context(analysis_info)
        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.Domain(analysis_info.get('Name', ''), dbot)
        command_results.append(CommandResults(indicator=indicator,
                                              outputs=context,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        desc = "No results were found"
        dbot = Common.DBotScore(val, DBotScoreType.DOMAIN, 'iDefense', 0, desc, reliability)
        indicator = Common.Domain(val, dbot)
        readable_output = f"No results were found for Domain {val}"
        command_results.append(CommandResults(indicator=indicator, readable_output=readable_output))

    return command_results


def uuid_command(client: Client, args: dict, reliability: DBotScoreReliability, doc_search_client: Client) -> CommandResults:
    """
    Search for indicator with the given uuid. When response return, checks which indicator found.
    Args:
        client: iDefense client
        args: arguments obtained with the command representing the value to search
    Returns:
        CommandResults containing the indicator, the response and a readable output
    """
    uuid: str = str(args.get('uuid'))
    res = {}
    try:
        res = client.threat_indicator_search(url_suffix=f'/v0/{uuid}')
    except Exception as e:
        if 'Failed to parse json object from response' in e.args[0]:
            return_results(CommandResults(indicator=None,
                                          raw_response={},
                                          readable_output=f"No results were found for uuid: {uuid}"))
        else:
            raise e

    indicator: Optional[Union[Common.IP, Common.Domain, Common.URL]] = None
    analysis_info = {}
    if len(res):
        dbot_score = _calculate_dbot_score(res.get('severity', 0))
        desc = 'Match found in IDefense database'
        indicator_value = res.get('key', '')
        indicator_type = res.get('type', '')
        # Create indicator by the uuid type returned
        if indicator_type.lower() == 'ip':
            dbot = Common.DBotScore(indicator_value, DBotScoreType.IP, 'iDefense', dbot_score, desc, reliability)
            indicator = Common.IP(indicator_value, dbot)
        elif indicator_type.lower() == 'domain':
            dbot = Common.DBotScore(indicator_value, DBotScoreType.DOMAIN, 'iDefense', dbot_score, desc, reliability)
            indicator = Common.Domain(indicator_value, dbot)
        elif indicator_type.lower() == 'url':
            dbot = Common.DBotScore(indicator_value, DBotScoreType.URL, 'iDefense', dbot_score, desc, reliability)
            indicator = Common.URL(indicator_value, dbot)
        last_published = res.get('last_published', '')
        last_published_format = parse_date_string(last_published, DATE_FORMAT)
        last_seen = res.get('last_seen', '')
        if last_seen:
            last_seen_format = parse_date_string(last_seen, DATE_FORMAT)
        else:
            last_seen_format = 'no Last Seen details available'
        analysis_info = {
            'Name': res.get('display_text', ''),
            'DbotReputation': dbot_score,
            'Confidence': res.get('confidence', 0),
            'ThreatTypes': res.get('threat_types', ''),
            'TypeOfUse': res.get('last_seen_as', ''),
            'LastPublished': str(last_published_format),
            'LastSeen': str(last_seen_format)
        }
        analysis_info = _enrich_analysis_result_with_intelligence(analysis_info, doc_search_client)
        context = iair_to_context(analysis_info)

    return CommandResults(indicator=indicator,
                          outputs=context,
                          raw_response=res,
                          readable_output=tableToMarkdown('Results', analysis_info))


def _enrich_analysis_result_with_intelligence(analysis_info, doc_search_client, indicatorTypeHash: bool = False):
    """
    Adds Intelligence reports and Intelligence alerts information to analysis result for the indicator using given doc search client                                        # noqa: E501
    Args:
        analysis_result obtained from _extract_analysis_info function call
        client: ACTI Document search contoller client
    Returns:
        analysis_result enriched with intelligence alert and intelligence report information if available for the indicator
    """

    indicator = analysis_info['MD5'] if indicatorTypeHash else analysis_info['Name']
    demisto.debug(f"getting ia for indicator {indicator}")

    alerts, reports = _get_ia_for_indicator(indicator, doc_search_client)

    if alerts:
        analysis_info['Intelligence Alerts'] = alerts
    if reports:
        analysis_info['Intelligence Reports'] = reports

    return analysis_info


def _get_ia_for_indicator(indicator: str, doc_search_client: Client):
    """
    Perform document controller api call with given doc search client to get
    Intelligence Alerts and Intelligence Reports for given indicator
    Args:
        client: ACTI Document search contoller client
    Returns:
        intelligence alert and intelligence report dictionaries if api has response else None
    """

    res = {}
    intelligence_alerts, intelligence_reports = None, None

    try:
        res = doc_search_client.threat_indicator_search(
            url_suffix='/v0', data={'type.values': ['intelligence_alert', 'intelligence_report'], 'links.display_text.values': indicator, 'links.display_text.match_all': 'true'})                                                                       # noqa: E501

        alerts = {item['title']: item['uuid'] for item in res.get('results', []) if item['type'] == 'intelligence_alert'}
        reports = {item['title']: item['uuid'] for item in res.get('results', []) if item['type'] == 'intelligence_report'}
        intelligence_alerts = {title: IDEFENSE_URL_TEMPLATE.format('intelligence_alert', uuid) for title, uuid in alerts.items()}
        intelligence_reports = {title: IDEFENSE_URL_TEMPLATE.format(
            'intelligence_report', uuid) for title, uuid in reports.items()}

    except Exception as e:
        if 'Error in API call [403]' in e.args[0]:
            return_results(f"Intelligence Alert & Intelligence Report enrichment (if present) is not possible! As your API token is not eligible to access Document API.\n Error: {str(e)}")                                               # noqa: E501
            demisto.debug(e.args[0])
        else:
            raise e

    return intelligence_alerts, intelligence_reports


def markdown_postprocessing(md_text: str) -> str:
    ''' Applies post processing steps to fix markdown content for XSOAR viewing
    Arg: md_text, markdown text to work on
    Returns: output with processed markdown'''

    result = fix_markdown(md_text)
    result = addBaseUrlToPartialPaths(result)
    result = convert_inline_image_to_encoded(result)
    return result


def fix_markdown(text: str) -> str:
    '''Fix markdown formatting issues
    Arg: Text - Markdown text to be fixed'
    Returns: output - Markdown with fixed formatting'''

    regex_header = r"([#]+)([^\/|\s]\w)"
    subst_header = "\\1 \\2"
    result = re.sub(regex_header, subst_header, text, 0)
    return result


def addBaseUrlToPartialPaths(content: str) -> str:
    '''
    append intelgraph's base URL to partial markdown links
    e.g. '/rest/files/download/...' => 'https://intelgraph.idefense.com/rest/files/download/...'
    e.g. '/#/node/region/view/...' => 'https://intelgraph.idefense.com/#/node/region/view/...
    '''

    files = r"\(\s?(\/rest\/.*?)\)"
    relative_links = r"\((\s?(/#.*?|#.*?))\)"

    def add_ig(match):
        match = match.group(1)
        if match[0] == " ":
            match = match[1:]
        if match[0] == '/':
            match = match[1:]
        return f'(https://intelgraph.idefense.com/{match})'

    content = re.sub(relative_links, add_ig, content)
    content = re.sub(files, add_ig, content)
    return content


def convert_inline_image_to_encoded(md_text: str) -> str:
    ''' Converts inline images in markdown to base64 encoded images
    arg: md_text, markdown text
    return: result updated markdown text'''
    regex = r'(!\[[^\]]+\])\((https?://[^\)]+)\)'
    matches = re.findall(regex, md_text)
    encoded_images = []
    params = demisto.params()
    api_key = params.get('api_token')
    if isinstance(api_key, dict):
        api_key = api_key.get('password')

    for single_match in matches:
        single_image_link = single_match[1]
        single_image_name = single_match[0]
        response = requests.get(single_image_link,
                                headers={"auth-token": api_key}).content
        data = base64.b64encode(response).decode('ascii')
        image_type = single_image_link.split(".")[-1]
        encoded_images.append(f'{single_image_name}(data:image/{image_type};base64,{data})')
    result = re.sub(regex, lambda match: encoded_images.pop(0), md_text, 0, re.MULTILINE)
    return result


def getThreatReport_command(doc_search_client: Client, args: dict, reliability: DBotScoreReliability):
    try:
        result = {}
        ia_ir_uuid: str = str(args.get('uuid'))
        result = doc_search_client.threat_indicator_search(url_suffix=f'/v0/{ia_ir_uuid}')
        custom_indicator, iair_link = _ia_ir_extract(result, reliability)
        return CommandResults(indicator=custom_indicator, raw_response=result,
                              readable_output=f"Report has been fetched!\nUUID: {result['uuid']}\nLink to view report: {iair_link}") # noqa

    except Exception as e:
        if 'Failed to parse json object from response' in e.args[0]:
            return CommandResults(indicator=None, raw_response={},
                                  readable_output=f"No report was found for UUID: {ia_ir_uuid} !!")
        elif 'Error in API call [403]' in e.args[0]:
            return_error(f"This API token doesn't have permission for accessing document API!.\n Error: {str(e)}")
        else:
            raise e


def _ia_ir_extract(Res: dict, reliability: DBotScoreReliability):
    """
    """
    threat_types = Res.get('threat_types', '')
    uuid = Res.get('uuid', '')

    context = {
        'created_on': Res.get('created_on', 'NA'),
        'display_text': Res.get('display_text', 'NA'),
        'dynamic_properties': Res.get('dynamic_properties', 'NA'),
        'index_timestamp': Res.get('index_timestamp', 'NA'),
        'last_modified': Res.get('last_modified', 'NA'),
        'last_published': Res.get('last_published', 'NA'),
        'links': Res.get('links', 'NA'),
        'threat_types': threat_types,
        'title': Res.get('title', 'NA'),
        'type': Res.get('type', 'NA'),
        'uuid': uuid,
        'analysis': markdown_postprocessing(Res.get('analysis', 'NA')),
        'sources_external': Res.get('sources_external', 'NA')
    }

    type_of_report = Res.get('type', 'NA')
    if 'intelligence_report' in type_of_report:
        context['conclusion'] = markdown_postprocessing(Res.get('conclusion', 'NA'))
        context['summary'] = markdown_postprocessing(Res.get('summary', 'NA'))
        severity_dbot_score = Common.DBotScore.NONE
        indicatortype = 'ACTI Intelligence Report'
        iair_link: str = IR_URL + uuid
    else:
        severity_dbot_score = Res.get('severity', 'NA')
        if severity_dbot_score != 'NA':
            severity_dbot_score = _calculate_dbot_score(severity_dbot_score)
        context['mitigation'] = markdown_postprocessing(Res.get('mitigation', 'NA'))
        context['severity'] = Res.get('severity', 'NA')
        context['abstract'] = markdown_postprocessing(Res.get('abstract', 'NA'))
        attachment_links = Res.get('attachment_links', '')
        fqlink: str = ''
        if attachment_links:
            for link in attachment_links:
                fqlink = fqlink + '\n- ' + (ATTACHMENT_LINK + link)
        else:
            fqlink = 'NA'
        context['attachment_links'] = fqlink
        indicatortype = 'ACTI Intelligence Alert'
        iair_link = IA_URL + uuid
    dbot_score = Common.DBotScore(indicator=uuid, indicator_type=DBotScoreType.CUSTOM,
                                  integration_name='ACTI Indicator Query',
                                  score=severity_dbot_score, reliability=reliability)
    custom_indicator = Common.CustomIndicator(indicator_type=indicatortype, dbot_score=dbot_score,
                                              value=uuid, data=context, context_prefix='IAIR')
    return custom_indicator, iair_link


def main():
    params = demisto.params()  # pragma: no cover
    api_key = params.get('api_token')  # pragma: no cover
    if isinstance(api_key, dict):  # pragma: no cover # integration version >=3.2.0
        api_key = api_key.get('password')  # pragma: no cover
    base_url = urljoin(params.get('url', ''))  # pragma: no cover
    reliability = params.get('integrationReliability', 'B - Usually reliable')  # pragma: no cover

    if DBotScoreReliability.is_valid_type(reliability):  # pragma: no cover
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)  # pragma: no cover
    else:
        Exception("ACTI error: Please provide a valid value for the Source Reliability parameter")  # pragma: no cover

    commands = {  # pragma: no cover
        'url': url_command,
        'ip': ip_command,
        'domain': domain_command,
        'acti-get-ioc-by-uuid': uuid_command
    }
    verify_certificate = not params.get('insecure', False)  # pragma: no cover
    proxy = params.get('use_proxy', False)  # pragma: no cover

    try:  # pragma: no cover
        command = demisto.command()  # pragma: no cover
        client = Client(base_url, api_key, verify_certificate, proxy, endpoint=ENDPOINTS['threatindicator'])  # pragma: no cover
        document_search_client = Client(base_url, api_key, verify_certificate,  # pragma: no cover
                                        proxy, endpoint=ENDPOINTS['document'])  # pragma: no cover
        demisto.debug(f'Command being called is {command}')  # pragma: no cover
        if command == 'test-module':  # pragma: no cover
            return_results(test_module(client))  # pragma: no cover
        elif command == 'acti-getThreatIntelReport':  # pragma: no cover
            return_results(getThreatReport_command(document_search_client, demisto.args(), reliability))  # pragma: no cover
        elif command in commands:  # pragma: no cover
            return_results(commands[command](client, demisto.args(), reliability, document_search_client))  # pragma: no cover

    except Exception as e:  # pragma: no cover
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')  # pragma: no cover


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
