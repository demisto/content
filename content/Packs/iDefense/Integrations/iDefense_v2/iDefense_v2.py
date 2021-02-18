from typing import Union

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


class Client(BaseClient):

    def __init__(self, input_url: str, api_key: str, verify_certificate: bool, proxy: bool):
        base_url = urljoin(input_url, '/rest/threatindicator/v0')
        headers = {
            "Content-Type": "application/json",
            'auth-token': api_key
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


def _extract_analysis_info(res: dict, dbot_score_type: str) -> List[dict]:
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
                dbot = Common.DBotScore(indicator_value, dbot_score_type, 'iDefense', dbot_score, desc)
                last_published = result_content.get('last_published', '')
                last_published_format = parse_date_string(last_published, DATE_FORMAT)
                analysis_info = {
                    'Name': result_content.get('display_text', ''),
                    'DbotReputation': dbot_score,
                    'Confidence': result_content.get('confidence', 0),
                    'ThreatTypes': result_content.get('threat_types', ''),
                    'TypeOfUse': result_content.get('last_seen_as', ''),
                    'LastPublished': str(last_published_format)
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
        client.threat_indicator_search(url_suffix='')
        return 'ok'
    except Exception as e:
        raise DemistoException(f"Error in API call - check the input parameters and the API Key. Error: {e}.")


def ip_command(client: Client, args: dict) -> List[CommandResults]:
    """

    Args:
        client: iDefense client
        args: arguments obtained with the command representing the indicator value to search

    Returns: CommandResults containing the indicator, the response and a readable output

    """
    ips: list = argToList(args.get('ip'))
    _validate_args("IP", ips)
    res = client.threat_indicator_search(url_suffix='/ip', data={'key.values': ips})
    analysis_results = _extract_analysis_info(res, DBotScoreType.IP)
    returned_ips = _check_returned_results(res)
    no_match_values = _check_no_match_values(ips, returned_ips)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info: dict = analysis_result.get('analysis_info', {})
        dbot = analysis_result.get('dbot')

        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.IP(analysis_info.get('Name', ''), dbot)
        command_results.append(CommandResults(indicator=indicator,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        desc = "No results were found on iDefense database"
        dbot = Common.DBotScore(val, DBotScoreType.IP, 'iDefense', 0, desc)
        indicator = Common.IP(val, dbot)
        readable_output = f"No results were found for ip {val}"
        command_results.append(CommandResults(indicator=indicator, readable_output=readable_output))

    return command_results


def url_command(client: Client, args: dict) -> List[CommandResults]:
    urls: list = argToList(args.get('url'))
    _validate_args("URL", urls)

    res = client.threat_indicator_search(url_suffix='/url', data={'key.values': urls})
    analysis_results = _extract_analysis_info(res, DBotScoreType.URL)
    returned_urls = _check_returned_results(res)
    no_match_values = _check_no_match_values(urls, returned_urls)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info: dict = analysis_result.get('analysis_info', {})
        dbot = analysis_result.get('dbot')

        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.URL(analysis_info.get('Name', ''), dbot)

        command_results.append(CommandResults(indicator=indicator,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        desc = "No results were found"
        dbot = Common.DBotScore(val, DBotScoreType.URL, 'iDefense', 0, desc)
        indicator = Common.URL(val, dbot)
        readable_output = f"No results were found for url {val}"
        command_results.append(CommandResults(indicator=indicator, readable_output=readable_output))

    return command_results


def domain_command(client: Client, args: dict) -> List[CommandResults]:

    domains: list = argToList(args.get('domain'))

    res = client.threat_indicator_search(url_suffix='/domain', data={'key.values': domains})
    analysis_results = _extract_analysis_info(res, DBotScoreType.DOMAIN)
    returned_domains = _check_returned_results(res)
    no_match_values = _check_no_match_values(domains, returned_domains)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info: dict = analysis_result.get('analysis_info', {})
        dbot = analysis_result.get('dbot')

        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.Domain(analysis_info.get('Name', ''), dbot)

        command_results.append(CommandResults(indicator=indicator,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        desc = "No results were found"
        dbot = Common.DBotScore(val, DBotScoreType.DOMAIN, 'iDefense', 0, desc)
        indicator = Common.Domain(val, dbot)
        readable_output = f"No results were found for Domain {val}"
        command_results.append(CommandResults(indicator=indicator, readable_output=readable_output))

    return command_results


def uuid_command(client: Client, args: dict) -> CommandResults:
    """
    Search for indicator with the given uuid. When response return, checks which indicator found.
    Args:
        client: iDefense client
        args: arguments obtained with the command representing the value to search

    Returns:
        CommandResults containing the indicator, the response and a readable output
    """
    uuid: str = str(args.get('uuid'))
    try:
        res = client.threat_indicator_search(url_suffix=f'/{uuid}')
    except Exception as e:
        if 'Failed to parse json object from response' in e.args[0]:
            return CommandResults(indicator=None, raw_response={},
                                  readable_output=f"No results were found for uuid {uuid}")
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
            dbot = Common.DBotScore(indicator_value, DBotScoreType.IP, 'iDefense', dbot_score, desc)
            indicator = Common.IP(indicator_value, dbot)
        elif indicator_type.lower() == 'domain':
            dbot = Common.DBotScore(indicator_value, DBotScoreType.DOMAIN, 'iDefense', dbot_score, desc)
            indicator = Common.Domain(indicator_value, dbot)
        elif indicator_type.lower() == 'url':
            dbot = Common.DBotScore(indicator_value, DBotScoreType.URL, 'iDefense', dbot_score, desc)
            indicator = Common.URL(indicator_value, dbot)
        last_published = res.get('last_published', '')
        last_published_format = parse_date_string(last_published, DATE_FORMAT)
        analysis_info = {
            'Name': res.get('display_text', ''),
            'DbotReputation': dbot_score,
            'Confidence': res.get('confidence', 0),
            'ThreatTypes': res.get('threat_types', ''),
            'TypeOfUse': res.get('last_seen_as', ''),
            'LastPublished': str(last_published_format)
        }
    return CommandResults(indicator=indicator,
                          raw_response=res,
                          readable_output=tableToMarkdown('Results', analysis_info))


def main():
    params = demisto.params()
    api_key = params.get('api_token', '')
    base_url = urljoin(params.get('url', ''))

    commands = {
        'url': url_command,
        'ip': ip_command,
        'domain': domain_command,
        'idefense-get-ioc-by-uuid': uuid_command
    }
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('use_proxy', False)

    try:
        client = Client(base_url, api_key, verify_certificate, proxy)
        command = demisto.command()
        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
