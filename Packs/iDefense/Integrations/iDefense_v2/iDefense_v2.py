from typing import Union, Tuple

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


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


def _validate_args(indicator_type: str, values: list) -> list:
    """
    Args:
        indicator_type: IP or URL
        value: indicator value

    Returns: True if the value matches to the corresponding regex

    """
    validate_indicators = []
    for value in values:
        if indicator_type == 'IP':
            if re.match(ipv4Regex, value):
                validate_indicators.append(value)
        elif indicator_type == 'URL':
            if re.match(urlRegex, value):
                validate_indicators.append(value)
    return validate_indicators


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

    if severity > 4:
        dbot_score = Common.DBotScore.BAD
    elif severity > 2:
        dbot_score = Common.DBotScore.SUSPICIOUS
    elif severity > 0:
        dbot_score = Common.DBotScore.GOOD
    else:
        dbot_score = Common.DBotScore.NONE
    return dbot_score


def _extract_analysis_info(res: dict, dbot_score_type: str) -> Tuple[dict, Optional[Common.DBotScore]]:
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
                analysis_info = {
                    'Name': result_content.get('display_text', ''),
                    'DbotReputation': dbot_score,
                    'Confidence': result_content.get('confidence', 0),
                    'ThreatTypes': result_content.get('threat_types', '')
                }
                analysis_results.append({'analysis_info': analysis_info, 'dbot': dbot})
    return analysis_results


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
        raise DemistoException(f"Error in API call - check the input parameters. Error: {e}")


def _check_returned_results(res: dict) -> list:
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


def _check_no_match_values(all_inputs, res) -> list:
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


def ip_command(client: Client, args: dict):
    """

    Args:
        client: iDefense client
        args: arguments obtained with the command representing the indicator value to search

    Returns: CommandResults containing the indicator, the response and a readable output

    """
    ips: list = argToList(args.get('ip'))

    res = client.threat_indicator_search(url_suffix='/ip', data={'key.values': ips})
    analysis_results = _extract_analysis_info(res, DBotScoreType.IP)
    returned_ips = _check_returned_results(res)
    no_match_values = _check_no_match_values(ips, returned_ips)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info = analysis_result.get('analysis_info')
        dbot = analysis_result.get('dbot')

        indicator: Optional[Common.IP] = None

        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.IP(analysis_info.get('display_text'), dbot)

        command_results.append(CommandResults(indicator=indicator,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        readable_output = f"No results were found for ip {val}"
        command_results.append(CommandResults(readable_output=readable_output))

    return command_results


def url_command(client: Client, args: dict) -> CommandResults:
    urls: list = argToList(args.get('url'))

    res = client.threat_indicator_search(url_suffix='/url', data={'key.values': urls})
    analysis_results = _extract_analysis_info(res, DBotScoreType.URL)
    returned_urls = _check_returned_results(res)
    no_match_values = _check_no_match_values(urls, returned_urls)
    command_results = []

    for analysis_result in analysis_results:
        analysis_info = analysis_result.get('analysis_info')
        dbot = analysis_result.get('dbot')

        indicator: Optional[Common.URL] = None

        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.URL(analysis_info.get('display_text'), dbot)

        command_results.append(CommandResults(indicator=indicator,
                                              raw_response=res,
                                              readable_output=readable_output))

    for val in no_match_values:
        readable_output = f"No results were found for url {val}"
        command_results.append(CommandResults(readable_output=readable_output))

    return command_results


def domain_command(client: Client, args: dict) -> CommandResults:
    domain: str = str(args.get('domain'))
    res = client.threat_indicator_search(url_suffix='/domain', data={'key.values': domain})
    analysis_info, dbot = _extract_analysis_info(res, domain, DBotScoreType.DOMAIN)

    indicator: Optional[Common.Domain] = None

    if len(analysis_info):
        readable_output = tableToMarkdown('Results', analysis_info)
        indicator = Common.Domain(domain, dbot)

    else:
        readable_output = f"No results were found for domain {domain}"

    return CommandResults(indicator=indicator,
                          raw_response=res,
                          readable_output=readable_output)


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
        dbot_score = _calculate_dbot_score(res.get('severity'))
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

        analysis_info = {
            'Name': res.get('display_text'),
            'DbotReputation': dbot_score,
            'Confidence': res.get('confidence'),
            'ThreatTypes': res.get('threat_types')
        }
    return CommandResults(indicator=indicator,
                          raw_response=res,
                          readable_output=tableToMarkdown('Results', analysis_info))


def check_some(client, args):
    x = argToList(args.get('ip'))
    x = _validate_args('IP', x)
    data = {'key.values': x}
    try:
        x = ip_command(client, args)
        # res = client.threat_indicator_search('ip', data)
        x
    except Exception as e:
        print(e.args)


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
        check_some(client,demisto.args())
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
