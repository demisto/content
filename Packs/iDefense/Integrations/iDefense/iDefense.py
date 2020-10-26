from typing import Union

from CommonServerPython import *

'''IMPORTS'''
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):

    def __init__(self, input_url, api_key, verify_certificate, proxy):
        base_url = urljoin(input_url, '/rest/threatindicator/v0')
        headers = {
            "Content-Type": "application/json",
            'auth-token': api_key
        }
        super(Client, self).__init__(base_url=base_url,
                                     verify=verify_certificate,
                                     headers=headers,
                                     proxy=proxy)

    def http_request(self, name, param):
        """
        initiates a http request to iDefense
        """

        data = self._http_request(
            method='GET',
            url_suffix=name,
            params=param
        )
        return data


def validate_args(indicator_type, value):
    if indicator_type == 'IP':
        if re.match(ipv4Regex, value):
            return True
        else:
            return False
    if indicator_type == 'URL':
        if re.match(urlRegex, value):
            return True
        else:
            return False


def _calculate_dbot_score(severity):
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


def _extract_analysis_info(res, indicator_value, dbot_score_type):
    """

    Args:
        res: response from http request
        indicator_value: value of indicator given as calling the command
        dbot_score_type: DBotScoreType

    Returns:
        analysis_info: dictionary contains the indicator details returned
        dbot: DBotScore regarding the specific indicator
    """
    dbot = None
    analysis_info = {}
    if res.get('total_size') > 0:
        dbot_score = _calculate_dbot_score(res.get('results')[0].get('severity'))
        desc = 'Match found in IDefense database'
        dbot = Common.DBotScore(indicator_value, dbot_score_type, 'iDefense', dbot_score, desc)
        analysis_info = {
            'Name': res.get('results')[0].get('key'),
            'Dbot Reputation': dbot_score,
            'confidence': res.get('results')[0].get('confidence'),
            'Threat Types': res.get('results')[0].get('threat_types')
        }
    return analysis_info, dbot


def test_module(client: Client) -> str:
    """
    Perform basic request to check if the connection to service was successful
    Args:
        client: iDefense client

    Returns:
        'ok' if the response is ok, else will raise an error

    """

    try:
        client.http_request("", {})
        return 'ok'
    except Exception as e:
        raise DemistoException(f"Error in API call - check the input parameters. Error: {e}")


def ip_command(client: Client, args) -> CommandResults:
    """

    Args:
        client: iDefense client
        args: arguments obtained with the command representing the indicator value to search

    Returns: CommandResults containing the indicator, the response and a readable output

    """
    ip = args.get('ip')

    if not validate_args('IP', ip):
        raise DemistoException(f'Invalid parameter was given, argument value is {ip}')

    data = {'key.values': ip}
    res = client.http_request('/ip', param=data)
    analysis_info, dbot = _extract_analysis_info(res, ip, DBotScoreType.IP)

    if len(analysis_info) == 0:
        return CommandResults(readable_output=f"No results were found for ip {ip}")
    else:
        return CommandResults(
            indicators=[Common.IP(ip, dbot)],
            raw_response=res,
            readable_output=tableToMarkdown('Results', analysis_info)
        )


def url_command(client: Client, args) -> CommandResults:
    url = args.get('url')
    if not validate_args('URL', url):
        raise DemistoException(f'Invalid parameter was given, argument value is {url}')

    data = {'key.values': url}
    res = client.http_request('/url', param=data)
    analysis_info, dbot = _extract_analysis_info(res, url, DBotScoreType.URL)

    if len(analysis_info) == 0:
        return CommandResults(readable_output=f"No results were found for url {url}")

    else:
        return CommandResults(
            indicators=[Common.URL(url, dbot)],
            raw_response=res,
            readable_output=tableToMarkdown('Results', analysis_info)
        )


def domain_command(client: Client, args) -> CommandResults:
    domain = args.get('domain')
    data = {'key.values': domain}
    res = client.http_request('/domain', param=data)
    analysis_info, dbot = _extract_analysis_info(res, domain, DBotScoreType.DOMAIN)
    if len(analysis_info) == 0:
        return CommandResults(readable_output=f"No results were found for domain {domain}")
    else:
        return CommandResults(
            indicators=[Common.Domain(domain, dbot)],
            raw_response=res,
            readable_output=tableToMarkdown('Results', analysis_info)
        )


def uuid_command(client: Client, args) -> CommandResults:
    uuid = args.get('uuid')
    try:
        res = client.http_request(f'/{uuid}', param={})
        dbot_score = _calculate_dbot_score(res.get('severity'))
        desc = 'Match found in IDefense database'

        indicator_value = res.get('key')
        indicator_type = res.get('type')
        indicator: Optional[Union[Common.IP, Common.Domain, Common.URL]] = None
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
            'Name': res.get('key'),
            'Dbot Reputation': dbot_score,
            'confidence': res.get('confidence'),
            'Threat Types': res.get('threat_types')
        }
        return CommandResults(
            indicators=[indicator],
            raw_response=res,
            readable_output=tableToMarkdown('Results', analysis_info)
        )
    except Exception as e:
        if 'Failed to parse json object from response' in e.args[0]:
            return CommandResults(readable_output=f"No results were found for uuid {uuid}")
        else:
            raise e


def main():
    demisto.debug(f'Command being called is {demisto.command()}')
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
        if command == 'test-module':
            test_module(client)
            return_results("ok")
        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
