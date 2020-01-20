from typing import Tuple, Dict
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

XFORCE_URL = 'https://exchange.xforce.ibmcloud.com'


class Client(BaseClient):
    def __init__(self, url: str, api_key: str, password: str, use_ssl: bool, use_proxy: bool):
        self.url = url
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json'},
                         auth=(api_key, password))

    def ip_report(self, ip: str) -> dict:
        return self._http_request('GET', f'/ipr/{ip}')

    def url_report(self, url: str) -> dict:
        return self._http_request('GET', f'/url/{url}').get('result')

    def cve_report(self, code: str) -> dict:
        return self._http_request('GET', f'/vulnerabilities/search/{code}')

    def get_recent_vulnerabilities(self) -> dict:
        return self._http_request('GET', f'/vulnerabilities')


def calculate_score(score: int, threshold: int) -> int:
    if score > threshold:
        return 3
    elif score > threshold / 2:
        return 2
    return 1


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Args:
        client: X-Force client
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    return 'ok' if client.ip_report('8.8.8.8').get('ip') == '8.8.8.8' else 'Connection failed.'


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
    Executes IP enrichment against X-Force Exchange.
    Args:
        client: X-Force client.
        args: the arguments for the command.
    Returns:
    """

    threshold = demisto.params().get('threshold', 50)
    report = client.ip_report(args['ip'])

    outputs = {'Address': report['ip'],
               'Score': report.get('score'),
               'Geo': {'Country': report.get('geo', {}).get('country', '')},
               'Malicious': {'Vendor': 'XFE'}
               }
    additional_info = {field.title(): report[field] for field in ['reason', 'reasonDescription', 'subnets']}
    dbot_score = {'Indicator': report['ip'], 'Type': 'ip', 'Vendor': 'XFE',
                  'Score': calculate_score(report['score'], threshold)}

    context = {'IP(obj.Address==val.Address)': outputs,
               'XForce.IP(obj.Address==val.Address)': additional_info,
               'DBotScore': dbot_score}

    table = {'Score': report['score'],
             'Reason': f'{additional_info["Reason"]}:\n{additional_info["ReasonDescription"]}',
             'Subnets': ', '.join(subnet.get('subnet') for subnet in additional_info['Subnets'])}
    mark_down = tableToMarkdown(f'X-Force IP Reputation for: {report["ip"]}\n'
                                f'{XFORCE_URL}/ip/{report["ip"]}', table, removeNull=True)

    return mark_down, context, report


def url_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    report = client.url_report(args['url'])
    threshold = demisto.params().get('threshold', 50)

    outputs = {'Data': report['url'], 'Malicious': {'Vendor': 'XFE'}}
    dbot_score = {'Indicator': report['url'], 'Type': 'url', 'Vendor': 'XFE',
                  'Score': calculate_score(report['score'], threshold)}

    context = {'URL(obj.Data==val.Data)': outputs, 'DBotScore': dbot_score}

    table = {'Score': report['score'],
             'Categories': '\n'.join(report['cats'].keys())
             }
    mark_down = tableToMarkdown(f'X-Force URL Reputation for: {report["url"]}\n'
                                f'{XFORCE_URL}/ip/{report["url"]}', table, removeNull=True)

    return mark_down, context, report


def domain_command(client: Client, args: Dict[str, str]) -> Tuple[dict, dict, dict]:
    return {}, {}, {}


def cve_latest_command(client: Client, args: Dict[str, str]) -> Tuple[dict, dict, dict]:
    return {}, {}, {}


def cve_search_command(client: Client, args: Dict[str, str]) -> Tuple[dict, dict, dict]:
    return {}, {}, {}


def main():
    params = demisto.params()
    credentials = params.get('credentials')

    LOG(f'Command being called is {demisto.command()}')
    client = Client(params.get('url'),
                    credentials.get('identifier'), credentials.get('password'),
                    use_ssl=not params.get('insecure', False),
                    use_proxy=params.get('proxy', False))
    commands = {
        'ip': ip_command,
        'url': url_command,
        'domain': url_command,
        'cve-latest': cve_latest_command,
        'cve-search': cve_search_command
    }

    command = demisto.command()

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
