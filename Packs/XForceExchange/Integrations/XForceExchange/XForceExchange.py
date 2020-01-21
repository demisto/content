from typing import Tuple, Dict
from collections import defaultdict
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

XFORCE_URL = 'https://exchange.xforce.ibmcloud.com'
DEFAULT_THRESHOLD = 7


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
    """

    Args:
        score:
        threshold:

    Returns:
        the total score of
    """

    if score > threshold:
        return 3
    elif score > threshold / 2:
        return 2
    return 1


def get_cve_results(cve_id: str, report: dict, threshold: int) -> Tuple[str, dict, dict]:
    outputs = {'ID': cve_id, 'CVSS': report.get('cvss', {}).get('version'),
               'Published': report.get('reported'),
               'Description': report.get('description')}
    dbot_score = {'Indicator': cve_id, 'Type': 'cve', 'Vendor': 'XFE',
                  'Score': calculate_score(round(report.get('risk_level', 0)), threshold)}
    additional_headers = ['xfbid', 'risk_level', 'reported', 'cvss', 'tagname', 'stdcode',
                          'title', 'description', 'platforms_affected', 'exploitability']
    additional_info = {string_to_context_key(field): report.get(field) for field in additional_headers}

    context = {'CVE(obj.ID==val.ID)': outputs, 'DBotScore': dbot_score,
               'XFE.CVE(obj.ID==val.ID)': additional_info}

    table_headers = ['title', 'description', 'risk_level', 'reported', 'exploitability']
    table = {'Version': report.get('cvss', {}).get('version'),
             'Access Vector': report.get('cvss', {}).get('access_vector'),
             'Complexity': report.get('cvss', {}).get('access_complexity'),
             'STD Code': '\n'.join(report.get('stdcode', [])),
             'Affected Platforms': '\n'.join(report.get('platforms_affected', [])),
             **{string_to_table_header(header): report.get(header) for header in table_headers}
             }
    markdown = tableToMarkdown(f'X-Force CVE Reputation for {cve_id}\n'
                               f'{XFORCE_URL}/vulnerability/search/{cve_id}',
                               table, removeNull=True)

    return markdown, context, report


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
        markdown - human readable presentation of the IP report.
        context - the results to return into Demisto's context.
        report - the raw data from X-Force client (used for debugging).
    """

    threshold = int(demisto.params().get('ip_threshold', DEFAULT_THRESHOLD))
    report = client.ip_report(args['ip'])

    outputs = {'Address': report['ip'],
               'Score': report.get('score'),
               'Geo': {'Country': report.get('geo', {}).get('country', '')},
               'Malicious': {'Vendor': 'XFE'}
               }
    additional_info = {string_to_context_key(field): report[field] for field in
                       ['reason', 'reasonDescription', 'subnets']}
    dbot_score = {'Indicator': report['ip'], 'Type': 'ip', 'Vendor': 'XFE',
                  'Score': calculate_score(report['score'], threshold)}

    context = {'IP(obj.Address==val.Address)': outputs,
               'XFE.IP(obj.Address==val.Address)': additional_info,
               'DBotScore': dbot_score}
    table = {'Score': report['score'],
             'Reason': f'{additional_info["Reason"]}:\n{additional_info["Reasondescription"]}',
             'Subnets': ', '.join(subnet.get('subnet') for subnet in additional_info['Subnets'])}
    markdown = tableToMarkdown(f'X-Force IP Reputation for: {report["ip"]}\n'
                               f'{XFORCE_URL}/ip/{report["ip"]}', table, removeNull=True)

    return markdown, context, report


def url_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
     Executes URL enrichment against X-Force Exchange.

     Args:
         client: X-Force client.
         args: the arguments for the command.
     Returns:
         markdown - human readable presentation of the URL report.
         context - the results to return into Demisto's context.
         report - the raw data from X-Force client (used for debugging).
     """

    report = client.url_report(args['url'])
    threshold = int(demisto.params().get('url_threshold', DEFAULT_THRESHOLD))

    outputs = {'Data': report['url'], 'Malicious': {'Vendor': 'XFE'}}
    dbot_score = {'Indicator': report['url'], 'Type': 'url', 'Vendor': 'XFE',
                  'Score': calculate_score(report['score'], threshold)}

    context = {'URL(obj.Data==val.Data)': outputs, 'DBotScore': dbot_score}

    table = {'Score': report['score'],
             'Categories': '\n'.join(report['cats'].keys())
             }
    markdown = tableToMarkdown(f'X-Force URL Reputation for: {report["url"]}\n'
                               f'{XFORCE_URL}/ip/{report["url"]}', table, removeNull=True)

    return markdown, context, report


def cve_latest_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
     Get details from latest vulnerabilities from X-Force Exchange.

     Args:
         client: X-Force client.
         args: the arguments for the command.
     Returns:
         markdown: human readable presentation of the IP report.
         context: the results to return into Demisto's context.
         report: the raw data from X-Force client (used for debugging).
    """

    threshold = int(demisto.params().get('threshold', DEFAULT_THRESHOLD))
    reports = client.get_recent_vulnerabilities()

    total_context: Dict[str, list] = defaultdict(list)
    total_markdown = ''

    for report in reports:
        cve_id = report.get('stdcode', [0])[0]
        markdown, context, _ = get_cve_results(cve_id, report, threshold)

        total_context['CVE(obj.ID==val.ID)'].append(context['CVE(obj.ID==val.ID)'])
        total_context['DBotScore'].append(context['DBotScore'])
        total_context['XFE.CVE(obj.ID==val.ID)'].append(context['XFE.CVE(obj.ID==val.ID)'])

        total_markdown += markdown

    return total_markdown, total_context, reports


def cve_search_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
     Executes CVE enrichment against X-Force Exchange.

     Args:
         client: X-Force client.
         args: the arguments for the command.
     Returns:
         markdown - human readable presentation of the URL report.
         context - the results to return into Demisto's context.
         report - the raw data from X-Force client (used for debugging).
     """

    threshold = demisto.params().get('cve_threshold', DEFAULT_THRESHOLD)
    report = client.cve_report(args['cve_id'])

    return get_cve_results(args['cve_id'], report[0], threshold)


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
