from typing import Tuple, Dict, Any
from collections import defaultdict
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

XFORCE_URL = 'https://exchange.xforce.ibmcloud.com'
DEFAULT_THRESHOLD = 7


class Client(BaseClient):
    """
    Client for X-Force Exchange RESTful API.

    Args:
          url (str): the URL of X-Force Exchange.
          api_key (str): the API key of X-Force Exchange.
          password (str): password for the API key (required for authentication).
          use_ssl (bool): specifies whether to verify the SSL certificate or not.
          use_proxy (bool): specifies if to use Demisto proxy settings.
    """

    def __init__(self, url: str, api_key: str, password: str, use_ssl: bool, use_proxy: bool):
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json'},
                         auth=(api_key, password))

    def ip_report(self, ip: str) -> dict:
        if not is_ip_valid(ip):
            raise DemistoException('The given IP was invalid')

        return self._http_request('GET', f'/ipr/{ip}')

    def url_report(self, url: str) -> dict:
        return self._http_request('GET', f'/url/{url}').get('result')

    def cve_report(self, code: str) -> dict:
        return self._http_request('GET', f'/vulnerabilities/search/{code}')

    def search_cves(self, q: str, start_date: str, end_date: str, bookmark: str) -> dict:
        params = {'q': q, 'startDate': start_date, 'endDate': end_date, 'bookmark': bookmark}
        params = {key: value for key, value in params.items() if value}
        return self._http_request('GET', '/vulnerabilities/fulltext', params=params)

    def file_report(self, file_hash: str) -> dict:
        return self._http_request('GET', f'/malware/{file_hash}').get('malware')

    def get_recent_vulnerabilities(self, start_date: str, end_date: str, limit: int) -> dict:
        params = {'startDate': start_date, 'endDate': end_date, 'limit': limit}
        params = {key: value for key, value in params.items() if value}
        return self._http_request('GET', '/vulnerabilities', params=params)

    def get_version(self) -> dict:
        return self._http_request('GET', '/version')

    def whois(self, host: str) -> dict:
        return self._http_request('GET', f'/whois/{host}')


def calculate_score(score: int, threshold: int) -> int:
    """
    Calculates and converts X-Force Exchange score into Demisto score.

    Args:
        score (int): the score from X-Force Exchange for certain indicator (1-10).
        threshold (int): the score threshold configured by the user.

    Returns:
        int - Demisto's score for the indicator
    """

    if score > threshold:
        return 3
    elif score > threshold / 2:
        return 2
    return 1


def get_cve_results(cve_id: str, report: dict, threshold: int) -> Tuple[str, dict, dict]:
    """
    Formats CVE report from X-Force Exchange into Demisto's outputs.

    Args:
        cve_id (str): the id (code) of the CVE.
        report (dict): the report from X-Force Exchange about the CVE.
        threshold (int): the score threshold configured by the user.

    Returns:
        str: the markdown to display inside Demisto.
        dict: the context to return into Demisto.
        dict: the report from X-Force Exchange (used for debugging).
    """

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
        client (Client): X-Force Exchange client.
    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """

    return 'ok' if ['build', 'created'] in client.get_version() else 'Connection failed.'


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
    Executes IP enrichment against X-Force Exchange.

    Args:
        client (Client): X-Force client.
        args (Dict[str, str]): the arguments for the command.
    Returns:
        str: human readable presentation of the IP report.
        dict: the results to return into Demisto's context.
        dict: the raw data from X-Force client (used for debugging).
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
         client (Client): X-Force client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the URL report.
         dict: the results to return into Demisto's context.
         dict: the raw data from X-Force client (used for debugging).
     """

    url = args.get('url', '') or args.get('domain', '')
    report = client.url_report(url)
    threshold = int(demisto.params().get('url_threshold', DEFAULT_THRESHOLD))

    outputs = {'Data': report['url'], 'Malicious': {'Vendor': 'XFE'}}
    dbot_score = {'Indicator': report['url'], 'Type': 'url', 'Vendor': 'XFE',
                  'Score': calculate_score(report['score'], threshold)}

    context = {'URL(obj.Data==val.Data)': outputs, 'DBotScore': dbot_score}

    table = {'Score': report['score'],
             'Categories': '\n'.join(report['cats'].keys())}
    markdown = tableToMarkdown(f'X-Force URL Reputation for: {report["url"]}\n'
                               f'{XFORCE_URL}/ip/{report["url"]}', table, removeNull=True)

    return markdown, context, report


def cve_search_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
     Get details about vulnerabilities (latest / search) from X-Force Exchange.

     Args:
         client (Client): X-Force client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the CVEs reports.
         context: the results to return into Demisto's context.
         report: the raw data from X-Force Exchange client (used for debugging).
    """

    threshold = int(demisto.params().get('cve_threshold', DEFAULT_THRESHOLD))

    if 'q' in args:
        reports = client.search_cves(args['q'], args.get('start_date', ''), args.get('end_date', ''),
                                     args.get('bookmark', ''))
        reports, total_rows, bookmark = reports['rows'], reports['total_rows'], reports['bookmark']
    else:
        reports = client.get_recent_vulnerabilities(args.get('start_date', ''), args.get('end_date', ''),
                                                    int(args.get('limit', 0)))
        total_rows, bookmark = '', ''

    total_context: Dict[str, Any] = defaultdict(list)
    total_markdown = ''

    for report in reports:
        cve_id = report.get('stdcode', [''])[0]
        markdown, context, _ = get_cve_results(cve_id, report, threshold)

        for key, value in context.items():
            total_context[key].append(value)

        total_markdown += markdown

    if total_rows and bookmark:
        total_context['XFE.CVESearch'] = {'TotalRows': total_rows, 'Bookmark': bookmark}

    return total_markdown, total_context, reports


def cve_get_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
     Executes CVE enrichment against X-Force Exchange.

     Args:
         client (Client): X-Force Exchange client.
         args (Dict[str, str]): the arguments for the command.

     Returns:
         str: human readable presentation of the CVE report.
         dict: the results to return into Demisto's context.
         dict: the raw data from X-Force client (used for debugging).
     """

    threshold = demisto.params().get('cve_threshold', DEFAULT_THRESHOLD)
    report = client.cve_report(args['cve_id'])

    return get_cve_results(args['cve_id'], report[0], threshold)


def file_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
    Executes file hash enrichment against X-Force Exchange.

    Args:
        client (Client): X-Force Exchange client.
        args (Dict[str, str]): the arguments for the command.

    Returns:
         str: human readable presentation of the file hash report.
         dict: the results to return into Demisto's context.
         dict: the raw data from X-Force Exchange client (used for debugging).
    """

    report = client.file_report(args.get('file', ''))
    hash_type = report['type']

    scores = {'high': 3, 'medium': 2, 'low': 1}
    context = build_dbot_entry(args.get('file'), indicator_type=report['type'],
                               vendor='XFE', score=scores.get(report['risk'], 0))
    file_key = f'XFE.{next(filter(lambda k: "File" in k, context.keys()), "File")}'  # type: ignore

    hash_info = {**report['origins'], 'Family': report['family'], 'FamilyMembers': report['familyMembers']}
    context[file_key] = hash_info

    download_servers = ','.join(server['ip'] for server in hash_info.get('downloadServers', {}).get('rows', []))
    cnc_servers = ','.join(server['domain'] for server in hash_info.get('CnCServers', {}).get('rows', []))
    table = {'CnC Servers': cnc_servers, 'Download Servers': download_servers,
             'Source': hash_info.get('external', {}).get('source'), 'Created Date': report['created'],
             'Type': hash_info.get('external', {}).get('malwareType')}
    markdown = tableToMarkdown(f'X-Force {hash_type} Reputation for {args.get("file")}\n'
                               f'{XFORCE_URL}/malware/{args.get("file")}', table, removeNull=True)

    return markdown, context, report


def whois_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
    Gets information about the given host address.

    Args:
        client (Client): X-Force Exchange client.
        args (Dict[str, str]): the arguments for the command.

    Returns:
         str: human readable presentation of the information about the host.
         dict: the results to return into Demisto's context.
         dict: the raw data from X-Force Exchange client (used for debugging).
    """

    result = client.whois(args['host'])

    outputs = {'Host': args['host'], 'RegistrarName': result.get('registrarName'),
               'Created': result.get('createdDate'), 'Updated': result.get('updatedDate'),
               'Expires': result.get('expiresDate'), 'Email': result.get('contactEmail'),
               'Contact': [{k.title(): v for k, v in contact.items()} for contact in result.get('contact', [])]}
    context = {'XFE.Whois(obj.Host==val.Host)': outputs}
    markdown = tableToMarkdown(f'X-Force Whois result for {args["host"]}', outputs, removeNull=True)

    return markdown, context, result


def main():
    params = demisto.params()
    credentials = params.get('credentials')

    client = Client(params.get('url'),
                    credentials.get('identifier'), credentials.get('password'),
                    use_ssl=not params.get('insecure', False),
                    use_proxy=params.get('proxy', False))
    commands = {
        'ip': ip_command,
        'url': url_command,
        'domain': url_command,
        'cve-latest': cve_search_command,
        'cve-search': cve_get_command,
        'file': file_command,
        'xfe-whois': whois_command,
        'xfe-search-cves': cve_search_command
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')

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
