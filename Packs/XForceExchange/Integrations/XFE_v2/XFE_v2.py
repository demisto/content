from collections import defaultdict
from typing import Tuple, Dict

from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

XFORCE_URL = 'https://exchange.xforce.ibmcloud.com'
DEFAULT_THRESHOLD = 7
DBOT_SCORE_KEY = 'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)'


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

    def url_report(self, url: str):
        try:
            response = self._http_request('GET', f'/url/{url}')
        except Exception as e:
            if "Not Found" in str(e):
                return "Not Found"
            raise
        return response.get('result')

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
    if not score:
        score = 0

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
    additional_headers = ['xfdbid', 'risk_level', 'reported', 'cvss', 'tagname', 'stdcode',
                          'title', 'description', 'platforms_affected', 'exploitability']
    additional_info = {string_to_context_key(field): report.get(field) for field in additional_headers}

    if dbot_score['Score'] == 3:
        outputs['Malicious'] = {'Vendor': 'XFE', 'Description': report.get('description')}

    context = {outputPaths['cve']: outputs,
               DBOT_SCORE_KEY: dbot_score,
               f'XFE.{outputPaths["cve"]}': additional_info}

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

    return 'ok' if client.url_report('google.com') else 'Connection failed.'


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes IP enrichment against X-Force Exchange.

    Args:
        client (Client): X-Force client.
        args (Dict[str, str]): the arguments for the command.
    Returns:
        str: human readable presentation of the IP report.
        dict: the results to return into Demisto's context.
        Any: the raw data from X-Force client (used for debugging).
    """

    threshold = int(demisto.params().get('ip_threshold', DEFAULT_THRESHOLD))

    markdown = ''
    context: dict = defaultdict(list)
    reports = []

    for ip in argToList(args.get('ip')):
        report = client.ip_report(ip)
        outputs = {'Address': report['ip'],
                   'Score': report.get('score'),
                   'Geo': {'Country': report.get('geo', {}).get('country', '')}}
        additional_info = {string_to_context_key(field): report[field] for field in
                           ['reason', 'reasonDescription', 'subnets']}
        dbot_score = {'Indicator': report['ip'], 'Type': 'ip', 'Vendor': 'XFE',
                      'Score': calculate_score(report['score'], threshold)}

        if dbot_score['Score'] == 3:
            outputs['Malicious'] = {'Vendor': 'XFE', 'Description': additional_info['Reasondescription']}

        context[outputPaths['ip']].append(outputs)
        context[f'XFE.{outputPaths["ip"]}'].append(additional_info)
        context[DBOT_SCORE_KEY].append(dbot_score)

        table = {'Score': report['score'],
                 'Reason': f'{additional_info["Reason"]}:\n{additional_info["Reasondescription"]}',
                 'Subnets': ', '.join(subnet.get('subnet') for subnet in additional_info['Subnets'])}
        markdown += tableToMarkdown(f'X-Force IP Reputation for: {report["ip"]}\n'
                                    f'{XFORCE_URL}/ip/{report["ip"]}', table, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def domain_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
     Executes URL enrichment against X-Force Exchange.

     Args:
         client (Client): X-Force client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the URL report.
         dict: the results to return into Demisto's context.
         Any: the raw data from X-Force client (used for debugging).
     """

    domains = argToList(args.get('domain', ''))
    threshold = int(demisto.params().get('url_threshold', DEFAULT_THRESHOLD))
    context: Dict[str, Any] = defaultdict(list)
    markdown = ''
    reports = []

    for domain in domains:
        report = client.url_report(domain)
        if report == "Not Found":
            markdown += f'Domain: {domain} not found\n'
            continue
        outputs = {'Name': report['url']}
        if report.get('score', 0):
            dbot_score = {
                'Indicator': report['url'],
                'Type': 'domain',
                'Vendor': 'XFE',
                'Score': calculate_score(report.get('score', 0), threshold)
            }

            if dbot_score['Score'] == 3:
                outputs['Malicious'] = {'Vendor': 'XFE'}

            context[outputPaths['domain']].append(outputs)
            context[DBOT_SCORE_KEY].append(dbot_score)

            table = {
                'Score': report['score'],
                'Categories': '\n'.join(report['cats'].keys())
            }

            markdown += tableToMarkdown(f'X-Force Domain Reputation for: {report["url"]}\n'
                                        f'{XFORCE_URL}/url/{report["url"]}', table, removeNull=True)

        else:
            markdown += f'### X-Force Domain Reputation for: {report["url"]}.\n{XFORCE_URL}/url/{report["url"]}\n' \
                        f'No information found.'

        reports.append(report)

    return markdown, context, reports


def url_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
     Executes URL enrichment against X-Force Exchange.

     Args:
         client (Client): X-Force client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the URL report.
         dict: the results to return into Demisto's context.
         Any: the raw data from X-Force client (used for debugging).
     """

    urls = argToList(args.get('url', ''))
    threshold = int(demisto.params().get('url_threshold', DEFAULT_THRESHOLD))
    context: Dict[str, Any] = defaultdict(list)
    markdown = ''
    reports = []

    for url in urls:
        report = client.url_report(url)
        if report == "Not Found":
            markdown += f'URL: {url} not found\n'
            continue
        outputs = {'Data': report['url']}
        dbot_score = {'Indicator': report['url'], 'Type': 'url', 'Vendor': 'XFE',
                      'Score': calculate_score(report['score'], threshold)}

        if dbot_score['Score'] == 3:
            outputs['Malicious'] = {'Vendor': 'XFE'}

        context[outputPaths['url']].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)

        table = {'Score': report['score'],
                 'Categories': '\n'.join(report['cats'].keys())}
        markdown += tableToMarkdown(f'X-Force URL Reputation for: {report["url"]}\n'
                                    f'{XFORCE_URL}/url/{report["url"]}', table, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def cve_search_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
     Get details about vulnerabilities (latest / search) from X-Force Exchange.

     Args:
         client (Client): X-Force client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the CVEs reports.
         dict: the results to return into Demisto's context.
         Any: the raw data from X-Force Exchange client (used for debugging).
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


def cve_get_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
     Executes CVE enrichment against X-Force Exchange.

     Args:
         client (Client): X-Force Exchange client.
         args (Dict[str, str]): the arguments for the command.

     Returns:
         str: human readable presentation of the CVE report.
         dict: the results to return into Demisto's context.
         Any: the raw data from X-Force client (used for debugging).
     """

    threshold = int(demisto.params().get('cve_threshold', DEFAULT_THRESHOLD))
    markdown = ''
    context: Dict[str, Any] = defaultdict(list)
    reports = []

    for cve_id in argToList(args.get('cve_id')):
        report = client.cve_report(cve_id)
        cve_markdown, cve_context, _ = get_cve_results(args['cve_id'], report[0], threshold)

        markdown += cve_markdown
        context[outputPaths['cve']].append(cve_context[outputPaths['cve']])
        context[DBOT_SCORE_KEY].append(cve_context[DBOT_SCORE_KEY])
        context[f'XFE.{outputPaths["cve"]}'].append(cve_context[f'XFE.{outputPaths["cve"]}'])

        reports.append(report)

    return markdown, context, reports


def file_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes file hash enrichment against X-Force Exchange.

    Args:
        client (Client): X-Force Exchange client.
        args (Dict[str, str]): the arguments for the command.

    Returns:
         str: human readable presentation of the file hash report.
         dict: the results to return into Demisto's context.
         Any: the raw data from X-Force Exchange client (used for debugging).
    """

    context: dict = defaultdict(list)
    markdown = ''
    reports = []

    for file_hash in argToList(args.get('file')):
        try:
            report = client.file_report(file_hash)
        except Exception as err:
            if 'Error in API call [404] - Not Found' in str(err):
                markdown += f'File: {file_hash} not found\n'
                continue
            else:
                raise

        hash_type = report['type']

        scores = {'high': 3, 'medium': 2, 'low': 1}

        file_context = build_dbot_entry(file_hash, indicator_type=report['type'],
                                        vendor='XFE', score=scores.get(report['risk'], 0))

        if outputPaths['file'] in file_context:
            context[outputPaths['file']].append(file_context[outputPaths['file']])

        if outputPaths['dbotscore'] in file_context:
            context[DBOT_SCORE_KEY].append(file_context[outputPaths['dbotscore']])

        file_key = f'XFE.{outputPaths["file"]}'

        report_data = report['origins'].get('external', {})
        family_value = report_data.get('family')

        hash_info = {**report['origins'], 'Family': family_value,
                     'FamilyMembers': report_data.get('familyMembers')}
        context[file_key] = hash_info

        download_servers = ','.join(server['ip'] for server in hash_info.get('downloadServers', {}).get('rows', []))
        cnc_servers = ','.join(server['domain'] for server in hash_info.get('CnCServers', {}).get('rows', []))
        table = {'CnC Servers': cnc_servers, 'Download Servers': download_servers,
                 'Source': hash_info.get('external', {}).get('source'),
                 'Created Date': report_data.get('firstSeen'),
                 'Type': hash_info.get('external', {}).get('malwareType')}
        markdown += tableToMarkdown(f'X-Force {hash_type} Reputation for {args.get("file")}\n'
                                    f'{XFORCE_URL}/malware/{args.get("file")}', table, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def whois_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Gets information about the given host address.

    Args:
        client (Client): X-Force Exchange client.
        args (Dict[str, str]): the arguments for the command.

    Returns:
         str: human readable presentation of the information about the host.
         dict: the results to return into Demisto's context.
         Any: the raw data from X-Force Exchange client (used for debugging).
    """

    result = client.whois(args['host'])

    contact = [{k.title(): v for k, v in contact.items()} for contact in result.get('contact', [])]
    outputs = {'Host': args['host'], 'RegistrarName': result.get('registrarName'),
               'Created': result.get('createdDate'), 'Updated': result.get('updatedDate'),
               'Expires': result.get('expiresDate'), 'Email': result.get('contactEmail'),
               'Contact': contact}

    domain = {'Name': args['host'], 'CreationDate': outputs['Created'],
              'ExpirationDate': outputs['Expires'], 'UpdatedDate': outputs['Updated'],
              'Organization': contact[0]['Organization'] if contact else '',
              'Registrant': {'Country': contact[0]['Country'] if contact else '',
                             'Name': contact[0]['Organization'] if contact else ''},
              'WHOIS': {'Registrar': {'Name': result.get('registrarName'),
                                      'Email': result.get('contactEmail')
                                      },
                        'UpdatedDate': outputs['Updated'], 'ExpirationDate': outputs['Expires'],
                        'CreationDate': outputs['Created']
                        }
              }

    domain['WHOIS']['Registrant'] = domain['Registrant']  # type: ignore

    context = {outputPaths['domain']: domain, 'XFE.Whois(obj.Host==val.Host)': outputs}
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
        'domain': domain_command,
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
            return_results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
