from collections import defaultdict
from typing import Dict, Tuple
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
RSTCLOUD_URL = 'https://api.rstcloud.net'
RST_URL = 'https://rstcloud.net/'
DEFAULT_THRESHOLD = 50
DEFAULT_EXPIRATION = 180
DBOT_SCORE_KEY = 'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, apikey, api_url='https://api.rstcloud.net/v1', verify=False, proxy=False):
        self.apikey = apikey
        self.api_url = api_url
        self.verify = verify
        self.proxy = proxy

    def get_indicator(self, value):
        """Gets reputation data using the '/ioc' API endpoint

            Args:
                value (str): an indicator value to get the reputation for
            Returns:
                Dict - dict containing the IOC reputation as returned from the API
                """
        endpoint = '/ioc'
        apiurl = self.api_url + endpoint + '?value=' + value
        headers = {"Accept": "*/*", "X-Api-Key": self.apikey}
        r = requests.get(apiurl, headers=headers,
                         verify=self.verify, proxies=self.proxy)
        return r.json()

    def submit_indicator(self, value, desc='manual submission'):
        """Submits an indicator using the '/ioc' API endpoint

            Args:
                value (str): an indicator value to submit as a new indicator
                desc (str): an indicator description why it is considered as malicious
            Returns:
                dict - contains the confirmation or error
                """
        endpoint = '/ioc'
        apiurl = self.api_url + endpoint
        payload = {'ioc_value': value, 'description': desc}
        headers = {"Accept": "*/*", "X-Api-Key": self.apikey}
        r = requests.post(apiurl, json=payload, headers=headers,
                          verify=self.verify, proxies=self.proxy)
        return r.json()

    def submit_falsepositive(self, value, desc='manual submission'):
        """Submits an indicator using the '/ioc' API endpoint

            Args:
                value (str): an indicator value to submit as a False Positive
                desc (str): an indicator description why it is considered as False Positive
            Returns:
                dict - contains the confirmation or error
                """
        endpoint = '/ioc'
        payload = {'ioc_value': value, 'description': desc}
        apiurl = self.api_url + endpoint
        headers = {"Accept": "*/*", "X-Api-Key": self.apikey}
        r = requests.put(apiurl, json=payload, headers=headers,
                         verify=self.verify, proxies=self.proxy)
        return r.json()


''' HELPER FUNCTIONS '''


def calculate_score(score: int, threshold: int, itype: str, lseen: int) -> int:
    """
    Calculates and converts RST Threat Feed score into XSOAR score.

    Args:
      score (int): the score from RST Threat Feed for certain indicator (0-100).
      threshold (int): the score threshold configured by the user.
      itype (str): indicator type - ip, domain, url
      lseen (int): last seen in epoch (sec)
    Returns:
      int - XSOAR's score for the indicator
    """
    expiry_limit = int(demisto.params().get('indicator_expiration_' + itype, DEFAULT_EXPIRATION))
    lseendays = (int(time.time()) - lseen) / 24 / 60 / 60
    if score > threshold and expiry_limit > lseendays:
        return 3  # malicious
    else:
        return 2  # suspicious


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
      client (Client): RST Threat Feed client.
    Returns:
      str: 'ok' if test passed, anything else will fail the test.
    """

    return 'ok' if client.get_indicator('1.1.1.1') else 'Connection failed.'


@logger
def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes IP enrichment against RST Threat Feed.

    Args:
      client (Client): RST Threat Feed client.
      args (Dict[str, str]): the arguments for the command.
    Returns:
      str: human readable presentation of the IP indicator.
      dict: the results to return into XSOAR's context.
      Any: the raw data from RST Threat Feed client (used for debugging).
    """
    addresses = argToList(args.get('ip', ''))
    threshold = int(demisto.params().get('threshold_ip', DEFAULT_THRESHOLD))
    context: Dict[str, Any] = defaultdict(list)
    markdown = ''
    results = []
    for ip in addresses:
        indicator = client.get_indicator(ip)
        if 'error' in indicator:
            dbot_score = {'Indicator': indicator['ioc_value'], 'Type': 'ip', 'Vendor': 'RST Cloud', 'Score': 0}
            markdown += f'IP: {ip} not found\n'
            context[DBOT_SCORE_KEY].append(dbot_score)
            continue
        else:
            total_score = int(indicator.get('score', {}).get('total'))
            outputs = {
                'Address': indicator['ioc_value'],
                'Geo': {
                    'Country': indicator.get('geo', {}).get('country', '')
                },
                'ASN': indicator.get('asn', {}).get('num', ''),
                'Tags': indicator.get('tags', '').get('str', ''),
                'MalwareFamily': indicator.get('threat', ''),
                'FirstSeenBySource': datetime.utcfromtimestamp(int(indicator.get('fseen', ''))).isoformat() + '.000Z',
                'LastSeenBySource': datetime.utcfromtimestamp(int(indicator.get('lseen', ''))).isoformat() + '.000Z'
            }
            asndata = {
                'Name': indicator.get('asn', {}).get('num', ''),
                'Org': indicator.get('asn', {}).get('org', ''),
                'ISP': indicator.get('asn', {}).get('isp', ''),
                'Cloud': indicator.get('asn', {}).get('cloud', ''),
                'DomainNumber': indicator.get('asn', {}).get('domains', ''),
                'FirstIP': indicator.get('asn', {}).get('firstip', '').get('netv4', ''),
                'LastIP': indicator.get('asn', {}).get('lastip', '').get('netv4', '')
            }
            additional_info = {
                'Address': indicator['ioc_value'],
                'Geo': {
                    'Country': indicator.get('geo', {}).get('country', ''),
                    'Region': indicator.get('geo', {}).get('region', ''),
                    'City': indicator.get('geo', {}).get('city', '')
                },
                'ASN': asndata,
                'FirstSeen': datetime.utcfromtimestamp(int(indicator.get('fseen', ''))).isoformat() + '.000Z',
                'LastSeen': datetime.utcfromtimestamp(int(indicator.get('lseen', ''))).isoformat() + '.000Z',
                'Tags': indicator.get('tags', '').get('str', ''),
                'Threat': indicator.get('threat', ''),
                'Score': indicator['score'],
                'Description': string_to_context_key(indicator.get('description', '')),
                'FalsePositive': indicator.get('fp', '').get('alarm', ''),
                'FalsePositiveDesc': indicator.get('fp', '').get('descr', '')
            }
            dbot_score = {'Indicator': indicator['ioc_value'], 'Type': 'ip', 'Vendor': 'RST Cloud',
                          'Score': calculate_score(total_score, threshold, 'ip', int(indicator.get('lseen', '')))}
            human_readable_score = ''
            if dbot_score['Score'] == 3:
                human_readable_score = 'Malicious'
                outputs[human_readable_score] = {'Vendor': 'RST Cloud',
                                                 'Description': additional_info['Description'], 'Score': total_score}
            if dbot_score['Score'] == 2:
                human_readable_score = 'Suspicious'
                outputs[human_readable_score] = {'Vendor': 'RST Cloud',
                                                 'Description': additional_info['Description'], 'Score': total_score}
            context[outputPaths['ip']].append(outputs)
            context[f'RST.{outputPaths["ip"]}'].append(additional_info)
            context[DBOT_SCORE_KEY].append(dbot_score)
            table = {'Score': total_score,
                     'Relevance': human_readable_score,
                     'Threat': ', '.join(threat for threat in additional_info["Threat"]),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f'\n{additional_info["Description"]}\n',
                     'Tags': ', '.join(tag for tag in additional_info['Tags'])}
            markdown += tableToMarkdown(f'RST Threat Feed IP Reputation for: {indicator["ioc_value"]}\n'
                                        f'{RST_URL}uuid?id={indicator["id"]}', table, removeNull=True)
            results.append(indicator)

    return markdown, context, results


@logger
def domain_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes URL enrichment against RST Threat Feed.

    Args:
      client (Client): RST Threat Feed client.
      args (Dict[str, str]): the arguments for the command.
    Returns:
      str: human readable presentation of the URL indicator.
      dict: the results to return into XSOAR's context.
      Any: the raw data from RST Threat Feed client (used for debugging).
    """

    domains = argToList(args.get('domain', ''))
    threshold = int(demisto.params().get('threshold_domain', DEFAULT_THRESHOLD))
    context: Dict[str, Any] = defaultdict(list)
    markdown = ''
    results = []

    for domain in domains:
        indicator = client.get_indicator(domain)
        if 'error' in indicator:
            dbot_score = {'Indicator': indicator['ioc_value'], 'Type': 'domain', 'Vendor': 'RST Cloud', 'Score': 0}
            markdown += f'Domain: {domain} not found\n'
            context[DBOT_SCORE_KEY].append(dbot_score)
            continue
        else:
            total_score = int(indicator.get('score', {}).get('total'))
            outputs = {
                'Name': indicator['ioc_value'],
                'Tags': indicator.get('tags', '').get('str', ''),
                'MalwareFamily': indicator.get('threat', ''),
                'FirstSeenBySource': datetime.utcfromtimestamp(int(indicator.get('fseen', ''))).isoformat() + '.000Z',
                'LastSeenBySource': datetime.utcfromtimestamp(int(indicator.get('lseen', ''))).isoformat() + '.000Z'
            }
            whoisdata = {'Age': indicator.get('whois', {}).get('age', ''),
                         'CreationDate': indicator.get('whois', {}).get('created', ''),
                         'UpdatedDate': indicator.get('whois', {}).get('updated', ''),
                         'ExpirationDate': indicator.get('whois', {}).get('expires', ''),
                         'Registrar': {'Name': indicator.get('whois', {}).get('registrar', '')},
                         'Registrant': {'Name': indicator.get('whois', {}).get('registrant', '')}
                         }
            additional_info = {
                'Name': indicator['ioc_value'],
                'WHOIS': whoisdata,
                'FirstSeen': datetime.utcfromtimestamp(int(indicator.get('fseen', ''))).isoformat() + '.000Z',
                'LastSeen': datetime.utcfromtimestamp(int(indicator.get('lseen', ''))).isoformat() + '.000Z',
                'Tags': indicator.get('tags', '').get('str', ''),
                'Threat': indicator.get('threat', ''),
                'Score': indicator['score'],
                'Description': string_to_context_key(indicator.get('description', '')),
                'FalsePositive': indicator.get('fp', '').get('alarm', ''),
                'FalsePositiveDesc': indicator.get('fp', '').get('descr', '')
            }
            dbot_score = {'Indicator': indicator['ioc_value'], 'Type': 'domain', 'Vendor': 'RST Cloud',
                          'Score': calculate_score(total_score, threshold, 'domain', int(indicator.get('lseen', '')))}
            human_readable_score = ''
            if dbot_score['Score'] == 3:
                human_readable_score = 'Malicious'
                outputs[human_readable_score] = {'Vendor': 'RST Cloud',
                                                 'Description': additional_info['Description'], 'Score': total_score}
            if dbot_score['Score'] == 2:
                human_readable_score = 'Suspicious'
                outputs[human_readable_score] = {'Vendor': 'RST Cloud',
                                                 'Description': additional_info['Description'], 'Score': total_score}
            context[outputPaths['domain']].append(outputs)
            context[f'RST.{outputPaths["domain"]}'].append(additional_info)
            context[DBOT_SCORE_KEY].append(dbot_score)
            table = {'Score': total_score,
                     'Relevance:': human_readable_score,
                     'Threat': ', '.join(threat for threat in additional_info["Threat"]),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f'\n{additional_info["Description"]}\n',
                     'Tags': ', '.join(tag for tag in additional_info['Tags'])}
            markdown += tableToMarkdown(f'RST Threat Feed Domain Reputation for: {indicator["ioc_value"]}\n'
                                        f'{RST_URL}uuid?id={indicator["id"]}', table, removeNull=True)
            results.append(indicator)

    return markdown, context, results


@logger
def url_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes URL enrichment against RST Threat Feed.

    Args:
      client (Client): RST Threat Feed client.
      args (Dict[str, str]): the arguments for the command.
    Returns:
      str: human readable presentation of the URL indicator.
      dict: the results to return into XSOAR's context.
      Any: the raw data from RST Threat Feed client (used for debugging).
    """

    urls = argToList(args.get('url', ''))
    threshold = int(demisto.params().get('threshold_url', DEFAULT_THRESHOLD))
    context: Dict[str, Any] = defaultdict(list)
    markdown = ''
    results = []

    for url in urls:
        indicator = client.get_indicator(url)
        if 'error' in indicator:
            dbot_score = {'Indicator': url, 'Type': 'url', 'Vendor': 'RST Cloud', 'Score': 0}
            markdown += f'URL: {url} not found\n'
            context[DBOT_SCORE_KEY].append(dbot_score)
            continue
        else:
            total_score = int(indicator.get('score', {}).get('total'))
            outputs = {
                'Data': url,
                'Tags': indicator.get('tags', '').get('str', ''),
                'MalwareFamily': indicator.get('threat', ''),
                'FirstSeenBySource': datetime.utcfromtimestamp(int(indicator.get('fseen', ''))).isoformat() + '.000Z',
                'LastSeenBySource': datetime.utcfromtimestamp(int(indicator.get('lseen', ''))).isoformat() + '.000Z'
            }
            additional_info = {
                'Data': url,
                'ResolveStatus': indicator.get('resolved', {}).get('status', ''),
                'FirstSeen': datetime.utcfromtimestamp(int(indicator.get('fseen', ''))).isoformat() + '.000Z',
                'LastSeen': datetime.utcfromtimestamp(int(indicator.get('lseen', ''))).isoformat() + '.000Z',
                'Tags': indicator.get('tags', '').get('str', ''),
                'Threat': indicator.get('threat', ''),
                'Score': indicator['score'],
                'Description': string_to_context_key(indicator.get('description', '')),
                'FalsePositive': indicator.get('fp', '').get('alarm', ''),
                'FalsePositiveDesc': indicator.get('fp', '').get('descr', '')
            }
            dbot_score = {'Indicator': url, 'Type': 'url', 'Vendor': 'RST Cloud',
                          'Score': calculate_score(total_score, threshold, 'url', int(indicator.get('lseen', '')))}
            human_readable_score = ''
            if dbot_score['Score'] == 3:
                human_readable_score = 'Malicious'
                outputs[human_readable_score] = {'Vendor': 'RST Cloud',
                                                 'Description': additional_info['Description'], 'Score': total_score}
            if dbot_score['Score'] == 2:
                human_readable_score = 'Suspicious'
                outputs[human_readable_score] = {'Vendor': 'RST Cloud',
                                                 'Description': additional_info['Description'], 'Score': total_score}
            context[outputPaths['url']].append(outputs)
            context[f'RST.{outputPaths["url"]}'].append(additional_info)
            context[DBOT_SCORE_KEY].append(dbot_score)
            table = {'Score': total_score,
                     'Relevance': human_readable_score,
                     'Threat': ', '.join(threat for threat in additional_info["Threat"]),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f'\n{additional_info["Description"]}\n',
                     'Tags': ', '.join(tag for tag in additional_info['Tags'])}
            markdown += tableToMarkdown(f'RST Threat Feed URL Reputation for: {url}\n'
                                        f'{RST_URL}uuid?id={indicator["id"]}', table, removeNull=True)
            results.append(indicator)

    return markdown, context, results


@logger
def submit_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    iocs = argToList(args.get('ioc', ''))
    description = argToList(args.get('description', 'manual submission'))
    context: Dict[str, Any] = defaultdict(list)
    markdown: str = ''
    results: List[str] = []
    num = 0
    for ioc in iocs:
        indicator = client.submit_indicator(ioc, description[num])
        num += 1
        if "status" in indicator.keys():
            markdown += f"Indicator: {ioc} was submitted as a potential threat indicator to RST Cloud\n"
        elif "error" in indicator.keys():
            markdown += f"Indicator: {ioc} was not submitted successfully due to the following error: {indicator['error']}\n"
    return markdown, context, results


@logger
def submitfp_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    iocs = argToList(args.get('ioc', ''))
    description = argToList(args.get('description', 'manual submission'))
    context: Dict[str, Any] = defaultdict(list)
    markdown = ''
    results: List[str] = []
    num = 0
    for ioc in iocs:
        indicator = client.submit_falsepositive(ioc, description[num])
        num += 1
        if indicator['status']:
            markdown += f"Indicator: {ioc} was submitted as False Positive to RST Cloud\n"
        elif indicator['error']:
            markdown += f"Indicator: {ioc} was not submitted successfully due to the following error: {indicator['error']}\n"
    return markdown, context, results


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    client = Client(params.get('apikey'), params.get('url'), params.get('insecure', False), params.get('proxy', False))
    LOG('RST: Client initialised...')
    commands = {
        'rst-threat-feed-ip': ip_command,
        'rst-threat-feed-domain': domain_command,
        'rst-threat-feed-url': url_command,
        'rst-threat-feed-submit': submit_command,
        'rst-threat-feed-submit-fp': submitfp_command,
    }

    command = demisto.command()
    LOG(f'RST: Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise Exception('Command not found.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
