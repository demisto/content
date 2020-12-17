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
        return Common.DBotScore.BAD
    else:
        return Common.DBotScore.SUSPICIOUS


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


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[list, list, list]:
    """
    Executes IP enrichment against RST Threat Feed.

    Args:
      client (Client): RST Threat Feed client.
      args (Dict[str, str]): the arguments for the command.
    Returns:
      list(str): human readable presentation of the IP indicators.
      list(dict): the results to return into XSOAR's context.
      list(dict): the raw results to return into XSOAR's context.
    """
    addresses = argToList(args.get('ip', ''))
    threshold = int(demisto.params().get('threshold_ip', DEFAULT_THRESHOLD))
    markdown = []
    raw_results = []
    indicators = []

    for ip in addresses:
        markdown_item = ''
        indicator = client.get_indicator(ip)
        if 'error' in indicator:
            if indicator['error'] == 'Not Found':
                score = Common.DBotScore(
                    indicator=ip,
                    indicator_type=DBotScoreType.IP,
                    integration_name='RST Cloud',
                    score=Common.DBotScore.NONE
                )
                markdown_item += f'IP: {ip} not found\n'
                raw_results.append(indicator)
                indicators.append(Common.IP(ip=indicator['ioc_value'], dbot_score=score))
                markdown.append(markdown_item)
                continue
            else:
                raise Exception(f"RST Threat Feed API error while getting a response "
                                f"for {indicator['ioc_value']}: {indicator['error']}\n")
        else:
            total_score = int(indicator.get('score', {}).get('total'))
            calc_score = calculate_score(total_score, threshold, 'ip', int(indicator.get('lseen', '')))
            dbot_score = Common.DBotScore(
                indicator=indicator['ioc_value'],
                indicator_type=DBotScoreType.IP,
                integration_name='RST Cloud',
                score=calc_score
            )

            human_readable_score = ''
            if calc_score == 3:
                human_readable_score = 'Malicious'
            if calc_score == 2:
                human_readable_score = 'Suspicious'
            result = Common.IP(
                ip=indicator['ioc_value'],
                asn=indicator.get('asn', {}).get('num', ''),
                geo_country=indicator.get('geo', {}).get('country', ''),
                dbot_score=dbot_score
            )
            table = {'Score': total_score,
                     'Relevance': human_readable_score,
                     'Threat': ', '.join(threat for threat in indicator.get('threat', '')),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f"\n{string_to_context_key(indicator.get('description', ''))}\n",
                     'Tags': ', '.join(tag for tag in indicator.get('tags', '').get('str', ''))}
            markdown_item += tableToMarkdown(f'RST Threat Feed IP Reputation for: {indicator["ioc_value"]}\n'
                                             f'{RST_URL}uuid?id={indicator["id"]}', table, removeNull=True)
            markdown.append(markdown_item)
            raw_results.append(indicator)
            indicators.append(result)

    return markdown, raw_results, indicators


def domain_command(client: Client, args: Dict[str, str]) -> Tuple[list, list, list]:
    """
    Executes Domain enrichment against RST Threat Feed.

    Args:
      client (Client): RST Threat Feed client.
      args (Dict[str, str]): the arguments for the command.
    Returns:
      list(str): human readable presentation of the Domain indicators.
      list(dict): the results to return into XSOAR's context.
      list(dict): the raw results to return into XSOAR's context.
    """

    domains = argToList(args.get('domain', ''))
    threshold = int(demisto.params().get('threshold_domain', DEFAULT_THRESHOLD))
    markdown = []
    raw_results = []
    indicators = []

    for domain in domains:
        markdown_item = ''
        indicator = client.get_indicator(domain)
        if 'error' in indicator:
            if indicator['error'] == 'Not Found':
                score = Common.DBotScore(
                    indicator=domain,
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name='RST Cloud',
                    score=Common.DBotScore.NONE
                )
                markdown_item += f'Domain: {domain} not found\n'
                raw_results.append(indicator)
                indicators.append(Common.Domain(domain=indicator['ioc_value'], dbot_score=score))
                markdown.append(markdown_item)
                continue
            else:
                raise Exception(f"RST Threat Feed API error while getting a response "
                                f"for {indicator['ioc_value']}: {indicator['error']}\n")
        else:
            total_score = int(indicator.get('score', {}).get('total'))
            calc_score = calculate_score(total_score, threshold, 'domain', int(indicator.get('lseen', '')))
            dbot_score = Common.DBotScore(
                indicator=indicator['ioc_value'],
                indicator_type=DBotScoreType.DOMAIN,
                integration_name='RST Cloud',
                score=calc_score
            )
            human_readable_score = ''
            if calc_score == 3:
                human_readable_score = 'Malicious'
            if calc_score == 2:
                human_readable_score = 'Suspicious'
            result = Common.Domain(
                domain=indicator['ioc_value'],
                creation_date=indicator.get('whois', {}).get('created', ''),
                updated_date=indicator.get('whois', {}).get('updated', ''),
                expiration_date=indicator.get('whois', {}).get('expires', ''),
                registrar_name=indicator.get('whois', {}).get('registrar', ''),
                registrant_name=indicator.get('whois', {}).get('registrant', ''),
                dbot_score=dbot_score
            )
            table = {'Score': total_score,
                     'Relevance:': human_readable_score,
                     'Threat': ', '.join(threat for threat in indicator.get('threat', '')),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f"\n{string_to_context_key(indicator.get('description', ''))}\n",
                     'Tags': ', '.join(tag for tag in indicator.get('tags', '').get('str', ''))}
            markdown_item += tableToMarkdown(f'RST Threat Feed Domain Reputation for: {indicator["ioc_value"]}\n'
                                             f'{RST_URL}uuid?id={indicator["id"]}', table, removeNull=True)
            markdown.append(markdown_item)
            raw_results.append(indicator)
            indicators.append(result)

    return markdown, raw_results, indicators


def url_command(client: Client, args: Dict[str, str]) -> Tuple[list, list, list]:
    """
    Executes URL enrichment against RST Threat Feed.

    Args:
      client (Client): RST Threat Feed client.
      args (Dict[str, str]): the arguments for the command.
    Returns:
      list(str): human readable presentation of the URL indicators.
      list(dict): the results to return into XSOAR's context.
      list(dict): the raw results to return into XSOAR's context.
    """

    urls = argToList(args.get('url', ''))
    threshold = int(demisto.params().get('threshold_url', DEFAULT_THRESHOLD))
    markdown = []
    raw_results = []
    indicators = []

    for url in urls:
        markdown_item = ''
        indicator = client.get_indicator(url)
        if 'error' in indicator:
            if indicator['error'] == 'Not Found':
                score = Common.DBotScore(
                    indicator=url,
                    indicator_type=DBotScoreType.URL,
                    integration_name='RST Cloud',
                    score=Common.DBotScore.NONE
                )
                markdown_item += f'URL: {url} not found\n'
                raw_results.append(indicator)
                indicators.append(Common.URL(url=indicator['ioc_value'], dbot_score=score))
                markdown.append(markdown_item)
                continue
            else:
                raise Exception(f"RST Threat Feed API error while getting a response "
                                f"for {indicator['ioc_value']}: {indicator['error']}\n")
        else:
            total_score = int(indicator.get('score', {}).get('total'))
            calc_score = calculate_score(total_score, threshold, 'url', int(indicator.get('lseen', '')))
            dbot_score = Common.DBotScore(
                indicator=indicator['ioc_value'],
                indicator_type=DBotScoreType.URL,
                integration_name='RST Cloud',
                score=calc_score
            )
            result = Common.URL(
                url=indicator['ioc_value'],
                dbot_score=dbot_score
            )
            human_readable_score = ''
            if calc_score == 3:
                human_readable_score = 'Malicious'
            if calc_score == 2:
                human_readable_score = 'Suspicious'

            table = {'Score': total_score,
                     'Relevance': human_readable_score,
                     'Threat': ', '.join(threat for threat in indicator.get('threat', '')),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f"\n{string_to_context_key(indicator.get('description', ''))}\n",
                     'Tags': ', '.join(tag for tag in indicator.get('tags', '').get('str', ''))}
            markdown_item += tableToMarkdown(f'RST Threat Feed URL Reputation for: {url}\n'
                                             f'{RST_URL}uuid?id={indicator["id"]}', table, removeNull=True)
            markdown.append(markdown_item)
            raw_results.append(indicator)
            indicators.append(result)

    return markdown, raw_results, indicators


def submit_command(client: Client, args: Dict[str, str]) -> list:
    iocs = argToList(args.get('ioc', ''))
    description = argToList(args.get('description', 'manual submission'))
    markdown = []
    for i in range(0, len(iocs)):
        indicator = client.submit_indicator(iocs[i], description[i])
        if "status" in indicator.keys():
            markdown.append(f"Indicator: {iocs[i]} was submitted as a potential threat indicator to RST Cloud\n")
        elif "error" in indicator.keys():
            raise Exception(f"Indicator: {iocs[i]} was not submitted successfully "
                            f"due to the following error: {indicator['error']}\n")
    return markdown


def submitfp_command(client: Client, args: Dict[str, str]) -> list:
    iocs = argToList(args.get('ioc', ''))
    description = argToList(args.get('description', 'manual submission'))
    markdown = []
    for i in range(0, len(iocs)):
        indicator = client.submit_falsepositive(iocs[i], description[i])
        if indicator['status']:
            markdown.append(f"Indicator: {iocs[i]} was submitted as False Positive to RST Cloud\n")
        elif indicator['error']:
            raise Exception(f"Indicator: {iocs[i]} was not submitted successfully due "
                            f"to the following error: {indicator['error']}\n")
    return markdown


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    client = Client(params.get('apikey'), params.get('url'), params.get('insecure', False), params.get('proxy', False))
    demisto.info('RST: Client initialised...')
    command = demisto.command()
    demisto.info(f'RST: Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command == 'rst-threat-feed-ip':
            markdown, raw_results, indicators = ip_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='RST.IP',
                    outputs_key_field='indicator',
                    outputs=raw_results[i],
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'rst-threat-feed-domain':
            markdown, raw_results, indicators = domain_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='RST.Domain',
                    outputs_key_field='indicator',
                    outputs=raw_results[i],
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'rst-threat-feed-url':
            markdown, raw_results, indicators = url_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='RST.URL',
                    outputs_key_field='indicator',
                    outputs=raw_results[i],
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'rst-threat-feed-submit':
            markdown = submit_command(client, demisto.args())
            for i in range(0, len(markdown)):
                output = CommandResults(readable_output=markdown[i])
                return_results(output)
        elif command == 'rst-threat-feed-submit-fp':
            markdown = submitfp_command(client, demisto.args())
            for i in range(0, len(markdown)):
                output = CommandResults(readable_output=markdown[i])
                return_results(output)
        else:
            raise Exception('Command not found.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
