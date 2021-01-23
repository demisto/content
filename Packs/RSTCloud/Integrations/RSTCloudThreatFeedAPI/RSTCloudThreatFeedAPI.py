from typing import Dict, Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
RSTCLOUD_URL = 'https://api.rstcloud.net'
RST_URL = 'https://rstcloud.net/'
DEFAULT_THRESHOLD = 50
DEFAULT_EXPIRATION = 180
DBOT_SCORE_KEY = 'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)'

''' CLIENT CLASS '''


class RSTIP(Common.IP):
    CONTEXT_PATH = 'IP(val.Address && val.Address == obj.Address)'

    def __init__(self, ip, dbot_score, asn=None, hostname=None, geo_latitude=None, geo_longitude=None,
                 geo_country=None, geo_description=None, detection_engines=None, positive_engines=None,
                 rstscore=None, tags=None, malwarefamily=None, firstseenbysource=None, lastseenbysource=None):
        super().__init__(ip, dbot_score, asn, hostname, geo_latitude, geo_longitude,
                         geo_country, geo_description, detection_engines, positive_engines)
        self.rstscore = rstscore
        self.tags = tags
        self.malwarefamily = malwarefamily
        self.firstseenbysource = firstseenbysource
        self.lastseenbysource = lastseenbysource

    def to_context(self):
        ret_value = super().to_context()
        ip_context = {
            'Address': self.ip
        }
        if self.rstscore:
            ip_context['RST Score'] = self.rstscore
        if self.tags:
            ip_context['Tags'] = self.tags

        if self.malwarefamily:
            ip_context['MalwareFamily'] = self.malwarefamily

        if self.lastseenbysource:
            ip_context['FirstSeenBySource'] = self.firstseenbysource

        if self.lastseenbysource:
            ip_context['LastSeenBySource'] = self.lastseenbysource

        ret_value[Common.IP.CONTEXT_PATH].update(ip_context)
        return ret_value


class RSTDomain(Common.Domain):
    CONTEXT_PATH = 'Domain(val.Name && val.Name == obj.Name)'

    def __init__(self, domain, dbot_score, dns=None, detection_engines=None, positive_detections=None,
                 organization=None, sub_domains=None, creation_date=None, updated_date=None, expiration_date=None,
                 domain_status=None, name_servers=None,
                 registrar_name=None, registrar_abuse_email=None, registrar_abuse_phone=None,
                 registrant_name=None, registrant_email=None, registrant_phone=None, registrant_country=None,
                 admin_name=None, admin_email=None, admin_phone=None, admin_country=None,
                 rstscore=None, tags=None, malwarefamily=None, firstseenbysource=None, lastseenbysource=None):
        super().__init__(domain, dbot_score, dns, detection_engines, positive_detections,
                         organization, sub_domains, creation_date, updated_date, expiration_date,
                         domain_status, name_servers,
                         registrar_name, registrar_abuse_email, registrar_abuse_phone,
                         registrant_name, registrant_email, registrant_phone, registrant_country,
                         admin_name, admin_email, admin_phone, admin_country)
        self.rstscore = rstscore
        self.tags = tags
        self.malwarefamily = malwarefamily
        self.firstseenbysource = firstseenbysource
        self.lastseenbysource = lastseenbysource

    def to_context(self):
        ret_value = super().to_context()
        domain_context = {
            'Name': self.domain
        }
        if self.rstscore:
            domain_context['RST Score'] = self.rstscore
        if self.tags:
            domain_context['Tags'] = self.tags

        if self.malwarefamily:
            domain_context['MalwareFamily'] = self.malwarefamily

        if self.lastseenbysource:
            domain_context['FirstSeenBySource'] = self.firstseenbysource

        if self.lastseenbysource:
            domain_context['LastSeenBySource'] = self.lastseenbysource

        ret_value[Common.Domain.CONTEXT_PATH].update(domain_context)

        return ret_value


class RSTUrl(Common.URL):
    CONTEXT_PATH = 'URL(val.Data && val.Data == obj.Data)'

    def __init__(self, url, dbot_score, detection_engines=None, positive_detections=None, category=None,
                 rstscore=None, tags=None, malwarefamily=None, firstseenbysource=None, lastseenbysource=None):
        super().__init__(url, dbot_score, detection_engines, positive_detections, category)
        self.rstscore = rstscore
        self.tags = tags
        self.malwarefamily = malwarefamily
        self.firstseenbysource = firstseenbysource
        self.lastseenbysource = lastseenbysource

    def to_context(self):
        ret_value = super().to_context()
        url_context = {
            'Data': self.url
        }
        if self.rstscore:
            url_context['RST Score'] = self.rstscore

        if self.tags:
            url_context['Tags'] = self.tags

        if self.malwarefamily:
            url_context['MalwareFamily'] = self.malwarefamily

        if self.lastseenbysource:
            url_context['FirstSeenBySource'] = self.firstseenbysource

        if self.lastseenbysource:
            url_context['LastSeenBySource'] = self.lastseenbysource

        ret_value[Common.URL.CONTEXT_PATH].update(url_context)

        return ret_value


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


def parse_indicator_response(res, indicator_type):
    indicator = {}
    indicator['IndicatorValue'] = res.get('ioc_value', '')
    indicator['IndicatorType'] = indicator_type
    if not 'error' in res:
        first_seen = str(int(res.get('fseen', '')) * 1000)
        last_seen = str(int(res.get('lseen', '')) * 1000)

        if first_seen:
            indicator['FirstSeen'] = timestamp_to_datestring(first_seen)
        if last_seen:
            indicator['LastSeen'] = timestamp_to_datestring(last_seen)

        if 'tags' in res:
            indicator['Tags'] = res.get('tags').get('str', '')
        if 'fp' in res:
            indicator['FalsePositive'] = res.get('fp', '')
        if 'id' in res:
            indicator['UUID'] = res.get('id', '')
            indicator['RSTReference'] = "https://rstcloud.net/uuid?id=" + res.get('id', '')
        if indicator_type == 'Domain':
            indicator['WhoisDomainCreationDate'] = res.get('whois', {}).get('created', '')
            indicator['WhoisDomainExpireDate'] = res.get('whois', {}).get('expires', '')
            indicator['WhoisDomainUpdateDate'] = res.get('whois', {}).get('updated', '')
            indicator['WhoisRegistrar'] = res.get('whois', {}).get('registrar', '')
            indicator['WhoisRegistrant'] = res.get('whois', {}).get('registrant', '')
            indicator['WhoisAge'] = res.get('whois', {}).get('age', '')
            indicator['Related'] = res.get('resolved').get('ip', '')
        if indicator_type == 'IP':
            indicator['CloudHosting'] = res.get('asn', {}).get('cloud', '')
            indicator['NumberOfDomainInASN'] = res.get('asn', {}).get('domains', '')
            indicator['Organization'] = res.get('asn', {}).get('org', '')
            indicator['ISP'] = res.get('asn', {}).get('isp', '')
            indicator['Geo'] = res.get('geo')
            indicator['Related'] = res.get('related').get('domains', '')
        if indicator_type == 'URL':
            indicator['Parsed'] = res.get('parsed', '')
            indicator['Status'] = res.get('resolved').get('status', '')
            indicator['CVE'] = res.get('cve', '')
    else:
        indicator['error'] = res.get('error', '')
    return indicator


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
                raw_results.append(parse_indicator_response(indicator, 'IP'))
                indicators.append(RSTIP(ip=indicator['ioc_value'], dbot_score=score))
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
            result = RSTIP(
                ip=indicator['ioc_value'],
                asn=indicator.get('asn', {}).get('num', ''),
                geo_country=indicator.get('geo', {}).get('country', ''),
                dbot_score=dbot_score,
                rstscore=total_score,
                tags=indicator.get('tags', '').get('str', ''),
                malwarefamily=indicator.get('threat', ''),
                firstseenbysource=timestamp_to_datestring(str(int(indicator.get('fseen', '')) * 1000)),
                lastseenbysource=timestamp_to_datestring(str(int(indicator.get('lseen', '')) * 1000))
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
            raw_results.append(parse_indicator_response(indicator, 'IP'))
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
                raw_results.append(parse_indicator_response(indicator, 'Domain'))
                indicators.append(RSTDomain(domain=indicator['ioc_value'], dbot_score=score))
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
            result = RSTDomain(
                domain=indicator['ioc_value'],
                dns=indicator.get('resolved', {}).get('ip', '').get('a', ''),
                creation_date=indicator.get('whois', {}).get('created', ''),
                updated_date=indicator.get('whois', {}).get('updated', ''),
                expiration_date=indicator.get('whois', {}).get('expires', ''),
                registrar_name=indicator.get('whois', {}).get('registrar', ''),
                registrant_name=indicator.get('whois', {}).get('registrant', ''),
                dbot_score=dbot_score,
                rstscore=total_score,
                tags=indicator.get('tags', '').get('str', ''),
                malwarefamily=indicator.get('threat', ''),
                firstseenbysource=timestamp_to_datestring(str(int(indicator.get('fseen', '')) * 1000)),
                lastseenbysource=timestamp_to_datestring(str(int(indicator.get('lseen', '')) * 1000))
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
            raw_results.append(parse_indicator_response(indicator, 'Domain'))
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
                raw_results.append(parse_indicator_response(indicator, 'URL'))
                indicators.append(RSTUrl(url=indicator['ioc_value'], dbot_score=score))
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
            result = RSTUrl(
                url=indicator['ioc_value'],
                dbot_score=dbot_score,
                rstscore=total_score,
                tags=indicator.get('tags', '').get('str', ''),
                malwarefamily=indicator.get('threat', ''),
                firstseenbysource=timestamp_to_datestring(str(int(indicator.get('fseen', '')) * 1000)),
                lastseenbysource=timestamp_to_datestring(str(int(indicator.get('lseen', '')) * 1000))
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
            raw_results.append(parse_indicator_response(indicator, 'URL'))
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
                    outputs_prefix='IP',
                    outputs_key_field='Address',
                    outputs={'Address': raw_results[i]['IndicatorValue'], 'RST': raw_results[i]},
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'rst-threat-feed-domain':
            markdown, raw_results, indicators = domain_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='Domain',
                    outputs_key_field='Name',
                    outputs={'Name': raw_results[i]['IndicatorValue'], 'RST': raw_results[i]},
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'rst-threat-feed-url':
            markdown, raw_results, indicators = url_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='URL',
                    outputs_key_field='Data',
                    outputs={'Data': raw_results[i]['IndicatorValue'], 'RST': raw_results[i]},
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
