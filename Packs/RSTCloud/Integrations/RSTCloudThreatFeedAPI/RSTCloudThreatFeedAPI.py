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
IPV4REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
DOMAINREGEX = r"(((?=[a-z0-9\-_]{1,63}\.)(xn--)?[a-z0-9_\-]+(-[a-z0-9_]+)*\.)+[a-z-0-9]{2,63})(:\d+)?"
URLREGEX = r"^(?:(?:(?:https?|ftps?):)?\/\/)?((?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)" + \
    r"(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])" + \
    r"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|" + \
    r"(?:(?:[a-z0-9\\u00a1-\\uffff][a-z0-9\\u00a1-\\uffff_-]{0,62})?" + \
    r"[a-z0-9\\u00a1-\\uffff]\.)+(?:[a-z\\u00a1-\\uffff]{2,}|xn--[a-z0-9]+\.?))(?::\d{2,5})?(?:[\/?#]\S*)?)$"

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


class Client:
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


def check_arg_type(arg_name: str, arg_value: str):
    """
        Checks that RST Threat Feed API parameters are valid.

        Args:
          arg_name (str): paramater name
          arg_value (str): paramater value to verify
        Returns:
          (str): a null string means OK while any text is an error
        """
    output = ''
    try:
        isinstance(int(arg_value), int)
        value = int(arg_value)
        if 'threshold' in arg_name:
            if value < 0 or value > 100:
                output = str(arg_name) + ': the value must be between 0 and 100; '
        if 'indicator_expiration' in arg_name:
            if value < 0:
                output = str(arg_name) + ': the value must be positive (>0); '
    except Exception:
        return str(arg_name) + ': bad format, must be a number; '
    return output


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
    """
    Parses responses from RST Threat Feed API.

    Args:
      res (Dict[str, str]): RST Threat Feed response
      indicator_type (str): IP, Domain or UL
    Returns:
      (Dict[str, str]): a result to return into XSOAR's context.
    """
    name = {'IP': 'Address', 'Domain': 'Name', 'URL': 'Data'}
    indicator = {name[indicator_type]: res.get('ioc_value', ''), 'Type': indicator_type}
    if 'error' not in res:
        first_seen = str(int(res.get('fseen', '')) * 1000)
        last_seen = str(int(res.get('lseen', '')) * 1000)
        indicator['Score'] = res.get('score').get('total')

        if first_seen:
            indicator['FirstSeen'] = timestamp_to_datestring(first_seen)
        if last_seen:
            indicator['LastSeen'] = timestamp_to_datestring(last_seen)
        if 'tags' in res:
            indicator['Tags'] = res.get('tags').get('str', '')
        if 'threat' in res:
            indicator['Threat'] = res.get('threat', '')
        if 'fp' in res:
            indicator['FalsePositive'] = res.get('fp').get('alarm', '')
            indicator['FalsePositiveDesc'] = res.get('fp').get('descr', '')
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
            indicator['ASN'] = res.get('asn', {}).get('num', '')
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
    result = ''
    params = ['threshold_ip', 'threshold_domain', 'threshold_url', 'indicator_expiration_ip',
              'indicator_expiration_domain', 'indicator_expiration_url']
    for param in params:
        result += check_arg_type(param, demisto.params().get(param))
    if result == '':
        if 'ioc_value' in client.get_indicator('1.1.1.1'):
            result += 'ok'
        else:
            result += 'Connection failed.'
    return result


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
    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    if check_arg_type('threshold_ip', str(threshold)) != '':
        raise Exception(str(threshold) + ': threshold must be from 0 to 100')
    markdown = []
    raw_results = []
    indicators = []

    for ip in addresses:
        markdown_item = ''
        ipv4regex = re.compile(IPV4REGEX)
        ipv4match = ipv4regex.fullmatch(ip)
        if ipv4match:
            indicator = client.get_indicator(ip)
        else:
            raise Exception('is not valid IP')
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
                score=calc_score,
                malicious_description=indicator.get('description', '')
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
                tags=indicator.get('tags', '').get('str', '')
            )
            table = {'Score': total_score,
                     'Relevance': human_readable_score,
                     'Threat': ', '.join(threat for threat in indicator.get('threat', '')),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f"{string_to_context_key(indicator.get('description', ''))}\n",
                     'Tags': ', '.join(tag for tag in indicator.get('tags', '').get('str', ''))}
            markdown_item += tableToMarkdown(f'RST Threat Feed IP Reputation for: {indicator["ioc_value"]}\n',
                                             table, removeNull=True)
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
    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    if check_arg_type('threshold_domain', str(threshold)) != '':
        raise Exception(str(threshold) + ': threshold must be from 0 to 100')
    markdown = []
    raw_results = []
    indicators = []

    for domain in domains:
        markdown_item = ''
        domainregex = re.compile(DOMAINREGEX)
        domainmatch = domainregex.fullmatch(domain)
        if domainmatch:
            indicator = client.get_indicator(domain)
        else:
            raise Exception('is not valid Domain name')
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
                score=calc_score,
                malicious_description=indicator.get('description', '')
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
                tags=indicator.get('tags', '').get('str', '')
            )
            table = {'Score': total_score,
                     'Relevance:': human_readable_score,
                     'Threat': ', '.join(threat for threat in indicator.get('threat', '')),
                     'Last Seen': time.strftime('%Y-%m-%d', time.localtime(int(indicator.get('lseen', '')))),
                     'Description': f"{string_to_context_key(indicator.get('description', ''))}\n",
                     'Tags': ', '.join(tag for tag in indicator.get('tags', '').get('str', ''))}
            markdown_item += tableToMarkdown(f'RST Threat Feed Domain Reputation for: {indicator["ioc_value"]}\n',
                                             table, removeNull=True)
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
    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    if check_arg_type('threshold_url', str(threshold)) != '':
        raise Exception(str(threshold) + ': threshold must be from 0 to 100')
    markdown = []
    raw_results = []
    indicators = []

    for url in urls:
        markdown_item = ''
        urlregex = re.compile(URLREGEX)
        urlmatch = urlregex.fullmatch(url)
        if urlmatch:
            indicator = client.get_indicator(url)
        else:
            raise Exception('is not valid URL')
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
                score=calc_score,
                malicious_description=indicator.get('description', '')
            )
            result = RSTUrl(
                url=indicator['ioc_value'],
                dbot_score=dbot_score,
                tags=indicator.get('tags', '').get('str', '')
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
                     'Description': f"{string_to_context_key(indicator.get('description', ''))}\n",
                     'Tags': ', '.join(tag for tag in indicator.get('tags', '').get('str', ''))}
            markdown_item += tableToMarkdown(f'RST Threat Feed URL Reputation for: {indicator["ioc_value"]}\n',
                                             table, removeNull=True)
            markdown.append(markdown_item)
            raw_results.append(parse_indicator_response(indicator, 'URL'))
            indicators.append(result)

    return markdown, raw_results, indicators


def submit_command(client: Client, args: Dict[str, str]) -> list:
    """
        Submits a new indicator to RST Threat Feed via API

        Args:
          client (Client): RST Threat Feed client.
          args (Dict[str, str]): the arguments for the command.
        Returns:
          list(str): human readable presentation of the API response
    """
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
    """
            Submits a potential False Positive indicator to RST Threat Feed via API

            Args:
              client (Client): RST Threat Feed client.
              args (Dict[str, str]): the arguments for the command.
            Returns:
              list(str): human readable presentation of the API response
    """
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
        elif command == 'ip':
            markdown, raw_results, indicators = ip_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='RST.IP',
                    outputs_key_field='Address',
                    outputs=raw_results[i],
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'domain':
            markdown, raw_results, indicators = domain_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='RST.Domain',
                    outputs_key_field='Name',
                    outputs=raw_results[i],
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'url':
            markdown, raw_results, indicators = url_command(client, demisto.args())
            for i in range(0, len(raw_results)):
                output = CommandResults(
                    readable_output=markdown[i],
                    outputs_prefix='RST.URL',
                    outputs_key_field='Data',
                    outputs=raw_results[i],
                    indicator=indicators[i]
                )
                return_results(output)
        elif command == 'rst-submit-new':
            markdown = submit_command(client, demisto.args())
            for i in range(0, len(markdown)):
                output = CommandResults(readable_output=markdown[i])
                return_results(output)
        elif command == 'rst-submit-fp':
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
