import re
import demistomock as demisto  # noqa: F401
import urllib3
from bs4 import BeautifulSoup, element
from CommonServerPython import *  # noqa: F401
from traceback import format_exc

# disable insecure warnings
urllib3.disable_warnings()

IP = 'IP'
DOMAIN = 'DOMAIN'
INTEGRATION_NAME = 'WebEx'
BASE_URL = "https://help.webex.com/en-us/WBX264/How-Do-I-Allow-Webex-Meetings-Traffic-on-My-Network"


def grab_domains(data: list) -> List:
    """ From WebExDomain Table get only domain names with wildcards"""
    domainList: List = []
    for lines in data:
        if len(lines) < 2:
            continue
        domains = lines[1].split(' ')
        cleanDomain = " ".join(re.findall(r"([\^]*[\*\.]*[a-z0-9]+\.+.*)*", domains[0]))

        # Strip Whitespace lines to remove blank values
        cleanDomain = cleanDomain.strip()
        if '\t\t\t' in cleanDomain:  # multiple domains in one line
            multiple_domains_lst = cleanDomain.split('\t\t\t')
            for domain in multiple_domains_lst:
                domainList.append(domain)
        elif len(cleanDomain) > 0:
            domainList.append(cleanDomain)
        # Dedup List
        list(dict.fromkeys(domainList))
    return domainList


def grab_CIDR_ips(data: list) -> List:
    """ From list of lists that contain all ips from webex table, get only CIDR ip addresses"""
    CIDR_ip_list: List = []
    for line in data[0]:
        values = line.split(' (CIDR)')
        CIDR_ip_list.append(values[0])
    # Dedup List
    list(dict.fromkeys(CIDR_ip_list))
    return CIDR_ip_list


def grab_domain_table(html_section: element.Tag) -> List:
    """ Gets the domain table from the html section"""
    table = html_section.find('table', attrs={'class': 'li'})
    table_body = table.find('tbody')
    rows = table_body.find_all('tr')
    data = []
    for row in rows:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])
    return data


def grab_ip_table(html_section: element.Tag) -> List:
    """ Gets the IP table from the html section and returns a list of lists"""
    rows = html_section.find_all('ul')
    data = []
    for row in rows:
        cols = row.find_all('li')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])  # Get rid of empty values
    return data


def parse_indicators_from_response(response: requests.Response) -> Dict[str, List[str]]:
    """ Parses the indicators from the raw html response from WebEx website"""
    soup = BeautifulSoup(response.text, "html.parser")

    # Get the IP and Domain Sections from the html
    ipsSection = soup.find("div", {"id": "id_135011"})
    domainsSection = soup.find("div", {"id": "id_135010"})

    # Get Domains
    domainTable = grab_domain_table(domainsSection)
    all_domains_lst = grab_domains(domainTable)

    # Get IPS
    ipTable = grab_ip_table(ipsSection)
    all_IPs_lst = grab_CIDR_ips(ipTable)

    all_info_dict = {IP: all_IPs_lst, DOMAIN: all_domains_lst}
    return all_info_dict


class Client(BaseClient):
    """ A client class that implements connectivity with the website."""

    def all_raw_data(self) -> requests.Response:
        """ Gets the entire html page from the website."""
        try:
            return self._http_request(
                method='GET',
                url_suffix='',
                resp_type='response')
        except DemistoException as e:
            raise e


def check_indicator_type(indicator: str) -> str:
    """Checks the indicator type.
        The indicator type can be classified as one of the following values: CIDR, IPv6CIDR, IP, IPv6 or Domain.

    Args:
        indicator: indicator value

    Returns:
        The type of the indicator
    """
    is_ip_indicator = FeedIndicatorType.ip_to_indicator_type(indicator)
    if is_ip_indicator:
        return is_ip_indicator
    elif '*' in indicator:
        return FeedIndicatorType.DomainGlob
    # domain
    else:
        return FeedIndicatorType.Domain


def test_module(client: Client) -> str:
    """Tests connectivity with the client.
    Args:
        client: Client object.

    Returns:
        str: ok if test passed else the exception message.
    """
    try:
        client.all_raw_data()
    except DemistoException as e:
        return e.message
    return 'ok'


def get_indicators_command(client: Client, **args) -> CommandResults:
    """ Gets indicators from the WebEx website and sends them to the war-room."""
    client = client
    limit = arg_to_number(args.get('limit', 20))
    requested_indicator_type = args.get('indicator_type', 'Both')

    res = client.all_raw_data()
    # parse the data from an html page to a list of dicts with ips and domains
    clean_res = parse_indicators_from_response(res)

    if not requested_indicator_type == 'Both':
        indicators = clean_res.get(requested_indicator_type)[:limit]  # type: ignore
    else:
        indicators = clean_res.get(IP)[:limit] + clean_res.get(DOMAIN)[:limit]  # type: ignore
    final_indicators_lst = []
    for value in indicators:
        type_ = check_indicator_type(value)
        indicators_and_type = {
            'value': value,
            'type': type_
        }
        final_indicators_lst.append(indicators_and_type)

    md = tableToMarkdown('Indicators from WebEx:', final_indicators_lst,
                         headers=['value', 'type'], removeNull=True)

    return CommandResults(
        readable_output=md,
    )


def fetch_indicators_command(client: Client, tags: tuple = None, tlp_color: str = None) -> list:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    res = client.all_raw_data()
    # parse the data from an html page to a list of dicts with ips and domains
    clean_res = parse_indicators_from_response(res)
    results = []
    indicator_mapping_fields = {'tags': tags, 'trafficlightprotocol': tlp_color}
    for indicator in clean_res.get(IP) + clean_res.get(DOMAIN):   # type: ignore
        results.append({
            'value': indicator,
            'type': check_indicator_type(indicator),
            'fields': indicator_mapping_fields
        })
    return results


def main():
    params = demisto.params()
    args = demisto.args()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    tags = params.get('feedTags'),
    tlp_color = params.get('tlp_color')
    command = demisto.command()

    try:
        client = Client(
            base_url=BASE_URL,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            results: CommandResults | str = test_module(client=client)
        elif command == 'fetch-indicators':
            res = fetch_indicators_command(client=client, tags=tags, tlp_color=tlp_color)
            for iter_ in batch(res, batch_size=2000):
                demisto.createIndicators(iter_)
                return
        elif command == 'webex-get-indicators':
            results = get_indicators_command(client=client, **args)
        else:
            return_error('Unrecognized command: ' + demisto.command())
        return_results(results)

    except DemistoException as e:
        # For any other integration command exception, return an error
        demisto.error(format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
