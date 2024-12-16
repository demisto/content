import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import urllib3
from bs4 import BeautifulSoup, element
from traceback import format_exc

# disable insecure warnings
urllib3.disable_warnings()

CIDR = 'CIDR'
DOMAIN = 'DOMAIN'
INTEGRATION_NAME = 'Webex'
BASE_URL = "https://help.webex.com/en-us/WBX264/How-Do-I-Allow-Webex-Meetings-Traffic-on-My-Network"
DOMAIN_REGEX = r"([\^]*[\*\.]*[a-z0-9+\-]+\.+.*)*"


def grab_domain_table(html_section: element.Tag) -> List:
    """ Gets the domain table from the given html section"""
    table = html_section.find('table', attrs={'class': 'li'})
    table_body = table.find('tbody')
    rows = table_body.find_all('tr')
    data = []
    for row in rows:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])  # Get rid of empty values
    return data


def grab_domains(data: list) -> List:
    """ From a given list of lists, that each contains a row from the webex table, text and domains,
        return a list of all the domains only
    """
    domainList: List = []
    # skip the last line of the table, it's a message and not a domain
    for lines in data[:-1]:
        domains = lines[1].split(' ')
        cleanDomain = " ".join(re.findall(DOMAIN_REGEX, domains[0]))

        # Strip Whitespace lines to remove blank values
        cleanDomain = cleanDomain.strip()
        if '\t\t\t' in cleanDomain:  # multiple domains in one line
            multiple_domains_lst = cleanDomain.split('\t\t\t')
            domainList += multiple_domains_lst
        elif cleanDomain:
            domainList.append(cleanDomain)
    # remove duplicates and convert it back to a list fot the slicing to work
    finel_domainList = list(set(domainList))
    return finel_domainList


def grab_ip_table(html_section: element.Tag) -> List:
    """ Gets the IP table as an html, parses it and
    returns a list of lists each one contains a row from the table
    """
    rows = html_section.find_all('ul')
    data = []
    for row in rows:
        cols = row.find_all('li')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])  # Get rid of empty values
    return data


def grab_CIDR_ips(data: list) -> List:
    """ From list of lists that contain all rows of the IP webex table,
        return a list with only CIDR ip addresses
    """
    CIDR_ip_list: List = []
    if not data[0]:
        raise DemistoException('Did not find any IP indicators in the IP table')

    for line in data[0]:
        values = line.split(' (CIDR)')
        CIDR_ip_list.append(values[0])
    # remove duplicates and convert it back to a list fot the slicing to work
    finel_CIDR_ip_list = list(set(CIDR_ip_list))
    return finel_CIDR_ip_list


def parse_indicators_from_response(response: requests.Response) -> Dict[str, List[str]]:
    """ Recives an html page from the Webex website that contains a IP table and a DOMAIN table.
    Parses the page, and returns a dict with two keys: DOMAIN and CIDR(ip ranges),
    while the value is a list of the related indicators.
    """
    try:
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
    except Exception as e:
        raise DemistoException(f'Failed to parse the response from the website. Error: {str(e)}')

    if not all_IPs_lst or not all_domains_lst:
        raise DemistoException('Did not find the expected indicators in the response from the website')
    all_info_dict = {CIDR: all_IPs_lst, DOMAIN: all_domains_lst}
    return all_info_dict


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


def test_module(client: Client) -> str:     # pragma: no cover
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
    """ Gets indicators from the Webex website and sends them to the war-room."""
    client = client
    limit = arg_to_number(args.get('limit', 20))
    requested_indicator_type = args.get('indicator_type', 'Both')
    if requested_indicator_type not in ['Both', 'CIDR', 'DOMAIN']:
        raise DemistoException('The indicator_type argument must be one of the following: Both, CIDR, DOMAIN')

    res = client.all_raw_data()
    clean_res = parse_indicators_from_response(res)

    # parse the data from an html page to a list of dicts with ips and domains
    if requested_indicator_type != 'Both':
        indicators = clean_res[requested_indicator_type][:limit]
    else:
        indicators = clean_res[CIDR][:limit] + clean_res[DOMAIN][:limit]
    final_indicators_lst = []
    for value in indicators:
        type_ = check_indicator_type(value)
        indicators_and_type = {
            'value': value,
            'type': type_
        }
        final_indicators_lst.append(indicators_and_type)

    md = tableToMarkdown('Indicators from Webex:', final_indicators_lst,
                         headers=['value', 'type'], removeNull=True)

    return CommandResults(
        readable_output=md,
    )


def fetch_indicators_command(client: Client,
                             tags: tuple = None,
                             tlp_color: str = None,
                             enrichment_excluded: bool = False) -> list:
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
    for indicator in clean_res[CIDR] + clean_res[DOMAIN]:
        indicator_obj: dict[str, Any] = {
            'value': indicator,
            'type': check_indicator_type(indicator),
            'fields': indicator_mapping_fields,
        }

        if enrichment_excluded:
            indicator_obj['enrichmentExcluded'] = enrichment_excluded

        results.append(indicator_obj)

    return results


def main():
    params = demisto.params()
    args = demisto.args()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    tags = params.get('feedTags'),
    tlp_color = params.get('tlp_color')
    enrichment_excluded = demisto.params().get('enrichmentExcluded', False)
    command = demisto.command()

    try:
        client = Client(
            base_url=BASE_URL,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            return_results(test_module(client=client))
        elif command == 'fetch-indicators':
            res = fetch_indicators_command(client=client, tags=tags, tlp_color=tlp_color, enrichment_excluded=enrichment_excluded)
            for iter_ in batch(res, batch_size=2000):
                demisto.createIndicators(iter_)
        elif command == 'webex-get-indicators':
            return_results(get_indicators_command(client=client, **args))
        else:
            raise NotImplementedError(f'command {command} is not implemented.')
    except DemistoException as e:
        # For any other integration command exception, return an error
        demisto.error(format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}.')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
