import re
from typing import Any, Callable, Dict, List, Optional, Tuple

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()
INTEGRATION_NAME = 'WebEx'


# From WebExDomain Table get only domain names with wildcards
def grab_domains(data):
    domainList: List = []
    for lines in data:
        domains = lines[1].split(' ')
        cleanDomain = " ".join(re.findall("([\^]*[\*\.]*[a-z0-9]+\.+.*)*", domains[0]))

        # Strip Whitespace lines to remove blank values
        cleanDomain = cleanDomain.strip()

        # Dedup List
        if cleanDomain not in domainList:
            if len(cleanDomain) > 0:
                domainList.append(cleanDomain)
    return domainList


def grab_ips(data):
    ipList: List = []
    for lines in data:
        for line in lines:
            values = line.split(' (CIDR)')
            cleanCidr = " ".join(re.findall("([0-9]+\.+[0-9]+\.+[0-9]+\.+[0-9]+\/[0-9]+)", values[0]))

            # Strip Whitespace lines to remove blank values
            cleanCidr = cleanCidr.strip()
            # Dedup List
            if cleanCidr not in ipList:
                if len(cleanCidr) > 0:
                    ipList.append(cleanCidr)
    return ipList


def grab_domain_table(html_section):
    # Get Clean List of Domains
    table = html_section.find('table', attrs={'class': 'li'})
    table_body = table.find('tbody')
    rows = table_body.find_all('tr')
    data = []
    for row in rows:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])  # Get rid of empty values
    return data


def grab_ip_table(html_section):
    rows = html_section.find_all('ul')
    data = []
    for row in rows:
        cols = row.find_all('li')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])  # Get rid of empty values
    return data


class Client:
    """
    Client to use in the WebEx Feed integration. Overrides BaseClient.
    WebEx IP address and Domain web service announcement:
    """

    def __init__(self, insecure: bool = False, tags: Optional[list] = None,
                 tlp_color: Optional[str] = None):
        """
        Implements class for WebEx feeds.
        :param urls_list: List of url, regions and service of each service.
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param tlp_color: Traffic Light Protocol color.
        """
        self._url = "https://help.webex.com/en-us/WBX264/How-Do-I-Allow-Webex-Meetings-Traffic-on-My-Network"
        self._verify: bool = insecure
        self.tags = [] if tags is None else tags
        self.tlp_color = tlp_color
        self._proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        try:
            response = requests.get(
                url=self._url,
                verify=self._verify,
                proxies=self._proxies,
            )
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            # Get the IP and Domain Sections from WebEx website
            ipsSection = soup.find("div", {"id": "id_135011"})
            domainsSection = soup.find("div", {"id": "id_135010"})

            # Get Domains from domain table
            domainTable = grab_domain_table(domainsSection)
            retDomains = grab_domains(domainTable)

            # Get IPS from IP Table
            ipTable = grab_ip_table(ipsSection)
            retIPs = grab_ips(ipTable)

            jsonStr = '[{"urls": ' + json.dumps(retDomains) + ',' + '"ips": ' + json.dumps(retIPs) + '}]'
            data = json.loads(jsonStr)
            indicators = [i for i in data if 'ips' in i or 'urls' in i]  # filter empty entries and add metadata]
            result.extend(indicators)
        except requests.exceptions.SSLError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                            f'Check your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n'
                            f'Check your Server URL parameter.\n\n{err}')
        except requests.exceptions.HTTPError as err:
            demisto.debug(str(err))
            raise Exception(f'Connection error in the API call to {INTEGRATION_NAME}.\n')
        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data to Json. \n\nError massage: {err}')
        return result

    @staticmethod
    def check_indicator_type(indicator):
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


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client: Client, indicator_type_lower: str, limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        indicator_type_lower: indicator type
        limit: limit the results

    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    # filter indicator_type specific entries

    if not indicator_type_lower == 'both':
        iterator = [i for i in iterator if indicator_type_lower in i]
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        if indicator_type_lower == 'both':
            values = item.get('ips', []) + item.get('urls', [])
        else:
            values = item.get(indicator_type_lower)
        if values:
            for value in values:
                type_ = Client.check_indicator_type(value)
                raw_data = {
                    'value': value,
                    'type': type_,
                }
                for key, val in item.items():
                    if key not in ['ips', 'urls']:
                        raw_data.update({key: val})

                indicator_mapping_fields = {}

                """
                indicator_mapping_fields = {
                    "port": argToList(item.get('tcpPorts', '')),
                    "service": item.get('serviceArea', '')
                }

                if item.get('expressRoute'):
                    indicator_mapping_fields["office365expressroute"] = item.get('expressRoute')
                if item.get('category'):
                    indicator_mapping_fields["office365category"] = item.get('category')
                if item.get('required'):
                    indicator_mapping_fields["office365required"] = item.get('required')
                if item.get('notes'):
                    indicator_mapping_fields["description"] = item.get('notes')
                """

                indicator_mapping_fields['tags'] = client.tags
                if client.tlp_color:
                    indicator_mapping_fields['trafficlightprotocol'] = client.tlp_color  # type: ignore

                indicators.append({
                    'value': value,
                    'type': type_,
                    'rawJSON': raw_data,
                    'fields': indicator_mapping_fields
                })

    return indicators


def get_indicators_command(client: Client, args: Dict[str, str]) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs.
    """
    indicator_type = str(args.get('indicator_type'))
    indicator_type_lower = indicator_type.lower()
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators = fetch_indicators(client, indicator_type_lower, limit)
    human_readable = tableToMarkdown('Indicators from WebEx Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators_command(client: Client) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.

    Args:
        client: Client object with request

    Returns:
        Indicators.
    """
    indicators = fetch_indicators(client, 'both')
    return indicators


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    use_ssl = not params.get('insecure', False)
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(use_ssl, tags, tlp_color)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'webex-get-indicators': get_indicators_command
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration. [{err}]'
        return_error(err_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
