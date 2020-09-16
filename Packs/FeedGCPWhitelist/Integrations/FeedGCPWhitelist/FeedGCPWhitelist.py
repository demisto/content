from CommonServerPython import *

# IMPORTS
import dns.resolver
import re
from typing import List, Dict, Callable, Tuple, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
GOOGLE_BASE_DNS = "_cloud-netblocks.googleusercontent.com"


def fetch_cidr(dns_address: str) -> List[Dict]:
    """Recursively builds a CIDR dictionary with the relevant ip and type

    Args:
        dns_address: the dns address to lookup

    Returns:
        CIDR list
    """
    cidr_arr = []
    regex_dns = r"(include:.*? )"
    regex_cidr = r"(ip.*?:.*? )"

    try:
        query_response_str = str(dns.resolver.query(dns_address, "TXT").response.answer[0][0])
    except IndexError:
        query_response_str = ''
    dns_matches = re.finditer(regex_dns, query_response_str)
    for match in dns_matches:
        m = match.group()
        address = m[8:len(m) - 1]
        cidr_arr += fetch_cidr(address)
    cidr_matches = re.finditer(regex_cidr, query_response_str)
    for match in cidr_matches:
        m = match.group()
        cidr_type = FeedIndicatorType.CIDR if(m[0:3] == "ip4") else FeedIndicatorType.IPv6CIDR
        cidr_ip = m[4:len(m) - 1]
        cidr_arr.append({"type": cidr_type, "ip": cidr_ip})
    return cidr_arr


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def build_iterator(self):
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the data.
        """
        return fetch_cidr(self._base_url)


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def get_indicators(client: Client, params: Dict[str, str], args: Dict[str, str]) -> Tuple[str, Dict[Any, Any], Dict[Any, Any]]:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()

    Returns:
        Outputs.
    """
    limit = int(args.get('limit', '10'))
    indicators = fetch_indicators(client, params)[:limit]
    human_readable = tableToMarkdown('Indicators from GCP Whitelist Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': indicators}


def fetch_indicators(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client (Client): Client object with request
        params: demisto.params() to retrieve tags

    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    iterator = client.build_iterator()
    indicators = []
    for indicator in iterator:
        indicator_obj = {
            'value': indicator["ip"],
            'type': indicator["type"],
            'rawJSON': {
                'value': indicator["ip"],
                'type': indicator["type"],
            },
            'fields': {}
        }
        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags
        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)
    return indicators


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=GOOGLE_BASE_DNS,
            verify=verify_certificate,
            proxy=proxy)

        commands: Dict[
            str, Callable[[Client, Dict[str, str], Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]
        ] = {
            'test-module': test_module,
            'gcp-whitelist-get-indicators': get_indicators
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.params(), demisto.args()))

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client, demisto.params())
            for single_batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(single_batch)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
