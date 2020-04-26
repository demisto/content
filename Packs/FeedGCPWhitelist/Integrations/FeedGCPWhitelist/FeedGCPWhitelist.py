from CommonServerPython import *

# IMPORTS
import dns.resolver
import re

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
GOOGLE_BASE_DNS = "_cloud-netblocks.googleusercontent.com"


def fetch_cidr(dnsAddress):
    cidr_arr = []
    regex_dns = r"(include:.*? )"
    regex_cidr = r"(ip4:.*? )"

    query_response_str = str(list(dns.resolver.query(dnsAddress, "TXT"))[0])
    dns_matches = re.finditer(regex_dns, query_response_str)
    for match in dns_matches:
        m = match.group()
        address = m[8:len(m) - 1]
        cidr_arr += fetch_cidr(address)
    cidr_matches = re.finditer(regex_cidr, query_response_str)
    for match in cidr_matches:
        m = match.group()
        address = m[4:len(m) - 1]
        cidr_arr.append(address)
    return cidr_arr


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def build_iterator(self):
        return fetch_cidr(self._base_url)


def test_module(client):
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def fetch_indicators(client):
    iterator = client.build_iterator()
    indicators = []
    for indicator in iterator:
        indicators.append({
            'value': indicator,
            'type': FeedIndicatorType.CIDR,
            'rawJSON': {
                'value': indicator,
                'type': FeedIndicatorType.CIDR,
            },
        })

    return indicators


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=GOOGLE_BASE_DNS,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            return_outputs(*test_module(client))

        elif demisto.command() == 'gcp-whitelist-get-indicators':
            demisto.createIndicators(fetch_indicators(client))
            return_outputs(str(fetch_indicators(client)))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
