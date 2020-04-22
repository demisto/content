from CommonServerPython import *

# IMPORTS
import dns.resolver
import re

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
INTEGRATION_NAME = 'GCP Whitelist'

def fetch_cidr(dnsAddress):
    cidr_arr = []
    regex_dns = r"(include:.*? )"
    regex_cidr = r"(ip4:.*? )"

    query_response_str = str(list(dns.resolver.query(dnsAddress, "TXT"))[0])
    dns_matches = re.finditer(regex_dns, query_response_str)
    for match in dns_matches:
        m = match.group()
        address = m[8:len(m)-1]
        cidr_arr += fetch_cidr(address)
    cidr_matches = re.finditer(regex_cidr, query_response_str)
    for match in cidr_matches:
        m = match.group()
        address = m[4:len(m)-1]
        cidr_arr.append(address)
    return cidr_arr


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def say_hello(self, name):
        return 'Hello'

    def build_iterator(self):
        demisto.log("build iterator - start")
        cidr_arr = fetch_cidr(self._base_url)
        demisto.log(str(cidr_arr))
        return "Build Iterator Temp"

def test_module(client):
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.build_iterator()
    return 'ok', {}, {}


def say_hello_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): HelloWorld client.
        args (dict): all command arguments.

    Returns:
        Hello {someone}

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
        raw_response (dict): Used for debugging/troubleshooting purposes -
                            will be shown only if the command executed with raw-response=true
    """
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )

def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url="_cloud-netblocks.googleusercontent.com",
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'gcp-whitelist-get-indicators':
            return_outputs(client.build_iterator())
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
