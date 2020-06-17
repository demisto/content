import json

import dateparser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
import base64
from requests.auth import HTTPBasicAuth
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    def __init__(self,  base_url, verify=True, proxy=False, ok_codes=None, headers=None, auth=None,
                 email=None, api_key=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers, auth=auth)
        self.email = email
        self.api_key = api_key
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def dehashed_search(self, asset_type, contains_op=None, is_op=None, regex_op=None, results_page_number=None):
        query_string = ''
        if asset_type == 'all_fields':
            query_string = ''
        query_string = f'{asset_type}'


        self._http_request('GET', 'search',
                           params={'query': query_string}, auth=(self.email, self.api_key))




def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def dehashed_search_command(client, args):
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
    asset_type = args.get('asset_type')
    contains_op = argToList(args.get('contains'))
    is_op = argToList(args.get('is'))
    regex_op = argToList(args.get('regex'))
    results_page_number = args.get('page')
    result = client.dehashed_search(asset_type, contains_op, is_op, regex_op, results_page_number)

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
    email = demisto.params().get('email')
    api_key = demisto.params().get('api_key')
    base_url = demisto.params().get('base_url')
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url,
            verify=verify_certificate,
            email=email,
            api_key=api_key,
            proxy=proxy,
            headers={'accept': 'application/json'}
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'dehashed-search':
            return_outputs(*dehashed_search_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
