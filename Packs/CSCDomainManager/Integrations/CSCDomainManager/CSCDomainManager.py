import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from CommonServerUserPython import *  # noqa


# Disable insecure warnings
# urllib3.disable_warnings()


''' CONSTANTS '''

DEFAULT_PAGE_SIZE = 15000
DEFAULT_LIMIT = 50
MAX_QUALIFIED_DOMAIN_NAMES = 50
ACCEPT_VAL = "application/json"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url: str, verify: bool, headers: dict, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def send_get_request(self, url_suffix, params) -> str:
        results = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            headers=self._headers
        )
        return results

def create_params_for_domains_search(args):
    selectors_mapping = {
        'domain_name': 'domain',
        'registration_date': 'registrationDate',
        'email': 'email',
        'organization': 'organization',
        'registry_expiry_date': 'registryExpiryDate',
        'sort': 'sort',
        'page': 'page',
        'page_size': 'page_size',
        'limit': 'limit'
    }

    param_list = []
    # Check each key in args and add to param_dict if present
    for arg_key, param_key in selectors_mapping.items():
        if args.get(arg_key):
            param_list.append(f"{param_key}=={args[arg_key]}")

    # Join the parameters with commas
    params_str = args.get('filter') or 'filter='
    if param_list:
        params_str += ','.join(param_list)

    return params_str


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def csc_domains_search_command(client: Client, args) -> Any:
    # just to organize the dict so it matches the api params
    qualified_domain_name = args.get('qualified_domain_name')
    if qualified_domain_name:
        return client.send_get_request("", qualified_domain_name)

    if args.get('page'):
        args['page'] = arg_to_number(args.get('page'))
        
    #args['page_size'] = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE #not sure we need default here
    #args['limit'] = arg_to_number(args.get('limit')) or DEFAULT_LIMIT #TODO to check if that was the meaning

    params_results = create_params_for_domains_search(args)
    results = client.send_get_request(url_suffix="/domains", params=params_results)
    
    # get domain with the given filters
    # what to do with page, size and limit?
    return results


def csc_domains_availability_check_command(client: Client, args) -> str:
    #waiting for more arguments
    
    qualified_domain_names = args.get('qualified_domain_names')
    if not qualified_domain_names:
        return ("Error")  # TODO to return a real error
    if len(qualified_domain_names.split(',')) > MAX_QUALIFIED_DOMAIN_NAMES:
        return ("Error")  # TODO to return a real error

    # get domains from api and return output
    domains_data = client.send_get_request("/availability", qualified_domain_names)  # can be or object or list

    for domain in domains_data:
        # put in each domain result, the fields written in the design
        pass
    # return the results in the required pattern
    return 'ok'


def csc_domains_configuration_list_command(client: Client, args):

    return


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})

        base_url = params.get('base_url')
        verify = not params.get('insecure', False)
        token = params.get('token', {}).get('password')
        apikey = params.get('credentials', {}).get('password')
        proxy = params.get('proxy', False)
        headers: dict = {
            'Authorization': 'Bearer ' + token,
            'apikey': apikey,
            'Accept': ACCEPT_VAL
        }
        
        client = Client(
            base_url=base_url,
            verify=verify,
            headers=headers,
            proxy=proxy
        )

        # results = client.send_get_request("/domains", "")

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            # results = test_module(client)
            results = client.send_get_request("/domains", "")
            return_results(results)

        elif demisto.command() == 'csc-domains-search':
            results = csc_domains_search_command(client, args)
            return_results(results)

        elif demisto.command() == 'csc-domains-availability-check':
            return_results(csc_domains_availability_check_command(client, args))

        elif demisto.command() == 'csc-domains-configuration-list':
            return_results(csc_domains_configuration_list_command(client, args))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
