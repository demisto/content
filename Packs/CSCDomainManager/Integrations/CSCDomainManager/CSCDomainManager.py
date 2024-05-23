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

DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50
MAX_QUALIFIED_DOMAIN_NAMES = 50
ACCEPT_VAL = "application/json"
SEARCH_OUTPUT_HEADERS = ['Qualified Domain Name',
                         'Domain',
                         'Managed Status',
                         'Registration Date',
                         'Registry Expiry Date',
                         'Paid Through Date',
                         'Name Servers',
                         'Dns Type',
                         'WhoisContacts'
                         #  'Whois Contact first Name',
                         #  'Whois Contact last Name',
                         #  'Whois Contact email'
                         ]
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

    def send_get_request(self, url_suffix, params) -> Any:
        results = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            headers=self._headers
        )
        return results


def create_params_string_for_domains_search(args):
    selectors_mapping = {
        'domain_name': 'domain',
        'registration_date': 'registrationDate',
        'email': 'email',
        'organization': 'organization',
        'registry_expiry_date': 'registryExpiryDate',
        'filter': 'filter',
        'sort': 'sort',
        'page': 'page',
        'page_size': 'size',
    }

    param_for_filter = []
    additional_params = []
    # Check each key in args and add to param_dict if present
    for arg_key, param_key in selectors_mapping.items():
        if args.get(arg_key):
            if arg_key in ['sort', 'page', 'page_size']:
                additional_params.append(f"{param_key}={args[arg_key]}")
            else:
                param_for_filter.append(f"{param_key}=={args[arg_key]}")

    # Join the parameters with commas
    params_str = 'filter='
    if param_for_filter:
        params_str += ','.join(param_for_filter)

    # Join the parameters with &
    if additional_params:
        params_str += "&" + "&".join(additional_params)

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


def extract_required_fields(domains_list):
    filtered_domains = []

    for domain in domains_list:
        filtered_domain = {
            'Qualified Domain Name': domain.get('qualifiedDomainName'),
            'Domain': domain.get('domain'),
            'Managed Status': domain.get('managedStatus'),
            'Registration Date': domain.get('registrationDate'),
            'Registry Expiry Date': domain.get('registryExpiryDate'),
            'Paid Through Date': domain.get('paidThroughDate'),
            'Name Servers': domain.get('nameServers'),
            'Dns Type': domain.get('dnsType'),
            'WhoisContacts': []
        }

        whois_contacts = domain.get('whoisContacts', [])
        for contact in whois_contacts:
            filtered_contact = {
                'firstName': contact.get('firstName'),
                'lastName': contact.get('lastName'),
                'email': contact.get('email')
            }
            filtered_domain['WhoisContacts'].append(filtered_contact)

        filtered_domains.append(filtered_domain)

    return filtered_domains


def csc_domains_search_command(client: Client, args) -> Any:
    qualified_domain_name = args.get('qualified_domain_name')
    if qualified_domain_name:
        return client.send_get_request(url_suffix="/domains/{qualified_domain_name}", params="")

    args['page_size'] = args.get('page_size') or DEFAULT_PAGE_SIZE
    if args.get('limit'):
        args['page'] = '1'
        args['page_size'] = args.get('limit')

    params_results = create_params_string_for_domains_search(args)
    domains_results = client.send_get_request(url_suffix="/domains", params=params_results)

    domains_list = domains_results.get('domains', [])
    domains_with_required_fields = extract_required_fields(domains_list)

    results = CommandResults(
        readable_output=tableToMarkdown('Filtered Domains', domains_with_required_fields, headers=SEARCH_OUTPUT_HEADERS),
        outputs_prefix='CSCDomainManager.Domain',
        outputs_key_field='QualifiedDomainName',
        outputs=domains_with_required_fields
    )
    return results


def csc_domains_availability_check_command(client: Client, args) -> str:
    # waiting for more arguments

    qualified_domain_names = args.get('qualified_domain_names')
    if not qualified_domain_names:
        return ("Error")  # TODO to return a real error
    if len(qualified_domain_names.split(',')) > MAX_QUALIFIED_DOMAIN_NAMES:
        return ("Error")  # TODO to return a real error

    # get domains from api and return output
    client.send_get_request("/availability", qualified_domain_names)  # can be or object or list

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

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
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
