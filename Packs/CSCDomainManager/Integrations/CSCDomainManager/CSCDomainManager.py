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
HR_HEADERS_FOR_DOMAINS_SEARCH = ['Qualified Domain Name',
                                 'Domain',
                                 'Managed Status',
                                 'Registration Date',
                                 'Registry Expiry Date',
                                 'Paid Through Date',
                                 'Name Servers',
                                 'Dns Type',
                                 #  'WhoisContacts'
                                 'Whois Contact first Name',
                                 'Whois Contact last Name',
                                 'Whois Contact email'
                                 ]
HR_HEADERS_FOR_DOMAIN_CONFI_LIST = ['Domain',
                                    'Domain Label',
                                    'Domain Status Code',
                                    'Domain extension',
                                    'Country',
                                    'Admin Email',
                                    'Admin Name',
                                    'Account Number',
                                    'Account Name'
                                    ]
HR_HEADERS_FOR_DOMAIN = ['Qualified Domain Name',
                         'Domain',
                         'Idn',
                         'Generic top-level domains',
                         'Managed Status',
                         'Registration Date',
                         'Registry Expiry Date',
                         'Paid Through Date',
                         'Country Code',
                         'Server Delete Prohibited',
                         'Server Transfer Prohibited',
                         'Server Update Prohibited',
                         'Name Servers',
                         'Dns Type',
                         'Whois Contact first Name',
                         'Whois Contact last Name',
                         'Whois Contact email'
                         ]

HR_HEADERS_FOR_AVAILABILITY = ['Qualified Domain Name',
                               'Code',
                               'Message',
                               'Price',
                               'Currency',
                               'List of the terms (months) available for registration'
                               ]
SEARCH_OPERATORS = ["gt=", "ge=", "lt=", "le=", "in=", "like="]
SELECTORS_MAPPING = {
    'domain_name': 'domain',
    'registration_date': 'registrationDate',
    'registration_org': 'regOrg',
    'admin_email': 'adminEmail',
    'email': 'email',
    'organization': 'organization',
    'registry_expiry_date': 'registryExpiryDate',
    'filter': 'filter',
    'sort': 'sort',
    'page': 'page',
    'page_size': 'size',
}
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


def create_params_string(args):
    param_for_filter: list[str] = []
    additional_params: list[str] = []

    for arg_key, param_key in SELECTORS_MAPPING.items():
        if args.get(arg_key):
            value = args[arg_key]
            if arg_key == 'filter':
                param_for_filter.append(value)
            elif isinstance(value, str) and len(value) >= 3 and value[:3] in SEARCH_OPERATORS:
                param_for_filter.append(f"{param_key}={value}")
            elif arg_key in ['sort', 'page', 'page_size']:
                additional_params.append(f"{param_key}={value}")
            else:
                param_for_filter.append(f"{param_key}=={value}")

    params_str = 'filter='
    if param_for_filter:
        params_str += ','.join(param_for_filter)

    if additional_params:
        params_str += "&" + "&".join(additional_params)

    return params_str


def extract_required_fields_for_domains_search_hr(domains_list) -> list:
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
            'Whois Contact first Name': [get_whois_contacts_fields_for_search_domains_command
                                         (domain.get('whoisContacts'), 'firstName')],
            'Whois Contact last Name': [get_whois_contacts_fields_for_search_domains_command
                                        (domain.get('whoisContacts'), 'lastName')],
            'Whois Contact email': [get_whois_contacts_fields_for_search_domains_command
                                    (domain.get('whoisContacts'), 'email')]
        }

        filtered_domains.append(filtered_domain)

    return filtered_domains


def extract_required_fields_for_domains_configurations_list_hr(configurations) -> list:
    filtered_configurations = []

    for config in configurations:
        filtered = {
            'Domain': config.get('domain'),
            'Domain Label': config.get('domainLabel'),
            'Domain Status Code': config.get('domainStatusCode'),
            'Domain extension': config.get('extension'),
            'Country': config.get('country'),
            'Admin Email': config.get('adminEmail'),
            'Admin Name': config.get('regEmail'),
            'Account Number': config.get('accounts').get('accountNumber'),
            'Account Name': config.get('accounts').get('accountName')
        }

        filtered_configurations.append(filtered)

    return filtered_configurations


def extract_required_fields_for_domain_hr(domain) -> dict:
    filtered = {'Qualified Domain Name': domain.get('qualifiedDomainName'),
                'Domain': domain.get('domain'),
                'Idn': domain.get('idn'),
                'Generic top-level domains': domain.get('newGtld'),
                'Managed Status': domain.get('managedStatus'),
                'Registration Date': domain.get('registrationDate'),
                'Registry Expiry Date': domain.get('registryExpiryDate'),
                'Paid Through Date': domain.get('paidThroughDate'),
                'Country Code': domain.get('countryCode'),
                'Server Delete Prohibited': domain.get('countryCode'),
                'Server Transfer Prohibited': domain.get('serverDeleteProhibited'),
                'Server Update Prohibited': domain.get('serverTransferProhibited'),
                'Name Servers': domain.get('nameServers'),
                'Dns Type': domain.get('dnsType'),
                'Whois Contact first Name': domain.get('whoisContacts')[0].get('firstName'),
                'Whois Contact last Name': domain.get('whoisContacts')[0].get('lastName'),
                'Whois Contact email': domain.get('whoisContacts')[0].get('email')
                }

    domain.get('whoisContacts')
    return filtered


def get_whois_contacts_fields_for_domain_command(whois_contact, field_names: str | List[str],
                                                 contact_type_condition: str) -> list:
    results = []
    if isinstance(field_names, str):
        field_names = [field_names]

    for contact in whois_contact:
        if contact.get('contactType') == contact_type_condition:
            combined_fields = ' '.join(contact[field] for field in field_names)
            results.append(combined_fields)

    return results


def get_whois_contacts_fields_for_search_domains_command(whois_contacts, field_name: str) -> list:
    results = []
    for contact in whois_contacts:
        results.append(contact.get(field_name))

    return results


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
        client.send_get_request("/domains", "")
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def csc_domains_search_command(client: Client, args) -> Any:
    domains_results = {}
    qualified_domain_name = args.get('qualified_domain_name')
    if qualified_domain_name:
        domains_results = client.send_get_request(url_suffix=f"/domains/{qualified_domain_name}", params="")

    else:
        args['page_size'] = args.get('page_size') or DEFAULT_PAGE_SIZE
        if args.get('limit'):
            args['page'] = '1'
            args['page_size'] = args.get('limit')

        params_results = create_params_string(args)
        domains_results = client.send_get_request(url_suffix="/domains", params=params_results)

    domains_list = domains_results.get('domains', [])
    domains_with_required_fields = extract_required_fields_for_domains_search_hr(domains_list)

    results = CommandResults(
        readable_output=tableToMarkdown('Filtered Domains', domains_with_required_fields,
                                        headers=HR_HEADERS_FOR_DOMAINS_SEARCH),
        outputs_prefix='CSCDomainManager.Domain',
        outputs_key_field='QualifiedDomainName',
        outputs=domains_with_required_fields
    )
    return results


def csc_domains_availability_check_command(client: Client, args) -> Any:
    domain_names = args.get('domain_name')
    params = f'qualifiedDomainNames={domain_names}'
    available_domains_results = (client.send_get_request("/availability", params)).get('results')

    hr_output = {
        'Qualified Domain Name': [result.get('qualifiedDomainName') for result in available_domains_results],
        'Code': [result.get('result').get('code') for result in available_domains_results],
        'Message': [result.get('result').get('message') for result in available_domains_results],
        'Price': [result.get('basePrice').get('price') for result
                  in available_domains_results if result.get('basePrice').get('price')],
        'Currency': [result.get('basePrice').get('currency') for result
                     in available_domains_results if result.get('basePrice').get('currency')],
        'List of the terms (months) available for registration': [result.get('availableTerms') for result
                                                                  in available_domains_results if result.get('availableTerms')]
    }

    results = CommandResults(
        readable_output=tableToMarkdown('Domains Availability', hr_output, headers=HR_HEADERS_FOR_AVAILABILITY),
        outputs_prefix='CSCDomainManager.Domain.Availability',
        outputs=available_domains_results
    )
    return results


def csc_domains_configuration_list_command(client: Client, args) -> Any:
    args['page_size'] = args.get('page_size') or DEFAULT_PAGE_SIZE
    if args.get('limit'):
        args['page'] = '1'
        args['page_size'] = args.get('limit')

    params_results = create_params_string(args)
    configurations_results = client.send_get_request(url_suffix="/domains/configuration", params=params_results)

    configurations_list = configurations_results.get('configurations', [])
    configurations_with_required_fields = extract_required_fields_for_domains_configurations_list_hr(configurations_list)

    results = CommandResults(
        readable_output=tableToMarkdown('Filtered Configurations',
                                        configurations_with_required_fields,
                                        headers=HR_HEADERS_FOR_DOMAIN_CONFI_LIST),
        outputs_prefix='CSCDomainManager.Domain.Configuration',
        outputs_key_field='CSCDomainManager.Domain.Configuration.Domain',
        outputs=configurations_with_required_fields
    )
    return results


def domain(client, args, reliability) -> Any:
    qualified_domain_name = args.get('domain')
    domain_json = client.send_get_request(url_suffix=f"/domains/{qualified_domain_name}", params="")

    dbot_score = Common.DBotScore(
        indicator=qualified_domain_name,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="CSCDomainManager",
        score=Common.DBotScore.NONE,
        reliability=reliability
    )

    domain_context = Common.Domain(
        domain=domain_json.get('domain'),
        creation_date=domain_json.get('registrationDate'),
        domain_idn_name=domain_json.get('idn'),
        expiration_date=domain_json.get('registryExpiryDate'),
        name_servers=domain_json.get('nameServers'),
        registrant_name=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                                     ['firstName', 'lastName'], 'REGISTRANT'),
        registrant_email=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                                      'email', 'REGISTRANT'),
        registrant_phone=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                                      'phone', 'REGISTRANT'),
        registrant_country=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                                        'country', 'REGISTRANT'),
        admin_name=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                                ['firstName', 'lastName'], 'ADMINISTRATIVE'),
        admin_email=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'), 'email', 'ADMINISTRATIVE'),
        admin_phone=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'), 'phone', 'ADMINISTRATIVE'),
        admin_country=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'), 'country', 'ADMINISTRATIVE'),
        tech_country=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'), 'country', 'TECHNICAL'),
        tech_name=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                               ['firstName', 'lastName'], 'TECHNICAL'),
        tech_organization=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'),
                                                                       'organization', 'TECHNICAL'),
        tech_email=get_whois_contacts_fields_for_domain_command(domain_json.get('whoisContacts'), 'email', 'TECHNICAL'),
        dbot_score=dbot_score
    )

    hr_data = extract_required_fields_for_domain_hr(domain_json)

    context_res = {}
    context_res.update(dbot_score.to_context())
    context_res.update(domain_context.to_context())

    results = CommandResults(
        readable_output=tableToMarkdown('Domain', hr_data, headers=HR_HEADERS_FOR_DOMAIN),
        outputs_prefix='CSCDomainManager.Domain',
        outputs=context_res
        # outputs_key_field ='QualifiedDomainName',
        # indicator = domain_context
    )
    return results


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
        headers = {
            'Authorization': 'Bearer ' + token,
            'apikey': apikey,
            'Accept': ACCEPT_VAL
        }

        # TODO to check
        reliability = params.get('integrationReliability')
        reliability = reliability if reliability else DBotScoreReliability.A

        if DBotScoreReliability.is_valid_type(reliability):
            reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise Exception("Please provide a valid value for the Source Reliability parameter.")

        client = Client(
            base_url=base_url,
            verify=verify,
            headers=headers,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            results = test_module(client)
            return_results(results)

        elif demisto.command() == 'csc-domains-search':
            results = csc_domains_search_command(client, args)
            return_results(results)

        elif demisto.command() == 'csc-domains-availability-check':
            return_results(csc_domains_availability_check_command(client, args))

        elif demisto.command() == 'csc-domains-configuration-list':
            return_results(csc_domains_configuration_list_command(client, args))

        elif demisto.command() == 'domain':
            return_results(domain(client, args, reliability))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
