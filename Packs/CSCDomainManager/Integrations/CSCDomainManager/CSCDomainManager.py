import copy
from functools import partial
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

''' CONSTANTS '''
DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE_SEARCH = 50
DEFAULT_PAGE_SIZE_CONFI = 1
DEFAULT_LIMIT = 50
MAX_QUALIFIED_DOMAIN_NAMES = 50
ACCEPT_VAL = "application/json"
BEARER_PREFIX = 'Bearer '
URL_SUFFIX = '/dbs/api/v2'
HR_HEADERS_FOR_DOMAINS_SEARCH = ['Qualified Domain Name',
                                 'Domain',
                                 'Managed Status',
                                 'Registration Date',
                                 'Registry Expiry Date',
                                 'Paid Through Date',
                                 'Name Servers',
                                 'Dns Type',
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
SELECTORS_MAPPING = {'domain_name': 'domain',
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

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify: bool, token: str = "", apikey: str = ""):
        headers = {
            'Authorization': f'{BEARER_PREFIX}{token}',
            'apikey': apikey,
            'Accept': ACCEPT_VAL
        }
        super().__init__(base_url=base_url, verify=verify, headers=headers)

    def send_get_request(self, url_suffix, params) -> Any:
        try:
            results = self._http_request(
                method="GET",
                url_suffix=url_suffix,
                params=params,
                headers=self._headers
            )
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 404:
                results = CommandResults(
                    readable_output="No results were found",
                    outputs=None,
                    raw_response=None,
                )
            else:
                raise e
        return results

    def get_qualified_domain_name(self, qualified_domain_name):
        result = self.send_get_request(f"/domains/{qualified_domain_name}", "")
        return result

    def get_domains(self, params):
        result = self.send_get_request("/domains", params)
        return result

    def get_available_domains(self, params):
        return self.send_get_request("/availability", params)

    def get_configurations(self, params):
        return self.send_get_request("/domains/configuration", params)


def parse_and_format_date(value: str) -> str:
    formatted_date = value
    date = dateparser.parse(value)
    if date is None:  # not a date
        return_error(f'Failed to execute {demisto.command()} command. Invalid Date')

    else:
        formatted_date = date.strftime("%d-%b-%Y")
    return formatted_date


def create_params_string(args) -> str:
    """
    Create a string of the params written by the given filters to use in http request

    Args:
        args: demisto.args()

    Returns:
        A string of the params written by the given filters
    """
    param_for_filter: list[str] = []
    additional_params: list[str] = []

    for arg_key, param_key in SELECTORS_MAPPING.items():
        if args.get(arg_key):
            value = args[arg_key]
            if arg_key == 'filter':
                param_for_filter.append(value)
            elif isinstance(value, str) and len(value) >= 3 and value[:3] in SEARCH_OPERATORS:
                if arg_key in ['registration_date', 'registry_expiry_date']:
                    value = value[:3] + parse_and_format_date(value[3:])
                param_for_filter.append(f"{param_key}={value}")
            elif arg_key in ['sort', 'page', 'page_size']:
                additional_params.append(f"{param_key}={value}")
            else:
                if arg_key in ['registration_date', 'registry_expiry_date']:
                    value = parse_and_format_date(value)
                param_for_filter.append(f"{param_key}=={value}")

    params_str = 'filter='
    if param_for_filter:
        params_str += ','.join(param_for_filter)

    if additional_params:
        params_str += "&" + "&".join(additional_params)

    return params_str


def get_domains_search_hr_fields(domains_list) -> list:
    """
    Create a list of domains with the fields for human readable, using the domain_list argument

    Args:
        domains_list: domains list that was output from the http request

    Returns:
        A list of domains with the fields for human readable
    """
    hr_formatted_domains = []
    if not isinstance(domains_list, list):
        domains_list = [domains_list]

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
            'Whois Contact first Name': domain.get('whoisContacts')[0].get('firstName'),
            'Whois Contact last Name': domain.get('whoisContacts')[0].get('lastName'),
            'Whois Contact email': domain.get('whoisContacts')[0].get('email')
        }

        hr_formatted_domains.append(filtered_domain)

    return hr_formatted_domains


def get_domains_configurations_hr_fields(configurations) -> list:
    """
    Create a list of domains configurations with the fields for human readable, using the configurations argument

    Args:
        configurations: domains configurations list that was output from the http request

    Returns:
        A list of domains configurations with the fields for human readable
    """
    hr_formatted_configurations = []

    for config in configurations:
        filtered = {
            'Domain': config.get('domain'),
            'Domain Label': config.get('domainLabel'),
            'Domain Status Code': config.get('domainStatusCode'),
            'Domain extension': config.get('extension'),
            'Country': config.get('country'),
            'Admin Email': config.get('adminEmail'),
            'Admin Name': config.get('regEmail'),
            'Account Number': config.get('account').get('accountNumber'),
            'Account Name': config.get('account').get('accountName')
        }

        hr_formatted_configurations.append(filtered)

    return hr_formatted_configurations


def get_domains_availability_check_hr_fields(available_domains) -> list:
    """
    Create a list of available domains with the fields for human readable, using the available_domains argument

    Args:
        available_domains: available domains list that was output from the http request

    Returns:
        A list of available domains with the fields for human readable
    """
    hr_formatted_available_domains = []

    for domain in available_domains:
        filtered = {
            'Qualified Domain Name': domain.get('qualifiedDomainName'),
            'Code': domain.get('result').get('code'),
            'Message': domain.get('result').get('message'),
            'Price': domain.get('basePrice').get('price'),
            'Currency': domain.get('basePrice').get('currency'),
            'List of the terms (months) available for registration': domain.get('availableTerms')
        }

        hr_formatted_available_domains.append(filtered)

    return hr_formatted_available_domains


def get_domain_hr_fields(domain) -> dict:
    """
    Create a dict of the domain with the fields for human readable, using the domain argument

    Args:
        domain: domain dict that was output from the http request

    Returns:
        A dict of the domain with the fields for human readable
    """
    hr_formatted_domain = {'Qualified Domain Name': domain.get('qualifiedDomainName'),
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
                           'Server Update Prohibite d': domain.get('serverTransferProhibited'),
                           'Name Servers': domain.get('nameServers'),
                           'Dns Type': domain.get('dnsType'),
                           'Whois Contact first Name': domain.get('whoisContacts')[0].get('firstName'),
                           'Whois Contact last Name': domain.get('whoisContacts')[0].get('lastName'),
                           'Whois Contact email': domain.get('whoisContacts')[0].get('email')
                           }

    domain.get('whoisContacts')
    return hr_formatted_domain


def get_whois_contacts_fields_for_domain(whois_contact, field_names: List[str], contact_type_condition: str) -> list:
    """
    Create a list of contact.field_name for each contact in whois_contacts. Specific arrangement for the domain command

    Args:
        whois_contacts: list of contacts
        field_name: the field to get for each contact
        contact_type_condition: a str to use for condition: choose the contacts with the specific contact_type

    Returns:
        A list of contact.field_name when contact is from type contact_type_condition
    """
    results = []

    for contact in whois_contact:
        if contact.get('contactType') == contact_type_condition:
            combined_fields = ' '.join(contact[field] for field in field_names)
            results.append(combined_fields)

    return results


def create_common_domain(domain_json, dbot_score):
    """
    Create Common.Domain for domain command

    Args:
        domain_json: json object of the domain got from the http request
        dbot_score: Common.DBotScore object

    Returns:
        A Common.Domain object
    """
    whois_contacts = domain_json.get('whoisContacts')
    get_contact_fields = partial(get_whois_contacts_fields_for_domain, whois_contacts)
    domain_context = Common.Domain(
        domain=domain_json.get('domain'),
        creation_date=domain_json.get('registrationDate'),
        domain_idn_name=domain_json.get('idn'),
        expiration_date=domain_json.get('registryExpiryDate'),
        name_servers=domain_json.get('nameServers'),
        registrant_name=get_contact_fields(['firstName', 'lastName'], 'REGISTRANT'),
        registrant_email=get_contact_fields(['email'], 'REGISTRANT'),
        registrant_phone=get_contact_fields(['phone'], 'REGISTRANT'),
        registrant_country=get_contact_fields(['country'], 'REGISTRANT'),
        admin_name=get_contact_fields(['firstName', 'lastName'], 'ADMINISTRATIVE'),
        admin_email=get_contact_fields(['email'], 'ADMINISTRATIVE'),
        admin_phone=get_contact_fields(['phone'], 'ADMINISTRATIVE'),
        admin_country=get_contact_fields(['country'], 'ADMINISTRATIVE'),
        tech_country=get_contact_fields(['country'], 'TECHNICAL'),
        tech_name=get_contact_fields(['firstName', 'lastName'], 'TECHNICAL'),
        tech_organization=get_contact_fields(['organization'], 'TECHNICAL'),
        tech_email=get_contact_fields(['email'], 'TECHNICAL'),
        dbot_score=dbot_score
    )

    return domain_context


def create_common_dbot_score(domain_name, reliability):
    dbot_score = Common.DBotScore(
        indicator=domain_name,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="CSCDomainManager",
        score=Common.DBotScore.NONE,
        reliability=reliability
    )
    return dbot_score


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: CSCDomainManager client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    message: str = ''
    try:
        client.send_get_request("/domains", "")
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key and Token are correctly set'
        else:
            raise e
    return message


def csc_domains_search_command(client: Client, args) -> CommandResults:
    """
    Returning a list of domains with the applied filters

    Args:
        client: CSCDomainManager client
        args: demisto.args()

    Returns:
        A list of domains with the applied filters
    """

    domains_results = {}
    qualified_domain_name = args.get('domain_name')
    if qualified_domain_name and '.' in qualified_domain_name:
        domains_list = client.get_qualified_domain_name(qualified_domain_name)
        if isinstance(domains_list, CommandResults):
            return domains_list

    else:
        args_copy = copy.deepcopy(args)
        if args_copy.get('limit'):
            args_copy['page'] = '1'
            args_copy['page_size'] = args_copy.get('limit')

        params_results = create_params_string(args_copy)
        domains_results = client.get_domains(params_results)
        if isinstance(domains_results, CommandResults):
            return domains_results
        domains_list = domains_results.get('domains', [])

    domains_with_required_fields = get_domains_search_hr_fields(domains_list)

    results = CommandResults(
        readable_output=tableToMarkdown('Filtered Domains', domains_with_required_fields,
                                        headers=HR_HEADERS_FOR_DOMAINS_SEARCH,
                                        removeNull=True),
        outputs_prefix='CSCDomainManager.Domain',
        outputs_key_field='QualifiedDomainName',
        outputs=domains_list
    )
    return results


def csc_domains_availability_check_command(client: Client, args) -> CommandResults:
    """
    Returning a list of available domains with the applied filters

    Args:
        client: CSCDomainManager client
        args: demisto.args()

    Returns:
        A list of available domains with the applied filters
    """
    domain_names = args.get('domain_name')
    params = f'qualifiedDomainNames={domain_names}'
    available_domains_results = client.get_available_domains(params).get('results')
    if isinstance(available_domains_results, CommandResults):
        return available_domains_results

    hr_output = get_domains_availability_check_hr_fields(available_domains_results)

    results = CommandResults(
        readable_output=tableToMarkdown('Domains Availability', hr_output,
                                        headers=HR_HEADERS_FOR_AVAILABILITY,
                                        removeNull=True),
        outputs_prefix='CSCDomainManager.Domain.Availability',
        outputs=available_domains_results
    )
    return results


def csc_domains_configuration_search_command(client: Client, args) -> CommandResults:
    """
    Returning a list of domains configurations with the applied filters

    Args:
        client: CSCDomainManager client
        args: demisto.args()

    Returns:
        A list of domains configurations with the applied filters
    """
    args_copy = copy.deepcopy(args)
    args_copy['page'] = args_copy.get('page') or DEFAULT_PAGE_SIZE_CONFI
    args_copy['page_size'] = args_copy.get('page_size') or DEFAULT_PAGE_SIZE_SEARCH

    if args_copy.get('limit'):
        args_copy['page'] = '1'
        args_copy['page_size'] = args_copy.get('limit')

    params_results = create_params_string(args_copy)
    configurations_results = client.get_configurations(params_results)
    if isinstance(configurations_results, CommandResults):
        return configurations_results

    configurations_list = configurations_results.get('configurations', [])
    configurations_with_required_fields = get_domains_configurations_hr_fields(configurations_list)

    results = CommandResults(
        readable_output=tableToMarkdown('Filtered Configurations',
                                        configurations_with_required_fields,
                                        headers=HR_HEADERS_FOR_DOMAIN_CONFI_LIST,
                                        removeNull=True),
        outputs_prefix='CSCDomainManager.Domain.Configuration',
        outputs_key_field='CSCDomainManager.Domain.Configuration.Domain',
        outputs=configurations_list
    )
    return results


def domain(client: Client, args, reliability):
    """
    Gets the domain

    Args:
        client: CSCDomainManager client
        args: demisto.args()
        reliability: The source reliability. Default set to A.

    Returns:
        domain data
    """
    domains_name = args.get('domain').split(",")
    final_data = []

    for name in domains_name:
        domain_json = client.get_qualified_domain_name(name)
        if isinstance(domain_json, CommandResults):  # domain not found, continue to next name
            continue

        hr_data = get_domain_hr_fields(domain_json)

        dbot_score = create_common_dbot_score(name, reliability)
        domain_context = create_common_domain(domain_json, dbot_score)
        results = CommandResults(
            readable_output=tableToMarkdown('Domain', hr_data, headers=HR_HEADERS_FOR_DOMAIN),
            outputs_prefix='CSCDomainManager.Domain',
            indicator=domain_context,
            outputs=domain_json
        )
        final_data.append(results)

    if final_data == []:  # if no domains were found
        final_data.append(CommandResults(
            readable_output="No results were found",
            outputs=None,
            raw_response=None,
        ))

    return final_data


def main():
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        base_url = f'{params.get("base_url")}{URL_SUFFIX}'
        verify = not params.get('insecure', False)
        token = params.get('token', {}).get('password')
        api_key = params.get('credentials', {}).get('password')

        reliability = params.get('integrationReliability')
        reliability = reliability if reliability else DBotScoreReliability.A

        if DBotScoreReliability.is_valid_type(reliability):
            reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise Exception("Please provide a valid value for the Source Reliability parameter.")

        client = Client(
            base_url=base_url,
            verify=verify,
            token=token,
            apikey=api_key
        )

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'csc-domains-search':
            return_results(csc_domains_search_command(client, args))

        elif demisto.command() == 'csc-domains-availability-check':
            return_results(csc_domains_availability_check_command(client, args))

        elif demisto.command() == 'csc-domains-configuration-search':
            return_results(csc_domains_configuration_search_command(client, args))

        elif demisto.command() == 'domain':
            return_results(domain(client, args, reliability))

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
