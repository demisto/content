import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Parameters received from the user
PARAMS = demisto.params()

# TOKEN
TOKEN = PARAMS.get('credentials', {}).get('password') or PARAMS.get('token')

# Service base URL
BASE_URL = 'https://jsonwhois.com'

# Headers to be sent in requests
HEADERS = {
    'Accept': 'application/json',
    'Authorization': f'Token token={TOKEN}'
}

# Self signed certificate so no need to verify by default
USE_SSL = not PARAMS.get('insecure', False)

''' HELPER FUNCTIONS '''


@logger
def http_request(method, url_suffix, params=None, max_retry=3):
    for _ in range(max_retry):
        res = requests.request(
            method,
            urljoin(BASE_URL, url_suffix),
            verify=USE_SSL,
            params=params,
            headers=HEADERS
        )
        if res.status_code == 200:
            break
    else:
        if 'res' in locals():
            raise DemistoException(f'Error enrich url with JsonWhoIS API. Status code: {res.status_code}')
        else:
            raise DemistoException('Error enrich url with JsonWhoIS API.')
    if res is None:
        raise DemistoException('Error from JsonWhoIs: Could not get a result from the API.')
    try:
        raw = res.json()
    except ValueError:
        raise DemistoException(f'Error from JsonWhoIs: Could not parse JSON from response. {res.text}')
    if 'error' in raw:
        raise DemistoException(f'Error from JsonWhoIs: {raw["error"]}')
    return raw


def dict_by_ec(cur_dict: dict):
    """ Create dict (Json) by entry contexts convention
    Capitalize first char, remove nulls
    :param cur_dict: dictionary
    :return: dictionary by conventions
    """
    if not cur_dict:
        return None
    return {key.capitalize(): value for key, value in cur_dict.items() if cur_dict[key]}


def list_by_ec(cur_list: list, needed_keys: list):
    """ Create list of dict (Json) by entry contexts convention
    Capitalize first char in dict, remove nulls, remove not needed parameters
    :param cur_list: list of dict
    :param needed_keys: key to save
    :return: modified list by description above
    """
    if not cur_list:
        return None
    cur_list = [createContext(index, removeNull=True) for index in cur_list]

    def cur_ec(index_ec):
        return {key.capitalize(): index_ec[key] for key in index_ec if key in needed_keys}
    cur_list = [cur_ec(contact) for contact in cur_list]
    return cur_list


''' COMMANDS + REQUESTS FUNCTIONS '''


@logger
def whois(url: str) -> tuple:
    """Get Rest API raw from JsonWhoIs API
    :param url: url to query
    :return: raw response and entry context
    """
    # Perform request
    params = {
        'domain': url
    }
    raw = http_request(method='GET',
                       url_suffix='/api/v1/whois',
                       params=params)
    # Build all ec
    ec = {
        'DomainStatus': raw.get('status'),
        'NameServers': list_by_ec(raw.get('nameservers'), needed_keys=['name']),
        'CreationDate': raw.get('created_on'),
        'UpdatedDate': raw.get('updated_on'),
        'ExpirationDate': raw.get('expires_on'),
        'Registrar': dict_by_ec(raw.get('registrar')),
        'Registrant': list_by_ec(raw.get('registrant_contacts'), needed_keys=['name', 'phone', 'email']),
        'Admin': list_by_ec(raw.get('admin_contacts'), needed_keys=['name', 'phone', 'email'])
    }
    createContext(ec, removeNull=True)

    return ec, raw


@logger
def whois_command():
    """Whois command"""
    # Get url arg
    domain = demisto.args().get('query')
    # Get parsed entry context and raw data
    ec, raw = whois(domain)

    # Create human-readable format
    human_readable = ''
    if ec.get('Admin'):
        human_readable += tableToMarkdown(name='Admin account', t=ec['Admin'])
    if ec.get('NameServers'):
        human_readable += tableToMarkdown(name='Name servers', t=ec['NameServers'])
    if ec.get('Registrant'):
        human_readable += tableToMarkdown(name='Registrant', t=ec['Registrant'])
    if ec.get('Registrar'):
        human_readable += tableToMarkdown(name='Registrar', t=ec['Registrar'])

    # Others table
    others_keys = ['DomainStatus', 'CreationDate', 'UpdatedDate', 'ExpirationDate']
    ec_others = {key: ec[key] for key in ec if key in others_keys}
    human_readable += tableToMarkdown(name='Others', t=ec_others)

    # Create full ec
    ec = {
        'Domain': {
            'WHOIS': ec
        }
    }

    return_outputs(readable_output=human_readable,
                   outputs=ec,
                   raw_response=raw)


@logger
def test_module():
    whois('whois.com')
    demisto.results('ok')


''' EXECUTION'''


def main():
    LOG(f'Command being called is {demisto.command()}')
    handle_proxy()
    try:
        if demisto.command() == 'whois':
            whois_command()
        if demisto.command() == 'test-module':
            test_module()

    # Log exceptions
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins'):
    main()
