''' IMPORTS '''
# std py packages

# 3-rd party py packages
import requests

# local py packages
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Parameters received from the user
PARAMS = demisto.params()

# TOKEN
TOKEN = PARAMS.get('token')

# Service base URL
BASE_URL = 'https://jsonwhois.com'

# Headers to be sent in requests
HEADERS = {
    'Accept': 'application/json',
    'Authorization': f'Token token={TOKEN}'
}

# Self signed certificate so no need to verify by default
USE_SSL = False

# Remove proxy if not set to true in params
handle_proxy()

# Counter for unstable REST API
COUNTER = 0

''' HELPER FUNCTIONS '''
def http_request(method, url_suffix, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        if COUNTER < 2:
            COUNTER += 1
            return http_request(method=method,
                                url_suffix=url_suffix,
                                params=params)
        url = demisto.args().get('query')
        return_error(f'Error enrich url "{url}" with JsonWhoIS API, status code {res.status_code}')
    return res.json()


@logger
def list_dict_by_ec(contacts: list):
    """ evaluate list of contacts by entry context "DOMAIN.WHOIS" definition

    :param contacts: list of contacts
    """
    keys_needed = ['name', 'email', 'phone']
    for contact in contacts:
        for key in list(contact.keys()):
            if key not in keys_needed:
                del contact[key]
            else:
                contact[key.capitalize()] = contact.pop(key)
    return contacts


''' COMMANDS + REQUESTS FUNCTIONS '''


@logger
def whois(url: str) -> tuple:
    """Get Rest API raw from JsonWhoIs service
    :param url: url to search on
    :return: dict object of JsonWhoIs service
    """
    # Params for request
    params = {
        'domain': url
    }

    # Perform request to JsonWhoIs
    demisto.debug('Perform JsonWhoIs request')
    raw = http_request(method='GET', url_suffix='/api/v1/whois', params=params)
    demisto.debug('Success JsonWhoIs request')

    # entry context by code convention
    ec: dict = {'Domain': {
        'WHOIS': {

        }
    }}

    res_shortcut = ec['Domain']['WHOIS']
    if 'status' in raw.keys():
        demisto.debug('JsonWhoIs parse status')
        res_shortcut['DomainStatus'] = raw['status']
    if 'nameservers' in raw.keys():
        demisto.debug('JsonWhoIs parse name servers')
        res_shortcut['NameServers'] = raw['nameservers']
    if 'created_on' in raw.keys():
        demisto.debug('JsonWhoIs parse creation date')
        res_shortcut['CreationDate'] = raw['created_on']
    if 'updated_on' in raw.keys():
        demisto.debug('JsonWhoIs parse update date')
        res_shortcut['UpdatedDate'] = raw['updated_on']
    if 'expires_on' in raw.keys():
        demisto.debug('JsonWhoIs parse Expiration date')
        res_shortcut['ExpirationDate'] = raw['expires_on']
    if 'registrant_contacts' in raw.keys():
        demisto.debug('JsonWhoIs parse registrant contacts')
        res_shortcut['Registrant'] = list_dict_by_ec(raw['registrant_contacts'])
    if 'admin_contacts' in raw.keys():
        demisto.debug('JsonWhoIs parse admin contacts')
        res_shortcut['Admin'] = list_dict_by_ec(raw['admin_contacts'])
    if 'registrar' in raw.keys():
        demisto.debug('JsonWhoIs parse registrar contacts')
        res_shortcut['Registrar'] = {}
        if isinstance(raw['registrar'], dict):
            if 'name' in raw['registrar'].keys():
                res_shortcut['Registrar']['Name'] = raw['registrar']['name']
    return ec, raw


@logger
def whois_command():
    """Whois command"""
    # Get url arg
    url = demisto.args().get('query')
    # Get parsed entry context and raw data
    ec, raw = whois(url)
    # Create human-readable format
    ec_shortcut = ec['Domain']['WHOIS']

    # Admin account table
    
    human_readable_admin = ''
    demisto.debug('Cretae admin table')
    if 'Admin' in ec_shortcut.keys():
        human_readable_admin = tableToMarkdown(name='Admin account', t=ec_shortcut['Admin'])
        del ec_shortcut['Admin']

    # Name servers table
    demisto.debug('Create name servers table')
    human_readable_ns = ''
    if 'NameServers' in ec_shortcut.keys():
        demisto.results(ec_shortcut['NameServers'])
        for server in ec_shortcut['NameServers']:
            del server['ipv4']
            del server['ipv6']
        human_readable_ns = tableToMarkdown(name='Name servers', t=ec_shortcut['NameServers'])
        del ec_shortcut['NameServers']

    demisto.debug('Create registrant table')
    # Registrant accounts table
    human_readable_registrant = ''
    if 'Registrant' in ec_shortcut.keys():
        human_readable_registrant = tableToMarkdown(name='Registrant', t=ec_shortcut['Registrant'])
        del ec_shortcut['Registrant']

    # Registrar accounts table
    demisto.debug('Create registrar table')
    human_readable_registrar = ''
    if 'Registrar' in ec_shortcut.keys():
        human_readable_registrar = tableToMarkdown(name='Registrar', t=ec_shortcut['Registrar'])
        del ec_shortcut['Registrar']

    # Others table
    demisto.debug('Create other table')
    human_readable_others = tableToMarkdown(name='Others', t=ec['Domain']['WHOIS'])

    demisto.debug('Aggregate tables')
    human_readable = (human_readable_admin
                      + human_readable_ns
                      + human_readable_registrar
                      + human_readable_registrant
                      + human_readable_others)

    return_outputs(raw_response=raw,
                   outputs=ec,
                   readable_output=human_readable)


@logger
def test_module():
    # unittest.main()
    ec, raw = whois('demisto.com')
    status = None
    if 'DomainStatus' in ec['Domain']['WHOIS'].keys():
        status = ec['Domain']['WHOIS']['DomainStatus']
    if status is None:
        demisto.results('Testing demisto.com url failed')
    demisto.results('ok')


''' EXECUTION'''
LOG('Command being called is %s' % (demisto.command()))
demisto.info(demisto.command())
try:
    if demisto.command() == 'whois':
        # This is the call made when performing whois command  with url argument.
        whois_command()
    if demisto.command() == 'test-module':
        # This is the call made pressing the test button
        test_module()

# Log exceptions
except Exception as e:
    LOG(e)
    LOG.print_log()
