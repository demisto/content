import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Integration configuration
USE_SSL_VERIFY = not demisto.params().get('insecure', False)

# Service base URL
SERVER = 'https://otx.alienvault.com'

# Headers to be sent in requests
HEADERS = {
}

# Remove proxy if not set to true in params
handle_proxy()

''' HELPER FUNCTIONS '''
URL = lambda source, command, value, section: f'{SERVER}+/api/v1/{source}/{command}/{section}'


def http_request(method, url_path, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        url_path,
        verify=USE_SSL_VERIFY,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))
    return res.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


# Test button
def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = http_request('GET', 'items/samples')


# IP commmand
def ip():
    # Define API path
    api_path = {
        'source': 'indicators',
        'command': 'IPv4',
        'value': demisto.args('ip'),
        'section': 'general'
    }
    url_path = URL(source=api_path['source'],
                   command=api_path['command'],
                   value=api_path['value'],
                   section=api_path['section'])

    # Raw data
    raw = http_request(method='GET',
                       url_path=url_path)

    # Define entry context
    ec = {
        'IP': {
            'Address': '',
            'ASN': '',
            'Geo': {
                'Country': '',
                'Location': ''
            }
        },
        'AlienVaultOTX': {
            'Reputation': '',
        }
    }


def ip_command():
    pass


# Domain command
def domain():
    pass


def domain_command():
    pass


# alienvault-search-ipv6 command
def alienvault_search_ipv6():
    ec = {
        'IP': {
            'Address': '',
            'ASN': '',
            'AlienVaultOtx': {
                'Reputation': '',
            }
        },
        'DBotScore': {
            'Indicator': '',
            'Score': '',
            'Type': '',
            'Vendor': ''
        }
    }


def alienvault_search_ipv6_command():
    pass


# alienvault-search-hostname command
def alienvault_search_hostname():
    ec = {
        'Hostname': '',
        'AlienVaultOTX': {
            'Alexa': '',
            'Whois': ''
        }
    }


def alienvault_search_hostname_command():
    pass


# file command
def file():
    ec = {
        'File': {
            'MD5': '',
            'SHA1': '',
            'SHA256': '',
            'Malicious': {
                'PulseIDs': ''
            }
        },
        'DBotScore': {
            'Indicator': '',
            'Score': '',
            'Type': '',
            'Vendor': ''
        }
    }


def file_command():
    pass


# alienvault-search-cve command
def alienvault_search_cve():
    ec = {
        'CVE': {
            'ID': '',
            'CVSS': '',
            'Published': '',
            'Modified': '',
            'Description': ''
        }
    }


def alienvault_search_cve_command():
    pass


# alienvault-get-related-urls-by-indicator command
def alienvault_get_related_urls_by_indicator():
    ec = {
        'URL': {
            'Data': ''
        }
    }


def alienvault_get_related_urls_by_indicator_command():
    pass


# alienvault-get-related-hashes-by-indicator command
def alienvault_get_related_hashes_by_indicator():
    ec = {
        'File': {
            'Hash': ''
        }
    }


def alienvault_get_related_hashes_by_indicator_command():
    pass


# alienvault-get-passive-dns-data-by-indicator command
def alienvault_get_passive_dns_data_by_indicator():
    ec = {
        'AlienVault': {
            'PassiveDNS': {
                'Domain': '',
                'IP': '',
                'Type:': '',
                'FirstSeen': '',
                'LastSeen': ''
            }
        }
    }


def alienvault_get_passive_dns_data_by_indicator_command():
    pass


# alienvault-search-pulses command
def alienvault_search_pulses():
    ec = {
        'AlienVault': {
            'Pulses': {
                'ID': '',
                'Author': {
                    'Id': '',
                    'Username': ''
                },
                'Count': '',
                'Modified': '',
                'Name': '',
                'Source': '',
                'SubscriberCount': '',
                'Tags': '',
                'Description': ''
            }
        }
    }


def alienvault_search_pulses_command():
    pass


# alienvault-get-pulse-details command
def alienvault_get_pulse_details():
    ec = {
        'AlienVault': {
            'Pulses': {
                'Description': '',
                'Created': '',
                'Author': {
                    'Username': ''
                },
                'ID': '',
                'Name': '',
                'Tags': '',
                'TargetedCountries': ''
            }
        }
    }


def alienvault_get_pulse_details_command():
    pass


# url command
def url():
    ec = {
        'URL': {
            'Data': ''
        }
    }


def url_command():
    pass


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'ip':
        ip_command()
    elif demisto.command() == 'domain':
        domain_command()
    elif demisto.command() == 'alienvault-search-ipv6':
        alienvault_search_ipv6_command()
    elif demisto.command() == 'alienvault-search-hostname':
        alienvault_search_hostname_command()
    elif demisto.command() == 'file':
        file_command()
    elif demisto.command() == 'alienvault-search-cve':
        alienvault_search_cve_command()
    elif demisto.command() == 'alienvault-get-related-urls-by-indicator':
        alienvault_get_related_urls_by_indicator_command()
    elif demisto.command() == 'alienvault-get-related-hashes-by-indicator':
        alienvault_get_related_hashes_by_indicator_command()
    elif demisto.command() == 'alienvault-get-passive-dns-data-by-indicator':
        alienvault_get_passive_dns_data_by_indicator_command()
    elif demisto.command() == 'alienvault-search-pulses':
        alienvault_search_pulses_command()
    elif demisto.command() == 'alienvault-get-pulse-details':
        alienvault_get_pulse_details_command()
    elif demisto.command() == 'url':
        url_command()

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
