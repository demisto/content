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

API_KEY = demisto.params()['api_key']

# Remove trailing slash to prevent wrong URL path to service
API_URL = demisto.params()['api_url'].rstrip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    os.environ.pop('HTTP_PROXY', None)
    os.environ.pop('HTTPS_PROXY', None)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)

''' HELPER FUNCTIONS '''


def http_request(uri, params=None):
    if params is None:
        params = {}

    params.update({
        'key': API_KEY
    })
    url = f'{API_URL}{uri}'
    res = requests.get(url,
                       params=params)

    if res.status_code != 200:
        raise Exception(f'Error in API call {url} [{res.status_code}] - {res.reason}')

    return res.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('/shodan/ports', {'query': 'test'})


def search_command():
    query = demisto.args()['query']
    facets = demisto.args().get('facets')
    page = int(demisto.args().get('page', 1))

    params = {'query': query}
    if facets:
        params['facets'] = facets
    if page:
        params['page'] = page

    http_request('/shodan/host/search', params)


def ip_command():
    ip = demisto.args()['ip']

    res = http_request(f'/shodan/host/{ip}')

    hostnames = res.get('hostnames')
    hostname = hostnames[0] if hostnames else ''  # It's a list, only if it exists and not empty we take the first value

    location = f'{round(res.get("latitude", 0.0), 3)},{round(res.get("longitude", 0.0), 3)}'

    ip_details = {
        'ASN': res.get('asn', ''),
        'Address': ip,
        'Hostname': hostname,
        'Geo': {
            'Country': res.get('country_name', ''),
            'Location': location
        }
    }

    shodan_ip_details = {
        'Tag': res.get('tags', []),
        'Latitude': res.get('latitude', 0.0),
        'Longitude': res.get('longitude', 0.0),
        'Org': res.get('org', ''),
        'ASN': res.get('asn', ''),
        'ISP': res.get('isp', ''),
        'LastUpdate': res.get('last_update', ''),
        'CountryName': res.get('country_name', ''),
        'Address': ip,
        'OS': res.get('os', ''),
        'Port': res.get('ports', [])
    }

    ec = {
        outputPaths['ip']: ip_details,
        'Shodan': {
            'IP': shodan_ip_details
        }
    }

    human_readable = tableToMarkdown(f'Shodan details for IP {ip}', {
        'Country': ec[outputPaths['ip']]['Geo']['Country'],
        'Location': ec[outputPaths['ip']]['Geo']['Location'],
        'ASN': ec[outputPaths['ip']]['ASN'],
        'ISP': ec['Shodan']['IP']['ISP'],
        'Ports': ', '.join([str(x) for x in ec['Shodan']['IP']['Port']]),
        'Hostname': ec[outputPaths['ip']]['Hostname']
    })

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': ec
    })


''' COMMANDS MANAGER / SWITCH PANEL '''

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    test_module()
    demisto.results('ok')
elif demisto.command() == 'search':
    search_command()
elif demisto.command() == 'ip':
    ip_command()
