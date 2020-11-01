import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

API_KEY = demisto.params()['api_key']

# Remove trailing slash to prevent wrong URL path to service
API_URL = demisto.params()['api_url'].rstrip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

handle_proxy()

''' HELPER FUNCTIONS '''


def http_request(method, uri, params=None, data=None, headers=None):
    if params is None:
        params = {}

    params.update({
        'key': API_KEY
    })

    url = f'{API_URL}{uri}'
    res = requests.request(method,
                           url,
                           params=params,
                           data=data,
                           headers=headers,
                           verify=USE_SSL)
    if res.status_code == 404:
        return {}
    if res.status_code != 200:
        error_msg = f'Error in API call {url} [{res.status_code}] - {res.reason}'
        if 'application/json' in res.headers['content-type'] and 'error' in res.json():
            error_msg += f': {res.json()["error"]}'

        return_error(error_msg)

    return res.json()


def alert_to_demisto_result(alert):
    ec = {
        'Shodan': {
            'Alert': {
                'ID': alert.get('id', ''),
                'Expires': alert.get('expires', 0)
            }
        }
    }

    human_readable = tableToMarkdown(f'Alert ID {ec["Shodan"]["Alert"]["ID"]}', {
        'Name': alert.get('name', ''),
        'IP': alert.get('filters', {'ip', ''})['ip'],
        'Expires': ec['Shodan']['Alert']['Expires']
    })

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': alert,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': ec
    })


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_scan_status(scan_id):
    res = http_request("GET", f'/shodan/scan/{scan_id}')

    ec = {
        'Shodan': {
            'Scan': {
                'ID': res.get('id', ''),
                'Status': res.get('status', '')
            }
        }
    }

    human_readable = tableToMarkdown(f'Scanning results for scan {scan_id}', {
        'ID': ec['Shodan']['Scan']['ID'],
        'Status': ec['Shodan']['Scan']['Status']
    })

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': ec
    })


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', '/shodan/ports', {'query': 'test'})


def search_command():
    query = demisto.args()['query']
    facets = demisto.args().get('facets')
    page = int(demisto.args().get('page', 1))

    params = {'query': query}
    if facets:
        params['facets'] = facets
    if page:
        params['page'] = page

    res = http_request('GET', '/shodan/host/search', params)

    matches = res.get('matches', [])
    for match in matches:
        location = match.get('location', {'city': '', 'country_name': '', 'longitude': 0, 'latitude': 0})
        ec = {
            'Shodan': {
                'Banner': {
                    'Org': match.get('org', ''),
                    'Isp': match.get('isp', ''),
                    'Transport': match.get('transport', ''),
                    'Asn': match.get('asn', ''),
                    'IP': match.get('ip_str', ''),
                    'Port': match.get('port', 0),
                    'Ssl': {
                        'versions': match.get('ssl', {'versions': []})['versions']
                    },
                    'Hostnames': match.get('hostnames', []),
                    'Location': {
                        'City': location['city'],
                        'Longitude': location['longitude'],
                        'Latitude': location['latitude'],
                        'Country': location['country_name']
                    },
                    'Timestamp': match.get('timestamp', ''),
                    'Domains': match.get('domains', []),
                    'OS': match.get('os', '')
                }
            }
        }

        human_readable = tableToMarkdown(f'Search results for query "{query}" - page {page}, facets: {facets}',
                                         {
                                             'IP': ec['Shodan']['Banner']['IP'],
                                             'Port': ec['Shodan']['Banner']['Port'],
                                             'Timestamp': ec['Shodan']['Banner']['Timestamp']
                                         })

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': match,
            'ContentsFormat': formats['json'],
            'HumanReadable': human_readable,
            'HumanReadableFormat': formats['markdown'],
            'EntryContext': ec
        })


def ip_command():
    ip = demisto.args()['ip']

    res = http_request('GET', f'/shodan/host/{ip}')

    if not res:
        demisto.results('No information available for the given IP.')
    else:
        hostnames = res.get('hostnames')
        # It's a list, only if it exists and not empty we take the first value.
        hostname = hostnames[0] if hostnames else ''

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


def shodan_search_count_command():
    query = demisto.args()['query']

    res = http_request('GET', '/shodan/host/count', {'query': query})

    ec = {
        'Shodan': {
            'Search': {
                'ResultCount': res.get('total', 0)
            }
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'HumanReadable': f'## {ec["Shodan"]["Search"]["ResultCount"]} results for query "{query}"',
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': ec
    })


def shodan_scan_ip_command():
    ips = demisto.args()['ips']

    res = http_request('POST', '/shodan/scan', data={'ips': ips})

    if 'id' not in res:
        demisto.results({
            'Type': entryTypes['error'],
            'Contents': res,
            'ContentsFormat': formats['json'],
            'HumanReadable': '## Unknown answer format, no "id" field in response',
            'HumanReadableFormat': formats['markdown'],
        })

    get_scan_status(res['id'])


def shodan_scan_internet_command():
    port = demisto.args()['port']

    try:
        port = int(port)
    except ValueError:
        return_error(f'Port must be number, not {port}')

    protocol = demisto.args()['protocol']

    res = http_request('POST', '/shodan/scan/internet', data={
        'port': port,
        'protocol': protocol
    })

    ec = {
        'Shodan': {
            'Scan': {
                'ID': res.get('id', '')
            }
        }
    }

    human_readable = tableToMarkdown(f'Intenet scanning results for port {port} and protocol {protocol}', {
        'ID': ec['Shodan']['Scan']['ID'],
    })

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'HumanReadable': human_readable,
        'HumanReadableFormat': formats['markdown'],
        'EntryContext': ec
    })


def shodan_scan_status_command():
    scan_id = demisto.args()['scanID']

    get_scan_status(scan_id)


def shodan_create_network_alert_command():
    alert_name = demisto.args()['alertName']
    ip = demisto.args()['ip']
    try:
        expires = int(demisto.args().get('expires', 0))
    except ValueError:
        return_error(f'Expires must be a number, not {expires}')

    res = http_request('POST', '/shodan/alert', data=json.dumps({
        'name': alert_name,
        'filters': {
            'ip': ip
        },
        'expires': expires
    }), headers={'content-type': 'application/json'})

    alert_to_demisto_result(res)


def shodan_network_get_alert_by_id_command():
    alert_id = demisto.args()['alertID']

    res = http_request('GET', f'/shodan/alert/{alert_id}/info')

    alert_to_demisto_result(res)


def shodan_network_get_alerts_command():
    res = http_request('GET', '/shodan/alert/info')

    if len(res) == 0:
        demisto.results('No alerts')
    else:
        for alert in res:
            alert_to_demisto_result(alert)


def shodan_network_delete_alert_command():
    alert_id = demisto.args()['alertID']

    http_request('DELETE', f'/shodan/alert/{alert_id}')

    demisto.results(f'Deleted alert {alert_id}')


def shodan_network_alert_set_trigger_command():
    alert_id = demisto.args()['alertID']
    trigger = demisto.args()['Trigger']

    res = http_request('PUT', f'/shodan/alert/{alert_id}/trigger/{trigger}')

    if not res.get('success', False):
        return_error(f'Failed setting trigger {trigger} for alert {alert_id}')

    demisto.results(f'Set trigger "{trigger}" for alert {alert_id}')


def shodan_network_alert_remove_trigger_command():
    alert_id = demisto.args()['alertID']
    trigger = demisto.args()['Trigger']

    res = http_request('DELETE', f'/shodan/alert/{alert_id}/trigger/{trigger}')

    if not res.get('success', False):
        return_error(f'Failed deleting trigger {trigger} for alert {alert_id}')

    demisto.results(f'Deleted trigger "{trigger}" for alert {alert_id}')


def shodan_network_alert_whitelist_service_command():
    alert_id = demisto.args()['alertID']
    trigger = demisto.args()['trigger']
    service = demisto.args()['service']

    res = http_request('PUT', f'/shodan/alert/{alert_id}/trigger/{trigger}/ignore/{service}')

    if not res.get('success', False):
        return_error(f'Failed whitelisting service "{service}" for trigger {trigger} in alert {alert_id}')

    demisto.results(f'Whitelisted service "{service}" for trigger {trigger} in alert {alert_id}')


def shodan_network_alert_remove_service_from_whitelist_command():
    alert_id = demisto.args()['alertID']
    trigger = demisto.args()['trigger']
    service = demisto.args()['service']

    res = http_request('DELETE', f'/shodan/alert/{alert_id}/trigger/{trigger}/ignore/{service}')

    if not res.get('success', False):
        return_error(
            f'Failed removing service "{service}" for trigger {trigger} in alert {alert_id} from the whitelist')

    demisto.results(f'Removed service "{service}" for trigger {trigger} in alert {alert_id} from the whitelist')


''' COMMANDS MANAGER / SWITCH PANEL '''

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    test_module()
    demisto.results('ok')
elif demisto.command() == 'search':
    search_command()
elif demisto.command() == 'ip':
    ip_command()
elif demisto.command() == 'shodan-search-count':
    shodan_search_count_command()
elif demisto.command() == 'shodan-scan-ip':
    shodan_scan_ip_command()
elif demisto.command() == 'shodan-scan-internet':
    shodan_scan_internet_command()
elif demisto.command() == 'shodan-scan-status':
    shodan_scan_status_command()
elif demisto.command() == 'shodan-create-network-alert':
    shodan_create_network_alert_command()
elif demisto.command() == 'shodan-network-get-alert-by-id':
    shodan_network_get_alert_by_id_command()
elif demisto.command() == 'shodan-network-get-alerts':
    shodan_network_get_alerts_command()
elif demisto.command() == 'shodan-network-delete-alert':
    shodan_network_delete_alert_command()
elif demisto.command() == 'shodan-network-alert-set-trigger':
    shodan_network_alert_set_trigger_command()
elif demisto.command() == 'shodan-network-alert-remove-trigger':
    shodan_network_alert_remove_trigger_command()
elif demisto.command() == 'shodan-network-alert-whitelist-service':
    shodan_network_alert_whitelist_service_command()
elif demisto.command() == 'shodan-network-alert-remove-service-from-whitelist':
    shodan_network_alert_remove_service_from_whitelist_command()
