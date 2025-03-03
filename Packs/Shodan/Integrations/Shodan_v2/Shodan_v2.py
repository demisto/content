import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
API_KEY = demisto.params().get('credentials', {}).get('password') or demisto.params().get('api_key')

if API_KEY is None:
    raise ValueError('Missing API key.')

# Remove trailing slash to prevent wrong URL path to service
API_URL = demisto.params()['api_url'].rstrip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

VENDOR = 'shodan'
PRODUCT = 'banner'
DEFAULT_MAX_EVENTS = 50_000
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'

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
    if res.status_code == 401:
        return_error('Error: the Shodan API key is invalid. Please check your API key.')
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
        'IP': alert.get('filters', {'ip': ''})['ip'],
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


def format_record_keys(dict_list: List[Dict]) -> List[Dict]:
    """
    Formats dictionary keys by replacing underscores with spaces and capitalizing each word.
    """
    new_list = []
    for input_dict in dict_list:
        new_dict = {}
        for key, value in input_dict.items():
            new_key = key.replace('_', ' ').title()
            new_dict[new_key] = value
        new_list.append(new_dict)
    return new_list


def add_time_to_events(events: list[dict]):
    """
    Adds the _time key to the events.
    Args:
        events: list[dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(event["created"])
            event["_time"] = create_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]


def filter_events(events: list[dict], limit: int, last_run: dict = {}) -> list[dict]:
    """
    Filters and sorts events based on the last fetch time, list of excluded IDs, and a limit.

    Args:
        events (list[dict]): List of events where each event is represented as a dictionary.
        limit (int): The maximum number of events to return.
        last_run (dict, optional): Dictionary containing the last fetch time and a list of event IDs to exclude.
                                   Default is an empty dictionary.
    """

    if last_fetch_time := arg_to_datetime(last_run.get('last_fetch_time')):
        events = [event for event in events if parse_event_date(event) >= last_fetch_time]

        if last_ids := last_run.get('last_event_ids'):
            events = [event for event in events if event['id'] not in last_ids]

    return events[:limit]


def parse_event_date(event: Dict) -> datetime:
    """
    Parses the 'created' field from an event dictionary into a datetime object.
    """
    return datetime.strptime(event['created'], DATE_FORMAT)


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
    Sends a basic GET request to verify API connectivity and performs a sample event fetch if event fetching is enabled.
    """
    params = demisto.params()
    is_fetch_events = argToBoolean(params.get('isFetchEvents', False))

    if is_fetch_events and not API_KEY:
        return_error("Missing API key - You must provide API KEY parameter.")

    if API_KEY:
        http_request('GET', '/shodan/alert/info')  # Checking with API key
    else:
        http_request('GET', '/shodan/ports', {'query': 'test'})  # Checking without API key


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
                        'versions': match.get('ssl', {'versions': []}).get('versions', [])
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
    ips = argToList(demisto.args()['ip'])
    results = []
    for ip in ips:
        res = http_request('GET', f'/shodan/host/{ip}')

        if not res:
            results.append(CommandResults(readable_output=f'No information available for the following IP: {ip}'))
        else:
            hostnames = res.get('hostnames')
            # It's a list, only if it exists and not empty we take the first value.
            hostname = hostnames[0] if hostnames else ''

            location = f'{round(res.get("latitude", 0.0), 3)},{round(res.get("longitude", 0.0), 3)}'

            relationships_list: list[EntityRelationship] = []

            vulns_list = res.get('vulns', [])
            for v in vulns_list:
                relationships_list.append(EntityRelationship(
                    entity_a=ip,
                    entity_a_type=FeedIndicatorType.IP,
                    name='related-to',
                    entity_b=v,
                    entity_b_type=FeedIndicatorType.CVE,
                    brand='ShodanV2'))

            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                reliability=demisto.params().get('integrationReliability'),
                score=0,
                integration_name='Shodan_v2'
            )

            ip_details = Common.IP(
                ip=ip,
                dbot_score=dbot_score,
                asn=res.get('asn', ''),
                hostname=hostname,
                geo_country=res.get('country_name', ''),
                geo_latitude=round(res.get("latitude", 0.0), 3),
                geo_longitude=round(res.get("longitude", 0.0), 3),
                relationships=relationships_list
            )

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
                'Port': res.get('ports', []),
                'Vulnerabilities': vulns_list
            }

            title = f'Shodan details for IP {ip}'

            human_readable = {
                'Country': res.get('country_name', ''),
                'Location': location,
                'ASN': res.get('asn', ''),
                'ISP': res.get('isp', ''),
                'Ports': ', '.join([str(x) for x in res.get('ports', [])]),
                'Hostname': hostname
            }

            readable_output = tableToMarkdown(
                name=title,
                t=human_readable,
                removeNull=True
            )

            results.append(CommandResults(
                readable_output=readable_output,
                raw_response=res,
                outputs=shodan_ip_details,
                relationships=relationships_list,
                outputs_prefix='Shodan.IP',
                indicator=ip_details
            ))
    return results


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
    expires = demisto.args().get('expires', 0)
    try:
        expires = int(expires)
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


def get_events_command(args: dict) -> tuple[str, list[dict]]:
    '''
    Get events command, used mainly for debugging
    '''
    events = http_request('GET', '/shodan/alert/info')
    if not isinstance(events, list):
        events = [events]

    limit = arg_to_number(args.get("max_fetch")) or DEFAULT_MAX_EVENTS
    events = filter_events(events, limit)

    hr = tableToMarkdown(f"{VENDOR.title()} - {PRODUCT.title()} Events:", format_record_keys(events))
    return hr, events


def fetch_events(last_run: dict, params: dict[str, str]) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from an API, filters them, and updates the last_run data with the latest event's date.

    Args:
        last_run (dict): A dictionary containing data from the last run. It should include 'last_fetch_time'
                         and 'last_event_ids', which represent the last fetch time and IDs of the last events processed.
        params (dict[str, str]): Dictionary of parameters. It should include 'max_fetch' to define the maximum number
                                 of events to fetch.

    Returns:
        tuple[Dict, List[Dict]]: A tuple where the first item is the updated last_run data, including the latest fetch
                                 time and event IDs, and the second item is a list of filtered events.
    """
    if not last_run.get("last_fetch_time"):  # If this is a first run
        last_run = {'last_fetch_time': datetime.now().strftime(DATE_FORMAT)}
        demisto.debug('First run detected. Setting last_fetch_time to now.')
        return last_run, []

    events = http_request('GET', '/shodan/alert/info')
    if not isinstance(events, list):
        events = [events]
    demisto.debug(f'Fetched {len(events)} events before filtering')

    limit = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_EVENTS
    events_filtered = filter_events(events, limit, last_run)
    demisto.debug(f'After filtering, {len(events_filtered)} events remain')

    if events_filtered:
        latest_fetch_time = max(parse_event_date(event) for event in events_filtered)
        latest_event_ids = [event.get("id") for event in events_filtered if parse_event_date(event) == latest_fetch_time]

        last_run["last_fetch_time"] = latest_fetch_time.strftime(DATE_FORMAT)
        last_run['last_event_ids'] = latest_event_ids
    else:
        demisto.debug('No new events found after filtering')

    return last_run, events_filtered


''' COMMANDS MANAGER / SWITCH PANEL '''

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    test_module()
    demisto.results('ok')
elif demisto.command() == 'search':
    search_command()
elif demisto.command() == 'ip':
    return_results(ip_command())
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
elif demisto.command() == 'shodan-get-events':
    args = demisto.args()
    hr, events = get_events_command(args)
    return_results(CommandResults(readable_output=hr))
    should_push_events = argToBoolean(args.get('should_push_events'))
    if should_push_events:
        add_time_to_events(events)
        send_events_to_xsiam(
            events,
            vendor=VENDOR,
            product=PRODUCT
        )
elif demisto.command() == 'fetch-events':
    params = demisto.params()
    last_run = demisto.getLastRun()
    demisto.debug(f'Last_run before the fetch: {last_run}')
    next_run, events = fetch_events(last_run, params)

    add_time_to_events(events)
    send_events_to_xsiam(
        events=events,
        vendor=VENDOR,
        product=PRODUCT
    )
    demisto.debug(f'last_run after the fetch {last_run}')
    demisto.setLastRun(next_run)
