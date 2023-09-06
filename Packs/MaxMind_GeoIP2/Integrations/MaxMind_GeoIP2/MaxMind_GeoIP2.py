import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
from collections import defaultdict
from requests.auth import HTTPBasicAuth
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

'''GLOBAL VARS'''
PARAMS = demisto.params()
BASE_URL = PARAMS.get('url')
APIKEY = PARAMS.get('credentials', {}).get('password') or PARAMS.get('apikey')
ACCOUNT_ID = PARAMS.get('credentials', {}).get('identifier') or PARAMS.get('account')
MODE = PARAMS.get('mode')
USE_SSL = not PARAMS.get('insecure', False)
PROXY = PARAMS.get('proxy')
API_VERSION = 'geoip/v2.1'

HR_HEADERS = [
    'IP',
    'Domain',
    'ASN',
    'Organization',
    'ISP',
    'Location',
    'Accuracy Radius',
    'User Type',
    'Continent',
    'ISO Code',
    'Country',
    'Registered Country',
    'TimeZone',
    'City',
    'Subdivision',
    'Is TOR Exit Node',
    'Is Hosting Provider',
    'Is Anonymous']

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

'''HELPER FUNCTIONS'''


def http_request(query):
    r = requests.request(
        'GET',
        BASE_URL + API_VERSION + '/' + MODE + '/' + query,
        headers=HEADERS,
        verify=USE_SSL,
        auth=HTTPBasicAuth(ACCOUNT_ID, APIKEY)
    )
    if r.status_code != 200:
        return_error(
            f'Error in API call to MaxMind, got status code - {r.status_code} and a reason: {r.reason}')
    return r


def create_map_entry(lat, lng):
    demisto.results({
        'Type': entryTypes['map'],
        'ContentsFormat': formats['json'],
        'Contents': {'lat': lat, 'lng': lng}
    })


def format_results(res_json):
    hr = defaultdict()  # type: dict
    maxmind_ec = defaultdict(lambda: defaultdict(int))  # type: dict
    ip_ec = defaultdict(lambda: defaultdict(int))  # type: dict
    if 'continent' in res_json:
        continent = res_json['continent']
        hr['Continent'] = continent['names']['en']
        maxmind_ec['Geo']['Continent'] = continent['names']['en']
    if 'city' in res_json:
        city = res_json['city']
        hr['City'] = city['names']['en']
        maxmind_ec['Geo']['City'] = city['names']['en']
    if 'country' in res_json:
        country = res_json['country']
        hr['Country'] = country['names']['en']
        maxmind_ec['Geo']['Country'] = country['names']['en']
        ip_ec['Geo']['Country'] = country['names']['en']
    if 'location' in res_json:
        location = res_json['location']
        ip_ec['Geo']['Location'] = str(location['latitude']) + ', ' + str(location['longitude'])
        maxmind_ec['Geo']['Location'] = str(location['latitude']) + ', ' + str(location['longitude'])
        create_map_entry(location['latitude'], location['longitude'])
        if 'time_zone' in location:
            hr['TimeZone'] = location['time_zone']
            maxmind_ec['Geo']['TimeZone'] = location['time_zone']
        if 'accuracy_radius' in location:
            hr['Accuracy Radius'] = location['accuracy_radius']
            maxmind_ec['Geo']['Accuracy'] = location['accuracy_radius']
    if 'registered_country' in res_json:
        hr['ISO Code'] = res_json['registered_country']['iso_code']
        maxmind_ec['ISO_Code'] = res_json['registered_country']['iso_code']
        registration = res_json['registered_country']['names']['en']
        hr['Registered Country'] = registration
        maxmind_ec['RegisteredCountry'] = registration
    if 'subdivisions' in res_json:
        subs = res_json['subdivisions'][0]
        hr['Subdivision'] = subs['names']['en']
        maxmind_ec['Geo']['Subdivision'] = subs['names']['en']
    if 'traits' in res_json:
        traits = res_json['traits']
        if 'user_type' in traits:
            hr['User Type'] = traits['user_type']
            maxmind_ec['UserType'] = traits['user_type']
        if 'domain' in traits:
            hr['Domain'] = traits['domain']
            maxmind_ec['Domain'] = traits['domain']
        if 'is_anonymous' in traits:
            hr['Is Anonymous'] = traits['is_anonymous']
            maxmind_ec['Anonymous'] = traits['is_anonymous']
        if 'is_hosting_provider' in traits:
            hr['Is Hosting Provider'] = traits['is_hosting_provider']
            maxmind_ec['Host'] = traits['is_hosting_provider']
        if 'is_tor_exit_node' in traits:
            hr['Is TOR Exit Node'] = traits['is_tor_exit_node']
            maxmind_ec['Tor'] = traits['is_tor_exit_node']
        if 'autonomous_system_number' in traits:
            hr['ASN'] = traits['autonomous_system_number']
            ip_ec['ASN'] = traits['autonomous_system_number']
            maxmind_ec['ASN'] = traits['autonomous_system_number']
        if 'autonomous_system_organization' in traits:
            hr['Organization'] = traits['autonomous_system_organization']
            maxmind_ec['Organization'] = traits['autonomous_system_organization']
        hr['IP'] = traits['ip_address']
        ip_ec['Address'] = traits['ip_address']
        maxmind_ec['Address'] = traits['ip_address']
        if 'isp' in traits:
            hr['ISP'] = traits['isp']
            maxmind_ec['ISP'] = traits['isp']
    dbot_score = {
        'Indicator': ip_ec.get('Address'),
        'Type': 'ip',
        'Vendor': 'MaxMind_GeoIP2',
        'Score': 0,
        'Reliability': PARAMS.get('integrationReliability')
    }
    return hr, ip_ec, maxmind_ec, dbot_score


''' FUNCTIONS '''


def get_geo_ip(query):
    raw = http_request(query)
    res_json = raw.json()
    return res_json


def geo_ip_command():
    ip_query = demisto.args().get('ip')
    res_json = get_geo_ip(ip_query)
    hr, ip_ec, maxmind_ec, dbot_score = format_results(res_json)
    ec = ({
        'IP(val.Address && val.Address == obj.Address)': ip_ec,
        'MaxMind(val.Address && val.Address == obj.Address)': maxmind_ec,
        'DBotScore': dbot_score
    })
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': res_json,
        'HumanReadable': tableToMarkdown(f'{ip_query} - Scan Results', hr, HR_HEADERS, removeNull=True),
        'EntryContext': ec
    })


''' EXECUTION CODE '''
LOG(f'command is {demisto.command()}')
try:
    handle_proxy()
    if demisto.command() == 'ip':
        geo_ip_command()
    if demisto.command() == 'test-module':
        raw = http_request('8.8.8.8')
        demisto.results('ok')
except Exception as e:
    LOG(e)
    LOG.print_log()
    return_error(str(e))
