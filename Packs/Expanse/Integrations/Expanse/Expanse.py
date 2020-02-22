import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import traceback
from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


API_KEY = demisto.params().get('api_key')
PAGE_LIMIT = demisto.params().get('page_limit')
FIRST_RUN = int(demisto.params().get('first_run', '7'))
SERVER = 'https://expander.expanse.co'
INSECURE = demisto.params().get('insecure')
PROXY = demisto.params().get('proxy')
BASE_URL = SERVER
EXPOSURE_EVENT_TYPES = "ON_PREM_EXPOSURE_APPEARANCE,ON_PREM_EXPOSURE_REAPPEARANCE"
API_ENDPOINTS = {
    "exposures/ip-ports": {
        "version": 2
    },
    "ip-range": {
        "version": 2
    },
    "assets/domains": {
        "version": 2
    },
    "IdToken": {
        "version": 1
    },
    "events": {
        "version": 1
    }
}

EXPOSURE_SEVERITY_MAPPING = {
    "NONE": 0,
    "UNKNOWN": 0,
    "CRITICAL": 3,
    "ROUTINE": 1,
    "WARNING": 2,
    "UNCATEGORIZED": 1
}

''' HELPER FUNCTIONS '''


def make_headers(endpoint, token):
    """
    provides proper headers for differing authentication methods to API
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    if API_ENDPOINTS[endpoint]['version'] == 1:
        headers['Authorization'] = 'Bearer ' + token

    elif API_ENDPOINTS[endpoint]['version'] == 2:
        headers['Authorization'] = 'JWT ' + token

    return headers


def make_url(endpoint):
    """
    build URL based on endpoint
    """
    url = "{BASE_URL}/api/v{version}/{endpoint}".format(
        BASE_URL=BASE_URL,
        version=API_ENDPOINTS[endpoint]['version'],
        endpoint=endpoint
    )
    return url


def get_page_token(url):
    o = {'pagetoken': False}
    for i in url.split("&"):
        r = i.split("=")
        o[r[0]] = r[1]
    return o['pageToken']


def do_auth():
    """
    perform authentication using API_KEY,
    stores token and stored timestamp in integration context,
    retrieves new token when expired
    """
    auth = demisto.getIntegrationContext()
    now_epoch = int(datetime.today().strftime('%s'))

    if ("token" in auth or "stored" in auth) and int(auth['stored']) + (60 * 60 * 4) > int(now_epoch):
        # if integration context contains token and stored and the token is not expired then return token
        return auth['token']
    else:
        # fetch new token
        r = http_request('GET', 'IdToken', token=API_KEY)
        if r.get('token') is None:
            return_error("Authorization failed")

        demisto.setIntegrationContext({
            'token': r['token'],
            'stored': now_epoch
        })
        return r['token']


def http_request(method, endpoint, params=None, token=False):
    """
    make api call
    """
    if not token:
        return_error("No authorization token provided")
    head = make_headers(endpoint, token)
    url = make_url(endpoint)
    r = requests.request(
        method,
        url,
        params=params,
        headers=head,
        verify=INSECURE
    )
    if r.status_code != 200:
        demisto.error(r.text)
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))

    try:
        res_json = r.json()
        return res_json
    except json.decoder.JSONDecodeError as err:
        raise ValueError(f'Failed to parse response as JSON. Original response:\n{r.text}.\nError: {str(err)}')


def parse_events(events):
    """
    build incidents from active exposures
    """
    incidents = []
    for event in events['data']:
        incident = {
            'name': "{type} on {ip}:{port}/{protocol}".format(
                type=event['payload']['exposureType'],
                ip=event['payload']['ip'],
                protocol=event['payload']['portProtocol'],
                port=event['payload']['port']
            ),
            'occurred': event['eventTime'],
            'rawJSON': json.dumps(event),
            'type': 'Expanse Appearance',
            'CustomFields': {
                'expanserawjsonevent': json.dumps(event)
            },
            'severity': EXPOSURE_SEVERITY_MAPPING[event['payload']['severity']]
        }
        incidents.append(incident)
    return incidents


def get_ip_context(data):
    """
    provide custom context information about ip address with data from Expanse API
    """
    return {
        "Address": data['search'],

        "Geo": {
            "Location": "{0}:{1}".format(
                data['locationInformation'][0]['geolocation']['latitude'],
                data['locationInformation'][0]['geolocation']['longitude']
            ),
            "Country": data['locationInformation'][0]['geolocation']['countryCode'],
            "Description": data['locationInformation'][0]['geolocation']['city']
        },
    }


def get_expanse_ip_context(data):
    """
    provide custom context information about ip address with data from Expanse API
    """
    c = {
        "Address": data['search'],
        "Version": data['ipVersion'],
        "BusinessUnits": [],
        "IPRange": {
            "StartAddress": data['startAddress'],
            "EndAddress": data['endAddress'],
            "RangeSize": data['rangeSize'],
            "ResponsiveIPCount": data['responsiveIpCount'],
            "RangeIntroduced": data['rangeIntroduced'],
            "AttributionReasons": []
        },
        "Geo": {
            "Location": "{0}:{1}".format(data['locationInformation'][0]['geolocation']['latitude'],
                                         data['locationInformation'][0]['geolocation']['longitude']),
            "Description": data['locationInformation'][0]['geolocation']['city'],
            "Latitude": data['locationInformation'][0]['geolocation']['latitude'],
            "Longitude": data['locationInformation'][0]['geolocation']['longitude'],
            "City": data['locationInformation'][0]['geolocation']['city'],
            "RegionCode": data['locationInformation'][0]['geolocation']['regionCode'],
            "CountryCode": data['locationInformation'][0]['geolocation']['countryCode']
        },
        "Annotations": {
            "Tags": data['annotations']['tags'],
            "AdditionalNotes": data['annotations']['additionalNotes'],
            "PointsOfContact": data['annotations']['pointsOfContact']
        },
        "SeverityCounts": {
            "CRITICAL": 0,
            "ROUTINE": 0,
            "WARNING": 0,
        }
    }
    for i in data['severityCounts']:
        if i['type'] == "CRITICAL":
            c['SeverityCounts']['CRITICAL'] = i['count']
        elif i['type'] == "ROUTINE":
            c['SeverityCounts']['ROUTINE'] = i['count']
        elif i['type'] == "WARNING":
            c['SeverityCounts']['WARNING'] = i['count']
    for i in data['businessUnits']:
        c['BusinessUnits'].append(i['name'])
    for i in data['attributionReasons']:
        c['IPRange']['AttributionReasons'].append(i['reason'])
    return c


def get_domain_context(data):
    """
    provide standard context information about domain with data from Expanse API
    """
    return {
        "Name": data['domain'],
        "DNS": data['details']['recentIps'],
        "CreationDate": data['whois'][0]['creationDate'],
        "DomainStatus": data['dnsResolutionStatus'],
        "ExpirationDate": data['whois'][0]['registryExpiryDate'],
        "NameServers": data['whois'][0]['nameServers'],
        "Organization": data['whois'][0]['registrant']['organization'],
        "Admin": {
            "Country": data['whois'][0]['admin']['country'],
            "Email": data['whois'][0]['admin']['emailAddress'],
            "Name": data['whois'][0]['admin']['name'],
            "Phone": data['whois'][0]['admin']['phoneNumber']
        },
        "Registrant": {
            "Country": data['whois'][0]['registrant']['country'],
            "Email": data['whois'][0]['registrant']['emailAddress'],
            "Name": data['whois'][0]['registrant']['name'],
            "Phone": data['whois'][0]['registrant']['phoneNumber']
        },
        "WHOIS": {
            "DomainStatus": data['whois'][0]['domainStatuses'],
            "NameServers": data['whois'][0]['nameServers'],
            "CreationDate": data['whois'][0]['creationDate'],
            "UpdatedDate": data['whois'][0]['updatedDate'],
            "ExpirationDate": data['whois'][0]['registryExpiryDate'],
            "Registrant": {
                "Email": data['whois'][0]['registrant']['emailAddress'],
                "Name": data['whois'][0]['registrant']['name'],
                "Phone": data['whois'][0]['registrant']['phoneNumber']
            },
            "Registrar": {
                "Name": data['whois'][0]['registrar']['name'],
                "AbuseEmail": data['whois'][0]['registrar']['abuseContactEmail'],
                "AbusePhone": data['whois'][0]['registrar']['abuseContactPhone']
            },
            "Admin": {
                "Name": data['whois'][0]['admin']['name'],
                "Email": data['whois'][0]['admin']['emailAddress'],
                "Phone": data['whois'][0]['admin']['phoneNumber']
            }
        },
    }


def get_expanse_domain_context(data):
    """
    provide custom context information about domain with data from Expanse API
    """
    c = {
        "Name": data['domain'],
        "DNS": data['details']['recentIps'],
        "CreationDate": data['whois'][0]['creationDate'],
        "DomainStatus": data['dnsResolutionStatus'],
        "ExpirationDate": data['whois'][0]['registryExpiryDate'],
        "NameServers": data['whois'][0]['nameServers'],
        "Organization": data['whois'][0]['registrant']['organization'],
        "Admin": {
            "Country": data['whois'][0]['admin']['country'],
            "Email": data['whois'][0]['admin']['emailAddress'],
            "Name": data['whois'][0]['admin']['name'],
            "Phone": data['whois'][0]['admin']['phoneNumber']
        },
        "Registrant": {
            "Country": data['whois'][0]['registrant']['country'],
            "Email": data['whois'][0]['registrant']['emailAddress'],
            "Name": data['whois'][0]['registrant']['name'],
            "Phone": data['whois'][0]['registrant']['phoneNumber']
        },
        "WHOIS": {
            "DomainStatus": data['whois'][0]['domainStatuses'],
            "NameServers": data['whois'][0]['nameServers'],
            "CreationDate": data['whois'][0]['creationDate'],
            "UpdatedDate": data['whois'][0]['updatedDate'],
            "ExpirationDate": data['whois'][0]['registryExpiryDate'],
            "Registrant": {
                "Email": data['whois'][0]['registrant']['emailAddress'],
                "Name": data['whois'][0]['registrant']['name'],
                "Phone": data['whois'][0]['registrant']['phoneNumber']
            },
            "Registrar": {
                "Name": data['whois'][0]['registrar']['name'],
                "AbuseEmail": data['whois'][0]['registrar']['abuseContactEmail'],
                "AbusePhone": data['whois'][0]['registrar']['abuseContactPhone']
            },
            "Admin": {
                "Name": data['whois'][0]['admin']['name'],
                "Email": data['whois'][0]['admin']['emailAddress'],
                "Phone": data['whois'][0]['admin']['phoneNumber']
            }
        },
        "DateAdded": data['dateAdded'],
        "FirstObserved": data['firstObserved'],
        "LastObserved": data['lastObserved'],
        "HasLinkedCloudResources": data['hasLinkedCloudResources'],
        "SourceDomain": data['sourceDomain'],
        "Tenant": data['tenant']['name'],
        "BusinessUnits": [],
        "DNSSEC": data['whois'][0]['dnssec'],
        "RecentIPs": data['details']['recentIps'],
        "CloudResources": data['details']['cloudResources'],
        "LastSubdomainMetadata": data['lastSubdomainMetadata'],
        "ServiceStatus": data['serviceStatus'],
        "LastSampledIP": data['lastSampledIp']
    }
    for i in data['businessUnits']:
        c['BusinessUnits'].append(i['name'])
    return c


def fetch_incidents_command():
    """
    retrieve active exposures from Expanse API and create incidents
    """
    now = datetime.today()
    today = datetime.strftime(now, "%Y-%m-%d")
    yesterday = datetime.strftime(now - timedelta(days=1), "%Y-%m-%d")
    last_run = demisto.getLastRun()
    start_date = yesterday
    end_date = yesterday

    if "start_time" not in last_run or "complete_for_today" not in last_run:
        # first time integration is running
        start_date = datetime.strftime(now - timedelta(days=FIRST_RUN), "%Y-%m-%d")
        demisto.setLastRun({
            'start_time': start_date,
            'complete_for_today': False
        })

    if last_run.get('complete_for_today') is True and last_run.get('start_time') == today:
        # wait until tomorrow to try again
        demisto.incidents([])
        return

    # fetch events
    params = {
        'startDateUtc': start_date,
        'endDateUtc': end_date,
        'eventType': EXPOSURE_EVENT_TYPES,
        'limit': PAGE_LIMIT
    }
    token = do_auth()

    if last_run.get('next'):
        # continue pulling events
        params['pageToken'] = last_run.get('next')

    events = http_request('GET', 'events', params=params, token=token)

    next_run = {
        "next": False,
        "complete_for_today": False,
        "start_time": yesterday
    }

    if events['meta']['dataAvailable'] is True:
        # parse events into incidents

        if events['pagination']['next']:
            # will retrieve more data with pageToken next run
            next = get_page_token(events['pagination']['next'])
            next_run['complete_for_today'] = False
            next_run['next'] = next

        else:
            # end of data, wait for tomorrow
            next_run['complete_for_today'] = True
            next_run['start_time'] = today

        incidents = parse_events(events)
        demisto.incidents(incidents)
    else:
        demisto.incidents([])

    demisto.setLastRun(next_run)


def ip_command():
    """
    searches by IP address in Expanse API for asset information
    """
    search = demisto.args()['ip']
    params = {
        "include": "annotations,severityCounts,attributionReasons,relatedRegistrationInformation,locationInformation",
        "inet": search
    }
    token = do_auth()
    results = http_request('GET', 'ip-range', params, token=token)
    try:
        ip = results['data'][0]
    except Exception:
        demisto.results("No data found")
        return

    ip['search'] = search

    dbot_context = {
        "Indicator": search,
        "Type": "ip",
        "Vendor": "Expanse",
        "Score": 0
    }
    ip_context = get_ip_context(ip)
    expanse_ip_context = get_expanse_ip_context(ip)

    ec = {
        'DBotScore': dbot_context,
        'IP(val.Address == obj.Address)': ip_context,
        'Expanse.IP(val.Address == obj.Address)': expanse_ip_context
    }
    human_readable = tableToMarkdown(F"IP information for: {search}", expanse_ip_context)

    return_outputs(human_readable, ec, ip)


def domain_command():
    """
    searches Expanse IP for asset information for a domain
    """
    search = demisto.args()['domain']
    params = {
        'domainSearch': search
    }
    token = do_auth()
    results = http_request('GET', "assets/domains", params, token=token)
    try:
        domain = results['data'][0]
    except Exception:
        # no results, exit gracefully
        demisto.results("No data found")
        return

    dbot_context = {
        "Indicator": search,
        "Type": "url",
        "Vendor": "Expanse",
        "Score": 0
    }
    domain_context = get_domain_context(domain)
    expanse_domain_context = get_expanse_domain_context(domain)

    ec = {
        'DBotScore': dbot_context,
        'Domain(val.Name == obj.Name)': domain_context,
        'Expanse.Domain(val.Name == obj.Name)': expanse_domain_context
    }

    human_readable = tableToMarkdown(F"Domain information for: {search}", expanse_domain_context)

    return_outputs(human_readable, ec, domain)


def test_module():
    token = do_auth()
    now = datetime.today()
    yesterday = datetime.strftime(now - timedelta(days=1), "%Y-%m-%d")

    params = {
        'startDateUtc': yesterday,
        'endDateUtc': yesterday,
        'eventType': EXPOSURE_EVENT_TYPES,
        'limit': 1
    }
    events = http_request('GET', 'events', params=params, token=token)

    parse_events(events)
    return True


def main():
    try:
        handle_proxy()

        active_command = demisto.command()

        if active_command == 'test-module':
            test_module()
            demisto.results('ok')

        elif active_command == 'fetch-incidents':
            fetch_incidents_command()

        elif active_command == 'ip':
            ip_command()

        elif active_command == 'domain':
            domain_command()

    # Log exceptions
    except Exception as e:
        demisto.error(str(e) + "\n\nTrace:\n" + traceback.format_exc())
        return_error(str(e))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
