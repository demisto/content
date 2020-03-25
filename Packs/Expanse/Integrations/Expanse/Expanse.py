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
VERIFY_CERTIFICATES = not demisto.params().get('insecure')
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
        'Accept': 'application/json',
        'User-Agent': 'Expanse_Demisto/1.0.0'
    }
    if endpoint == "IdToken":
        headers['Authorization'] = 'Bearer ' + token
    else:
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

    if ("token" in auth or "stored" in auth) and int(auth['stored']) + (60 * 60 * 2) > int(now_epoch):
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
        verify=VERIFY_CERTIFICATES
    )
    if r.status_code != 200:
        demisto.error(r.text)
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))

    try:
        res_json = r.json()
        return res_json
    except json.decoder.JSONDecodeError as err:
        raise ValueError('Failed to parse response as JSON. Original response:\n{rtext}.\nError: {error}'
                         .format(rtext=r.text, error=str(err)))


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


def is_not_empty_value(value):
    """
    Checks for empty response values. Demisto recommends returning the None type if a value is empty,
    rather than an empty string/list.
    """
    return value != "" and value != [] and value != [""]


def get_ip_context(data):
    """
    provide custom context information about ip address with data from Expanse API
    """
    geo = {}
    if len(data.get('locationInformation', [])) > 0:
        if (data['locationInformation'][0].get('geolocation', {}).get('latitude') is not None
           and data['locationInformation'][0].get('geolocation', {}).get('longitude') is not None):
            geo["Location"] = "{0}:{1}".format(
                data['locationInformation'][0].get('geolocation', {}).get('latitude'),
                data['locationInformation'][0].get('geolocation', {}).get('longitude')
            )
        geo["Country"] = data['locationInformation'][0].get('geolocation', {}).get('countryCode')
        geo["Description"] = data['locationInformation'][0].get('geolocation', {}).get('city')
    return {
        "Address": data['search'],
        "Geo": geo,
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
        "Annotations": {
            "AdditionalNotes": data['annotations'].get('additionalNotes'),
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

    geo = {}
    if len(data.get("locationInformation", [])) > 0:
        geo = {
            "Description": data['locationInformation'][0]['geolocation'].get('city'),
            "Latitude": data['locationInformation'][0]['geolocation'].get('latitude'),
            "Longitude": data['locationInformation'][0]['geolocation'].get('longitude'),
            "City": data['locationInformation'][0]['geolocation'].get('city'),
            "RegionCode": data['locationInformation'][0]['geolocation'].get('regionCode'),
            "CountryCode": data['locationInformation'][0]['geolocation'].get('countryCode')
        }
        if (data['locationInformation'][0].get('geolocation', {}).get('latitude') is not None
           and data['locationInformation'][0].get('geolocation', {}).get('longitude') is not None):
            geo["Location"] = "{0}:{1}".format(
                data['locationInformation'][0].get('geolocation', {}).get('latitude'),
                data['locationInformation'][0].get('geolocation', {}).get('longitude')
            )
    c["Geo"] = geo

    points_of_contact = ",".join([poc["email"] for poc in data['annotations'].get('pointsOfContact', [])])
    c["Annotations"]["PointsOfContact"] = points_of_contact if is_not_empty_value(points_of_contact) else None

    tags = ",".join([tag["name"] for tag in data['annotations'].get('tags', [])])
    c["Annotations"]["Tags"] = tags if is_not_empty_value(tags) else None

    return c


def get_domain_context(data):
    """
    provide standard context information about domain with data from Expanse API
    """
    return {
        "Name": data['domain'],
        "DNS": data['details'].get('recentIps') if is_not_empty_value(data['details'].get('recentIps')) else None,
        "CreationDate": data['whois'][0]['creationDate'],
        "DomainStatus": data['dnsResolutionStatus'],
        "ExpirationDate": data['whois'][0]['registryExpiryDate'],
        "NameServers": data['whois'][0]['nameServers'],
        "Organization": data['whois'][0]['registrant']['organization'],
        "Admin": {
            "Country": data['whois'][0]['admin'].get('country'),
            "Email": data['whois'][0]['admin'].get('emailAddress'),
            "Name": data['whois'][0]['admin'].get('name'),
            "Phone": data['whois'][0]['admin'].get('phoneNumber')
        },
        "Registrant": {
            "Country": data['whois'][0]['registrant'].get('country'),
            "Email": data['whois'][0]['registrant'].get('emailAddress'),
            "Name": data['whois'][0]['registrant'].get('name'),
            "Phone": data['whois'][0]['registrant'].get('phoneNumber')
        },
        "WHOIS": {
            "DomainStatus": data['whois'][0]['domainStatuses'],
            "NameServers": data['whois'][0]['nameServers'],
            "CreationDate": (data['whois'][0].get('creationDate')
                             if is_not_empty_value(data['whois'][0].get('creationDate'))
                             else None),
            "UpdatedDate": (data['whois'][0].get('updatedDate')
                            if is_not_empty_value(data['whois'][0].get('updatedDate'))
                            else None),
            "ExpirationDate": (data['whois'][0].get('registryExpiryDate')
                               if is_not_empty_value(data['whois'][0].get('registryExpiryDate'))
                               else None),
            "Registrant": {
                "Email": data['whois'][0]['registrant'].get('emailAddress'),
                "Name": data['whois'][0]['registrant'].get('name'),
                "Phone": data['whois'][0]['registrant'].get('phoneNumber')
            },
            "Registrar": {
                "Name": data['whois'][0]['registrar'].get('name'),
                "AbuseEmail": data['whois'][0]['registrar'].get('abuseContactEmail'),
                "AbusePhone": data['whois'][0]['registrar'].get('abuseContactPhone')
            },
            "Admin": {
                "Name": data['whois'][0]['admin'].get('name'),
                "Email": data['whois'][0]['admin'].get('emailAddress'),
                "Phone": data['whois'][0]['admin'].get('phoneNumber')
            }
        },
    }


def get_expanse_domain_context(data):
    """
    provide custom context information about domain with data from Expanse API
    """
    c = {
        "Name": data['domain'],
        "DNS": data['details'].get('recentIps') if is_not_empty_value(data['details'].get('recentIps')) else None,
        "CreationDate": data['whois'][0].get('creationDate'),
        "DomainStatus": data.get('dnsResolutionStatus'),
        "ExpirationDate": (data['whois'][0].get('registryExpiryDate')
                           if is_not_empty_value(data['whois'][0].get('registryExpiryDate'))
                           else None),
        "NameServers": data['whois'][0].get('nameServers'),
        "Organization": data['whois'][0]['registrant'].get('organization'),
        "Admin": {
            "Country": (data['whois'][0]['admin'].get('country')
                        if is_not_empty_value(data['whois'][0]['admin'].get('country'))
                        else None),
            "Email": (data['whois'][0]['admin'].get('emailAddress')
                      if is_not_empty_value(data['whois'][0]['admin'].get('emailAddress'))
                      else None),
            "Name": (data['whois'][0]['admin'].get('name')
                     if is_not_empty_value(data['whois'][0]['admin'].get('name'))
                     else None),
            "Phone": (data['whois'][0]['admin'].get('phoneNumber')
                      if is_not_empty_value(data['whois'][0]['admin'].get('phoneNumber'))
                      else None)
        },
        "Registrant": {
            "Country": (data['whois'][0]['registrant'].get('country')
                        if is_not_empty_value(data['whois'][0]['registrant'].get('country'))
                        else None),
            "Email": (data['whois'][0]['registrant'].get('emailAddress')
                      if is_not_empty_value(data['whois'][0]['registrant'].get('emailAddress'))
                      else None),
            "Name": (data['whois'][0]['registrant'].get('name')
                     if is_not_empty_value(data['whois'][0]['registrant'].get('name'))
                     else None),
            "Phone": (data['whois'][0]['registrant'].get('phoneNumber')
                      if is_not_empty_value(data['whois'][0]['registrant'].get('phoneNumber'))
                      else None)
        },
        "WHOIS": {
            "DomainStatus": (data['whois'][0].get('domainStatuses')
                             if is_not_empty_value(data['whois'][0].get('domainStatuses'))
                             else None),
            "NameServers": (data['whois'][0].get('nameServers')
                            if is_not_empty_value(data['whois'][0].get('nameServers'))
                            else None),
            "CreationDate": (data['whois'][0].get('creationDate')
                             if is_not_empty_value(data['whois'][0].get('creationDate'))
                             else None),
            "UpdatedDate": (data['whois'][0].get('updatedDate')
                            if is_not_empty_value(data['whois'][0].get('updatedDate'))
                            else None),
            "ExpirationDate": (data['whois'][0].get('registryExpiryDate')
                               if is_not_empty_value(data['whois'][0].get('registryExpiryDate'))
                               else None),
            "Registrant": {
                "Email": (data['whois'][0]['registrant'].get('emailAddress')
                          if is_not_empty_value(data['whois'][0]['registrant'].get('emailAddress'))
                          else None),
                "Name": (data['whois'][0]['registrant'].get('name')
                         if is_not_empty_value(data['whois'][0]['registrant'].get('name'))
                         else None),
                "Phone": (data['whois'][0]['registrant'].get('phoneNumber')
                          if is_not_empty_value(data['whois'][0]['registrant'].get('phoneNumber'))
                          else None)
            },
            "Registrar": {
                "Name": (data['whois'][0]['registrar'].get('name')
                         if is_not_empty_value(data['whois'][0]['registrar'].get('name'))
                         else None),
                "AbuseEmail": (data['whois'][0]['registrar'].get('abuseContactEmail')
                               if is_not_empty_value(data['whois'][0]['registrar'].get('abuseContactEmail'))
                               else None),
                "AbusePhone": (data['whois'][0]['registrar'].get('abuseContactPhone')
                               if is_not_empty_value(data['whois'][0]['registrar'].get('abuseContactPhone'))
                               else None)
            },
            "Admin": {
                "Name": (data['whois'][0]['admin'].get('name')
                         if is_not_empty_value(data['whois'][0]['admin'].get('name'))
                         else None),
                "Email": (data['whois'][0]['admin'].get('emailAddress')
                          if is_not_empty_value(data['whois'][0]['admin'].get('emailAddress'))
                          else None),
                "Phone": (data['whois'][0]['admin'].get('phoneNumber')
                          if is_not_empty_value(data['whois'][0]['admin'].get('phoneNumber'))
                          else None)
            }
        },
        "DateAdded": data['dateAdded'],
        "FirstObserved": data['firstObserved'],
        "LastObserved": data['lastObserved'],
        "HasLinkedCloudResources": data['hasLinkedCloudResources'],
        "SourceDomain": data.get('sourceDomain') if is_not_empty_value(data.get('sourceDomain')) else None,
        "Tenant": data['tenant'].get('name') if is_not_empty_value(data['tenant'].get('name')) else None,
        "BusinessUnits": [],
        "DNSSEC": data['whois'][0].get('dnssec') if is_not_empty_value(data['whois'][0].get('dnssec')) else None,
        "RecentIPs": data['details'].get('recentIps') if is_not_empty_value(data['details'].get('recentIps')) else None,
        "CloudResources": (data['details'].get('cloudResources')
                           if is_not_empty_value(data['details'].get('cloudResources'))
                           else None),
        "LastSubdomainMetadata": (data.get('lastSubdomainMetadata')
                                  if is_not_empty_value(data.get('lastSubdomainMetadata'))
                                  else None),
        "ServiceStatus": data.get('serviceStatus') if is_not_empty_value(data.get('serviceStatus')) else None,
        "LastSampledIP": data.get('lastSampledIp') if is_not_empty_value(data.get('lastSampledIp')) else None
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
    human_readable = tableToMarkdown("IP information for: {search}".format(search=search), expanse_ip_context)

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

    human_readable = tableToMarkdown("Domain information for: {search}".format(search=search), expanse_domain_context)

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
