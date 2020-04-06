import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import dateparser
import json
import re
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
BEHAVIOR_ENABLED = demisto.params().get('behavior', False)
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
    },
    "behavior/risky-flows": {
        "version": 1
    },
    "assets/certificates": {
        "version": 2
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
        'User-Agent': 'Expanse_Demisto/1.1.0'
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


def get_next_offset(url):
    offset = 0
    matches = re.findall(r'offset\]\=(\d+)', url)
    if matches != []:
        offset = matches[0]
    return offset


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
    demisto.debug("Making request to {} with params: {}".format(url, params))
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


def parse_behavior(risky_flows):
    """
    build incidents from risky flows
    """
    incidents = []
    for flow in risky_flows['data']:
        incident = {
            'name': "{rule} {int_}{int_port} : {ext}{ext_port}".format(
                rule=flow['riskRule']['name'],
                int_=flow['internalAddress'],
                int_port=flow['internalPort'],
                ext=flow['externalAddress'],
                ext_port=flow['externalPort']
            ),
            'occurred': flow['observationTimestamp'],
            'rawJSON': json.dumps(flow),
            'type': 'Expanse Behavior',
            'CustomFields': {
                'expanserawjsonevent': json.dumps(flow)
            },
            'severity': 2  # All behavior is cast to a warning, we can revisit if critically is added to flow data
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


def get_expanse_certificate_context(data):
    """
    provide custom context information about certificate with data from Expanse API
    """
    return {
        "SearchTerm": data['search'],
        "CommonName": data['commonName'],
        "FirstObserved": data['firstObserved'],
        "LastObserved": data['lastObserved'],
        "DateAdded": data['dateAdded'],
        "Provider": data['providers'][0]['name'],
        "NotValidBefore": data['certificate']['validNotBefore'],
        "NotValidAfter": data['certificate']['validNotAfter'],
        "Issuer": {
            "Name": data['certificate']['issuerName'],
            "Email": data['certificate']['issuerEmail'],
            "Country": data['certificate']['issuerCountry'],
            "Org": data['certificate']['issuerOrg'],
            "Unit": data['certificate']['issuerOrgUnit'],
            "AltNames": data['certificate']['issuerAlternativeNames'],
            "Raw": data['certificate']['issuer']
        },
        "Subject": {
            "Name": data['certificate']['subjectName'],
            "Email": data['certificate']['subjectEmail'],
            "Country": data['certificate']['subjectCountry'],
            "Org": data['certificate']['subjectOrg'],
            "Unit": data['certificate']['subjectOrgUnit'],
            "AltNames": data['certificate']['subjectAlternativeNames'],
            "Raw": data['certificate']['subject']
        },
        "Properties": data['properties'][0],
        "MD5Hash": data['certificate']['md5Hash'],
        "PublicKeyAlgorithm": data['certificate']['publicKeyAlgorithm'],
        "PublicKeyBits": data['certificate']['publicKeyBits'],
        "BusinessUnits": data['businessUnits'][0]['name'],
        "CertificateAdvertisementStatus": data['certificateAdvertisementStatus'][0],
        "ServiceStatus": ','.join(data['serviceStatus']),
        "RecentIPs": ','.join(data['details']['recentIps']),
        "CloudResources": ','.join(data['details']['cloudResources']),
        "PemSha1": data['certificate']['pemSha1'],
        "PemSha256": data['certificate']['pemSha256']
    }


def get_expanse_behavior_context(data):
    """
    provides custom context information from the Expanse Behavior API
    """

    def flow_to_str(flow):
        """
        Reduces a risky flow to a summary string
        """
        return "{in_ip}:{in_port} ({in_co}) {direction} {ex_ip}:{ex_port} ({ex_co}) {pro} violates {rule} at {t}".format(
            in_ip=flow['internalAddress'],
            in_port=flow['internalPort'],
            in_co=flow['internalCountryCode'],
            direction="<-" if flow['flowDirection'] == "INBOUND" else "->",
            ex_ip=flow['externalAddress'],
            ex_port=flow['externalPort'],
            ex_co=flow['externalCountryCode'],
            pro=flow['protocol'],
            rule=flow['riskRule']['name'],
            t=flow['observationTimestamp']
        )

    def flow_to_obj(flow):
        return {
            "InternalAddress": flow['internalAddress'],
            "InternalPort": flow['internalPort'],
            "InternalCountryCode": flow['internalCountryCode'],
            "ExternalAddress": flow['externalAddress'],
            "ExternalPort": flow['externalPort'],
            "ExternalCountryCode": flow['externalCountryCode'],
            "Protocol": flow['protocol'],
            "Timestamp": flow['observationTimestamp'],
            "Direction": flow['flowDirection'],
            "RiskRule": flow['riskRule']['name']
        }

    return {
        "SearchTerm": data[0]['internalAddress'],
        "InternalAddress": data[0]['internalAddress'],
        "InternalCountryCode": data[0]['internalCountryCode'],
        "BusinessUnit": data[0]['businessUnit']['name'],
        "FlowSummaries": '\n'.join([flow_to_str(flow) for flow in data]),
        "Flows": [flow_to_obj(flow) for flow in data],
        "ExternalAddresses": ','.join(set([flow['externalAddress'] for flow in data])),
        "InternalDomains": ','.join(data[0]['internalDomains']),
        "InternalIPRanges": ','.join(data[0]['internalTags']['ipRange']),
        "InternalExposureTypes": ','.join(data[0]['internalExposureTypes'])
    }


def fetch_events_incidents_command(start_date, end_date, token, next_=None):
    """
    retrieve active exposures from Expanse API and create incidents
    """
    params = {
        'startDateUtc': start_date,
        'endDateUtc': end_date,
        'eventType': EXPOSURE_EVENT_TYPES,
        'limit': PAGE_LIMIT
    }

    if next_:
        params['pageToken'] = next_

    events = http_request('GET', 'events', params=params, token=token)

    if events['meta']['dataAvailable'] is True:

        if events['pagination']['next']:
            # will retrieve more data with pageToken next run
            next_page_token = get_page_token(events['pagination']['next'])
        else:
            next_page_token = None

        incidents = parse_events(events)
        return (incidents, next_page_token)
    return ([], None)


def fetch_behavior_incidents_command(start_date, token, offset=0):
    """
    retrieve risky flow details from Expanse Behavior API and create incidents
    """
    params = {
        'filter[created-after]': start_date + 'T00:00:00.000Z',
        'page[limit]': PAGE_LIMIT,
        'page[offset]': offset if offset is not None else 0
    }

    flows = http_request('GET', 'behavior/risky-flows', params=params, token=token)

    if flows['meta']['totalCount'] is not None and flows['meta']['totalCount'] > 0:
        if flows['pagination']['next']:
            next_offset = get_next_offset(flows['pagination']['next'])
        else:
            next_offset = None

        incidents = parse_behavior(flows)
        return (incidents, next_offset)
    return ([], None)


def fetch_incidents_command():
    """
    Parent command to wrap events and behavior fetch commands
    """

    # Check if it's been run
    now = datetime.today()
    today = datetime.strftime(now, "%Y-%m-%d")
    yesterday = datetime.strftime(now - timedelta(days=1), "%Y-%m-%d")
    last_run = demisto.getLastRun()
    start_date = yesterday
    end_date = yesterday

    if "start_time" not in last_run or "complete_for_today" not in last_run:
        # first time integration is running
        start_date = datetime.strftime(now - timedelta(days=FIRST_RUN), "%Y-%m-%d")

    if last_run.get('complete_for_today') is True and last_run.get('start_time') == today:
        # wait until tomorrow to try again
        return

    # Refresh JWT
    token = do_auth()

    # Fetch Events
    more_events = True
    page_token = None

    while more_events:
        event_incidents, page_token = fetch_events_incidents_command(start_date, end_date, token, page_token)
        for incident in event_incidents:
            demisto.debug("Adding event incident name={name}, type={type}, severity={severity}".format(**incident))
        demisto.incidents(event_incidents)
        if page_token is None:
            more_events = False

    # Fetch Behavior
    if BEHAVIOR_ENABLED:
        more_behavior = True
        next_offset = None

        while more_behavior:
            behavior_incidents, next_offset = fetch_behavior_incidents_command(start_date, token, next_offset)
            for incident in behavior_incidents:
                demisto.debug("Adding behavior incident name={name}, type={type}, severity={severity}".format(**incident))
            demisto.incidents(behavior_incidents)
            if next_offset is None:
                more_behavior = False

    # Save last_run
    demisto.setLastRun({
        "complete_for_today": True,
        "start_time": yesterday
    })


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


def certificate_command():
    """
    searches by domain name for certificate information
    """
    search = demisto.args()['common_name']
    params = {
        "commonNameSearch": search
    }
    token = do_auth()
    results = http_request('GET', 'assets/certificates', params, token=token)
    try:
        certs = results['data']
        if len(results['data']) == 0:
            demisto.results("No data found")
            return
    except Exception:
        demisto.results("No data found")
        return

    cert = certs[0]  # just return the first one
    cert['search'] = search

    expanse_cert_context = get_expanse_certificate_context(cert)

    ec = {
        'Expanse.Certificate(val.SearchTerm == obj.SearchTerm)': expanse_cert_context
    }
    human_readable = tableToMarkdown("Certificate information for: {search}".format(search=search), expanse_cert_context)

    return_outputs(human_readable, ec, cert)


def behavior_command():
    """
    searches by ip for behavior details from Expanse
    """
    search = demisto.args()['ip']
    start_time = arg_to_timestamp(
        demisto.args().get('start_time'),
        arg_name='start_time',
        required=False
    )

    now = datetime.today()
    time_range = datetime.strftime(now - timedelta(days=FIRST_RUN), "%Y-%m-%d")
    if start_time is None:
        start_time = time_range + 'T00:00:00.000Z'
    params = {
        "filter[internal-ip-range]": search,
        'page[limit]': 20,
        'filter[created-after]': start_time,
    }
    token = do_auth()
    results = http_request('GET', 'behavior/risky-flows', params, token=token)
    try:
        behaviors = results['data']
        if len(behaviors) == 0:
            demisto.results("No data found")
            return
    except Exception:
        demisto.results("No data found")
        return

    expanse_behavior_context = get_expanse_behavior_context(behaviors)

    ec = {
        'Expanse.Behavior(val.SearchTerm == obj.SearchTerm)': expanse_behavior_context
    }

    del expanse_behavior_context['Flows']  # Remove flow objects from human readable response
    human_readable = tableToMarkdown("Expanse Behavior information for: {search}".format(search=search), expanse_behavior_context)

    return_outputs(human_readable, ec, behaviors)


def arg_to_timestamp(arg, arg_name: str, required: bool = False):
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp that str - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # if the arg is string of date format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        return arg


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

        elif active_command == 'expanse-get-certificate':
            certificate_command()

        elif active_command == 'expanse-get-behavior':
            behavior_command()

    # Log exceptions
    except Exception as e:
        demisto.error(str(e) + "\n\nTrace:\n" + traceback.format_exc())
        return_error(str(e))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
