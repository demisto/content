import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import datetime
import requests


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
ARGS = demisto.args()
API_KEY = PARAMS.get('api_key')
PAGE_LIMIT = PARAMS.get('page_limit')
SERVER = 'https://expander.expanse.co'
INSECURE = PARAMS.get('insecure')
PROXY = demisto.params().get('proxy')
BASE_URL = SERVER
EXPOSURE_EVENT_TYPES = "ON_PREM_EXPOSURE_APPEARANCE,ON_PREM_EXPOSURE_REAPPEARANCE"
LOG("Context")
LOG(demisto.getIntegrationContext())
#demisto.setIntegrationContext()

API_ENDPOINTS = {
    "exposures/ip-ports" :{
        "version" : 2
    },
    "ip-range" : {
        "version" : 2
    },
    "assets/domains" :{
        "version" : 2
    },
    "IdToken": {
        "version": 1
    },
    "events" :{
        "version": 1
    }
}

EXPOSURE_SEVERITY_MAPPING = {
    "NONE"         : 0 ,
    "UNKNOWN"      : 0 ,
    "CRITICAL"     : 3 ,
    "ROUTINE"      : 1,
    "WARNING"      : 2,
    "UNCATEGORIZED": 1
}

''' HELPER FUNCTIONS '''

def make_headers(endpoint, token):
    ''' provides proper headers for differing authentication methods to API '''
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
    ''' build URL based on endpoint'''
    url = "{BASE_URL}/api/v{version}/{endpoint}".format(
        BASE_URL=BASE_URL,
        version=API_ENDPOINTS[endpoint]['version'],
        endpoint=endpoint
    )
    return url
def get_page_token(url):
    o = { 'pagetoken': False }
    for i in url.split("&"):
        r = i.split("=")
        o[r[0]] = r[1]
    return o['pageToken']

# Event types to retrieve from events API
EXPOSURE_EVENT_TYPES = 'ON_PREM_EXPOSURE_APPEARANCE,ON_PREM_EXPOSURE_REAPPEARANCE'


def do_auth():
    ''' perform authentication using API_KEY, retrieves token for subsequent API calls '''
    r = http_request('POST','IdToken',token=API_KEY)
    if not r['token']:
        return 'Authorization failed'
    return r['token']

def parse_response(resp):
    ''' parse response from api '''
    try:
        res_json = resp.json()
        resp.raise_for_status()
        return res_json
    except requests.exceptions.HTTPError:
        demisto.log(err_msg)
        sys.exit(1)
    except AttributeError:
        return resp

    except Exception as err:
        demisto.info(resp)
        err_msg = err
        return return_error(err_msg)

def http_request(method, endpoint, params=None, token=False):
    ''' make api call '''
    if not token:
        return_error("No authorization token provided")
    head = make_headers(endpoint, token)
    url = make_url(endpoint)
    info = {
        "url": url,
        "params": params,
        "headers": head,
    }
    #demisto.info(info)
    r = requests.request(
        method,
        url ,
        params=params,
        headers=head,
        verify=INSECURE
    )
    if r.status_code is not 200:
        demisto.info(r.text)
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))

    return parse_response(r)

def parse_events(events):
    ''' build incidents from active exposures '''

    incidents = []
    for event in events['data']:
        incident = {
            'name' :  "{type} on {ip}:{port}/{protocol}".format(
                type=event['payload']['exposureType'],
                ip=event['payload']['ip'],
                protocol=event['payload']['portProtocol'],
                port=event['payload']['port']
            ),
            'occurred' : event['eventTime'],
            'rawJSON' : json.dumps(event),
            'severity' : EXPOSURE_SEVERITY_MAPPING[event['payload']['severity']]
        }
        incidents.append(incident)
    return incidents

def get_ip_context(data):
    ''' provide custom context information about ip address with data from Expanse API '''
    return {
            "Address": data['search'],
            #"ASN" : None,
            #"Hostname": None,
            "Geo" : {
                "Location" : "{0}:{1}".format( data['locationInformation'][0]['geolocation']['latitude'],data['locationInformation'][0]['geolocation']['longitude'] ),
                "Country" : data['locationInformation'][0]['geolocation']['countryCode'],
                "Description" : data['locationInformation'][0]['geolocation']['city']
            },
            #"DetectionEngines": 0,
            #"PositiveDetections": 0

        }

def get_expanse_ip_context(data):
    ''' provide custom context information about ip address with data from Expanse API '''
    c =  {
            "Address" : data['search'],
            "Version" : data['ipVersion'],
            "BusinessUnits": [],
            "IPRange" : {
                "StartAddress": data['startAddress'],
                "EndAddress": data['endAddress'],
                "RangeSize" : data['rangeSize'],
                "ResponsiveIPCount": data['responsiveIpCount'],
                "RangeIntroduced": data['rangeIntroduced'],
                "AttributionReasons": []
            },
            "Geo" : {
                "Location": "{0}:{1}".format(data['locationInformation'][0]['geolocation']['latitude'],
                                             data['locationInformation'][0]['geolocation']['longitude']),
                "Description": data['locationInformation'][0]['geolocation']['city'],
                "Latitude" : data['locationInformation'][0]['geolocation']['latitude'],
                "Longitude": data['locationInformation'][0]['geolocation']['longitude'],
                "City" : data['locationInformation'][0]['geolocation']['city'],
                "RegionCode": data['locationInformation'][0]['geolocation']['regionCode'],
                "CountryCode": data['locationInformation'][0]['geolocation']['countryCode']
            },
            "Annotations" : {
                "Tags": data['annotations']['tags'],
                "AdditionalNotes" : data['annotations']['additionalNotes'],
                "PointsOfContact": data['annotations']['pointsOfContact']
            },
            "SeverityCounts" : {
                "CRITICAL": 0,
                "ROUTINE" : 0,
                "WARNING" : 0,
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
    ''' provide standard context information about domain with data from Expanse API '''
    return {
        "Name": data['domain'],
        "DNS" : data['details']['recentIps'],
        "CreationDate" : data['whois'][0]['creationDate'],
        "DomainStatus" : data['dnsResolutionStatus'],
        "ExpirationDate": data['whois'][0]['registryExpiryDate'],
        "NameServers": data['whois'][0]['nameServers'],
        "Organization" : data['whois'][0]['registrant']['organization'],
        "Admin" :{
            "Country": data['whois'][0]['admin']['country'],
            "Email": data['whois'][0]['admin']['emailAddress'],
            "Name": data['whois'][0]['admin']['name'],
            "Phone": data['whois'][0]['admin']['phoneNumber']
        },
        "Registrant" :{
            "Country": data['whois'][0]['registrant']['country'],
            "Email": data['whois'][0]['registrant']['emailAddress'],
            "Name": data['whois'][0]['registrant']['name'],
            "Phone": data['whois'][0]['registrant']['phoneNumber']
        },
        "WHOIS" : {
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
        #"WHOIS/History": None,
        # "DetectionEngines": None,
        # "PositiveDetections": 0,
        # "Subdomains": None,
        # "UpdatedDate" : None,
    }

def get_expanse_domain_context(data):
    ''' provide custom context information about domain with data from Expanse API '''
    c =  {
        "Name" : data['domain'],
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
        "FirstObserved" : data['firstObserved'],
        "LastObserved" : data['lastObserved'],
        "HasLinkedCloudResources" : data['hasLinkedCloudResources'],
        "SourceDomain": data['sourceDomain'],
        "Tenant" : data['tenant']['name'],
        "BusinessUnits": [],
        "DNSSEC" : data['whois'][0]['dnssec'],
        "RecentIPs": data['details']['recentIps'],
        "CloudResources" : data['details']['cloudResources'],
        "LastSubdomainMetadata" : data['lastSubdomainMetadata'],
        "ServiceStatus" : data['serviceStatus'],
        "LastSampledIP" : data['lastSampledIp']
    }
    for i in data['businessUnits']:
        c['BusinessUnits'].append(i['name'])
    return c

'''MAIN FUNCTIONS'''

def fetch_incidents_command():
    ''' retrieve active exposures from Expanse API and create incidents '''
    now = datetime.datetime.today()
    today = datetime.datetime.strftime(now,"%Y-%m-%d")
    yesterday = datetime.datetime.strftime(now - datetime.timedelta(days=1),"%Y-%m-%d")
    last_run = demisto.getLastRun()
    LOG(last_run)
    try:
        "start_time" in last_run and "complete_for_today" in last_run
        # integration has ran before

    except:
        # first time integration is running
        demisto.setLastRun({
            'start_time': yesterday,
            'complete_for_today': False
        })

    if last_run.get('complete_for_today') == True and last_run.get('start_time') == today:
        # wait until tomorrow to try again
        # gracefully exit
        LOG('Waiting for tomorrow')
        demisto.incidents([])
        return

    start_date = yesterday
    end_date = yesterday

    # fetch events
    params = {
        'startDateUtc': start_date,
        'endDateUtc' : end_date,
        'eventType' : EXPOSURE_EVENT_TYPES,
        'limit' : PAGE_LIMIT
    }
    token = do_auth()

    if last_run.get('next'):
        # continue pulling events
        params['pageToken'] = last_run.get('next')

    events = http_request('GET','events', params=params, token=token )

    next_run = {
        "next": False,
        "complete_for_today": False,
        "start_time": yesterday
    }


    if events['meta']['dataAvailable'] == True:
        # should handle pagination here
        incidents = parse_events(events)
        demisto.incidents(incidents)

        if events['pagination']['next']:
            next = get_page_token(events['pagination']['next'])
            LOG("More data available")
            next_run['complete_for_today'] = False
            next_run['next'] = next

        else:
            next_run['complete_for_today'] = True
            next_run['start_time'] = yesterday
            next_run['next'] = False

    demisto.setLastRun(next_run)

    return True

def exposures_command():
    '''  not implemented, function will search for active exposures from search paramater   '''
    ip = ARGS['ip']
    token3 = do_auth()
    results = http_request('GET','exposures/ip-ports',{ 'inet': ip }, token=token3 )
    exposures = parse_exposures(results)
    demisto.results(exposures)

def ip_command():
    ''' searches by IP address in Expanse API for asset information'''
    search = ARGS['ip']
    params = {
        "include" : "annotations,severityCounts,attributionReasons,relatedRegistrationInformation,locationInformation",
        "inet" : search
    }
    token = do_auth()
    results = http_request('GET','ip-range', params, token=token )
    try:
        ip = results['data'][0]
    except:
        # no results, exit gracefully
        demisto.results("No data found")
        return

    ip['search'] = search

    dbot_context = {
        "Indicator" : search,
         "Type" : "ip",
        "Vendor" : "Expanse",
        "Score" : 0
    }
    ip_context = get_ip_context(ip)
    expanse_ip_context = get_expanse_ip_context(ip)

    ec = {
        'DBotScore' : dbot_context,
        'IP(val.Address == obj.Address)' : ip_context,
        'Expanse.IP(val.Address == obj.Address)' : expanse_ip_context
    }
    human_readable = tableToMarkdown(F"IP information for: {search}", expanse_ip_context)

    return_outputs(human_readable, ec, ip)

def domain_command():
    ''' searches Expanse IP for asset information for a domain '''
    search = ARGS['domain']
    params = {
        'domainSearch': search
    }
    token = do_auth()
    results = http_request('GET', "assets/domains",params, token=token )
    try:
        domain = results['data'][0]
    except:
        # no results, exit gracefully
        demisto.results("No data found")
        return

    dbot_context = {
        "Indicator" : search,
        "Type": "url",
        "Vendor": "Expanse",
        "Score": 0
    }
    domain_context = get_domain_context(domain)
    expanse_domain_context = get_expanse_domain_context(domain)

    ec = {
        'DBotScore' : dbot_context,
        'Domain(val.Name == obj.Name)' : domain_context,
        'Expanse.Domain(val.Name == obj.Name)' : expanse_domain_context
    }

    human_readable = tableToMarkdown(F"Domain information for: {search}", expanse_domain_context)

    return_outputs(human_readable, ec, domain )

def test_module():
    do_auth()
    return True

''' COMMANDS MANAGER / SWITCH PANEL '''

try:
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

    elif active_command == 'exposures':
        exposures_command()

    LOG.print_log(verbose=False)

# Log exceptions
except Exception as e:
    LOG('FATAL ERROR')
    LOG(e)
    LOG.print_log()
    return_error(str(e))
