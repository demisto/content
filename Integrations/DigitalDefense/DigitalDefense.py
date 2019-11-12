import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import json
import socket
import struct
import signal
import math
from datetime import datetime, tzinfo, timedelta

''' GLOBAL VARS '''
# Params:
API_TOKEN = demisto.params().get('apiToken')
INCIDENT_VULN_MIN_SEVERITY = demisto.params().get('incidentSeverity')
INCIDENT_FREQUENCY = demisto.params().get('incidentFrequency')

# Endpoints:
BASE_URL = "https://vm.frontline.cloud"
VULN_ENDPOINT = BASE_URL + "/api/scanresults/active/vulnerabilities/"
HOST_ENDPOINT = BASE_URL + "/api/scanresults/active/hosts/"
SCAN_ENDPOINT = BASE_URL + "/api/scans/"

# FrontlineVM request header for API calls:
FVM_HEADER = {'Authorization': 'Token ' + str(API_TOKEN)}

# Minimum time to timeout functions (5 mins)
MIN_TIMEOUT = 300

# HEADERS:
VULN_DATA_HEADERS = ['vuln-id',
                     'hostname',
                     'ip-address',
                     'vuln-title',
                     'date-created',
                     'ddi-severity',
                     'vuln-info']

HOST_HEADERS = ['ID',
                'Hostname',
                'IP',
                'DNSHostname',
                'MAC',
                'OS',
                'OSType',
                'CriticalVulnCount']


'''HELPER FUNCTIONS'''


class EndOfTime(Exception):
    '''
    Exception to catch timeout for functions
    '''
    pass


def function_timeout(signum, frame):
    '''
    Used to raise EndOfTime exception for timeout functions.
    '''
    raise EndOfTime('Function has timed out')


def get_function_timeout_time(data_count):
    '''
    Returns time (in seconds) to timeout function
    based upon the amount of data to pull.
    '''
    timeout_time = math.ceil(data_count / 2)
    if timeout_time < MIN_TIMEOUT:
        timeout_time = MIN_TIMEOUT
    return timeout_time


def get_all_data(first_page):
    '''
    Retrieves all data if multiple pages of data from API request.
    '''
    request_url = first_page.get('next')
    have_all_data = False
    current_data = {}
    all_data = []
    while not have_all_data:
        resp = requests.get(url=request_url, headers=FVM_HEADER, timeout=30)
        if not resp.ok:
            msg = "FrontlineVM get_all_data -- status code: " + str(resp.status_code)
            demisto.debug(msg)
        resp.raise_for_status()
        current_data = json.loads(resp.text)
        all_data.extend(current_data.get('results', []))
        if current_data.get('next'):
            request_url = current_data.get('next')
        else:
            have_all_data = True
    return all_data


def get_fvm_data(request_url, **kwargs):
    ''' Retrieves data from FrontlineVM API '''
    data = []
    current_data = {}
    resp = requests.get(request_url, headers=FVM_HEADER, timeout=30, **kwargs)
    resp.raise_for_status()
    current_data = json.loads(resp.text)
    data.extend(current_data.get('results', []))
    # if there is a next page of data, iterate through pages to get all data:
    if current_data.get('next'):
        # setup a timeout for get_all_data function:
        data_count = current_data.get('count')
        timeout_time = get_function_timeout_time(data_count)
        signal.signal(signal.SIGALRM, function_timeout)
        signal.alarm(timeout_time)
        try:
            all_data = get_all_data(current_data)
            data.extend(all_data)
        except EndOfTime:
            return_error("Error: FrontlineVM get_fvm_data function exceeds timeout time.")
        except Exception as err:
            return_error("Error: FrontlineVM get_fvm_data failed.", error=err.message)
    return data


def parse_params(param_dict):
    '''
        This parses the given dictionary and modifies it to comply with our API endpoint queries
        of indexing multiple queries (?_0_first_query=value0_1_query1=value_2_query2=value2)
    '''
    param_index = 0
    new_param_dict = {}
    for key in param_dict:
        new_key = "_" + str(param_index) + "_" + key
        new_param_dict[new_key] = param_dict[key]
        param_index += 1
    return new_param_dict


def get_query_date_param(day_input):
    ''' Returns a datetime object of days from now to given day_input   '''
    now = datetime.utcnow()
    query_date = (now - timedelta(days=int(day_input))).replace(hour=0, minute=0, second=0, microsecond=0)
    query_date = datetime.strftime(query_date, "%Y-%m-%dT%H:%M:%SZ")
    return query_date


''' FETCH INCIDENT FUNCTIONS '''


def get_fetch_frequency_td():
    ''' Returns the INCIDENT_FREQUENCY as a datetime.timedelta object    '''
    fetch_frequency = INCIDENT_FREQUENCY.split()
    demisto.debug("FrontlineVM get_fetch_incident_td -- using frequency: " + str(fetch_frequency))
    if "min" in str(fetch_frequency[1]):
        return timedelta(minutes=int(fetch_frequency[0]))
    else:
        return timedelta(hours=int(fetch_frequency[0]))


def create_vuln_event_object(vuln):
    ''' creates a vulnerability event object given a vulnerability  '''
    vuln_event = {}
    vuln_event['vuln-id'] = vuln.get('id')
    vuln_event['hostname'] = vuln.get('hostname')
    vuln_event['ip-address'] = vuln.get('ip_address')
    vuln_event['port'] = vuln.get("port")
    vuln_event['scan-id'] = vuln.get('scan_id')
    vuln_event['vuln-title'] = vuln.get('title')
    vuln_event['date-created'] = vuln.get('active_view_date_created')
    vuln_event['ddi-severity'] = vuln['severities']['ddi']
    vuln_event['vuln-info'] = vuln.get('data')
    return vuln_event


def vulns_to_incident(vulns, start_time_dt):
    incidents = []
    for vuln in vulns:
        # get vuln active view (av) date created values:
        av_date_created_str = vuln.get('active_view_date_created')
        av_date_created_dt = datetime.strptime(av_date_created_str, "%Y-%m-%dT%H:%M:%S.%fZ")

        # Skip if vuln created before current start_time:
        if (av_date_created_dt < start_time_dt):
            continue
        vuln_event = create_vuln_event_object(vuln)
        incident = {
            'name': vuln.get('title'),
            'occurred': vuln.get('active_view_date_created'),
            'details': vuln.get('data'),
            'rawJSON': json.dumps(vuln_event)
        }
        incidents.append(incident)
    return incidents


def fetch_incidents():
    try:
        last_run = demisto.getLastRun()
        # Check if last_run exists and has a start_time, else create new start_time timestamp:
        if last_run and last_run.get('start_time', False):
            start_time = last_run.get('start_time')
            # Check if user selected fetch frequency is within last_run[start_time]:
            fetch_frequency_td = get_fetch_frequency_td()
            if ((datetime.utcnow() - datetime.utcfromtimestamp(int(start_time))) < fetch_frequency_td):
                debug_msg = "frequency (" + str(fetch_frequency_td) + ") is within last start_time, sending empty incidents."
                demisto.debug("FrontlineVM fetch_incidents -- " + debug_msg)
                demisto.setLastRun({'start_time': last_run.get('start_time')})
                demisto.incidents([])
                return
            else:
                debug_msg = "frequency (" + str(fetch_frequency_td) + ") exceeds last start_time, getting incident events."
                demisto.debug("FrontlineVM fetch_incident -- " + debug_msg)
        else:
            now = datetime.utcnow()
            start_time = now.strftime("%s")
        start_time_dt = datetime.utcfromtimestamp(int(start_time))
        start_time_str = start_time_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        demisto.debug("FrontlineVM fetch_incident -- continuing with start_time of " + str(start_time_str))

        # Fetch vulnerabilities:
        req_params = {}
        req_params['lte_vuln_severity_ddi'] = str(INCIDENT_VULN_MIN_SEVERITY)
        req_params['gte_vuln_date_created'] = start_time_str
        req_params = parse_params(req_params)
        vulns = get_fvm_data(VULN_ENDPOINT, params=req_params)

        # Create incidents
        if vulns:
            demisto.debug("FrontlineVM fetch_incidents -- getting all incidents.")
            incidents = vulns_to_incident(vulns, start_time_dt)
        else:
            demisto.debug("FrontlineVM fetch_incidents -- no new vulnerabilities found, no incidents created.")
            incidents = []

        now = datetime.utcnow()
        start_time = now.strftime("%s")
        demisto.info("FrontlineVM fetch_incident -- creating new start_time of " + str(now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))
        demisto.setLastRun({'start_time': start_time})
        demisto.incidents(incidents)
    except Exception as err:
        return_error("Error: FrontlineVM fetching_incidents -- " + str(err.message))


''' COMMAND FUNCTIONS   '''


def get_hosts(ip_address, hostname, label_name, max_days_since_scan):
    ''' Returns a list of hosts from Frontline.Cloud based on user input from Arguments    '''
    # Prepare parameters for Frontline API request:
    req_params = {}
    if ip_address:
        req_params['eq_host_ip_address'] = str(ip_address)
    if hostname:
        req_params['iexact_host_hostname'] = str(hostname)
    if label_name:
        req_params['eq_host_labels'] = str(label_name)
    if max_days_since_scan:
        try:
            query_date = get_query_date_param(max_days_since_scan)
            req_params['gte_host_date_created'] = str(query_date)
        except ValueError:
            debug_msg = "incorrect data type input for argument max_days_since_scan, should be number of days"
            demisto.debug("FrontlineVM get_hosts -- " + debug_msg)
            return_error("Error: max_days_since_scan value should be a number representing days.")
    req_params = parse_params(req_params)
    hosts = get_fvm_data(HOST_ENDPOINT, params=req_params)
    return hosts


def get_assets_command():
    ''' Pulls host information from FrontlineVM '''
    # Get Arguments:
    ip_address = demisto.args().get('ip_address')
    hostname = demisto.args().get('hostname')
    label_name = demisto.args().get('label_name')
    max_days_since_scan = demisto.args().get('max_days_since_scan')

    hosts = get_hosts(ip_address, hostname, label_name, max_days_since_scan)

    # Condensing Host data for HumanReadable and EntryContext:
    asset_output = {}
    host_list = []
    ip_list = []
    host_id_list = []
    for host in hosts:
        host_obj = {}
        host_obj['ID'] = host.get('id', None)
        host_obj['Hostname'] = host.get('hostname', '')
        host_obj['IP'] = host.get('ip_address', '')
        host_obj['DNSHostname'] = host.get('dns_name', '')
        host_obj['MAC'] = host.get('mac_address', '')
        host_obj['OS'] = host.get('os')
        host_obj['OSType'] = host.get('os_type')
        host_obj['CriticalVulnCount'] = host['active_view_vulnerability_severity_counts']['weighted']['ddi']['counts']['critical']
        host_list.append(host_obj)
        ip_list.append(host.get('ip_address'))
        host_id_list.append(host.get('id'))

    # Linking Context:
    asset_output['Hosts'] = host_list
    asset_output['IPList'] = ip_list

    ec = {'FrontlineVM(val.Hosts && val.Hosts == obj.Hosts)': asset_output}

    output = {
        # indicates entry type to the War room
        'Type': entryTypes['note'],

        # raw data callable from War Room CLI with "raw-response=true"
        'Contents': hosts,

        # format of the content from the Contents field
        'ContentsFormat': formats['json'],

        # content that displays in the War Room:
        'HumanReadable': tableToMarkdown('FrontlineVM: Assets Found', host_list, headers=HOST_HEADERS, removeNull=True),

        # Format of the content from the HumanReadable field
        'ReadableContentsFormat': formats['markdown'],

        # Data added to the investigation context (Output Context), which you can use in playbooks
        'EntryContext': ec
    }
    demisto.results(output)


def get_vulns(severity, min_severity, max_days_since_created, min_days_since_created, host_id):
    # Prepare parameters for Frontline API request:
    req_params = {}
    if min_severity and severity:
        debug_msg = "Selecting both \'min_severity\' and \'severity\' will yield to the minimum severity."
        demisto.debug("FrontlineVM get_vulns -- " + debug_msg)
    if min_severity:
        req_params['lte_vuln_severity_ddi'] = str(min_severity)
    elif severity:
        req_params['eq_vuln_severity_ddi'] = str(severity)
    if max_days_since_created:
        try:
            query_date = get_query_date_param(max_days_since_created)
            req_params['lte_vuln_active_view_date_first_created'] = str(query_date)
        except ValueError:
            debug_msg = "incorrect input type for argument max_days_since_created, should be number of days"
            demisto.debug("FrontlineVM get_vulns -- " + debug_msg)
            return_error("Error: max_days_since_created value should be a number representing days.")
    if min_days_since_created:
        try:
            query_date = get_query_date_param(min_days_since_created)
            req_params['gte_vuln_date_created'] = str(query_date)
        except ValueError:
            debug_msg = "incorrect input type for argument min_days_since_created, should be number of days"
            demisto.debug("FrontlineVM get_vulns -- " + debug_msg)
            return_error("Error: min_days_since_created value should be a number representing days.")
    if host_id:
        VulnEndpoint = HOST_ENDPOINT + str(host_id) + "/vulnerabilities/"
    else:
        VulnEndpoint = VULN_ENDPOINT
    req_params = parse_params(req_params)
    vulns = get_fvm_data(VulnEndpoint, params=req_params)
    return vulns


def create_vuln_obj(vuln):
    vuln_obj = {}
    vuln_obj['vuln-id'] = vuln.get('id')
    vuln_obj['hostname'] = vuln.get('hostname')
    vuln_obj['ip-address'] = vuln.get('ip_address')
    vuln_obj['vuln-title'] = vuln.get('title')
    vuln_obj['date-created'] = vuln.get('active_view_date_created')
    vuln_obj['ddi-severity'] = vuln['severities']['ddi']
    vuln_obj['vuln-info'] = vuln.get('data')
    return vuln_obj


def format_vuln_data_output(vuln_data_output, vuln_list, vuln_data_list):
    # FrontlineVM Vulnerability Data Output:
    vuln_data_ec = {
        'FrontlineVM(val.Vulns && val.Vulns == obj.Vulns)': vuln_data_output
    }

    # To decrease line number length:
    table_name = "FrontlineVM: Vulnerabilities Found"
    return {
        'Type': entryTypes['note'],
        'Contents': vuln_list,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown(table_name, vuln_data_list, headers=VULN_DATA_HEADERS, removeNull=True),
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': vuln_data_ec
    }


def format_vuln_stat_output(vuln_stat_output, vuln_stat_headers):
    # Vulnerability statistics output:
    vuln_stat_ec = {
        'FrontlineVM(val.Object && val.Object == obj.Object)': vuln_stat_output
    }
    return {
        'Type': entryTypes['note'],
        'Contents': vuln_stat_output,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('FrontlineVM: Vulnerability Statisctics', vuln_stat_output, headers=vuln_stat_headers),
        'EntryContext': vuln_stat_ec
    }


def get_vuln_outputs(vuln_list):
    output = []
    vuln_data_output = {}
    vuln_stat_output = {}

    vuln_severity_count = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'trivial': 0,
        'info': 0
    }

    vuln_stat_output = {}
    vuln_stat_output['vulnerability-count'] = len(vuln_list)
    vuln_data_list = []
    ip_list = []

    if len(vuln_list) > 0:
        demisto.debug('FrontlineVM get_vuln_outputs -- iterating through vulns')
    else:
        demisto.debug('FrontlineVM get_vuln_outputs -- get vulns request returned empty')

    # Condensing Vuln data for HumanReadable and EntryContext:
    for vuln in vuln_list:
        vuln_obj = create_vuln_obj(vuln)    # vulnerability data output
        vuln_severity_count[str(vuln['severities']['ddi'])] += 1
        vuln_data_list.append(vuln_obj)
        ip_list.append(vuln.get('ip_address'))

    # Include severity in vulnerability statistic header if severity exists:
    vuln_stat_headers = ['vulnerability-count']
    for k, v in vuln_severity_count.items():
        # Include severity level (critical, high, medium, etc...) in output header if vulnerability exists for that severity.
        if v > 0:
            vuln_stat_headers.append(str(k) + "-severity-count")
            vuln_stat_output[str(k) + "-severity-count"] = v

    vuln_data_output['Vulns'] = vuln_data_list
    vuln_data_output['IPList'] = ip_list

    # Format and generate output:
    data_output = format_vuln_data_output(vuln_data_output, vuln_list, vuln_data_list)
    output.append(data_output)

    stat_output = format_vuln_stat_output(vuln_stat_output, vuln_stat_headers)
    output.append(stat_output)
    return output


def get_hostID_from_ip_address(ip_address):
    host = get_fvm_data(HOST_ENDPOINT, params={'_0_eq_host_ip_address': str(ip_address)})
    if len(host) >= 1:
        return host[0].get('id')
    else:
        msg = 'Host not found within Frontline.Cloud given host IP Address.'
        demisto.debug('Frontline.Cloud get_hostID_from_ip_address -- ' + msg)
        return_error("Error: " + msg)


def get_vulns_command():
    ''' Pulls vulnerability information from FrontlineVM    '''
    # Get Arugments:
    severity = demisto.args().get('severity')
    min_severity = demisto.args().get('min_severity')
    max_days_since_created = demisto.args().get('max_days_since_created')
    min_days_since_created = demisto.args().get('min_days_since_created')
    host_id = demisto.args().get('host_id')
    ip_address = demisto.args().get('ip_address')

    vulns = []
    if ip_address:
        host_id = get_hostID_from_ip_address(ip_address)
    vulns = get_vulns(severity, min_severity, max_days_since_created, min_days_since_created, host_id)
    output = get_vuln_outputs(vulns)
    demisto.results(output)


#########################
# CREATING SCAN METHODS:
#########################
class _tz_UTC(tzinfo):
    ''' UTC '''
    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return 'UTC'

    def dst(self, dt):
        return timedelta(0)


def ip2long(ip_address):
    '''
        Convert an IPv4 address from dotted-quad string format to 32-bit packed binary format,
        as a bytes object four characters in length.
    '''
    return struct.unpack("!L", socket.inet_aton(ip_address))[0]


def long2ip(ip_address):
    '''
        Convert a 32-bit packed IPv4 address (a bytes-like object four bytes in length)
        to its standard dotted-quad string representation.
    '''
    return socket.inet_ntoa(struct.pack("!L", ip_address))


def get_network_data():
    try:
        url = BASE_URL + "/api/networkprofiles/?_0_eq_networkprofile_internal=True"
        resp = requests.get(url, headers=FVM_HEADER)
        resp.raise_for_status()
        return json.loads(resp.text)
    except Exception as err:
        return_error('Error: getting network data -- ' + str(err))
    return []


def get_scan_data(network_data, low_ip, high_ip):
    for profile in network_data:
        # If there is no scanner using this profile, then continue to the next profile
        if len(profile.get('scanner_names', "")) == 0:
            continue
        scanner_id = profile.get('scanner_ids')[0]
        scanner_url = BASE_URL + "/api/scanners/" + str(scanner_id) + "/"
        scanner_resp = requests.get(scanner_url, headers=FVM_HEADER)
        scanner_resp.raise_for_status()
        scanner = json.loads(scanner_resp.text)
        if scanner.get('status', '') == 'online':
            url = BASE_URL + "/api/networkprofiles/" + str(profile['id']) + "/rules/"
            profile_data = []
            current_data = None
            have_all_data = False
            while not have_all_data:
                resp = requests.get(url, headers=FVM_HEADER)
                resp.raise_for_status()
                current_data = json.loads(resp.text)
                profile_data.extend(current_data.get('results', []))
                if (current_data.get('next', None)):
                    url = current_data.get('next')
                else:
                    have_all_data = True
            for rule in profile_data:
                if rule.get('ip_address_range', None):
                    # to decrease line number length:
                    rule_high_ip_num = rule['ip_address_range']['high_ip_number']
                    rule_low_ip_num = rule['ip_address_range']['low_ip_number']
                    if (rule_high_ip_num >= high_ip) and (rule_low_ip_num <= low_ip):
                        return json.dumps({'profile_id': profile['id']})
    return_error("Error: no scan data found.")


def get_business_group():
    demisto.debug('FrontlineVM get_business_group -- checking if user allows business groups.')
    url = BASE_URL + "/api/session/"
    resp = requests.get(url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
    resp.raise_for_status()
    data = json.loads(resp.text)
    if data.get('account_allow_businessgroups_setting'):
        business_groups_url = BASE_URL + "/api/businessgroups/?_0_eq_businessgroup_name=Enterprise Admins"
        bus_resp = requests.get(business_groups_url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
        if bus_resp.ok:
            bus_data = json.loads(bus_resp.text)
            return bus_data[0]
    return None


def get_correct_ip_order(low_ip_address, high_ip_address):
    ''' Checks if user inputed ip address in correct order from low to high (used for range of assets to scan) '''
    low_ip_number = ip2long(low_ip_address)
    high_ip_number = ip2long(high_ip_address)

    # if low_ip != high_ip, user inputed two different IP addresses -> range of assets to scan.
    if (low_ip_address != high_ip_address) and (low_ip_number > high_ip_number):
        low_ip_number, high_ip_number = high_ip_number, low_ip_number
        low_ip_address, high_ip_address = high_ip_address, low_ip_address
    return {
        'low_ip_number': low_ip_number,
        'low_ip_address': low_ip_address,
        'high_ip_number': high_ip_number,
        'high_ip_address': high_ip_address
    }


def build_scan(low_ip_address, high_ip_address, scan_policy):
    """ Prepare scan data for POST request  """

    # check order of given ip address and assign accordingly
    asset_ips = get_correct_ip_order(low_ip_address, high_ip_address)
    low_ip_number = asset_ips.get('low_ip_number')
    low_ip_address = asset_ips.get('low_ip_address')
    high_ip_number = asset_ips.get('high_ip_number')
    high_ip_address = asset_ips.get('high_ip_address')

    # Get client's network and available scanner info to perform scan:
    scan_policy = str(scan_policy)
    network_data = get_network_data()
    scanner_data = json.loads(get_scan_data(network_data, low_ip_number, high_ip_number))

    # Set time for scan:
    now = datetime.now(_tz_UTC())
    tz = "UTC"
    tzoffset = 0
    scan = {}

    # Scan name will change if user is scanning range (low ip address not equal to high ip address)
    if low_ip_address == high_ip_address:
        scan['name'] = ("Demisto Scan " + " [" + str(low_ip_address) + "]")
    elif low_ip_address != high_ip_address:
        scan['name'] = ("Demisto Scan " + "[" + str(low_ip_address) + "-" + str(high_ip_address) + "]")
    else:
        scan['name'] = ("Demisto Scan")

    scan['description'] = "New network device auto scan launch from Demisto."

    # Setting the schedule of the scan:
    scan['schedule'] = {
        "id": None,
        "end_date": None,
        "start_date": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "recurring": False,
        "recurrence_rules": [],
        "timezone": tz,
        "timezone_offset": tzoffset
    }
    scan['workflow'] = "va_workflow"
    scan['exclude_from_active_view'] = False
    scan['notify'] = False
    scan['internal'] = True
    scan['recipients'] = []
    scan['scan_policy'] = scan_policy
    scan['scan_speed'] = "normal"
    scan['asset_groups'] = []
    scan['asset_filter'] = {}

    # If users' FrontlineVM account allows business groups, include the business group ID:
    business_group = get_business_group()
    if business_group:
        scan['businessgroups'] = [{"id": business_group['id']}]

    # Set the network target for this scan:
    scan['adhoc_targets'] = []
    scan['adhoc_targets'].append({
        "rule_action": "include",
        "network_profile_id": int(scanner_data['profile_id']),
        "inclusion": "full",
        "ip_address_range": {
            "low_ip_address": low_ip_address,
            "high_ip_address": high_ip_address,
            "low_ip_number": low_ip_number,
            "high_ip_number": high_ip_number,
            "ipv6": False,
            "dhcp": False,
            "fragile": False,
            "cidr_block": None
        }
    })
    return scan


def scan_asset(ip_address, scan_policy):
    # Check if user inputs either a range of addresses to scan or a single asset to scan:
    if "-" in ip_address:
        low_ip_address = ip_address.split("-")[0].strip()
        high_ip_address = ip_address.split("-")[1].strip()
    else:
        low_ip_address = ip_address
        high_ip_address = ip_address
    scan_payload = build_scan(low_ip_address, high_ip_address, scan_policy)
    header = {}
    header['Authorization'] = 'Token ' + str(API_TOKEN)
    header['Content-Type'] = "application/json;charset=utf-8"
    resp = requests.post(SCAN_ENDPOINT, data=json.dumps(scan_payload), headers=header)
    resp.raise_for_status()
    scan_response = json.loads(resp.text)
    return scan_response


def scan_policy_exists(policy_selected):
    policy_url = SCAN_ENDPOINT + "policies/"
    demisto.debug("FrontlineVM scan_policy_exists -- checking if user defined policy exists within Frontline.Cloud")
    try:
        resp = requests.get(policy_url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
        resp.raise_for_status()
        data = json.loads(resp.text)
        for policy in data:
            if policy_selected == policy.get('name', ""):
                return True
        return False
    except Exception as err:
        return_error("Error: FrontlineVM scan_policy_exists failed", error=err.message)


def scan_asset_command():
    ip_address = demisto.args().get('ip_address')
    policy_name = str(demisto.args().get('scan_policy'))
    if not scan_policy_exists(policy_name):
        return_error("Error: Scan Policy entered '" + policy_name + "' does not exist.")

    try:
        scan_response = scan_asset(ip_address, policy_name)

        # Condense Scan data for HumanReadable and EntryContext with scan_output:
        scan_output = {}
        # Gathering the low and high ip addresses of the asset(s) to scan from the POST request response:
        low_ip = str(scan_response['adhoc_targets'][0]['ip_address_range']['low_ip_address'])
        high_ip = str(scan_response['adhoc_targets'][0]['ip_address_range']['high_ip_address'])

        # Build appropriate headers for HumanReadable output, dependent on if user is scanning one asset or a range of assets:
        if low_ip == high_ip:
            scan_headers = ['ID', 'Name', 'IP', 'Policy']
            scan_output['IP'] = scan_response['adhoc_targets'][0]['ip_address_range']['low_ip_address']
        else:
            scan_headers = ['ID', 'Name', 'IP-Range', 'Policy']
            scan_output['IP-Range'] = low_ip + "-" + high_ip

        scan_output['ID'] = scan_response.get('id')
        scan_output['Name'] = scan_response.get('name')
        scan_output['Policy'] = scan_response.get('scan_policy')

        # Linking Context
        ec = {
            'FrontlineVM(val.ID && val.ID == obj.ID)': {
                'Scan': scan_output
            }
        }
        output = {
            'Type': entryTypes['note'],     # War room
            'Contents': scan_response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('FrontlineVM: Performing Scan', scan_output, headers=scan_headers, removeNull=True),
            'EntryContext': ec
        }
        demisto.results(output)
    except Exception as err:
        return_error('Error performing scan. Exception: ' + str(err))


def test_module():
    session_url = BASE_URL + "/api/session/"
    resp = requests.get(session_url, headers=FVM_HEADER)
    if resp.ok:
        demisto.results('ok')
    else:
        return_error("Error: Test method failed. Invalid API Token.")


''' EXECUTION CODE  '''


def main():
    LOG('command is %s' % (demisto.command(), ))
    try:
        if demisto.command() == 'test-module':
            test_module()
        if demisto.command() == 'frontline-get-assets':
            get_assets_command()
        if demisto.command() == 'frontline-get-vulns':
            get_vulns_command()
        if demisto.command() == 'frontline-scan-asset':
            scan_asset_command()
        if demisto.command() == 'fetch-incidents':
            fetch_incidents()
    except Exception as e:
        LOG(e)
        LOG.print_log(verbose=False)
        return_error("Error: " + str(e.message))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
