import demistomock as demisto
from CommonServerPython import *
import json
import math
import re
import requests
import signal
import socket
import struct
import urllib3
from datetime import datetime, timedelta, UTC
from typing import Any

# disable insecure warnings
urllib3.disable_warnings()

# Params:
VERIFY_SSL = not demisto.params().get('insecure', False)
API_TOKEN = demisto.params().get('apiToken')
INCIDENT_VULN_MIN_SEVERITY = demisto.params().get('incidentSeverity')
INCIDENT_FREQUENCY = demisto.params().get('incidentFrequency')


def get_base_url():
    ''' Removes forward slash from end of url input '''
    url = demisto.params().get('frontlineURL')
    url = re.sub(r'\/$', '', url)
    return url


# Endpoints:
BASE_URL = get_base_url()
VULN_ENDPOINT = BASE_URL + "/api/scanresults/active/vulnerabilities/"
HOST_ENDPOINT = BASE_URL + "/api/scanresults/active/hosts/"
SCAN_ENDPOINT = BASE_URL + "/api/scans/"

# FrontlineVM (FVM) header for API authorization when performing:
API_AUTH_HEADER = {'Authorization': 'Token ' + str(API_TOKEN)}


# Minimum time to timeout functions (5 mins)
MIN_TIMEOUT = 300   # seconds

# HEADERS for Demisto command outputs:
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

SCAN_HEADERS = ['ID', 'Name', 'IP', 'Policy']

'''HELPER FUNCTIONS'''


class EndOfTime(Exception):
    ''' Raised when functions timeout '''


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
    Retrieves all data if multiple pages are present in API request.
    '''
    request_url = first_page.get('next')
    have_all_data = False
    current_data = {}   # type: Dict[str, Any]
    all_data = []       # type: List[Dict]
    while not have_all_data:
        resp = requests.get(url=request_url, headers=API_AUTH_HEADER, timeout=30, verify=VERIFY_SSL)
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
    data = []   # type: List
    current_data = {}   # type: Dict
    resp = requests.get(request_url, headers=API_AUTH_HEADER, timeout=30, verify=VERIFY_SSL, **kwargs)
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
            return_error("Error: FrontlineVM get_fvm_data failed. \n" + str(err))
    return data


def parse_params(param_dict):
    '''
        This parses the given dictionary and modifies it to comply with our API endpoint queries
        of indexing multiple queries (?_0_first_query=value0_1_query1=value_2_query2=value2)
    '''
    param_index = 0
    new_param_dict = {}
    for key in param_dict:
        # 'ordering' key shouldn't be using the same param indexing as queries.
        if key == 'ordering':
            continue
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


def get_fetch_frequency():
    ''' Returns the INCIDENT_FREQUENCY as a datetime object.    '''
    fetch_frequency = INCIDENT_FREQUENCY.split()
    demisto.debug("FrontlineVM get_fetch_incident_td -- using frequency: " + str(fetch_frequency))
    if "min" in str(fetch_frequency[1]):
        return timedelta(minutes=int(fetch_frequency[0]))
    return timedelta(hours=int(fetch_frequency[0]))


def create_vuln_event_object(vuln):
    ''' Creates a vulnerability event object given raw vulnerability data.  '''
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


def vulns_to_incident(vulns, last_start_time):
    '''
        Iterate through vulnerabilities and create incident if
        vulnerability has been created since last start_time.
    '''
    incidents = []
    for vuln in vulns:
        # get vulnerability active view (av) date created values:
        av_date_created_str = vuln.get('active_view_date_created')
        av_date_created = datetime.strptime(av_date_created_str, "%Y-%m-%dT%H:%M:%S.%fZ")

        # Create incident if vuln created after last run start time:
        if av_date_created > last_start_time:
            vuln_event = create_vuln_event_object(vuln)
            incident = {
                'name': vuln.get('title'),
                'occurred': vuln.get('active_view_date_created'),
                'details': vuln.get('data'),
                'rawJSON': json.dumps(vuln_event)
            }
            incidents.append(incident)
    return incidents


def fetch_vulnerabilities(last_start_time_str):
    ''' Pulls vulnerability data for fetch_incidents.   '''
    # Pull vulnerabilities:
    req_params = {}
    req_params['lte_vuln_severity_ddi'] = str(INCIDENT_VULN_MIN_SEVERITY)
    req_params['gte_vuln_date_created'] = last_start_time_str
    req_params['ordering'] = "active_view_date_created"
    req_params = parse_params(req_params)
    vulns = get_fvm_data(VULN_ENDPOINT, params=req_params)
    return vulns


def fetch_incidents():
    ''' Method to fetch Demisto incidents by pulling any new vulnerabilities found.   '''
    try:
        new_start_time = datetime.utcnow()    # may be used to update new start_time if no incidents found.
        new_start_time_str = new_start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        incidents: list[dict[str, Any]] = []
        last_run = demisto.getLastRun()

        # Check if last_run exists and has a start_time to continue:
        if last_run and last_run.get('start_time', False):
            last_start_time_str = last_run.get('start_time')    # last start time as string
            last_start_time = datetime.strptime(last_start_time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            fetch_frequency = get_fetch_frequency()             # gets user set frequency as datetime object

            # Return empty list if time since last_start_time has not exceeded frequency time:
            if (datetime.utcnow() - last_start_time) < fetch_frequency:
                debug_msg = "Time since last_start_time has not exceeded frequency time (" + str(fetch_frequency) + "). "
                debug_msg += "Sending empty list of incidents."
                demisto.debug("FrontlineVM fetch_incidents -- " + debug_msg)
                demisto.incidents(incidents)
                return

            # Begin fetching incidents:
            debug_msg = "Time since last_start_time exceeds frequency time (" + str(fetch_frequency) + "). Fetching incidents. "
            debug_msg += "Continuing from last start_time: " + str(last_start_time_str)
            demisto.debug("FrontlineVM fetch_incident -- " + debug_msg)

            # Fetch vulnerabilities and create incidents:
            vulns = fetch_vulnerabilities(last_start_time_str)
            if vulns:
                demisto.debug("FrontlineVM fetch_incidents -- vulnerabilities found, getting incidents.")
                incidents = vulns_to_incident(vulns, last_start_time)

                if len(incidents) > 0:
                    # Reference the last fetched incident as the new_start_time:
                    last_incident = incidents[-1]
                    new_start_time_str = str(last_incident.get('occurred'))
            else:
                demisto.debug("FrontlineVM fetch_incidents -- no new vulnerabilities found, no incidents created.")

        demisto.info("FrontlineVM fetch_incident -- new start_time: " + str(new_start_time_str))
        demisto.setLastRun({'start_time': new_start_time_str})
        demisto.incidents(incidents)
    except Exception as err:
        return_error("Error: FrontlineVM fetching_incidents -- " + str(err))


def get_assets(ip_address, hostname, label_name, max_days_since_scan):
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
            demisto.debug("FrontlineVM get_assets -- " + debug_msg)
            return_error("Error: max_days_since_scan value should be a number representing days.")
    req_params = parse_params(req_params)
    hosts = get_fvm_data(HOST_ENDPOINT, params=req_params)
    return hosts


def get_asset_output(host_list):
    ''' Get and prepare output from list of raw host data '''
    # Condensing Host data for HumanReadable and EntryContext:
    host_obj_list = []
    for host in host_list:
        host_obj = {}
        host_obj['ID'] = host.get('id', None)
        host_obj['Hostname'] = host.get('hostname', '')
        host_obj['IP'] = host.get('ip_address', '')
        host_obj['DNSHostname'] = host.get('dns_name', '')
        host_obj['MAC'] = host.get('mac_address', '')
        host_obj['OS'] = host.get('os')
        host_obj['OSType'] = host.get('os_type')
        host_obj['CriticalVulnCount'] = host['active_view_vulnerability_severity_counts']['weighted']['ddi']['counts']['critical']
        host_obj_list.append(host_obj)
    return host_obj_list


def get_assets_command():
    ''' Pulls host information from Frontline.Cloud '''
    # Get Arguments:

    ip_address = demisto.args().get('ip_address')
    hostname = demisto.args().get('hostname')
    label_name = demisto.args().get('label_name')
    max_days_since_scan = demisto.args().get('max_days_since_scan')

    hosts = get_assets(ip_address, hostname, label_name, max_days_since_scan)
    asset_output = get_asset_output(hosts)

    asset_entry_context = {'FrontlineVM.Hosts(val.ID && val.ID == obj.ID)': asset_output}

    asset_output_tablename = 'FrontlineVM: Assets Found'
    demisto.results({
        # indicates entry type to the War room
        'Type': entryTypes['note'],

        # raw data callable from War Room CLI with "raw-response=true"
        'Contents': hosts,

        # format of the content from the Contents field
        'ContentsFormat': formats['json'],

        # content that displays in the War Room:
        'HumanReadable': tableToMarkdown(asset_output_tablename,
                                         asset_output,
                                         headers=HOST_HEADERS,
                                         removeNull=True),

        # Format of the content from the HumanReadable field
        'ReadableContentsFormat': formats['markdown'],

        # Data added to the investigation context (Output Context), which you can use in playbooks
        'EntryContext': asset_entry_context
    })


def get_vulns(severity, min_severity, max_days_since_created, min_days_since_created, host_id):
    ''' Pull vulnerability data based upon user inputted parameters.    '''
    # Prepare parameters for Frontline API request:
    req_params = {}
    if min_severity and severity:
        msg = "Selecting both \'min_severity\' and \'severity\' will yield to the minimum severity."
        demisto.debug("FrontlineVM get_vulns -- " + msg)

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
        vuln_endpoint = HOST_ENDPOINT + str(host_id) + "/vulnerabilities/"
    else:
        vuln_endpoint = VULN_ENDPOINT
    req_params = parse_params(req_params)
    vulns = get_fvm_data(vuln_endpoint, params=req_params)
    return vulns


def create_vuln_obj(vuln):
    ''' Create condensed vulnerability object from raw vulnerability data.  '''
    vuln_obj = {}
    vuln_obj['vuln-id'] = vuln.get('id')
    vuln_obj['hostname'] = vuln.get('hostname')
    vuln_obj['ip-address'] = vuln.get('ip_address')
    vuln_obj['vuln-title'] = vuln.get('title')
    vuln_obj['date-created'] = vuln.get('active_view_date_created')
    vuln_obj['ddi-severity'] = vuln['severities']['ddi']
    vuln_obj['vuln-info'] = vuln.get('data')
    return vuln_obj


def get_vuln_outputs(vuln_list):
    ''' Get and prepare output from list of raw vulnerability data '''

    vuln_stat_output = {}   # type: Dict
    vuln_stat_output['Vulnerabilities'] = len(vuln_list)
    vuln_data_list = []

    # Condensing Vulns for HumanReadable and EntryContext:
    for vuln in vuln_list:
        vuln_obj = create_vuln_obj(vuln)
        vuln_severity = str(vuln['severities']['ddi']).capitalize()
        if vuln_stat_output.get(vuln_severity):
            vuln_stat_output[vuln_severity] += 1
        else:
            vuln_stat_output[vuln_severity] = 1
        vuln_data_list.append(vuln_obj)

    return {
        'data_output': vuln_data_list,    # condensed vuln data pulled from Frontline.Cloud
        'stat_output': vuln_stat_output,    # statistical vulnerability data
    }


def get_host_id_from_ip_address(ip_address):
    '''
        Get host ID within Frontline.Cloud given IP address.
        Host ID used to pull vulnerability data for that specific host.
    '''
    hosts_with_given_ip = get_fvm_data(HOST_ENDPOINT, params={'_0_eq_host_ip_address': str(ip_address)})
    if len(hosts_with_given_ip) < 1:
        msg = 'Host not found within Frontline.Cloud given host IP Address. Host will not be included in querying vulnerabilities'
        demisto.error('Frontline.Cloud get_host_id_from_ip_address -- ' + msg)  # print to demisto log in ERROR
        demisto.debug('Frontline.Cloud get_host_id_from_ip_address -- ' + msg)
    first_relevant_host = hosts_with_given_ip[0]
    return first_relevant_host.get('id')


def get_vulns_command():
    ''' Pulls vulnerability information from Frontline.Cloud    '''
    # Get Arugments:
    severity = demisto.args().get('severity')
    min_severity = demisto.args().get('min_severity')
    max_days_since_created = demisto.args().get('max_days_since_created')
    min_days_since_created = demisto.args().get('min_days_since_created')
    host_id = demisto.args().get('host_id')
    ip_address = demisto.args().get('ip_address')

    if ip_address:
        host_id = get_host_id_from_ip_address(ip_address)
    vulns = get_vulns(severity, min_severity, max_days_since_created, min_days_since_created, host_id)

    # get both vuln data and vuln statistical output
    output = get_vuln_outputs(vulns)

    # Vuln Data Output:
    vuln_data_table_name = "FrontlineVM: Vulnerabilities Found"
    vuln_data_output = output.get('data_output')

    # Vuln Statistical Output:
    vuln_stat_table_name = "FrontlineVM: Vulnerability Statisctics"
    vuln_stat_output = output.get('stat_output')
    vuln_stat_headers = list(vuln_stat_output.keys())

    demisto.results([
        {
            'Type': entryTypes['note'],
            'Contents': vulns,
            'ContentsFormat': formats['json'],
            'HumanReadable': tableToMarkdown(vuln_data_table_name,
                                             vuln_data_output,
                                             headers=VULN_DATA_HEADERS,
                                             removeNull=True),
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {'FrontlineVM.Vulns(val.vuln-id && val.vuln-id == obj.vuln-id)': vuln_data_output}
        },
        {
            'Type': entryTypes['note'],
            'Contents': vuln_stat_output,
            'ContentsFormat': formats['json'],
            'HumanReadable': tableToMarkdown(vuln_stat_table_name,
                                             vuln_stat_output,
                                             headers=vuln_stat_headers),
            'EntryContext': {'FrontlineVM.VulnStats(1>0)': vuln_stat_output}
        }
    ])


def ip_address_to_number(ip_address):
    '''
        This is used sp explain this is used for our API
        Convert an IPv4 address from dotted-quad string format to 32-bit packed binary format,
        as a bytes object four characters in length.

        This is specifically used for creating scan payloads when sending POST requests using
        our FrontlineVM API within the build_scan method.
    '''
    return struct.unpack("!L", socket.inet_aton(ip_address))[0]


def ip_number_to_address(ip_number):
    '''
        Convert a 32-bit packed IPv4 address (a bytes-like object four bytes in length)
        to its standard dotted-quad string representation.

        This is specifically used for creating scan payloads when sending POST requests using
        our FrontlineVM API within the build_scan method.
    '''
    return socket.inet_ntoa(struct.pack("!L", ip_number))


def get_network_data():
    ''' Get network data. Used to perform scan. '''
    try:
        url = BASE_URL + "/api/networkprofiles/?_0_eq_networkprofile_internal=True"
        resp = requests.get(url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
        resp.raise_for_status()
        return json.loads(resp.text)
    except Exception as err:
        return_error('Error: getting network data -- ' + str(err))
    return []   # placed to satisfy pylint (inconsistent-return-statements error)


def get_scan_data(network_data, low_ip, high_ip):
    ''' Iterate through network data to find appropriate scanner profile to use to perform scan.'''
    for profile in network_data:
        # If there is no scanner using this profile, then continue to the next profile
        if len(profile.get('scanner_names', "")) == 0:
            continue
        scanner_id = profile.get('scanner_ids')[0]
        scanner_url = BASE_URL + "/api/scanners/" + str(scanner_id) + "/"
        scanner_resp = requests.get(scanner_url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
        scanner_resp.raise_for_status()
        scanner = json.loads(scanner_resp.text)
        if scanner.get('status', '') == 'online':
            url = BASE_URL + "/api/networkprofiles/" + str(profile['id']) + "/rules/"
            profile_data = []   # type: List
            have_all_data = False
            while not have_all_data:
                resp = requests.get(url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
                resp.raise_for_status()
                current_data = json.loads(resp.text)
                profile_data.extend(current_data.get('results', []))
                if current_data.get('next', None):
                    url = current_data.get('next')
                else:
                    have_all_data = True
            for rule in profile_data:
                if rule.get('ip_address_range', None):
                    rule_high_ip_num = rule['ip_address_range']['high_ip_number']
                    rule_low_ip_num = rule['ip_address_range']['low_ip_number']
                    if (rule_high_ip_num >= high_ip) and (rule_low_ip_num <= low_ip):
                        return {'profile_id': profile['id']}
    return_error("Error: no scanner profile found for given ip range(s).")
    return {}   # placed to satisfy pylint (inconsistent-return-statements error)


def get_business_group():
    ''' Get business group data if user account allows businessgroups setting. '''
    demisto.debug('FrontlineVM get_business_group -- checking if user allows business groups.')
    # Getting users's FrontlineVM session/account info:
    url = BASE_URL + "/api/session/"
    user_session = requests.get(url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
    user_session.raise_for_status()
    data = json.loads(user_session.text)
    if data.get('account_allow_businessgroups_setting'):
        business_groups_url = BASE_URL + "/api/businessgroups/?_0_eq_businessgroup_name=Enterprise Admins"
        bus_resp = requests.get(business_groups_url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
        if bus_resp.ok:
            bus_data = json.loads(bus_resp.text)
            return bus_data[0]
    return None


def get_correct_ip_order(low_ip_address, high_ip_address):
    ''' Checks if user input ip address is in correct order (low-high). '''
    low_ip_number = ip_address_to_number(low_ip_address)
    high_ip_number = ip_address_to_number(high_ip_address)

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


def build_scan(low_ip_address, high_ip_address, scan_policy, scan_name):
    ''' Prepare scan data payload for POST request. '''

    # check order of given ip address and assign accordingly
    asset_ips = get_correct_ip_order(low_ip_address, high_ip_address)
    low_ip_number = asset_ips.get('low_ip_number')
    low_ip_address = asset_ips.get('low_ip_address')
    high_ip_number = asset_ips.get('high_ip_number')
    high_ip_address = asset_ips.get('high_ip_address')

    # Get client's network and available scanner info to perform scan:
    scan_policy = str(scan_policy)
    network_data = get_network_data()
    scanner_data = get_scan_data(network_data, low_ip_number, high_ip_number)

    # Set time for scan:
    now = datetime.now(UTC)
    time_zone = "UTC"
    tzoffset = 0
    scan = {}   # type: Dict[str, Any]

    # Scan name will change if user is scanning range (low ip address not equal to high ip address)
    if scan_name is not None:
        scan['name'] = str(scan_name)[:100]
    elif low_ip_address == high_ip_address:
        scan['name'] = ("Cortex XSOAR Scan " + " [" + str(low_ip_address) + "]")
    else:
        scan['name'] = ("Cortex XSOAR Scan " + "[" + str(low_ip_address) + "-" + str(high_ip_address) + "]")

    scan['description'] = "New network device auto scan launch from Demisto."

    # Setting the schedule of the scan:
    scan['schedule'] = {
        "id": None,
        "end_date": None,
        "start_date": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "recurring": False,
        "recurrence_rules": [],
        "timezone": time_zone,
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


def scan_asset(ip_address, scan_policy, scan_name, ip_range_start, ip_range_end):
    ''' Build scan payload and make POST request to perform scan. '''
    try:
        if ip_address:
            low_ip_address = ip_address
            high_ip_address = ip_address
        elif ip_range_start and ip_range_end:
            low_ip_address = ip_range_start
            high_ip_address = ip_range_end
        else:
            low_ip_address = ""
            high_ip_address = ""
            msg = "Invalid arguments. Must input either a single ip_address or range of ip addresses to scan."
            demisto.debug(msg)
            return_error(msg)
        if ip_address and (ip_range_start or ip_range_end):
            msg = "Inputting a single \'ip_address\' and a range of addresses will yield to the single ip_address to scan"
            demisto.debug("FrontlineVM scan_asset -- " + msg)

        scan_payload = build_scan(low_ip_address, high_ip_address, scan_policy, scan_name)
        header = {}
        header['Authorization'] = 'Token ' + str(API_TOKEN)
        header['Content-Type'] = "application/json;charset=utf-8"
        resp = requests.post(SCAN_ENDPOINT, data=json.dumps(scan_payload), headers=header, verify=VERIFY_SSL)
        if resp.ok:
            scan_data = json.loads(resp.text)
        else:
            scan_data = None
            msg = ("ERROR: Scan request returned with status code: " + str(resp.status_code))
            demisto.debug("FrontlineVM scan_asset -- " + msg)
            return_error(msg)
        return scan_data
    except Exception as err:
        return_error("Error: FrontlineVM scan_asset failed " + str(err))


def scan_policy_exists(policy_selected):
    ''' Check whether user input scan policy exists within their Frontline.Cloud account. '''
    policy_url = SCAN_ENDPOINT + "policies"
    demisto.debug("FrontlineVM scan_policy_exists -- checking if user defined policy exists within Frontline.Cloud")
    try:
        resp = requests.get(policy_url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
        resp.raise_for_status()
        data = json.loads(resp.text)
        return any(policy_selected == policy.get('name', '') for policy in data)
    except Exception as err:
        return_error("Error: FrontlineVM scan_policy_exists failed " + str(err))


def get_ip_addresses_from_scan_data(scan_response):
    '''
        Retrieve low and high ip address values from scan data.
        Checking that each key/value pair exists in nested dictionary
    '''
    adhoc_target_list = scan_response.get("adhoc_targets")
    adhoc_target = adhoc_target_list[0] if adhoc_target_list else None
    ip_address_range = adhoc_target.get('ip_address_range') if adhoc_target else None
    low_ip_address = ip_address_range.get('low_ip_address') if ip_address_range else None
    high_ip_address = ip_address_range.get('high_ip_address') if ip_address_range else None
    return {'low': low_ip_address, 'high': high_ip_address}


def scan_asset_command():
    ''' Peform scan on Frontline.Cloud '''
    ip_address = demisto.args().get('ip_address')
    policy_name = str(demisto.args().get('scan_policy'))
    scan_name = demisto.args().get('scan_name')
    ip_range_start = demisto.args().get('ip_range_start')
    ip_range_end = demisto.args().get('ip_range_end')
    if not scan_policy_exists(policy_name):
        return_error("Error: Scan Policy entered '" + policy_name + "' does not exist.")

    try:
        scan_response = scan_asset(ip_address, policy_name, scan_name, ip_range_start, ip_range_end)
        # Gather IP addresses from scan response data:
        ip_addresses = get_ip_addresses_from_scan_data(scan_response)
        low_ip = ip_addresses.get('low')
        high_ip = ip_addresses.get('high')

        # Condense Scan data for HumanReadable and EntryContext with scan_output:
        scan_output = {}

        # Build appropriate headers for HumanReadable output, dependent on if user is scanning one asset or a range of assets:
        is_only_one_asset = (low_ip == high_ip)
        if is_only_one_asset:
            scan_output['IP'] = low_ip
        else:
            scan_output['IP'] = low_ip + "-" + high_ip

        scan_output['ID'] = scan_response.get('id')
        scan_output['Name'] = scan_response.get('name')
        scan_output['Policy'] = scan_response.get('scan_policy')

        # Linking Context
        entry_context = {
            'FrontlineVM.Scans(val.ID && val.ID == obj.ID)': {
                'Scan': scan_output
            }
        }
        output = {
            'Type': entryTypes['note'],     # War room
            'Contents': scan_response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('FrontlineVM: Performing Scan', scan_output, headers=SCAN_HEADERS, removeNull=True),
            'EntryContext': entry_context
        }
        demisto.results(output)
    except Exception as err:
        return_error('Error performing scan. Exception: ' + str(err))


def test_module():
    ''' Test integration method '''
    session_url = BASE_URL + "/api/session/"
    resp = requests.get(session_url, headers=API_AUTH_HEADER, verify=VERIFY_SSL)
    if resp.ok:
        demisto.results('ok')
    else:
        return_error("Error: Test method failed. Invalid API Token.")


def main():
    ''' Integration main method '''
    LOG(f'command is {demisto.command()}')
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
    except Exception as err:
        LOG(err)
        LOG.print_log(verbose=False)
        return_error("Error: " + str(err))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
