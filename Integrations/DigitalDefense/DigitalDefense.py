import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import json
import sys
import socket
import struct
from datetime import datetime, tzinfo, timedelta

''' GLOBAL VARS '''
API_TOKEN = demisto.params().get('apiToken')
INCIDENT_VULN_SEVERITY = demisto.params().get('incidentSeverity')
INCIDENT_FREQUENCY = demisto.params().get('incidentFrequency')
FVM_URL = "https://vm.frontline.cloud"
VULN_ENDPOINT = FVM_URL + "/api/scanresults/active/vulnerabilities/"
HOST_ENDPOINT = FVM_URL + "/api/scanresults/active/hosts/"
SCAN_ENDPOINT = FVM_URL + "/api/scans/"

''' HELPER FUNCTIONS '''
def get_fvm_data(request_url, api_token, **kwargs):
    data = []
    current_data = {}
    resp = requests.get(request_url, headers={'Authorization': 'Token ' + str(API_TOKEN)}, timeout=30, **kwargs)
    resp.raise_for_status()
    current_data = json.loads(resp.text)
    data.extend(current_data.get('results', []))
    while current_data.get('next', None):
        resp = requests.get(url=current_data.get('next'), headers={'Authorization': 'Token ' + str(API_TOKEN)}, timeout=30)
        if not resp.ok:
            demisto.debug("FrontlineVM get_fvm_data -- response error (status code: "+str(resp.status_code)+")")
        current_data = {}
        resp.raise_for_status()
        current_data = json.loads(resp.text)
        data.extend(current_data.get('results', []))
    return data

def parse_params(param_dict):
    param_index = 0
    new_param_dict = {}
    for key in param_dict:
        new_key = "_"+str(param_index)+"_"+key
        new_param_dict[new_key] = param_dict[key]
        param_index += 1
    return new_param_dict


def get_fetch_frequency_td():
    ''' Returns the INCIDENT_FREQUENCY as a datetime.timedelta object    '''
    fetch_frequency = INCIDENT_FREQUENCY.split()
    demisto.debug("FrontlineVM get_fetch_incident_td -- using frequency: " + str(fetch_frequency))
    if "min" in str(fetch_frequency[1]):
        return timedelta(minutes=int(fetch_frequency[0]))
    else:
        return timedelta(hours=int(fetch_frequency[0]))


def get_vuln_incidents(vulns, start_time_dt):
    incidents = []
    for vuln in vulns:
        av_date_created_str = vuln.get('active_view_date_created')
        av_date_created_dt = datetime.strptime(av_date_created_str, "%Y-%m-%dT%H:%M:%S.%fZ")

        # Skip if vuln created before current start_time:
        if (av_date_created_dt < start_time_dt):
            continue
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
                demisto.debug("FrontlineVM fetch_incident -- frequency (" + str(fetch_frequency_td) +") within last start_time, sending empty incidents.")
                demisto.setLastRun({'start_time': last_run.get('start_time')})
                demisto.incidents([])
                return
            else:
                demisto.debug("FrontlineVM fetch_incident -- frequency (" + str(fetch_frequency_td) +") exceeds last start_time, continuing to fetch incident events.")
        else:
            now = datetime.utcnow()
            start_time = now.strftime("%s")
        start_time_dt = datetime.utcfromtimestamp(int(start_time))
        start_time_str = start_time_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        demisto.debug("FrontlineVM fetch_incident -- continuing with start_time of " + str(start_time_str))

        # Fetch vulnerabilities:
        req_params = {}
        req_params['lte_vuln_severity_ddi'] = str(INCIDENT_VULN_SEVERITY)
        req_params['gte_vuln_date_created'] = start_time_str
        req_params = parse_params(req_params)
        vulns = get_fvm_data(VULN_ENDPOINT, API_TOKEN, params=req_params)

        # Create incidents
        if vulns:
            demisto.debug("FrontlineVM fetch_incidents -- getting all incidents.")
            incidents = get_vuln_incidents(vulns, start_time_dt)
        else:
            demisto.debug("FrontlineVM fetch_incidents -- no new vulnerabilities found, no incidents created.")
            incidents = []

        now = datetime.utcnow()
        start_time = now.strftime("%s")
        demisto.info("FrontlineVM fetch_incident -- creating new start_time of " + str(now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))
        demisto.setLastRun({'start_time': start_time})
        demisto.incidents(incidents)
        #return
    except Exception as err:
        return_error("ERROR FrontlineVM fetching_incidents -- " + str(err.message))


''' COMMAND FUNCTIONS   '''
def get_assets(ip_address, hostname, label_name, scanned_within_last):
    ''' Returns a list of assets from Frontline.Cloud based on user input from Arguments    '''
    # Prepare parameters for Frontline API request:
    req_params = {}
    if ip_address:
        req_params['eq_host_ip_address'] = str(ip_address)
    if hostname:
        req_params['iexact_host_hostname'] = str(hostname)
    if label_name:
        req_params['eq_host_labels'] = str(label_name)
    if scanned_within_last:
        now = datetime.utcnow()
        query_date = (now - timedelta(days=int(scanned_within_last))).replace(hour=0, minute=0, second=0, microsecond=0)
        query_date = datetime.strftime(query_date, "%Y-%m-%dT%H:%M:%SZ")
        req_params['gte_host_date_created'] = str(query_date)
    req_params = parse_params(req_params)
    hosts = get_fvm_data(HOST_ENDPOINT, API_TOKEN, params=req_params)
    return hosts


def get_assets_command():
    ''' Pulls host information from FrontlineVM '''
    # Get Arguments:
    ip_address = demisto.args().get('ip_address', None)
    hostname = demisto.args().get('hostname', None)
    label_name = demisto.args().get('label_name', None)
    scanned_within_last = demisto.args().get('scanned_within_last', None)

    hosts = get_assets(ip_address, hostname, label_name, scanned_within_last)

    # Condensing Host data for HumanReadable and EntryContext:
    host_headers = ['host-id', 'hostname', 'ip-address', 'dns-hostname', 'mac-address', 'os', 'os-type', 'ddi-critical-count']
    get_asset_output = {}
    host_list = []
    ip_list = []
    host_id_list = []
    for host in hosts:
        host_obj = {}
        host_obj['host-id'] = host.get('id', None)
        host_obj['hostname'] = host.get('hostname', '')
        host_obj['ip-address'] = host.get('ip_address', '')
        host_obj['dns-hostname'] = host.get('dns_name', '')
        host_obj['mac-address'] = host.get('mac_address', '')
        host_obj['os'] = host.get('os')
        host_obj['os-type'] = host.get('os_type')
        host_obj['ddi-critical-count'] = host['active_view_vulnerability_severity_counts']['weighted']['ddi']['counts']['critical']
        host_list.append(host_obj)
        ip_list.append(host.get('ip_address'))
        host_id_list.append(host.get('id'))

    # Linking Context:
    get_asset_output['Hosts'] = host_list
    get_asset_output['HostId'] = host_id_list
    get_asset_output['IPList'] = ip_list

    ec = {'FrontlineVM(val.Hosts && val.Hosts == obj.Hosts)': get_asset_output}

    output = {
        'Type': entryTypes['note'],         # indicates entry type to the War room
        'Contents': hosts,                  # raw data callable from War Room CLI with "raw-response=true"
        'ContentsFormat': formats['json'],  # format of the content from the Contents field
        'HumanReadable': tableToMarkdown('FrontlineVM: Assets Found', host_list, headers=host_headers, removeNull=True),    # content that displays in the War Room
        'ReadableContentsFormat': formats['markdown'],      # Format of the content from the HumanReadable field
        'EntryContext': ec  # Data added to the investigation context (Output Context), which you can use in playbooks
    }
    return output

def get_vulns(severity, min_severity, days_older_than, days_newer_than, host_id):
    # Prepare parameters for Frontline API request:
    req_params = {}
    if min_severity and severity:
        demisto.log("FrontlineVM get_vulns_command -- Selecting both \'min_severity\' and \'severity\' arguments will yield to selecting the minimum severity of vulnerabilities to pull.")
    if min_severity:
        req_params['lte_vuln_severity_ddi'] = str(min_severity)
    elif severity:
        req_params['eq_vuln_severity_ddi'] = str(severity)
    if days_older_than:
        now = datetime.utcnow()
        query_date = (now - timedelta(days=int(days_older_than))).replace(hour=0, minute=0, second=0, microsecond=0)
        query_date = datetime.strftime(query_date, "%Y-%m-%dT%H:%M:%SZ")
        req_params['lte_vuln_active_view_date_first_created']=str(query_date)
    if days_newer_than:
        now = datetime.utcnow()
        query_date = (now - timedelta(days=int(days_newer_than))).replace(hour=0, minute=0, second=0, microsecond=0)
        query_date = datetime.strftime(query_date, "%Y-%m-%dT%H:%M:%SZ")
        req_params['gte_vuln_date_created'] = str(query_date)
    if host_id:
        VulnEndpoint = HOST_ENDPOINT + str(host_id) + "/vulnerabilities/"
    else:
        VulnEndpoint = VULN_ENDPOINT
    req_params = parse_params(req_params)
    vulns = get_fvm_data(VulnEndpoint, API_TOKEN, params=req_params)
    return vulns


def get_vuln_outputs(vuln_list):
    output = []
    vuln_data_output = {}
    vuln_stat_output = {}

    vuln_severity_count = {
        'critical':0,
        'high':0,
        'medium':0,
        'low':0,
        'trivial':0,
        'info':0
    }

    vuln_data_obj = {}
    vuln_stat_obj = {}
    vuln_stat_obj['vulnerability-count'] = len(vuln_list)
    vuln_data_list = []
    ip_list = []

    if len(vuln_list) > 0:
        demisto.debug('FrontlineVM get_vuln_outputs -- interating through vulns')
    else:
        demisto.debug('FrontlineVM get_vuln_outputs -- get vulns request returned empty')
    # Condensing Vuln data for HumanReadable and EntryContext:
    for vuln in vuln_list:
        vuln_obj = {}
        vuln_obj['vuln-id'] = vuln.get('id')
        vuln_obj['hostname'] = vuln.get('hostname')
        vuln_obj['ip-address'] = vuln.get('ip_address')
        vuln_obj['vuln-title'] = vuln.get('title')
        vuln_obj['date-created'] = vuln.get('active_view_date_created')
        vuln_obj['ddi-severity'] = vuln['severities']['ddi']
        vuln_obj['vuln-info'] = vuln.get('data')
        vuln_severity_count[str(vuln['severities']['ddi'])] += 1
        vuln_data_list.append(vuln_obj)
        ip_list.append(vuln.get('ip_address'))

    vuln_data_headers = ['vuln-id', 'hostname', 'ip-address', 'vuln-title', 'date-created', 'ddi-severity', 'vuln-info']
    vuln_stat_headers = ['vulnerability-count']
    for k, v in vuln_severity_count.items():
        if v > 0:
            vuln_stat_headers.append(str(k) + "-severity-count")
            vuln_stat_obj[str(k)+"-severity-count"] = v

    vuln_data_output['Vulns'] = vuln_data_list
    vuln_data_output['IPList'] = ip_list
    vuln_stat_output = vuln_stat_obj

    vuln_data_ec = {
        'FrontlineVM(val.Vulns && val.Vulns == obj.Vulns)': vuln_data_output
    }

    data_output = {
        'Type': entryTypes['note'],
        'Contents': vuln_list,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('FrontlineVM: Vulnerabilities Found', vuln_data_list, headers=vuln_data_headers, removeNull=True),
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext':vuln_data_ec
    }
    output.append(data_output)

    vuln_stat_ec = {
        'FrontlineVM(val.Object && val.Object == obj.Object)': vuln_stat_output
    }

    stat_output = {
        'Type': entryTypes['note'],
        'Contents': vuln_stat_output,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('FrontlineVM: Vulnerability Statisctics', vuln_stat_output, headers=vuln_stat_headers),
        'EntryContext': vuln_stat_ec

    }
    output.append(stat_output)
    return output


def get_vulns_command():
    ''' Pulls vulnerability information from FrontlineVM    '''
    # Get Arugments:
    severity = demisto.args().get('severity')
    min_severity = demisto.args().get('min_severity')
    days_older_than = demisto.args().get('days_older_than')
    days_newer_than = demisto.args().get('days_newer_than')
    host_id = demisto.args().get('host_id')
    ip_address = demisto.args().get('ip_address')

    vulns = []
    if ip_address:
        host = get_fvm_data(HOST_ENDPOINT, API_TOKEN, params={'_0_eq_host_ip_address': str(ip_address)})
        if len(host) >= 1:
            host_id = host[0].get('id')
        else:
            demisto.debug('Frontline.Cloud get_vuln_command -- Host not found within Frontline.Cloud given host IP Address.')
    vulns = get_vulns(severity, min_severity, days_older_than, days_newer_than, host_id)
    return get_vuln_outputs(vulns)


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
    ''' Converts IP from string to number. '''
    return struct.unpack("!L", socket.inet_aton(ip_address))[0]


def long2ip(ip_address):
    ''' Converts IP from number to string. '''
    return socket.inet_ntoa(struct.pack("!L", ip_address))


def get_network_data():
    try:
        url = FVM_URL + "/api/networkprofiles/?_0_eq_networkprofile_internal=True"
        resp = requests.get(url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
        resp.raise_for_status()
        return json.loads(resp.text)
    except Exception as err:
        print('ERROR getting network data: ' + str(err))
    return None


def get_scan_data(network_data, low_ip, high_ip):
    for profile in network_data:
        #If there is no scanner using this profile, then continue to the next profile
        if len(profile.get('scanner_names', "")) == 0:
            continue
        status_url = FVM_URL + "/api/scanners/" + str(profile.get('scanner_ids')[0]) + "/"
        status_resp = requests.get(status_url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
        status_resp.raise_for_status()
        status = json.loads(status_resp.text)
        if status.get('status', '') == 'online':
            url = FVM_URL + "/api/networkprofiles/" + str(profile['id']) + "/rules/"
            profile_data = []
            current_data = None
            have_all_data = False
            while not have_all_data:
                resp = requests.get(url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
                resp.raise_for_status()
                current_data = json.loads(resp.text)
                profile_data.extend(current_data.get('results', []))
                if (current_data.get('next', None)):
                    url = current_data.get('next')
                else:
                    have_all_data = True
            for rule in profile_data:
                if rule.get('ip_address_range', None):
                    if (rule['ip_address_range']['high_ip_number'] >= high_ip) and (rule['ip_address_range']['low_ip_number'] <= low_ip):
                        return json.dumps({
                            'scanner_name': profile['scanner_names'][0],
                            'scanner_id': profile['scanner_ids'][0],
                            'profile_name': profile['name'],
                            'profile_id': profile['id']
                        })
    return_error("Error: no scan data found.")


def get_business_group():
    url = FVM_URL + "/api/session/"
    resp = requests.get(url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
    resp.raise_for_status()
    data = json.loads(resp.text)
    if data.get('account_allow_businessgroups_setting', None):
        bus_url = FVM_URL + "/api/businessgroups/?_0_eq_businessgroup_name=Enterprise Admins"
        bus_resp = requests.get(bus_url, headers={'Authorization': 'Token ' + str(API_TOKEN)})
        bus_data = json.loads(bus_resp.text)
        for grp in bus_data:
            return grp
    return None


def build_scan(low_ip_address, high_ip_address, scan_policy):
    low_ip_number = ip2long(low_ip_address)
    high_ip_number = ip2long(high_ip_address)

    # Check IP address order if range provided:
    if (low_ip_address != high_ip_address) and (low_ip_number > high_ip_number):
        temp_ip_number = low_ip_number
        low_ip_number = high_ip_number
        high_ip_number = temp_ip_number
        temp_ip_address = low_ip_address
        low_ip_address = high_ip_address
        high_ip_address = temp_ip_address

    scan_policy = str(scan_policy)
    network_data = get_network_data()
    scanner_data = json.loads(get_scan_data(network_data, low_ip_number, high_ip_number))
    now = datetime.now(_tz_UTC())
    tz = "UTC"
    tzoffset = 0
    scan = {}
    if low_ip_address == high_ip_address:
        scan['name'] = ("Demisto Scan "+" ["+str(low_ip_address)+"]")
    elif low_ip_address != high_ip_address:
        scan['name'] = ("Demisto Scan "+"["+str(low_ip_address)+"-"+str(high_ip_address)+"]")
    else:
        scan['name'] = ("Demisto Scan")
    scan['description'] = "New network device auto scan launch from Demisto."
    scan['schedule'] = {
        "id": None,
        "end_date": None,
        "start_date":now.strftime("%Y-%m-%dT%H:%M:%S%z"),
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

    business_group = get_business_group()
    if business_group:
        scan['businessgroups'] = [{"id": business_group['id']}]
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
            if str(policy_selected) == policy.get('name', ""):
                return True
        return False
    except Exception as err:
        demisto.error("FrontlineVM scan_policy_exists -- Exception: " + str(err.message))
        return_error(err.message)


def scan_asset_command():
    ip_address = demisto.args().get('ip_address')
    scan_policy = str(demisto.args().get('scan_policy'))
    if scan_policy != "Default" and not scan_policy_exists(scan_policy):
        return_error("Scan Policy entered '" + str(scan_policy) + "' does not exist.")

    try:
        scan_response = scan_asset(ip_address, scan_policy)

        # Condense Scan data for HumanReadable and EntryContext:
        scan_output = {}
        low_ip = str(scan_response['adhoc_targets'][0]['ip_address_range']['low_ip_address'])
        high_ip = str(scan_response['adhoc_targets'][0]['ip_address_range']['high_ip_address'])
        if low_ip == high_ip:
            scan_headers = ['scan-id', 'name', 'ip-address', 'policy']
            scan_output['ip-address'] = scan_response['adhoc_targets'][0]['ip_address_range']['low_ip_address']
        else:
            scan_headers = ['scan-id', 'name', 'ip-address-range', 'Policy']
            scan_output['ip-address-range'] = low_ip + "-" + high_ip

        scan_output['scan-id'] = scan_response.get('id')
        scan_output['name'] = scan_response.get('name')
        scan_output['policy'] = scan_response.get('scan_policy')

        # Linking Context
        ec = {
            'FrontlineVM(val.Scan && val.Scan == obj.Scan)':{
                'Scan':scan_output
            }
        }
        output = {
            'Type': entryTypes['note'], # War room
            'Contents':scan_response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('FrontlineVM: Performing Scan', scan_output, headers=scan_headers, removeNull=True),
            'EntryContext': ec
        }
        return output
    except Exception as err:
        return_error('Error performing scan. Exception: ' + str(err))


def test_module():
    try:
        session_url = FVM_URL + "/api/session/"
        resp = requests.get(session_url, headers={'Authorization':'Token '+str(API_TOKEN)})
        if resp.status_code == 200:
            demisto.results('ok')
        else:
            demisto.error("Test method failed. User has invalid API Token.")
            demisto.results('Test failed, invalid API Token.')
        resp.raise_for_status()
    except Exception as err:
        demisto.results('Test Failed: ' + str(err))


''' EXECUTION CODE  '''
def main():
    LOG('command is %s' % (demisto.command(), ))
    try:
        if demisto.command() == 'test-module':
            test_module()
        if demisto.command() == 'frontline-get-assets':
            demisto.results(get_assets_command())
        if demisto.command() == 'frontline-get-vulns':
            demisto.results(get_vulns_command())
        if demisto.command() == 'frontline-scan-asset':
            demisto.results(scan_asset_command())
        if demisto.command() == 'fetch-incidents':
            fetch_incidents()
    except Exception as e:
        LOG(e)
        LOG.print_log(verbose=False)
        return_error(e.message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
