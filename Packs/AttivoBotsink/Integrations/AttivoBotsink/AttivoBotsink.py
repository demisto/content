import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import json
import os
import socket
import time
from datetime import datetime

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER = demisto.params()['server']
API_USER = demisto.params()['credentials']['identifier']
API_PASS = demisto.params()['credentials']['password']
VERIFY_SSL = not demisto.params()['insecure']

handle_proxy()


class BSAPI:
    BS_DEFAULT_PORT = 8443
    TIMEOUT = 20

    def __init__(self, bs_host, bs_port=BS_DEFAULT_PORT, verify_ssl=False, timeout=TIMEOUT):
        self.bs_host = bs_host
        self.bs_port = bs_port
        self.timeout = timeout
        self.session_key = None
        self.base_url = f"https://{self.bs_host}:{self.bs_port}/api"
        self.verify_ssl = verify_ssl

    def do_request(self, url, data=None, headers=None, files=None, method=None, content_type='application/json',
                   json_dump=True):
        # Guess the method if not provided
        if not method:
            if data:
                method = 'post'

            else:
                method = 'get'

        headers = {}
        if self.session_key:
            headers = {'sessionKey': self.session_key}

        if content_type:
            headers['content-type'] = content_type

        url = self.base_url + url
        # Convert data dictionary to a string
        if data and json_dump:
            data = json.dumps(data)

        request_func = getattr(requests, method)
        r = None

        try:
            r = request_func(url, headers=headers, data=data, files=files, verify=self.verify_ssl)
        except requests.exceptions.SSLError:
            demisto.error("SSL verification failed")
            demisto.results(f"SSL verification to {url} failed")
        except requests.exceptions.ConnectionError as e:
            demisto.error(f"Could not connect to: {SERVER}")
            demisto.error(f"Exception: {e}")
            demisto.results(f"Could not connect to {SERVER} ({e})")
        except Exception as e:
            demisto.error(f"Generic Exception: {e}")
            demisto.error(f"Type is: {e.__class__.__name__}")

        if r is not None and r.content:
            try:
                json_res = r.json()
            except ValueError:
                return_error(f'Failed deserializing response JSON - {r.content}')
            return json_res
        else:
            return None

    def login(self, bs_user, bs_pass):
        url = "/auth/login"
        login_data = {'userName': base64.b64encode(bs_user.encode()).decode(),
                      'password': base64.b64encode(bs_pass.encode()).decode()}

        login_status = self.do_request(url, data=login_data)
        if login_status and 'sessionKey' in login_status:
            self.session_key = login_status['sessionKey']

        return (login_status)

    def logout(self):
        url = "/auth/logout"
        logout_status = self.do_request(url)
        return (logout_status)

    def deploy_decoys(self, target_ip, vlan=None, decoy_number=1):
        url = "/autodeploy/config"
        if vlan:
            data = {"config": [{"ipAddress": target_ip, "vlanID": vlan, "numberOfIPsToAcquire": decoy_number}]}
        else:
            data = {"config": [{"ipAddress": target_ip, "numberOfIPsToAcquire": decoy_number}]}

        deploy_status = self.do_request(url, data=data, content_type=None)
        return (deploy_status)

    def get_threatdirect_rules(self):
        url = "/nwinterfaces/get"
        td_decoys = self.do_request(url)
        return (td_decoys)

    def get_bs_health(self):
        url = "/device/health"
        health = self.do_request(url)
        return health

    def get_monitoring_rules(self):
        url = "/interfaces/get"
        monitoring_rules = self.do_request(url, data='{}', method='post', json_dump=None)
        return (monitoring_rules)

    def get_deceptive_objects(self, object_type, object_id):
        if object_type == 'USERS':
            if object_id == 'ALL':
                url = "/obj_group_cfg/summary/user"
            else:
                url = f"/obj_group_cfg/user/{object_id}"
        else:
            response = f"Unknown option: {object_type}"
            return (response)

        deceptive_objects = self.do_request(url)
        return (deceptive_objects)

    def get_playbooks(self):
        url = '/pb/getAll'
        return self.do_request(url)

    def run_playbook(self, playbook_id, attacker_ip):
        'This simulates an internal playbook execution based on the attacker IP'
        url = '/pb/runplaybook'
        data = {'attacker_ip': attacker_ip, 'playbook_id': playbook_id}
        return self.do_request(url, data=data)

    def get_events(self, severity_start=None, severity_end=None, timestamp_start=None, timestamp_end=None,
                   offset=None, acknowledged='unacknowledged', attacker_ip=None, category=None,
                   device=None, service=None, target_os=None, target_host=None, target_ip=None,
                   target_vlan=None, keywords=None, description=None, comments=None):

        url = "/eventsquery/alerts"

        query_data = {
            'severity_start': severity_start,
            'severity_end': severity_end,
            'timestampStart': timestamp_start,
            'timestampEnd': timestamp_end,
            'offset': offset,
            'acknowledged': acknowledged,
            'attackerIp': [] if attacker_ip is None else attacker_ip,
            'category': [] if category is None else category,
            'device': [] if device is None else device,
            'service': [] if service is None else service,
            'targetOs': [] if target_os is None else target_os,
            'targetHost': [] if target_host is None else target_host,
            'targetIP': [] if target_ip is None else target_ip,
            'targetVLAN': [] if target_vlan is None else target_vlan,
            'keywords': [] if keywords is None else keywords,
            'description': [] if description is None else description,
            'comments': [] if comments is None else comments
        }

        event_data = self.do_request(url, data=query_data)
        return (event_data)

    def convert_severity_string(self, severity_string):
        conversion = {
            'VeryHigh': 14,
            'Very High': 14,
            'High': 11,
            'Medium': 7,
            'Low': 4,
            'VeryLow': 3,
            'Very Low': 3,
            'SystemActivity': 0,
            'System Activity': 0
        }
        if severity_string in conversion:
            return conversion[severity_string]
        else:
            return None

    def convert_to_demisto_severity(self, attivo_severity):
        if attivo_severity >= 14:  # Very High
            demisto_severity = 3
        elif attivo_severity >= 11:  # High
            demisto_severity = 3
        elif attivo_severity >= 7:  # Medium
            demisto_severity = 2
        else:  # Low
            demisto_severity = 1

        return demisto_severity


def valid_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False


def date_to_epoch(date):
    date_pattern1 = r'\d{4}-\d{2}-\d{2}$'
    date_format1 = '%Y-%m-%d'
    date_pattern2 = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
    date_format2 = '%Y-%m-%dT%H:%M:%SZ'

    epoch = None
    if re.match(date_pattern2, date):
        epoch = int(time.mktime(time.strptime(date, date_format2))) * 1000
    elif re.match(date_pattern1, date):
        epoch = int(time.mktime(time.strptime(date, date_format1))) * 1000

    return epoch


''' EXECUTION CODE '''
attivo_api = BSAPI(SERVER, verify_ssl=VERIFY_SSL)

if demisto.command() == 'attivo-get-events':
    args = demisto.args()
    login_status = attivo_api.login(API_USER, API_PASS)
    attacker_ip = args['attacker_ip']
    severity_string = args['severity']

    start_date = args.get('alerts_start_date')
    if start_date is not None:
        timestampStart = date_to_epoch(start_date)
    else:
        one_day = 24 * 60 * 60
        timestampStart = (int(time.time()) - one_day) * 1000

    end_date = args.get('alerts_end_date')
    if end_date is not None:
        timestampEnd = date_to_epoch(end_date)
    else:
        timestampEnd = int(time.time()) * 1000

    if timestampEnd is None:
        demisto.info(f"Bad date: {end_date}\nDate should be of the format yyyy-mm-dd or yyyy-mm-ddThh:mm:ssZ")
        return_error(f"Bad date: {end_date}\nDate should be of the format yyyy-mm-dd or yyyy-mm-ddThh:mm:ssZ")

    if timestampStart is None:
        demisto.info(
            f"\nBad date: {start_date}\nDate should be of the format yyyy-mm-dd or yyyy-mm-ddThh:mm:ssZ")
        return_error(
            f"\nBad date: {start_date}\nDate should be of the format yyyy-mm-dd or yyyy-mm-ddThh:mm:ssZ")

    severity_end = "15"
    severity_start = attivo_api.convert_severity_string(severity_string)
    attacker_ips = [attacker_ip]

    demisto.info(f"Pulling events for {attacker_ip} and severity {severity_start} from {timestampStart} "
                 f"to {timestampEnd}")

    events = attivo_api.get_events(severity_start=severity_start, severity_end=severity_end,
                                   timestamp_start=timestampStart, timestamp_end=timestampEnd,
                                   attacker_ip=attacker_ips)

    attivo_api.logout()

    brief_events = []
    context = []
    for event in events['eventdata']:
        brief_events.append({
            'Attack Name': event['attackName'],
            'Severity': event['details']['Severity'],
            'Target IP': event['details']['Target IP'],
            'Target OS': event['details']['Target OS'],
            'Timestamp': event['details']['Timestamp'],
        })
        context.append({k.replace(' ', ''): v for k, v in list(event['details'].items())})

    headers = ['Attack Name', 'Severity', 'Timestamp', 'Target IP', 'Target OS']
    entry = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': events['eventdata'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Found {len(brief_events)} events:', brief_events, headers=headers),
        'EntryContext': {'Attivo.Events.Count': len(events['eventdata']),
                         'Attivo.Events.List': context}
    }

    demisto.results(entry)

if demisto.command() == 'fetch-incidents':
    login_status = attivo_api.login(API_USER, API_PASS)
    date_pattern = "%Y-%m-%dT%H:%M:%S.%fZ"
    os.environ['TZ'] = 'UTC'

    FETCH_SEVERITY = demisto.params()['fetch_severity']
    FIRST_FETCH = int(demisto.params()['first_fetch'])

    severity_start = attivo_api.convert_severity_string(FETCH_SEVERITY)
    if not severity_start:
        demisto.info(f"Attivo fetch-incidents: Unknown severity specified ('{FETCH_SEVERITY}') using Medium")
        severity_start = 7  # Medium
    severity_end = "15"  # Very High

    # When run for the first time, get events from the specified number of days
    one_day = 24 * 60 * 60
    first_fetch_seconds = (int(time.time()) - (one_day * FIRST_FETCH)) * 1000
    last_run_time = demisto.getLastRun().get('time', None)

    if last_run_time is None or last_run_time == 0:
        last_run_time = first_fetch_seconds

    demisto.info(f"Attivo fetch-incidents: Last run time {last_run_time}, severity {FETCH_SEVERITY}:{severity_start}")

    new_last_run = 0.0
    incidents = []

    events = attivo_api.get_events(timestamp_start=last_run_time, timestamp_end='now',
                                   severity_start=severity_start, severity_end=severity_end)
    if 'error' in events:
        demisto.error("fetch-incidents error: {}".format(events['error']))
        sys.exit()

    demisto.info("Total new Attivo incidents to add: {}".format(len(events['eventdata'])))

    for event in events['eventdata']:
        event_date = event['timeStamp']
        date_obj = datetime.strptime(event_date, date_pattern)
        event_timestamp = int((date_obj - datetime(1970, 1, 1)).total_seconds()) * 1000 + date_obj.microsecond / 1000
        new_last_run = max(new_last_run, event_timestamp)

        demisto_severity = attivo_api.convert_to_demisto_severity(event['alertLevel'])
        event_type = event['details']['Attack Phase']
        incidents.append({
            'name': event['attackName'],
            'occurred': event_date,
            'details': event['attackDesc'],
            'severity': demisto_severity,
            'type': event_type,
            'rawJSON': json.dumps(event)
        })

    if len(incidents) > 0 and new_last_run > 0:
        new_last_run += 1
        demisto.info(f"Setting new last run value to {new_last_run}")
        demisto.setLastRun({'time': new_last_run})
    else:
        demisto.info("No new Attivo incidents to add")

    logout_status = attivo_api.logout()
    demisto.incidents(incidents)

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    login_status = attivo_api.login(API_USER, API_PASS)

    if login_status and 'sessionKey' in login_status:
        demisto.info("Attivo Login successful (session key = {})".format(login_status['sessionKey']))
        logout_status = attivo_api.logout()
        demisto.results('ok')
        sys.exit(0)
    else:
        demisto.error(f"Login to {SERVER} failed")
        demisto.error(f"API Results: {login_status}")
        demisto.results(f"Login to {SERVER} failed\n{login_status}")

if demisto.command() == 'attivo-list-playbooks':
    login_status = attivo_api.login(API_USER, API_PASS)
    all_playbooks = attivo_api.get_playbooks()
    brief_playbooks = []
    for playbook in all_playbooks['pb']:
        brief_playbook = {
            'ID': playbook['id'],
            'Name': playbook['name']
        }
        demisto.info("INVESTIGATE {}".format(playbook['investigate']))
        if len(playbook['investigate']) > 0:
            investigate_names = []
            for investigate in playbook['investigate']:
                investigate_names.append(investigate['name'])
            brief_playbook['Investigate'] = ', '.join(investigate_names)
        else:
            brief_playbook['Investigate'] = []

        if len(playbook['analyze']) > 0:
            analyze_names = []
            for analyze in playbook['analyze']:
                analyze_names.append(analyze['name'])
            brief_playbook['Analyze'] = ', '.join(analyze_names)
        else:
            brief_playbook['Analyze'] = []

        if len(playbook['manage']) > 0:
            manage_names = []
            for manage in playbook['manage']:
                manage_names.append(manage['name'])
            brief_playbook['Manage'] = ', '.join(manage_names)
        else:
            brief_playbook['Manage'] = []

        if len(playbook['isolate']) > 0:
            isolate_names = []
            for isolate in playbook['isolate']:
                isolate_names.append(isolate['name'])
            brief_playbook['Isolate'] = ', '.join(isolate_names)
        else:
            brief_playbook['Isolate'] = []

        brief_playbooks.append(brief_playbook)

    headers = ['Name', 'ID', 'Investigate', 'Analyze', 'Manage', 'Isolate']
    entry = {
        'Type': entryTypes['note'],
        'Contents': brief_playbooks,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('Attivo playbooks', brief_playbooks, headers=headers),
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {}
    }

    demisto.results(entry)
    logout_status = attivo_api.logout()

if demisto.command() == 'attivo-run-playbook':
    playbook_name = demisto.args()['playbook_name']
    attacker_ip = demisto.args()['attacker_ip']
    playbook_id = None
    playbook_status = None
    login_status = attivo_api.login(API_USER, API_PASS)
    all_playbooks = attivo_api.get_playbooks()
    for playbook in all_playbooks['pb']:
        if playbook['name'] == playbook_name:
            playbook_id = playbook['id']
            break

    if not playbook_id:
        demisto.error(f"ID not found for Attivo playbook named: {playbook_name}")
        status_message = f"Failed: could not find playbook named '{playbook_name}'"
        status = False
    else:
        demisto.info(
            f"Running Attivo playbook named {playbook_name} ({playbook_id}) with attacker IP {attacker_ip}")
        playbook_status = attivo_api.run_playbook(playbook_id, attacker_ip)
        demisto.info(f"Run playbook status = {playbook_status}")

        if 'error' in playbook_status:
            error_text = playbook_status['error']
            status_message = error_text
            status = False
        elif 'status' in playbook_status:
            status_text = playbook_status['status']
            if status_text == 'submitted':
                status = True
                status_message = f"Attivo playbook '{playbook_name}' (ID={playbook_id}) has been run with attacker " \
                                 f"IP {attacker_ip}"
            else:
                status = False
                status_message = f"Attivo playbook has not been run.  Status = '{status_text}'"
        else:
            status = False
            status_message = "Attivo playbook has not been run.  Status = 'Unknown failure'"

    entry = {
        'Type': entryTypes['note'],
        'Contents': playbook_status,
        'ContentsFormat': formats['json'],
        'HumanReadable': status_message,
        'ReadableContentsFormat': formats['text'],
        'EntryContext': {'Attivo.Playbook.Status': status,
                         'Attivo.Playbook.Message': status_message}
    }

    demisto.results(entry)
    logout_status = attivo_api.logout()

if demisto.command() == 'attivo-deploy-decoy':
    vulnerable_ip = demisto.args()['vulnerable_ip']
    decoy_number = demisto.args()['decoy_number']
    login_status = attivo_api.login(API_USER, API_PASS)
    demisto.info(f"Deploying {decoy_number} decoy(s) on the subnet of {vulnerable_ip}")
    deploy_status = {}
    deploy_status = attivo_api.deploy_decoys(vulnerable_ip, decoy_number=decoy_number)
    demisto.info(f"Deployment status = {deploy_status}")

    status = False
    status_text = "Unknown failure"
    if 'result' in deploy_status:
        status_text = deploy_status['result'][0]['success']
        if status_text is True:
            status = True
    elif 'success' in deploy_status:
        status_text = deploy_status['success']
        if status_text is True:
            status = True
    elif 'error' in deploy_status:
        status_text = deploy_status['error']

    if status:
        status_message = f"{decoy_number} new Attivo decoy(s) deployed on the subnet with {vulnerable_ip}"
    else:
        status_message = f"No Attivo decoys have been deployed. {status_text}"

    entry = {
        'Type': entryTypes['note'],
        'Contents': deploy_status,
        'ContentsFormat': formats['json'],
        'HumanReadable': status_message,
        'ReadableContentsFormat': formats['text'],
        'EntryContext': {'Attivo.DeployDecoy.Status': status,
                         'Attivo.DeployDecoy.Message': status_message}
    }

    demisto.results(entry)
    logout_status = attivo_api.logout()

if demisto.command() == 'attivo-list-users':
    demisto.info("Retrieving information about all deceptive users")
    login_status = attivo_api.login(API_USER, API_PASS)

    user_groups = attivo_api.get_deceptive_objects('USERS', 'ALL')
    users = {}  # type: Dict
    for user_group in user_groups['objGroup']:
        group_id = user_group['esid']
        group_name = user_group['name']
        users_in_group = attivo_api.get_deceptive_objects('USERS', group_id)
        for user_object in users_in_group['objGroup']['objects']:
            user = user_object['username']
            if user in users:
                users[user].append(group_name)
            else:
                users[user] = [group_name]

    all_users = []
    for user in sorted(users.keys(), key=lambda x: x.lower()):
        user_entry = {'User': user, 'Groups': ", ".join(users[user])}
        all_users.append(user_entry)

    headers = ['User', 'Groups']
    entry = {
        'Type': entryTypes['note'],
        'Contents': all_users,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('Attivo deceptive users', all_users, headers=headers),
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {}
    }

    demisto.results(entry)
    logout_status = attivo_api.logout()

if demisto.command() == 'attivo-check-user':
    user = demisto.args()['user']
    demisto.info(f"Check Attivo for user = {user}")
    login_status = attivo_api.login(API_USER, API_PASS)

    is_deceptive = False
    this_user_object = None

    user_groups = attivo_api.get_deceptive_objects('USERS', 'ALL')
    in_groups = []
    for user_group in user_groups['objGroup']:
        group_id = user_group['esid']
        users_in_group = attivo_api.get_deceptive_objects('USERS', group_id)
        for user_object in users_in_group['objGroup']['objects']:
            this_user = user_object['username']
            if this_user == user:
                this_user_object = user_object
                is_deceptive = True
                in_groups.append(user_group['name'])
                break

    output_table = {'User': user, 'Is Deceptive': str(is_deceptive), 'Groups': ', '.join(in_groups)}

    entry = {
        'Type': entryTypes['note'],
        'Contents': this_user_object,
        'ContentsFormat': formats['text'],
        'HumanReadable': output_table,
        'ReadableContentsFormat': formats['table'],
        'EntryContext': {
            'Attivo.User.Name': user,
            'Attivo.User.IsDeceptive': is_deceptive,
            'Attivo.User.Groups': in_groups
        }
    }

    demisto.info(
        f"User {user}, deceptive = {is_deceptive}, group(s) = {in_groups}")
    demisto.results(entry)
    logout_status = attivo_api.logout()

if demisto.command() == 'attivo-list-hosts':
    demisto.info('Retrieving information about all deceptive hosts')
    login_status = attivo_api.login(API_USER, API_PASS)

    all_hosts = []

    td_monitoring = attivo_api.get_threatdirect_rules()
    bs_monitoring = attivo_api.get_monitoring_rules()

    if td_monitoring.get('forwarder_vm_monitoring_rules') is not None \
            and td_monitoring.get('forwarder_vm_monitoring_rules').get('forwarderVmMonitoringRules') is not None:

        for rule in td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
            if rule['type'] == 'onNet':
                td_type = "EP"
            else:
                td_type = "VM"

            host_names = []
            if 'dnsName' in rule and rule['dnsName']:
                host_names.append(rule['dnsName'])

            host_entry = {'IP': rule['ip'],
                          'MAC': rule['customized_mac'],
                          'VLAN': rule['vlanID'],
                          'DHCP': rule['dhcpip'],
                          'TD Name': rule['threatDirectName'],
                          'TD Type': td_type,
                          'Host Name': ', '.join(host_names)
                          }
            all_hosts.append(host_entry)

    if bs_monitoring.get('cfg_monitoring_rules') is not None \
            and bs_monitoring.get('cfg_monitoring_rules').get('monitoringRules') is not None:

        for rule in bs_monitoring['cfg_monitoring_rules']['monitoringRules']:
            # demisto.info("BS RULE: {}".format(rule))
            vlan = rule['vlanID']
            if vlan == -1:
                vlan = None

            host_names = []
            if 'dnsName' in rule and rule['dnsName']:
                host_names.append(rule['dnsName'])
            if 'interfaceName' in rule and rule['interfaceName']:
                host_names.append(rule['interfaceName'])

            host_entry = {'IP': rule['ipAddress'],
                          'MAC': rule['externalMAC'],
                          'DHCP': rule['isDHCPIP'],
                          'VLAN': vlan,
                          'User Defined': rule['userDefined'],
                          'Host Name': ", ".join(host_names)
                          }
            if td_monitoring is not None:
                host_entry['TD Name'] = ''
                host_entry['TD Type'] = ''
            all_hosts.append(host_entry)

    headers = ['IP', 'Host Name', 'MAC', 'VLAN', 'DHCP']

    if td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
        headers.append('TD Name')
        headers.append('TD Type')

    entry = {
        'Type': entryTypes['note'],
        'Contents': all_hosts,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown(f"Attivo deceptive hosts (network decoys): {len(all_hosts)}",
                                         all_hosts, headers=headers),
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {}
    }

    demisto.results(entry)
    logout_status = attivo_api.logout()

if demisto.command() == 'attivo-check-host':
    host = demisto.args()['host']
    demisto.info(f"Check Attivo for host = {host}")
    login_status = attivo_api.login(API_USER, API_PASS)

    is_deceptive = False
    this_rule = None
    host_info = {}

    if valid_ip(host):
        ip_address = host
        host_name = None
    else:
        host_name = host
        ip_address = None

    # Check native Monitoring Rules
    bs_monitoring = attivo_api.get_monitoring_rules()
    if bs_monitoring is not None and bs_monitoring.get('cfg_monitoring_rules') is not None and \
            bs_monitoring.get('cfg_monitoring_rules').get('monitoringRules') is not None:

        for rule in bs_monitoring['cfg_monitoring_rules']['monitoringRules']:
            this_ip = rule['ipAddress']
            mac = rule['externalMAC']
            dhcp = rule['isDHCPIP']
            vlan = rule['vlanID']
            if vlan == -1:
                vlan = None
            user_defined = rule['userDefined']
            this_host_name = []
            if 'dnsName' in rule and rule['dnsName']:
                this_host_name.append(rule['dnsName'])
            if 'interfaceName' in rule and rule['interfaceName']:
                this_host_name.append(rule['interfaceName'])

            if (ip_address and this_ip == ip_address) or (host_name and this_host_name and host_name in this_host_name):
                this_rule = rule
                is_deceptive = True
                demisto.info(
                    f"Attivo BOTSink IP/Host match ({this_ip}) ({this_host_name}) ({user_defined}) ({mac}) ({dhcp}) ({vlan})")
                host_info = {'ip': this_ip, 'name': this_host_name, 'user_defined': user_defined, 'mac': mac,
                             'dhcp': dhcp, 'vlan': vlan}
                break

    if not is_deceptive:
        # Check ThreatDirect Monitoring Rules
        td_monitoring = attivo_api.get_threatdirect_rules()
        if td_monitoring is not None and td_monitoring.get('forwarder_vm_monitoring_rules') is not None \
                and td_monitoring.get('forwarder_vm_monitoring_rules').get('forwarderVmMonitoringRules') is not None:

            for rule in td_monitoring['forwarder_vm_monitoring_rules']['forwarderVmMonitoringRules']:
                this_ip = rule['ip']
                this_host_name = []
                mac = rule['customized_mac']
                vlan = rule['vlanID']
                dhcp = rule['dhcpip']
                td_name = rule['threatDirectName']
                if rule['type'] == 'onNet':
                    td_type = "EP"
                else:
                    td_type = "VM"
                if 'dnsName' in rule and rule['dnsName']:
                    this_host_name.append(rule['dnsName'])

                if (ip_address and this_ip == ip_address) or (
                        host_name and this_host_name and host_name in this_host_name):
                    this_rule = rule
                    is_deceptive = True
                    demisto.info(
                        f"Attivo ThreatDirect IP match ({this_ip}) ({this_host_name}) ({mac}) ({dhcp}) ({vlan}) ({td_name}) ({td_type})")
                    host_info = {'ip': this_ip, 'name': this_host_name, 'mac': mac, 'dhcp': dhcp, 'vlan': vlan,
                                 'td_name': td_name, 'td_type': td_type}
                    break
                # elif host_name and this_host_name and host_name in this_host_name:
                #   this_rule = rule
                #   is_deceptive = True
                #   demisto.info("Attivo ThreatDirect host match ({ip}) ({name})
                #   ({user_defined}) ({mac}) ({dhcp}) ({vlan})".format(this_ip, #this_host_name,
                #   user_defined, mac, dhcp, vlan))
                # break

    if is_deceptive:
        output_table = {'Is Deceptive': 'True',
                        'IP Address': this_ip,
                        'Host Names': ', '.join(this_host_name),
                        'MAC Address': mac,
                        'DHCP': str(dhcp),
                        'User Defined': str(user_defined),
                        'VLAN': vlan
                        }
    else:
        output_table = {'Is Deceptive': 'False',
                        'IP Address': ip_address,
                        'Host Names': host_name,
                        'MAC Address': '',
                        'DHCP': '',
                        'User Defined': '',
                        'VLAN': ''
                        }

    entry = {'Type': entryTypes['note'],
             'Contents': output_table,
             'ContentsFormat': formats['table'],
             'HumanReadable': output_table,
             'ReadableContentsFormat': formats['table'],
             'EntryContext': {'Attivo.Host.HostInfo': host_info,
                              'Attivo.Host.IsDeceptive': is_deceptive
                              }
             }

    demisto.info(f"Deception status for {host} is {is_deceptive}")
    demisto.results(entry)
    logout_status = attivo_api.logout()
