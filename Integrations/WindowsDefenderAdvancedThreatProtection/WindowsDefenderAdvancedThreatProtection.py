import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
requests.packages.urllib3.disable_warnings()

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBAL VARS '''

SERVER = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
BASE_URL = SERVER + '/api'
TENANT_ID = demisto.params()['tenant_id']
TOKEN = demisto.params()['token']
USE_SSL = not demisto.params().get('unsecure', False)
FETCH_SEVERITY = demisto.params()['fetch_severity'].split(',')
FETCH_STATUS = demisto.params().get('fetch_status').split(',')

''' HELPER FUNCTIONS '''


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_token():
    """
    Check if we have a valid token and if not get one
    """
    ctx = demisto.getIntegrationContext()
    if ctx.get('token') and ctx.get('stored'):
        if epoch_seconds() - ctx.get('stored') < 60 * 60 - 30:
            return ctx.get('token')
    headers = {
        'Authorization': TOKEN,
        'Accept': 'application/json'
    }
    token_url = 'https://demistobot.demisto.com/atp-token'
    r = requests.get(token_url, headers=headers, params={'tenant': TENANT_ID, 'product': 'ATP'}, verify=USE_SSL)
    if r.status_code not in {200, 201}:
        return_error('Error in authentication with the application. Please check the credentials.')
    data = r.json()
    if r.status_code != requests.codes.ok:
        error_object = json.loads(data.get('detail'))
        error_details = error_object.get('error_description')
        if error_details:
            return_error(error_details)
        else:
            return_error(error_object)
    demisto.setIntegrationContext({'token': data.get('token'), 'stored': epoch_seconds()})
    return data.get('token')


def http_request(method, url_suffix, json=None, params=None):

    r = requests.request(
        method,
        BASE_URL + url_suffix,
        json=json,
        headers={
            'Authorization': 'Bearer ' + get_token(),
            'Content-Type': 'application/json'
        }
    )
    if r.status_code not in {200, 201}:
        return_error('Error in API call to ATP [%d] - %s' % (r.status_code, r.reason))
    if not r.text:
        return {}
    return r.json()


def alert_to_incident(alert):
    incident = {}
    incident['rawJSON'] = json.dumps(alert)
    incident['name'] = 'Windows Defender ATP Alert ' + alert['id']
    return incident


def capitalize_first_letter(string):
    return string[:1].upper() + string[1:]


''' FUNCTIONS '''


def isolate_machine_command():

    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    isolation_type = demisto.args().get('isolation_type')
    response = isolate_machine(machine_id, comment, isolation_type)
    ec = {
        'MicrosoftATP.Machine(val.ID && val.ID === obj.ID)': {
            'ID': machine_id,
            'Isolation': {
                'Isolated': True,
                'Requestor': response['requestor'],
                'RequestorComment': response['requestorComment']
            }
        }
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'The isolation request has been submitted successfully',
        'EntryContext': ec
    }
    demisto.results(entry)


def isolate_machine(machine_id, comment, isolation_type):

    cmd_url = '/machines/{}/isolate'.format(machine_id)
    json = {
        'Comment': comment
    }
    if isolation_type:
        json['IsolationType'] = isolation_type
    response = http_request('POST', cmd_url, json=json)
    return response


def unisolate_machine_command():

    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    response = unisolate_machine(machine_id, comment)
    ec = {
        'MicrosoftATP.Machine(val.ID && val.ID === obj.ID)': {
            'ID': machine_id,
            'Isolation': {
                'Isolated': False,
                'Requestor': response['requestor'],
                'RequestorComment': response['requestorComment']
            }
        }
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'The request to stop the isolation has been submitted successfully',
        'EntryContext': ec
    }
    demisto.results(entry)


def unisolate_machine(machine_id, comment):

    cmd_url = '/machines/{}/unisolate'.format(machine_id)
    json = {
        'Comment': comment
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_machines_command():

    machines = get_machines()['value']

    hostname = demisto.args().get('hostname')
    ip = demisto.args().get('ip')
    risk_score = demisto.args().get('risk_score')
    health_status = demisto.args().get('health_status')

    output = []
    endpoint_context = []

    for machine in machines:
        computer_dns_name = machine['computerDnsName']
        last_external_ip = machine['lastExternalIpAddress']
        machine_risk_score = machine['riskScore']
        machine_health_status = machine['healthStatus']
        if (hostname and hostname != computer_dns_name) or (ip and ip != last_external_ip) or \
                (risk_score and risk_score != machine_risk_score) or \
                (health_status and health_status != machine_health_status):
            continue
        current_machine_output = {
            'ComputerDNSName': computer_dns_name,
            'ID': machine['id'],
            'AgentVersion': machine['agentVersion'],
            'FirstSeen': machine['firstSeen'],
            'LastSeen': machine['lastSeen'],
            'HealthStatus': machine_health_status,
            'IsAADJoined': machine['isAadJoined'],
            'LastExternalIPAddress': last_external_ip,
            'LastIPAddress': machine['lastIpAddress'],
            'Tags': machine['machineTags'],
            'OSBuild': machine['osBuild'],
            'OSPlatform': machine['osPlatform'],
            'RBACGroupID': machine['rbacGroupId'],
            'RiskScore': machine_risk_score
        }
        current_endpoint_output = {
            'Hostname': machine['computerDnsName'],
            'IPAddress': machine['lastExternalIpAddress'],
            'OS': machine['osPlatform']
        }
        rbac_group_name = machine.get('rbacGroupName')
        if rbac_group_name:
            current_machine_output['RBACGroupName'] = rbac_group_name
        aad_device_id = machine.get('aadDeviceId')
        if aad_device_id:
            current_machine_output['AADDeviceID'] = aad_device_id
        os_version = machine.get('osVersion')
        if os_version:
            current_machine_output['OSVersion'] = os_version
            current_endpoint_output['OSVersion'] = os_version
        output.append(current_machine_output)
        endpoint_context.append(current_endpoint_output)

    if output:
        ec = {
            'MicrosoftATP.Machine(val.ID && val.ID === obj.ID)': output,
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context
        }

        entry = {
            'Type': entryTypes['note'],
            'Contents': machines,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Windows Defender ATP machines', output, removeNull=True),
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def get_machines():

    cmd_url = '/machines'
    response = http_request('GET', cmd_url)
    return response


def get_file_related_machines_command():

    file = demisto.args()['file']
    machines = get_file_related_machines(file)['value']
    if machines:
        output = []
        endpoint_context = []
        for machine in machines:
            current_machine_output = {
                'ComputerDNSName': machine['computerDnsName'],
                'ID': machine['id'],
                'AgentVersion': machine['agentVersion'],
                'FirstSeen': machine['firstSeen'],
                'LastSeen': machine['lastSeen'],
                'HealthStatus': machine['healthStatus'],
                'IsAADJoined': machine['isAadJoined'],
                'LastExternalIPAddress': machine['lastExternalIpAddress'],
                'LastIPAddress': machine['lastIpAddress'],
                'Tags': machine['machineTags'],
                'OSBuild': machine['osBuild'],
                'OSPlatform': machine['osPlatform'],
                'RBACGroupID': machine['rbacGroupId'],
                'RiskScore': machine['riskScore'],
                'RelatedFile': file
            }
            current_endpoint_output = {
                'Hostname': machine['computerDnsName'],
                'IPAddress': machine['lastExternalIpAddress'],
                'OS': machine['osPlatform']
            }
            rbac_group_name = machine.get('rbacGroupName')
            if rbac_group_name:
                current_machine_output['RBACGroupName'] = rbac_group_name
            aad_device_id = machine.get('aadDeviceId')
            if aad_device_id:
                current_machine_output['AADDeviceID'] = aad_device_id
            os_version = machine.get('osVersion')
            if os_version:
                current_machine_output['OSVersion'] = os_version
                current_endpoint_output['OSVersion'] = os_version
            output.append(current_machine_output)
            endpoint_context.append(current_endpoint_output)

        ec = {
            'MicrosoftATP.Machine(val.ID && val.ID === obj.ID)': output,
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context
        }

        title = 'Windows Defender ATP machines related to file {}'.format(file)
        entry = {
            'Type': entryTypes['note'],
            'Contents': machines,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, output, removeNull=True),
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def get_file_related_machines(file):

    cmd_url = '/files/{}/machines'.format(file)
    response = http_request('GET', cmd_url)
    return response


def get_machine_details_command():

    machine_id = demisto.args()['machine_id']
    machine = get_machine_details(machine_id)
    if machine:
        output = []
        endpoint_context = []
        current_machine_output = {
            'ComputerDNSName': machine['computerDnsName'],
            'ID': machine['id'],
            'AgentVersion': machine['agentVersion'],
            'FirstSeen': machine['firstSeen'],
            'LastSeen': machine['lastSeen'],
            'HealthStatus': machine['healthStatus'],
            'IsAADJoined': machine['isAadJoined'],
            'LastExternalIPAddress': machine['lastExternalIpAddress'],
            'LastIPAddress': machine['lastIpAddress'],
            'Tags': machine['machineTags'],
            'OSBuild': machine['osBuild'],
            'OSPlatform': machine['osPlatform'],
            'RBACGroupID': machine['rbacGroupId'],
            'RiskScore': machine['riskScore']
        }
        current_endpoint_output = {
            'Hostname': machine['computerDnsName'],
            'IPAddress': machine['lastExternalIpAddress'],
            'OS': machine['osPlatform']
        }
        rbac_group_name = machine.get('rbacGroupName')
        if rbac_group_name:
            current_machine_output['RBACGroupName'] = rbac_group_name
        aad_device_id = machine.get('aadDeviceId')
        if aad_device_id:
            current_machine_output['AADDeviceID'] = aad_device_id
        os_version = machine.get('osVersion')
        if os_version:
            current_machine_output['OSVersion'] = os_version
            current_endpoint_output['OSVersion'] = os_version
        output.append(current_machine_output)
        endpoint_context.append(current_endpoint_output)
        ec = {
            'MicrosoftATP.Machine(val.ID && val.ID === obj.ID)': output,
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context
        }

        title = 'Windows Defender ATP machine {} details'.format(machine_id)
        entry = {
            'Type': entryTypes['note'],
            'Contents': machine,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, output, removeNull=True),
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def get_machine_details(machine_id):

    cmd_url = '/machines/{}'.format(machine_id)
    response = http_request('GET', cmd_url)
    return response


def block_file_command():

    file_sha1 = demisto.args().get('sha1')
    comment = demisto.args().get('comment')
    title = demisto.args().get('title')
    expiration_time = demisto.args().get('expiration_time')
    severity = demisto.args().get('severity')
    recommended_actions = demisto.args().get('recommended_actions')

    _ = block_file(file_sha1, comment, title, expiration_time, severity, recommended_actions)


def block_file(file_sha1, comment, title, expiration_time, severity, recommended_actions):

    cmd_url = '/tiindicators'
    json = {
        'indicator': file_sha1,
        'indicatorType': 'FileSha1',
        'action': 'AlertAndBlock',
        'title': title,
        'expirationTime': expiration_time,
        'severity': severity,
        'description': comment,
        'recommendedActions': recommended_actions
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_user_related_machines_command():

    user_id = demisto.args()['user_id']

    machines = get_user_related_machines(user_id)['value']

    if machines:
        output = []
        endpoint_context = []
        for machine in machines:
            current_machine_output = {
                'ComputerDNSName': machine['computerDnsName'],
                'ID': machine['id'],
                'AgentVersion': machine['agentVersion'],
                'FirstSeen': machine['firstSeen'],
                'LastSeen': machine['lastSeen'],
                'HealthStatus': machine['healthStatus'],
                'IsAADJoined': machine['isAadJoined'],
                'LastExternalIPAddress': machine['lastExternalIpAddress'],
                'LastIPAddress': machine['lastIpAddress'],
                'Tags': machine['machineTags'],
                'OSBuild': machine['osBuild'],
                'OSPlatform': machine['osPlatform'],
                'RBACGroupID': machine['rbacGroupId'],
                'RiskScore': machine['riskScore'],
                'RelatedFile': file
            }
            current_endpoint_output = {
                'Hostname': machine['computerDnsName'],
                'IPAddress': machine['lastExternalIpAddress'],
                'OS': machine['osPlatform']
            }
            rbac_group_name = machine.get('rbacGroupName')
            if rbac_group_name:
                current_machine_output['RBACGroupName'] = rbac_group_name
            aad_device_id = machine.get('aadDeviceId')
            if aad_device_id:
                current_machine_output['AADDeviceID'] = aad_device_id
            os_version = machine.get('osVersion')
            if os_version:
                current_machine_output['OSVersion'] = os_version
                current_endpoint_output['OSVersion'] = os_version
            output.append(current_machine_output)
            endpoint_context.append(current_endpoint_output)
        ec = {
            'MicrosoftATP.Machine(val.ID && val.ID === obj.ID)': output,
            'Endpoint(val.Hostname && val.Hostname === obj.Hostname)': endpoint_context
        }
        title = 'Windows Defender ATP machines related to file {}'.format(file)
        entry = {
            'Type': entryTypes['note'],
            'Contents': machines,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, output, removeNull=True),
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def get_user_related_machines(user_id):

    cmd_url = '/users/{}/machines'.format(user_id)
    response = http_request('GET', cmd_url)
    return response


def stop_and_quarantine_file_command():

    machine_id = demisto.args().get('machine_id')
    file_sha1 = demisto.args().get('file')
    comment = demisto.args().get('comment')

    _ = stop_and_quarantine_file(machine_id, file_sha1, comment)


def stop_and_quarantine_file(machine_id, file_sha1, comment):

    cmd_url = '/machines/{}/stopAndQuarantineFile'.format(machine_id)
    json = {
        'Comment': comment,
        'Sha1': file_sha1
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def run_antivirus_scan_command():

    machine_id = demisto.args().get('machine_id')
    scan_type = demisto.args().get('scan_type')
    comment = demisto.args().get('comment')

    _ = run_antivirus_scan(machine_id, comment, scan_type)

    demisto.results('Antivirus scan successfully triggered')


def run_antivirus_scan(machine_id, comment, scan_type):

    cmd_url = '/machines/{}/runAntiVirusScan'.format(machine_id)
    json = {
        'Comment': comment,
        'ScanType': scan_type
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def list_alerts_command():

    alerts = list_alerts()['value']

    severity = demisto.args().get('severity')
    status = demisto.args().get('status')

    output = []
    for alert in alerts:
        alert_severity = alert['severity']
        alert_status = alert['status']
        if (severity and severity != alert_severity) or (status and status != alert_status):
            continue
        current_alert_output = {}
        for key, value in alert.iteritems():
            if value or value is False:
                current_alert_output[capitalize_first_letter(key).replace('Id', 'ID')] = value
        output.append(current_alert_output)

    if output:
        ec = {
            'MicrosoftATP.Alert(val.ID && val.ID === obj.ID)': output
        }

        title = 'Windows Defender ATP alerts'

        entry = {
            'Type': entryTypes['note'],
            'Contents': alerts,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, output, removeNull=True),
            'EntryContext': ec
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def list_alerts():
    cmd_url = '/alerts'
    response = http_request('GET', cmd_url)
    return response


def update_alert_command():

    alert_id = demisto.args()['alert_id']
    assigned_to = demisto.args().get('assigned_to')
    status = demisto.args().get('status')
    classification = demisto.args().get('classification')
    determination = demisto.args().get('determination')

    if all(v is None for v in [assigned_to, status, classification, determination]):
        return_error('No arguments were given to update the alert')

    json = {}
    context = {
        'ID': alert_id
    }
    if assigned_to:
        json['assignedTo'] = assigned_to
        context['AssignedTo'] = assigned_to
    if status:
        json['status'] = status
        context['Status'] = status
    if classification:
        json['classification'] = classification
        context['Classification'] = classification
    if determination:
        json['determination'] = determination
        context['Determination'] = determination

    _ = update_alert(alert_id, json)

    ec = {
        'MicrosoftATP.Alert(val.ID && val.ID === obj.ID)': context
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': '',
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Alert {0} was updated successfully'.format(alert_id),
        'EntryContext': ec
    }

    demisto.results(entry)


def update_alert(alert_id, json):
    cmd_url = '/alerts/' + alert_id
    response = http_request('PATCH', cmd_url, json=json)
    return response


def get_alert_related_domains(alert_id):
    cmd_url = '/alerts/{}/domains'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def get_alert_related_files(alert_id):
    cmd_url = '/alerts/{}/files'.format(alert_id)
    response = http_request('GET', cmd_url)['value']
    return response


def get_alert_related_ips(alert_id):
    cmd_url = '/alerts/{}/ips'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def fetch_incidents():

    last_run = demisto.getLastRun()
    if last_run and last_run['last_alert_fetched_time']:
        last_alert_fetched_time = datetime.strptime(last_run['last_alert_fetched_time'], '%Y-%m-%dT%H:%M:%S.%f')
    else:
        last_alert_fetched_time = datetime.now() - timedelta(days=300)

    latest_creation_time = last_alert_fetched_time

    alerts = list_alerts()['value']

    incidents = []

    for alert in alerts:
        # Removing 'Z' from timestamp and converting to datetime
        alert_creation_time = datetime.strptime(alert['alertCreationTime'][:-2], '%Y-%m-%dT%H:%M:%S.%f')
        alert_status = alert['status']
        alert_severity = alert['severity']
        if alert_creation_time > last_alert_fetched_time and alert_status in FETCH_STATUS \
                and alert_severity in FETCH_SEVERITY:
            _ = alert['id']
            # alert['RelatedFiles'] = get_alert_related_files(alert_id)
            # alert['RelatedDomains'] = get_alert_related_domains(alert_id)
            # alert['RelatedIPs'] = get_alert_related_ips(alert_id)
            incident = alert_to_incident(alert)
            incidents.append(incident)
            if alert_creation_time > latest_creation_time:
                latest_creation_time = alert_creation_time

    demisto.setLastRun({
        'last_alert_fetched_time': datetime.strftime(latest_creation_time, '%Y-%m-%dT%H:%M:%S.%f')
    })

    demisto.incidents(incidents)


def test_function():
    cmd_url = '/alerts?$top=1'
    _ = http_request('GET', cmd_url)
    demisto.results('ok')


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        test_function()

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

    elif demisto.command() == 'microsoft-atp-isolate-machine':
        isolate_machine_command()

    elif demisto.command() == 'microsoft-atp-unisolate-machine':
        unisolate_machine_command()

    elif demisto.command() == 'microsoft-atp-get-machines':
        get_machines_command()

    elif demisto.command() == 'microsoft-atp-get-file-related-machines':
        get_file_related_machines_command()

    elif demisto.command() == 'microsoft-atp-get-machine-details':
        get_machine_details_command()

    elif demisto.command() == 'microsoft-atp-block-file':
        block_file_command()

    elif demisto.command() == 'microsoft-atp-get-user-related-machines':
        get_user_related_machines_command()

    elif demisto.command() == 'microsoft-atp-stop-and-quarantine-file':
        stop_and_quarantine_file_command()

    elif demisto.command() == 'microsoft-atp-run-antivirus-scan':
        run_antivirus_scan_command()

    elif demisto.command() == 'microsoft-atp-list-alerts':
        list_alerts_command()

    elif demisto.command() == 'microsoft-atp-update-alert':
        update_alert_command()

except Exception, e:
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
