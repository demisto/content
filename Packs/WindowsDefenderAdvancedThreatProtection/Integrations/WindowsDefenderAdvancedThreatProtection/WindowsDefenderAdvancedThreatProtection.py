import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
AUTH_AND_TOKEN_URL = demisto.params()['auth_id'].split('@')
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = demisto.params()['enc_key']
USE_SSL = not demisto.params().get('insecure', False)
FETCH_SEVERITY = demisto.params()['fetch_severity'].split(',')
FETCH_STATUS = demisto.params().get('fetch_status').split(',')
if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
else:
    TOKEN_RETRIEVAL_URL = AUTH_AND_TOKEN_URL[1]
APP_NAME = 'ms-defender-atp'

''' HELPER FUNCTIONS '''


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """

    Args:
        content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key (str): encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """
    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)
    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


def get_access_token():
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    valid_until = integration_context.get('valid_until')
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token
    headers = get_x_content_info_headers()
    headers['Accept'] = 'application/json'
    dbot_response = requests.post(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        data=json.dumps({
            'app_name': APP_NAME,
            'registration_id': AUTH_ID,
            'encrypted_token': get_encrypted(TENANT_ID, ENC_KEY)
        }),
        verify=USE_SSL
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info('Authentication failure from server: {} {} {}'.format(
                dbot_response.status_code, dbot_response.reason, dbot_response.text))
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += ' Server message: {}'.format(server_msg)
        except Exception as ex:
            demisto.error('Failed parsing error response - Exception: {}'.format(ex))
        raise Exception(msg)
    try:
        gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
        demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    expires_in = parsed_response.get('expires_in', 3595)
    time_now = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    demisto.setIntegrationContext({
        'access_token': access_token,
        'valid_until': time_now + expires_in
    })
    return access_token


def http_request(method, url_suffix, json=None, params=None):

    token = get_access_token()
    r = requests.request(
        method,
        BASE_URL + url_suffix,
        json=json,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        verify=USE_SSL
    )
    if r.status_code not in {200, 201}:
        try:
            error = r.json().get('error')
            msg = error['message'] if 'message' in error else r.reason
            return_error('Error in API call to ATP [%d] - %s' % (r.status_code, msg))
        except ValueError:
            msg = r.text if r.text else r.reason
            return_error('Error in API call to ATP [%d] - %s' % (r.status_code, msg))
    if not r.text:
        return {}
    try:
        return r.json()
    except ValueError:
        return {}


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
                'Requestor': response.get('requestor'),
                'RequestorComment': response.get('requestorComment')
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
                'Requestor': response.get('requestor'),
                'RequestorComment': response.get('requestorComment')
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

    machines = get_machines().get('value', [])

    hostname = demisto.args().get('hostname')
    ip = demisto.args().get('ip')
    risk_score = demisto.args().get('risk_score')
    health_status = demisto.args().get('health_status')

    output = []
    endpoint_context = []

    for machine in machines:
        computer_dns_name = machine.get('computerDnsName')
        last_external_ip = machine.get('lastExternalIpAddress')
        machine_risk_score = machine.get('riskScore')
        machine_health_status = machine.get('healthStatus')
        if (hostname and hostname != computer_dns_name) or (ip and ip != last_external_ip) or \
                (risk_score and risk_score != machine_risk_score) or \
                (health_status and health_status != machine_health_status):
            continue
        current_machine_output = {
            'ComputerDNSName': computer_dns_name,
            'ID': machine.get('id'),
            'AgentVersion': machine.get('agentVersion'),
            'FirstSeen': machine.get('firstSeen'),
            'LastSeen': machine.get('lastSeen'),
            'HealthStatus': machine_health_status,
            'IsAADJoined': machine.get('isAadJoined'),
            'LastExternalIPAddress': last_external_ip,
            'LastIPAddress': machine.get('lastIpAddress'),
            'Tags': machine.get('machineTags'),
            'OSBuild': machine.get('osBuild'),
            'OSPlatform': machine.get('osPlatform'),
            'RBACGroupID': machine.get('rbacGroupId'),
            'RiskScore': machine_risk_score
        }
        current_endpoint_output = {
            'Hostname': machine.get('computerDnsName'),
            'IPAddress': machine.get('lastExternalIpAddress'),
            'OS': machine.get('osPlatform')
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
    else:
        entry = 'No results found'  # type: ignore
    demisto.results(entry)


def get_machines():

    cmd_url = '/machines'
    response = http_request('GET', cmd_url)
    return response


def get_file_related_machines_command():

    file = demisto.args()['file']
    machines = get_file_related_machines(file).get('value', [])
    if machines:
        output = []
        endpoint_context = []
        for machine in machines:
            current_machine_output = {
                'ComputerDNSName': machine.get('computerDnsName'),
                'ID': machine.get('id'),
                'AgentVersion': machine.get('agentVersion'),
                'FirstSeen': machine.get('firstSeen'),
                'LastSeen': machine.get('lastSeen'),
                'HealthStatus': machine.get('healthStatus'),
                'IsAADJoined': machine.get('isAadJoined'),
                'LastExternalIPAddress': machine.get('lastExternalIpAddress'),
                'LastIPAddress': machine.get('lastIpAddress'),
                'Tags': machine.get('machineTags'),
                'OSBuild': machine.get('osBuild'),
                'OSPlatform': machine.get('osPlatform'),
                'RBACGroupID': machine.get('rbacGroupId'),
                'RiskScore': machine.get('riskScore'),
                'RelatedFile': file
            }
            current_endpoint_output = {
                'Hostname': machine.get('computerDnsName'),
                'IPAddress': machine.get('lastExternalIpAddress'),
                'OS': machine.get('osPlatform')
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
    else:
        entry = 'No results found'  # type: ignore
    demisto.results(entry)


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
            'ComputerDNSName': machine.get('computerDnsName'),
            'ID': machine.get('id'),
            'AgentVersion': machine.get('agentVersion'),
            'FirstSeen': machine.get('firstSeen'),
            'LastSeen': machine.get('lastSeen'),
            'HealthStatus': machine.get('healthStatus'),
            'IsAADJoined': machine.get('isAadJoined'),
            'LastExternalIPAddress': machine.get('lastExternalIpAddress'),
            'LastIPAddress': machine.get('lastIpAddress'),
            'Tags': machine.get('machineTags'),
            'OSBuild': machine.get('osBuild'),
            'OSPlatform': machine.get('osPlatform'),
            'RBACGroupID': machine.get('rbacGroupId'),
            'RiskScore': machine.get('riskScore')
        }
        current_endpoint_output = {
            'Hostname': machine.get('computerDnsName'),
            'IPAddress': machine.get('lastExternalIpAddress'),
            'OS': machine.get('osPlatform')
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
    else:
        entry = 'No results found'  # type: ignore
    demisto.results(entry)


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

    block_file(file_sha1, comment, title, expiration_time, severity, recommended_actions)


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


def get_user_related_machines(user_id):

    cmd_url = '/users/{}/machines'.format(user_id)
    response = http_request('GET', cmd_url)
    return response


def stop_and_quarantine_file_command():

    machine_id = demisto.args().get('machine_id')
    file_sha1 = demisto.args().get('file')
    comment = demisto.args().get('comment')

    stop_and_quarantine_file(machine_id, file_sha1, comment)


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

    run_antivirus_scan(machine_id, comment, scan_type)

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

    alerts = list_alerts().get('value', [])

    severity = demisto.args().get('severity')
    status = demisto.args().get('status')

    output = []
    for alert in alerts:
        alert_severity = alert.get('severity')
        alert_status = alert.get('status')
        if (severity and severity != alert_severity) or (status and status != alert_status):
            continue
        current_alert_output = {}
        for key, value in alert.items():
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
    else:
        entry = 'No results found'  # type: ignore
    demisto.results(entry)


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

    update_alert(alert_id, json)

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


def get_advanced_hunting_command():
    query = demisto.args().get('query')
    response = get_advanced_hunting(query)
    results = response.get('Results')
    if isinstance(results, list) and len(results) == 1:
        report_id = results[0].get('ReportId')
        if report_id:
            results[0]['ReportId'] = str(report_id)
    ec = {
        'MicrosoftATP.Hunt.Result': results
    }
    hr = tableToMarkdown('Hunt results', results, removeNull=True)

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }

    demisto.results(entry)


def get_advanced_hunting(query):
    cmd_url = '/advancedqueries/run'
    json = {
        'Query': query
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def create_alert_command():
    args = demisto.args()
    response = create_alert(
        args.get('machine_id'),
        args.get('severity'),
        args.get('title'),
        args.get('description'),
        args.get('event_time'),
        args.get('report_id'),
        args.get('recommended_action'),
        args.get('category')
    )
    output = {
        'MachineID': response.get('machineId'),
        'RecommendedAction': response.get('recommendedAction'),
        'Title': response.get('title'),
        'Description': response.get('description'),
        'Severity': response.get('severity'),
        'Category': response.get('Category'),
        'ReportID': response.get('reportId'),
        'ID': response.get('id'),
        'Status': response.get('status')
    }
    output = {k: v for k, v in output.items() if v is not None}
    ec = {
        'MicrosoftATP.Alert': output
    }
    hr = tableToMarkdown('Alert created:', output)

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }

    demisto.results(entry)


def create_alert(machine_id, severity, title, description, event_time, report_id, rec_action, category):
    cmd_url = '/alerts/CreateAlertByReference'
    json = {
        'machineId': machine_id,
        'severity': severity,
        'title': title,
        'description': description,
        'eventTime': event_time,
        'reportId': report_id
    }
    if rec_action:
        json['recommendedAction'] = rec_action
    if category:
        json['category'] = category
    response = http_request('POST', cmd_url, json=json)
    return response


def get_alert_related_user_command():
    alert_id = demisto.args().get('id')
    response = get_alert_related_user(alert_id)
    output = {
        'ID': response.get('id'),
        'AlertID': alert_id,
        'FirstSeen': response.get('firstSeen'),
        'LastSeen': response.get('lastSeen'),
        'MostPrevalentMachineID': response.get('mostPrevalentMachineId'),
        'LogonTypes': response.get('logonTypes'),
        'LogonCount': response.get('logOnMachinesCount'),
        'DomainAdmin': response.get('isDomainAdmin'),
        'NetworkUser': response.get('isOnlyNetworkUser')
    }
    ec = {
        'MicrosoftATP.User(val.AlertID === obj.AlertID && val.ID === obj.ID)': output
    }
    hr = tableToMarkdown('Alert Related User:', output, removeNull=True)

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }

    demisto.results(entry)


def get_alert_related_user(alert_id):
    cmd_url = '/alerts/{}/user'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def fetch_incidents():
    last_run = demisto.getLastRun()

    if last_run and last_run['last_alert_fetched_time']:
        last_alert_fetched_time = datetime.strptime(last_run['last_alert_fetched_time'], '%Y-%m-%dT%H:%M:%S.%f')
    else:
        last_alert_fetched_time = datetime.now() - timedelta(days=300)

    previous_ids = last_run.get('last_ids', [])
    latest_creation_time = last_alert_fetched_time

    alerts = list_alerts()['value']
    incidents = []
    last_ids = []

    for alert in alerts:
        # Removing 'Z' from timestamp and converting to datetime
        alert_creation_time = datetime.strptime(alert['alertCreationTime'][:-2], '%Y-%m-%dT%H:%M:%S.%f')
        alert_status = alert['status']
        alert_severity = alert['severity']
        if alert_creation_time >= last_alert_fetched_time and alert_status in FETCH_STATUS and \
                alert_severity in FETCH_SEVERITY and alert['id'] not in previous_ids:
            incident = alert_to_incident(alert)
            incidents.append(incident)
            if alert_creation_time == latest_creation_time:
                last_ids.append(alert["id"])
            if alert_creation_time > latest_creation_time:
                latest_creation_time = alert_creation_time
                last_ids = [alert['id']]

    if not last_ids:
        last_ids = previous_ids

    demisto.setLastRun({
        'last_alert_fetched_time': datetime.strftime(latest_creation_time, '%Y-%m-%dT%H:%M:%S.%f'),
        "last_ids": last_ids

    })
    demisto.incidents(incidents)


def test_function():
    token = get_access_token()
    response = requests.get(
        BASE_URL + '/alerts',
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        params={'$top': '1'},
        verify=USE_SSL
    )
    try:
        _ = response.json() if response.text else {}
        if not response.ok:
            return_error(f'API call to Windows Advanced Threat Protection. '
                         f'Please check authentication related parameters. '
                         f'[{response.status_code}] - {response.reason}')

        demisto.results('ok')

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'API call to Windows Advanced Threat Protection failed, could not parse result. '
                     f'Please check authentication related parameters. [{response.status_code}]')


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

    elif demisto.command() == 'microsoft-atp-stop-and-quarantine-file':
        stop_and_quarantine_file_command()

    elif demisto.command() == 'microsoft-atp-run-antivirus-scan':
        run_antivirus_scan_command()

    elif demisto.command() == 'microsoft-atp-list-alerts':
        list_alerts_command()

    elif demisto.command() == 'microsoft-atp-update-alert':
        update_alert_command()

    elif demisto.command() == 'microsoft-atp-advanced-hunting':
        get_advanced_hunting_command()

    elif demisto.command() == 'microsoft-atp-create-alert':
        create_alert_command()

    elif demisto.command() == 'microsoft-atp-get-alert-related-user':
        get_alert_related_user_command()

except Exception as e:
    return_error(str(e))
