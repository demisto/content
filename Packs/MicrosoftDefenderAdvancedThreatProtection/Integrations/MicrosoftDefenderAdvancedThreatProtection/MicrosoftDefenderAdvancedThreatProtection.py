import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
requests.packages.urllib3.disable_warnings()

try:
    handle_proxy()
except Exception as e:
    return_error('An error has occurred in the Microsoft Defender Advanced Threat Protection integration:'
                 ' {err}'.format(err=str(e)))


''' GLOBAL VARS '''

SERVER = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
BASE_URL = SERVER + '/api'
TENANT_ID = demisto.params()['tenant_id']
AUTH_AND_TOKEN_URL = demisto.params()['auth_id'].split('@')
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = demisto.params()['enc_key']
USE_SSL = not demisto.params().get('insecure', False)
ALERT_SEVERITIES_TO_FETCH = demisto.params()['fetch_severity']
ALERT_STATUS_TO_FETCH = demisto.params().get('fetch_status')
ALERT_TIME_TO_FETCH = demisto.params().get('first_fetch_timestamp', '3 days')

if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line disable-secrets-detection
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
    calling_context = demisto.callingContext.get('context', {})  # type: ignore[attr-defined]
    brand_name = calling_context.get('IntegrationBrand', '')
    instance_name = calling_context.get('IntegrationInstance', '')
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token
    headers = {'Accept': 'application/json'}
    headers['X-Content-Version'] = CONTENT_RELEASE_VERSION
    headers['X-Branch-Name'] = CONTENT_BRANCH_NAME
    headers['X-Content-Name'] = brand_name or instance_name or 'Name not found'

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


def http_request(method, url_suffix, json=None, data=None, params=None):

    token = get_access_token()
    r = requests.request(
        method,
        BASE_URL + url_suffix,
        json=json,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        verify=USE_SSL,
        data=data

    )
    if r.status_code not in {200, 201}:
        try:
            error = r.json().get('error')
            msg = error['message'] if 'message' in error else r.reason
            return_error('Error in API call to ATP [%d] - %s' % (r.status_code, r.text))
        except ValueError:
            msg = r.text if r.text else r.reason
            return_error('Error in API call to ATP [%d] - %s' % (r.status_code, msg))
    if not r.text:
        return {}
    try:
        return r.json()
    except ValueError:
        return {}


def alert_to_incident(alert, alert_creation_time):
    incident = {
        'rawJSON': json.dumps(alert),
        'name': 'Microsoft Defender ATP Alert ' + alert['id'],
        'occurred': alert_creation_time.isoformat() + 'Z'
    }

    return incident


''' REQUESTS '''


def isolate_machine_request(machine_id, comment, isolation_type):
    """Isolates a machine from accessing external network.

    Args:
        machine_id (str): Machine ID
        comment (str): Comment to associate with the action.
        isolation_type (str): Type of the isolation.

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action
    """
    cmd_url = '/machines/{}/isolate'.format(machine_id)
    json = {
        "Comment": comment,
        "IsolationType": isolation_type
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def unisolate_machine_request(machine_id, comment):
    """Undo isolation of a machine.

    Args:
        machine_id (str): Machine ID
        comment (str): Comment to associate with the action.

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action
    """
    cmd_url = '/machines/{}/unisolate'.format(machine_id)
    json = {
        'Comment': comment
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_machines_request(filter_req):
    """Retrieves a collection of Machines that have communicated with Microsoft Defender ATP cloud on the last 30 days.

    Returns:
        dict. Machine's info
    """
    cmd_url = '/machines'
    if filter_req:
        cmd_url += f'?$filter={filter_req}'
    response = http_request('GET', cmd_url)
    return response


def get_file_related_machines_request(file):
    """Retrieves a collection of Machines related to a given file hash.

    Args:
        file (str): File's hash

    Returns:
        dict. Related machines
    """
    cmd_url = '/files/{}/machines'.format(file)
    response = http_request('GET', cmd_url)
    return response


def get_machine_details_request(machine_id):
    """Retrieves specific Machine by its machine ID.

    Args:
        machine_id (str): Machine ID

    Returns:
        dict. Machine's info
    """
    cmd_url = '/machines/{}'.format(machine_id)
    response = http_request('GET', cmd_url)
    return response


def run_antivirus_scan_request(machine_id, comment, scan_type):
    """Initiate Windows Defender Antivirus scan on a machine.

    Args:
        machine_id (str): Machine ID
        comment (str): 	Comment to associate with the action
        scan_type (str): Defines the type of the Scan (Quick, Full)

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action
    """
    cmd_url = '/machines/{}/runAntiVirusScan'.format(machine_id)
    json = {
        'Comment': comment,
        'ScanType': scan_type
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def list_alerts_request(filter_req=None):
    """Retrieves a collection of Alerts.

    Returns:
        dict. Alerts info
    """
    cmd_url = '/alerts'
    if filter_req:
        cmd_url += f'?$filter={filter_req}'
    response = http_request('GET', cmd_url)
    return response


def update_alert_request(alert_id, json):
    """Updates properties of existing Alert.

    Returns:
        dict. Alerts info
    """
    cmd_url = '/alerts/{}'.format(alert_id)
    response = http_request('PATCH', cmd_url, json=json)
    return response


def get_advanced_hunting_request(query):
    """Retrieves results according to query.

    Args:
        query (str): Query to do advanced hunting on

    Returns:
        dict. Advanced hunting results
    """
    cmd_url = '/advancedqueries/run'
    json = {
        'Query': query
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def create_alert(machine_id, severity, title, description, event_time, report_id, rec_action, category):
    """Creates new Alert on top of Event.

    Args:
        machine_id (str): ID of the machine on which the event was identified
        severity (str): Severity of the alert
        title (str): Title for the alert
        description (str): Description of the alert
        event_time (str): The precise time of the event as string
        report_id (str): The reportId of the event
        rec_action (str): Action that is recommended to be taken by security officer when analyzing the alert
        category (Str): Category of the alert

    Returns:
        dict. Related domains
    """
    cmd_url = '/alerts/CreateAlertByReference'
    json = {
        'machineId': machine_id,
        'severity': severity,
        'title': title,
        'description': description,
        'eventTime': event_time,
        'reportId': report_id,
        'recommendedAction': rec_action,
        'category': category
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_alert_related_domains_request(alert_id):
    """Retrieves all domains related to a specific alert.

    Args:
        alert_id (str): Alert ID

    Returns:
        dict. Related domains
    """
    cmd_url = '/alerts/{}/domains'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def get_alert_related_files_request(alert_id):
    """Retrieves all files related to a specific alert.

    Args:
        alert_id (str): Alert ID

    Returns:
        dict. Related files
    """
    cmd_url = '/alerts/{}/files'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def get_alert_related_ips_request(alert_id):
    """Retrieves all IPs related to a specific alert.

    Args:
        alert_id (str): Alert ID

    Returns:
        dict. Related IPs
    """
    cmd_url = '/alerts/{}/ips'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def get_alert_related_user_request(alert_id):
    """Retrieves the User related to a specific alert.

    Args:
        alert_id (str): Alert ID

    Returns:
        dict. Related user
    """
    cmd_url = '/alerts/{}/user'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def get_machine_action_by_id_request(action_id):
    """Retrieves specific Machine Action by its ID.

    Args:
        action_id (str): Action ID

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine Action entity
    """
    cmd_url = '/machineactions/{}'.format(action_id)
    response = http_request('GET', cmd_url)
    return response


def get_machine_actions_request(filter_req):
    """Retrieves all Machine Actions.

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine Action entity
    """
    cmd_url = '/machineactions'
    if filter_req:
        cmd_url += f'?$filter={filter_req}'
    response = http_request('GET', cmd_url)
    return response


def get_investigation_package_request(machine_id, comment):
    """Collect investigation package from a machine.

    Args:
        machine_id (str): Machine ID
        comment (str): Comment to associate with the action
    Returns:

        dict. Machine's investigation_package
    """
    cmd_url = '/machines/{}/collectInvestigationPackage'.format(machine_id)
    json = {
        'Comment': comment
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_investigation_package_sas_uri_request(action_id):
    """Get a URI that allows downloading of an Investigation package.

    Args:
        action_id (str): Action ID

    Returns:
        dict. An object that holds the link for the package
    """
    cmd_url = '/machineactions/{}/getPackageUri'.format(action_id)
    response = http_request('GET', cmd_url)
    return response


def restrict_app_execution_request(machine_id, comment):
    """Restrict execution of all applications on the machine except a predefined set.

    Args:
        machine_id (str): Machine ID
        comment (str): Comment to associate with the action

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action
    """
    cmd_url = '/machines/{}/restrictCodeExecution'.format(machine_id)
    json = {
        'Comment': comment
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def remove_app_restriction_request(machine_id, comment):
    """Enable execution of any application on the machine.

    Args:
        machine_id (str): Machine ID
        comment (str): Comment to associate with the action

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action
    """
    cmd_url = '/machines/{}/unrestrictCodeExecution'.format(machine_id)
    json = {
        'Comment': comment
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def stop_and_quarantine_file_request(machine_id, file_sha1, comment):
    """Stop execution of a file on a machine and delete it.

    Args:
        machine_id (str): Machine ID
        file_sha1: (str): File's hash
        comment (str): Comment to associate with the action

    Notes:
        Machine action is a collection of actions you can apply on the machine, for more info
        https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action
    """
    cmd_url = '/machines/{}/stopAndQuarantineFile'.format(machine_id)
    json = {
        'Comment': comment,
        'Sha1': file_sha1
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_investigation_by_id_request(investigation_id):
    """Get the investigation ID and return the investigation details.

    Args:
        investigation_id (str): The investigation ID

    Returns:
        dict. Investigations entity
    """
    cmd_url = '/investigations/{}'.format(investigation_id)
    response = http_request('GET', cmd_url)
    return response


def get_alert_by_id_request(alert_id):
    """Get the alert ID and return the alert details.

    Args:
        alert_id (str): The alert ID

    Returns:
        dict. Alert's entity
    """
    cmd_url = '/alerts/{}'.format(alert_id)
    response = http_request('GET', cmd_url)
    return response


def get_investigation_list_request():
    """Retrieves a collection of Investigations.

    Returns:
        dict. A collection of Investigations entities.
    """
    cmd_url = '/investigations'
    response = http_request('GET', cmd_url)
    return response


def start_investigation_request(machine_id, comment):
    """Start automated investigation on a machine.

    Args:
        machine_id (str): The Machine ID
        comment (str): Comment to associate with the action

    Returns:
        dict. Investigation's entity
    """
    cmd_url = '/machines/{}/startInvestigation'.format(machine_id)
    json = {
        'Comment': comment,
    }
    response = http_request('POST', cmd_url, json=json)
    return response


def get_domain_statistics_request(domain):
    """Retrieves the statistics on the given domain.

    Args:
        domain (str): The Domain's address

    Returns:
        dict. Domain's statistics
    """
    cmd_url = '/domains/{}/stats'.format(domain)
    response = http_request('GET', cmd_url)
    return response


def get_file_statistics_request(file_sha1):
    """Retrieves the statistics on the given file.

    Args:
        file_sha1 (str): The file's hash

    Returns:
        dict. File's statistics
    """
    cmd_url = '/files/{}/stats'.format(file_sha1)
    response = http_request('GET', cmd_url)
    return response


def get_ip_statistics_request(ip):
    """Retrieves the statistics on the given IP.

    Args:
        ip (str): The IP address

    Returns:
        dict. IP's statistics
    """
    cmd_url = '/ips/{}/stats'.format(ip)
    response = http_request('GET', cmd_url)
    return response


def get_domain_alerts_request(domain):
    """Retrieves a collection of Alerts related to a given domain address.

    Args:
        domain (str): The Domain's address

    Returns:
        dict. Alerts entities
    """
    cmd_url = '/domains/{}/alerts'.format(domain)
    response = http_request('GET', cmd_url)
    return response


def get_file_alerts_request(file_sha1):
    """Retrieves a collection of Alerts related to a given file hash.

    Args:
        file_sha1 (str): The file's hash

    Returns:
        dict. Alerts entities
    """
    cmd_url = '/files/{}/alerts'.format(file_sha1)
    response = http_request('GET', cmd_url)
    return response


def get_ip_alerts_request(ip):
    """Retrieves a collection of Alerts related to a given IP.

    Args:
        ip (str): The IP address

    Returns:
        dict. Alerts entities
    """
    cmd_url = '/ips/{}/alerts'.format(ip)
    response = http_request('GET', cmd_url)
    return response


def get_user_alerts_request(username):
    """Retrieves a collection of Alerts related to a given  user ID.

    Args:
        username (str): The user ID

    Returns:
        dict. Alerts entities
    """
    cmd_url = '/users/{}/alerts'.format(username)
    response = http_request('GET', cmd_url)
    return response


def get_domain_machines_request(domain):
    """Retrieves a collection of Machines that have communicated to or from a given domain address.

    Args:
        domain (str): The Domain's address

    Returns:
        dict. Machines entities
    """
    cmd_url = '/domains/{}/machines'.format(domain)
    response = http_request('GET', cmd_url)
    return response


def get_user_machines_request(username):
    """Retrieves a collection of machines related to a given user ID.

    Args:
        username (str): The user name

    Returns:
        dict. Machines entities
    """
    cmd_url = '/users/{}/machines'.format(username)
    response = http_request('GET', cmd_url)
    return response


def add_remove_machine_tag_request(machine_id, action, tag):
    """Retrieves a collection of machines related to a given user ID.

    Args:
        machine_id (str): The machine ID
        action (str): Add or Remove action
        tag (str): The tag name

    Returns:
        dict. Updated machine's entity
    """
    cmd_url = '/machines/{}/tags'.format(machine_id)
    new_tags = {
        "Value": tag,
        "Action": action
    }
    response = http_request('POST', cmd_url, json=new_tags)
    return response


def get_file_data_request(file_hash):
    """Retrieves a File by identifier SHA1.

    Args:
        file_hash(str): The file SHA1 hash

    Returns:
        dict. File entities
    """
    cmd_url = '/files/{}'.format(file_hash)
    response = http_request('GET', cmd_url)
    return response


''' Commands '''


def get_alert_related_user_command():
    """Retrieves the User related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = demisto.args().get('id')
    response = get_alert_related_user_request(alert_id)

    user_data = get_user_data(response)
    context_output = {
        'AlertID': alert_id,
        'User': user_data
    }
    ec = {
        'MicrosoftATP.AlertUser(val.AlertID === obj.AlertID)': context_output
    }

    hr = tableToMarkdown('Alert Related User:', user_data, removeNull=True)
    return hr, ec, response


def get_user_data(user_response):
    """Get the user raw response and returns the user info in context and human readable format

    Returns:
        dict. User data
    """
    user_data = {
        'ID': user_response.get('id'),
        'AccountName': user_response.get('accountName'),
        'AccountDomain': user_response.get('accountDomain'),
        'AccountSID': user_response.get('accountSid'),
        'FirstSeen': user_response.get('firstSeen'),
        'LastSeen': user_response.get('lastSeen'),
        'MostPrevalentMachineID': user_response.get('mostPrevalentMachineId'),
        'LeastPrevalentMachineID': user_response.get('leastPrevalentMachineId'),
        'LogonTypes': user_response.get('logonTypes'),
        'LogonCount': user_response.get('logOnMachinesCount'),
        'DomainAdmin': user_response.get('isDomainAdmin'),
        'NetworkUser': user_response.get('isOnlyNetworkUser')
    }
    return user_data


def isolate_machine_command():
    """Isolates a machine from accessing external network.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']

    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    isolation_type = demisto.args().get('isolation_type')
    machine_action_response = isolate_machine_request(machine_id, comment, isolation_type)
    machine_action_data = get_machine_action_data(machine_action_response)

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_action_data
    }
    human_readable = tableToMarkdown("The isolation request has been submitted successfully:", machine_action_data,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, machine_action_response


def unisolate_machine_command():
    """Undo isolation of a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    machine_action_response = unisolate_machine_request(machine_id, comment)
    machine_action_data = get_machine_action_data(machine_action_response)

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_action_data
    }

    human_readable = tableToMarkdown("The request to stop the isolation has been submitted successfully:",
                                     machine_action_data, headers=headers, removeNull=True)
    return human_readable, entry_context, machine_action_response


def get_machines_command():
    """Retrieves a collection of machines that have communicated with WDATP cloud on the last 30 days

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    hostname = demisto.args().get('hostname', '')
    ip = demisto.args().get('ip', '')
    risk_score = demisto.args().get('risk_score', '')
    health_status = demisto.args().get('health_status', '')
    os_platform = demisto.args().get('os_platform', '')

    fields_to_filter_by = {
        'computerDnsName': hostname,
        'lastIpAddress': ip,
        'riskScore': risk_score,
        'healthStatus': health_status,
        'osPlatform': os_platform
    }
    filter_req = reformat_filter(fields_to_filter_by)
    machines_response = get_machines_request(filter_req)
    machines_list = get_machines_list(machines_response)

    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machines_list
    }
    human_readable = tableToMarkdown('Microsoft Defender ATP Machines:', machines_list, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, machines_response


def get_machines_list(machines_response):
    """Get a raw response of machines list

    Args:
        machines_response (dict): The raw response with the machines list in it

    Returns:
        list. Machines list
    """
    machines_list = []
    for machine in machines_response['value']:
        machine_data = get_machine_data(machine)
        machines_list.append(machine_data)
    return machines_list


def reformat_filter(fields_to_filter_by):
    """Get a dictionary with all of the fields to filter

    Args:
        fields_to_filter_by (dict): Dictionary with all the fields to filter

    Returns:
        string. Filter to send in the API request
    """
    filter_req = ''
    for field_key, field_value in fields_to_filter_by.items():
        if field_value:
            filter_req += f"{field_key}+eq+'{field_value}'&"
    return filter_req


def get_file_related_machines_command():
    """Retrieves a collection of Machines related to a given file hash.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    file = demisto.args()['file_hash']
    machines_response = get_file_related_machines_request(file)
    machines_list = get_machines_list(machines_response)

    context_output = {
        'File': file,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.FileMachine(val.ID === obj.ID)': context_output
    }
    human_readable = tableToMarkdown(f'Microsoft Defender ATP machines related to file {file}', machines_list,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, machines_response


def get_machine_details_command():
    """Retrieves specific Machine by its machine ID or computer name.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    machine_id = demisto.args()['machine_id']
    machine_response = get_machine_details_request(machine_id)
    machine_data = get_machine_data(machine_response)

    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machine_data
    }
    human_readable = tableToMarkdown(f'Microsoft Defender ATP machine {machine_id} details:', machine_data,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, machine_response


def run_antivirus_scan_command():
    """Initiate Windows Defender Antivirus scan on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = demisto.args().get('machine_id')
    scan_type = demisto.args().get('scan_type')
    comment = demisto.args().get('comment')

    machine_action_response = run_antivirus_scan_request(machine_id, comment, scan_type)
    machine_action_data = get_machine_action_data(machine_action_response)

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_action_data
    }
    human_readable = tableToMarkdown('Antivirus scan successfully triggered', machine_action_data, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, machine_action_response


def list_alerts_command():
    """Initiate Windows Defender Antivirus scan on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    severity = demisto.args().get('severity')
    status = demisto.args().get('status')
    fields_to_filter_by = {
        'severity': severity,
        'status': status
    }
    filter_req = reformat_filter(fields_to_filter_by)
    alerts_response = list_alerts_request(filter_req)
    alerts_list = get_alerts_list(alerts_response)

    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': alerts_list
    }
    human_readable = tableToMarkdown('Microsoft Defender ATP alerts:', alerts_list, headers=headers, removeNull=True)
    return human_readable, entry_context, alerts_response


def get_alerts_list(alerts_response):
    """Get a raw response of alerts list

    Args:
        alerts_response (dict): The raw response with the alerts list in it

    Returns:
        list. Alerts list
    """
    alerts_list = []
    for alert in alerts_response['value']:
        alert_data = get_alert_data(alert)
        alerts_list.append(alert_data)
    return alerts_list


def update_alert_command():
    """Updates properties of existing Alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = demisto.args()['alert_id']
    assigned_to = demisto.args().get('assigned_to')
    status = demisto.args().get('status')
    classification = demisto.args().get('classification')
    determination = demisto.args().get('determination')
    comment = demisto.args().get('comment')

    args_list = [assigned_to, status, classification, determination, comment]
    check_given_args_update_alert(args_list)
    json, context = add_args_to_json_and_context(alert_id, assigned_to, status, classification, determination, comment)
    alert_response = update_alert_request(alert_id, json)
    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': context
    }
    human_readable = f'The alert {alert_id} has been updated successfully'
    return human_readable, entry_context, alert_response


def check_given_args_update_alert(args_list):
    """Gets an arguments list and returns an error if all of them are empty
    """
    if all(v is None for v in args_list):
        return_error('No arguments were given to update the alert')


def add_args_to_json_and_context(alert_id, assigned_to, status, classification, determination, comment):
    """Gets arguments and returns the json and context with the arguments inside
    """
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
    if comment:
        json['comment'] = comment
        context['Comment'] = comment
    return json, context


def get_advanced_hunting_command():
    """Get results of advanced hunting according to user query.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    query = demisto.args().get('query')
    response = get_advanced_hunting_request(query)
    results = response.get('Results')
    if isinstance(results, list) and len(results) == 1:
        report_id = results[0].get('ReportId')
        if report_id:
            results[0]['ReportId'] = str(report_id)
    entry_context = {
        'MicrosoftATP.Hunt.Result': results
    }
    human_readable = tableToMarkdown('Hunt results', results, removeNull=True)

    return human_readable, entry_context, response


def create_alert_command():
    """Creates new Alert on top of Event.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    args = demisto.args()
    alert_response = create_alert(
        args.get('machine_id'),
        args.get('severity'),
        args.get('title'),
        args.get('description'),
        args.get('event_time'),
        args.get('report_id'),
        args.get('recommended_action'),
        args.get('category')
    )
    alert_data = get_alert_data(alert_response)

    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': alert_data
    }
    human_readable = tableToMarkdown('Alert created:', alert_data, headers=headers, removeNull=True)
    return human_readable, entry_context, alert_response


def get_alert_related_files_command():
    """Retrieves all files related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['Sha1', 'Sha256', 'SizeInBytes', 'FileType', 'FilePublisher', 'FileProductName']
    alert_id = demisto.args().get('id')
    limit = demisto.args().get('limit')
    offset = demisto.args().get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    response = get_alert_related_files_request(alert_id)
    response_files_list = response['value']

    files_data_list = []
    from_index = min(offset, len(response_files_list))
    to_index = min(offset + limit, len(response_files_list))
    for file_obj in response_files_list[from_index:to_index]:
        files_data_list.append(get_file_data(file_obj))

    context_output = {
        'AlertID': alert_id,
        'Files': files_data_list
    }
    entry_context = {
        'MicrosoftATP.AlertFile(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = tableToMarkdown(f'Alert {alert_id} Related Files:', files_data_list, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, response_files_list


def check_limit_and_offset_values(limit, offset):
    """Gets the limit and offset values and return an error if the values are invalid
    """
    if not limit.isdigit():
        return_error("Error: You can only enter a positive integer or zero to limit argument.")
    elif not offset.isdigit():
        return_error("Error: You can only enter a positive integer to offset argument.")
    else:
        limit_int = int(limit)
        offset_int = int(offset)

        if limit_int == 0:
            return_error("Error: The value of the limit argument must be a positive integer.")

        return limit_int, offset_int


def get_file_data(file_response):
    """Get file raw response and returns the file's info for context and human readable.

    Returns:
        dict. File's info
    """
    file_data = assign_params(**{
        'Sha1': file_response.get('sha1'),
        'Sha256': file_response.get('sha256'),
        'Md5': file_response.get('md5'),
        'GlobalPrevalence': file_response.get('globalPrevalence'),
        'GlobalFirstObserved': file_response.get('globalFirstObserved'),
        'GlobalLastObserved': file_response.get('globalLastObserved'),
        'SizeInBytes': file_response.get('size'),
        'FileType': file_response.get('fileType'),
        'IsPeFile': file_response.get('isPeFile'),
        'FilePublisher': file_response.get('filePublisher'),
        'FileProductName': file_response.get('fileProductName'),
        'Signer': file_response.get('signer'),
        'Issuer': file_response.get('issuer'),
        'SignerHash': file_response.get('signerHash'),
        'IsValidCertificate': file_response.get('isValidCertificate'),
        'DeterminationType': file_response.get('determinationType'),
        'DeterminationValue': file_response.get('determinationValue')
    })
    return file_data


def get_alert_related_ips_command():
    """Retrieves all IPs related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = demisto.args().get('id')
    limit = demisto.args().get('limit')
    offset = demisto.args().get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    response = get_alert_related_ips_request(alert_id)
    response_ips_list = response['value']

    ips_list = []
    from_index = min(offset, len(response_ips_list))
    to_index = min(offset + limit, len(response_ips_list))

    for ip in response_ips_list[from_index:to_index]:
        ips_list.append(ip['id'])

    context_output = {
        'AlertID': alert_id,
        'IPs': ips_list
    }
    entry_context = {
        'MicrosoftATP.AlertIP(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = f'Alert {alert_id} Related IPs: {ips_list}'
    return human_readable, entry_context, response_ips_list


def get_alert_related_domains_command():
    """Retrieves all domains related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = demisto.args().get('id')
    limit = demisto.args().get('limit')
    offset = demisto.args().get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)
    response = get_alert_related_domains_request(alert_id)
    response_domains_list = response['value']
    domains_list = []
    from_index = min(offset, len(response_domains_list))
    to_index = min(offset + limit, len(response_domains_list))
    for domain in response_domains_list[from_index:to_index]:
        domains_list.append(domain['host'])
    context_output = {
        'AlertID': alert_id,
        'Domains': domains_list
    }
    entry_context = {
        'MicrosoftATP.AlertDomain(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = f'Alert {alert_id} Related Domains: {domains_list}'
    return human_readable, entry_context, response_domains_list


def get_machine_action_by_id_command():
    """Returns machine's actions, if machine ID is None, return all actions.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    action_id = demisto.args().get('id', '')
    status = demisto.args().get('status', '')
    machine_id = demisto.args().get('machine_id', '')
    type = demisto.args().get('type', '')
    requestor = demisto.args().get('requestor', '')
    if action_id:
        for index in range(3):
            try:
                response = get_machine_action_by_id_request(action_id)
                if response:
                    break
            except Exception as e:
                if 'ResourceNotFound' in str(e) and index < 3:
                    time.sleep(1)
                else:
                    return_error(f'Machine action {action_id} was not found')
        response = get_machine_action_by_id_request(action_id)
        action_data = get_machine_action_data(response)
        human_readable = tableToMarkdown(f'Action {action_id} Info:', action_data, headers=headers, removeNull=True)
        context_output = action_data
    else:
        # A dictionary that contains all of the fields the user want to filter results by.
        # It will be sent in the request so the requested filters are applied on the results
        fields_to_filter_by = {
            'status': status,
            'machineId': machine_id,
            'type': type,
            'requestor': requestor
        }
        filter_req = reformat_filter(fields_to_filter_by)
        response = get_machine_actions_request(filter_req)
        machine_actions_list = []
        for machine_action in response['value']:
            machine_actions_list.append(get_machine_action_data(machine_action))
        human_readable = tableToMarkdown('Machine actions Info:', machine_actions_list, headers=headers,
                                         removeNull=True)
        context_output = machine_actions_list
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': context_output
    }
    return human_readable, entry_context, response


def get_machine_action_data(machine_action_response):
    """Get machine raw response and returns the machine action info in context and human readable format.

    Notes:
         Machine action is a collection of actions you can apply on the machine, for more info
         https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action's info
    """
    action_data = \
        {
            "ID": machine_action_response.get('id'),
            "Type": machine_action_response.get('type'),
            "Scope": machine_action_response.get('scope'),
            "Requestor": machine_action_response.get('requestor'),
            "RequestorComment": machine_action_response.get('requestorComment'),
            "Status": machine_action_response.get('status'),
            "MachineID": machine_action_response.get('machineId'),
            "ComputerDNSName": machine_action_response.get('computerDnsName'),
            "CreationDateTimeUtc": machine_action_response.get('creationDateTimeUtc'),
            "LastUpdateTimeUtc": machine_action_response.get('lastUpdateTimeUtc'),
            "RelatedFileInfo": {
                "FileIdentifier": machine_action_response.get('fileIdentifier'),
                "FileIdentifierType": machine_action_response.get('fileIdentifierType')

            }
        }
    return action_data


def get_machine_investigation_package_command():
    """Collect investigation package from a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    machine_action_response = get_investigation_package_request(machine_id, comment)
    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Initiating collect investigation package from {machine_id} machine :',
                                     action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def get_investigation_package_sas_uri_command():
    """Returns a URI that allows downloading an Investigation package.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    action_id = demisto.args().get('action_id')
    response = get_investigation_package_sas_uri_request(action_id)
    link = {'Link': response['value']}
    human_readable = f'Success. This link is valid for a very short time and should be used immediately for' \
                     f' downloading the package to a local storage{link["Link"]}'
    entry_context = {
        'MicrosoftATP.InvestigationURI(val.Link === obj.Link)': link
    }
    return human_readable, entry_context, response


def restrict_app_execution_command():
    """Restrict execution of all applications on the machine except a predefined set.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    machine_action_response = restrict_app_execution_request(machine_id, comment)

    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Initiating Restrict execution of all applications on the machine {machine_id} '
                                     f'except a predefined set:', action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def remove_app_restriction_command():
    """Enable execution of any application on the machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    machine_action_response = remove_app_restriction_request(machine_id, comment)

    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Removing applications restriction on the machine {machine_id}:', action_data,
                                     headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def stop_and_quarantine_file_command():
    """Stop execution of a file on a machine and delete it.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = demisto.args().get('machine_id')
    file_sha1 = demisto.args().get('file_hash')
    comment = demisto.args().get('comment')
    machine_action_response = stop_and_quarantine_file_request(machine_id, file_sha1, comment)
    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Stopping the execution of a file on {machine_id} machine and deleting it:',
                                     action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def get_investigations_by_id_command():
    """Returns the investigation info, if investigation ID is None, return all investigations.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'StartTime', 'EndTime', 'CancelledBy', 'InvestigationState', 'StatusDetails', 'MachineID',
               'ComputerDNSName', 'TriggeringAlertID']
    investigation_id = demisto.args().get('id', '')
    limit = demisto.args().get('limit')
    offset = demisto.args().get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    if investigation_id:
        response = get_investigation_by_id_request(investigation_id)
        investigation_data = get_investigation_data(response)
        human_readable = tableToMarkdown(f'Investigation {investigation_id} Info:', investigation_data, headers=headers,
                                         removeNull=True)
        context_output = investigation_data
    else:
        response = get_investigation_list_request()['value']
        investigations_list = []
        from_index = min(offset, len(response))
        to_index = min(offset + limit, len(response))
        for investigation in response[from_index:to_index]:
            investigations_list.append(get_investigation_data(investigation))
        human_readable = tableToMarkdown('Investigations Info:', investigations_list, headers=headers, removeNull=True)
        context_output = investigations_list
    entry_context = {
        'MicrosoftATP.Investigation(val.ID === obj.ID)': context_output
    }
    return human_readable, entry_context, response


def get_investigation_data(investigation_response):
    """Get investigation raw response and returns the investigation info for context and human readable.

    Args:
        investigation_response: The investigation raw response
    Returns:
        dict. Investigation's info
    """
    investigation_data = {
        "ID": investigation_response.get('id'),
        "StartTime": investigation_response.get('startTime'),
        "EndTime": investigation_response.get('endTime'),
        "InvestigationState": investigation_response.get('state'),
        "CancelledBy": investigation_response.get('cancelledBy'),
        "StatusDetails": investigation_response.get('statusDetails'),
        "MachineID": investigation_response.get('machineId'),
        "ComputerDNSName": investigation_response.get('computerDnsName'),
        "TriggeringAlertID": investigation_response.get('triggeringAlertId')
    }
    return investigation_data


def start_investigation_command():
    """Start automated investigation on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'StartTime', 'EndTime', 'CancelledBy', 'InvestigationState', 'StatusDetails', 'MachineID',
               'ComputerDNSName', 'TriggeringAlertID']
    machine_id = demisto.args().get('machine_id')
    comment = demisto.args().get('comment')
    response = start_investigation_request(machine_id, comment)
    investigation_id = response['id']
    investigation_data = get_investigation_data(response)
    human_readable = tableToMarkdown(f'Starting investigation {investigation_id} on {machine_id} machine:',
                                     investigation_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.Investigation(val.ID === obj.ID)': investigation_data
    }
    return human_readable, entry_context, response


def get_domain_statistics_command():
    """Retrieves the statistics on the given domain.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    domain = demisto.args().get('domain')
    response = get_domain_statistics_request(domain)
    domain_statistics = get_domain_statistics(response)
    human_readable = tableToMarkdown(f'Statistics on {domain} domain:', domain_statistics, removeNull=True)

    context_output = {
        'Domain': domain,
        'Statistics': domain_statistics
    }
    entry_context = {
        'MicrosoftATP.DomainStatistics(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_domain_statistics(domain_stat_response):
    """Gets the domain statistics response and returns it in context format.

    Returns:
        (dict). domain statistics context
    """
    domain_statistics = assign_params(**{
        "Host": domain_stat_response.get('host'),
        "OrgPrevalence": domain_stat_response.get('orgPrevalence'),
        "OrgFirstSeen": domain_stat_response.get('orgFirstSeen'),
        "OrgLastSeen": domain_stat_response.get('orgLastSeen')
    })
    return domain_statistics


def get_domain_alerts_command():
    """Retrieves a collection of Alerts related to a given domain address.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    domain = demisto.args().get('domain')
    response = get_domain_alerts_request(domain)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'Domain {domain} related alerts Info:', alerts_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Domain': domain,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.DomainAlert(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_alert_data(alert_response):
    """Get alert raw response and returns the alert info in context and human readable format.

    Returns:
        dict. Alert info
    """
    alert_data = {
        "ID": alert_response.get('id'),
        "IncidentID": alert_response.get('incidentId'),
        "InvestigationID": alert_response.get('investigationId'),
        "InvestigationState": alert_response.get('investigationState'),
        "AssignedTo": alert_response.get('assignedTo'),
        "Severity": alert_response.get('severity'),
        "Status": alert_response.get('status'),
        "Classification": alert_response.get('classification'),
        "Determination": alert_response.get('determination'),
        "DetectionSource": alert_response.get('detectionSource'),
        "Category": alert_response.get('category'),
        "ThreatFamilyName": alert_response.get('threatFamilyName'),
        "Title": alert_response.get('title'),
        "Description": alert_response.get('description'),
        "AlertCreationTime": alert_response.get('alertCreationTime'),
        "FirstEventTime": alert_response.get('firstEventTime'),
        "LastEventTime": alert_response.get('lastEventTime'),
        "LastUpdateTime": alert_response.get('lastUpdateTime'),
        "ResolvedTime": alert_response.get('resolvedTime'),
        "MachineID": alert_response.get('machineId'),
        "ComputerDNSName": alert_response.get('computerDnsName'),
        "AADTenantID": alert_response.get('aadTenantId'),
        "Comments": [
            {
                "Comment": alert_response.get('comment'),
                "CreatedBy": alert_response.get('createdBy'),
                "CreatedTime": alert_response.get('createdTime')
            }
        ],
        "Evidence": alert_response.get('evidence')
    }

    return alert_data


def get_domain_machine_command():
    """Retrieves a collection of Machines that have communicated to or from a given domain address.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """

    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    domain = demisto.args().get('domain')
    response = get_domain_machines_request(domain)
    machines_list = get_machines_list(response)
    human_readable = tableToMarkdown(f'Machines that have communicated with {domain} domain:', machines_list,
                                     headers=headers, removeNull=True)
    context_output = {
        'Domain': domain,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.DomainMachine(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_machine_data(machine):
    """Get machine raw response and returns the machine's info in context and human readable format.

    Returns:
        dict. Machine's info
    """
    machine_data = assign_params(**{
        'ID': machine.get('id'),
        'ComputerDNSName': machine.get('computerDnsName'),
        'FirstSeen': machine.get('firstSeen'),
        'LastSeen': machine.get('lastSeen'),
        'OSPlatform': machine.get('osPlatform'),
        'OSVersion': machine.get('version'),
        'OSProcessor': machine.get('osProcessor'),
        'LastIPAddress': machine.get('lastIpAddress'),
        'LastExternalIPAddress': machine.get('lastExternalIpAddress'),
        'AgentVersion': machine.get('agentVersion'),
        'OSBuild': machine.get('osBuild'),
        'HealthStatus': machine.get('healthStatus'),
        'RBACGroupID': machine.get('rbacGroupId'),
        'RBACGroupName': machine.get('rbacGroupName'),
        'RiskScore': machine.get('riskScore'),
        'ExposureLevel': machine.get('exposureLevel'),
        'AADDeviceID': machine.get('aadDeviceId'),
        'IsAADJoined': machine.get('isAadJoined'),
        'MachineTags': machine.get('machineTags'),
    })
    return machine_data


def get_file_statistics_command():
    """Retrieves the statistics on the given file.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    file_sha1 = demisto.args().get('file_hash')
    response = get_file_statistics_request(file_sha1)
    file_stat = get_file_statistics(response)
    human_readable = tableToMarkdown(f'Statistics on {file_sha1} file:', file_stat, removeNull=True)
    context_output = {
        'Sha1': file_sha1,
        'Statistics': file_stat
    }
    entry_context = {
        'MicrosoftATP.FileStatistics(val.Sha1 === obj.Sha1)': context_output
    }
    return human_readable, entry_context, response


def get_file_statistics(file_stat_response):
    """Gets the file statistics response and returns it in context format.

    Returns:
        (dict). File statistics context
    """
    file_stat = assign_params(**{
        "OrgPrevalence": file_stat_response.get('orgPrevalence'),
        "OrgFirstSeen": file_stat_response.get('orgFirstSeen'),
        "OrgLastSeen": file_stat_response.get('orgLastSeen'),
        "GlobalPrevalence": file_stat_response.get('globalPrevalence'),
        "GlobalFirstObserved": file_stat_response.get('globalFirstObserved'),
        "GlobalLastObserved": file_stat_response.get('globalLastObserved'),
        "TopFileNames": file_stat_response.get('topFileNames')
    })
    return file_stat


def get_file_alerts_command():
    """Retrieves a collection of Alerts related to a given file hash.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    file_sha1 = demisto.args().get('file_hash')
    response = get_file_alerts_request(file_sha1)
    alerts_list = get_alerts_list(response)
    hr = tableToMarkdown(f'File {file_sha1} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'Sha1': file_sha1,
        'Alerts': alerts_list
    }
    ec = {
        'MicrosoftATP.FileAlert(val.Sha1 === obj.Sha1)': context_output
    }
    return hr, ec, response


def get_ip_statistics_command():
    """Retrieves the statistics on the given IP.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    ip = demisto.args().get('ip')
    response = get_ip_statistics_request(ip)
    ip_statistics = get_ip_statistics(response)
    hr = tableToMarkdown(f'Statistics on {ip} IP:', ip_statistics, removeNull=True)
    context_output = {
        'IPAddress': ip,
        'Statistics': ip_statistics
    }
    ec = {
        'MicrosoftATP.IPStatistics(val.IPAddress === obj.IPAddress)': context_output
    }
    return hr, ec, response


def get_ip_statistics(ip_statistics_response):
    """Gets the IP statistics response and returns it in context format.

    Returns:
        (dict). IP statistics context
    """
    ip_statistics = assign_params(**{
        "OrgPrevalence": ip_statistics_response.get('orgPrevalence'),
        "OrgFirstSeen": ip_statistics_response.get('orgFirstSeen'),
        "OrgLastSeen": ip_statistics_response.get('orgLastSeen')
    })
    return ip_statistics


def get_ip_alerts_command():
    """Retrieves a collection of Alerts related to a given IP.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    ip = demisto.args().get('ip')
    response = get_ip_alerts_request(ip)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'IP {ip} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'IPAddress': ip,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.IPAlert(val.IPAddress === obj.IPAddress)': context_output
    }
    return human_readable, entry_context, response


def get_user_alerts_command():
    """Retrieves a collection of Alerts related to a given user ID.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    username = demisto.args().get('username')
    response = get_user_alerts_request(username)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'User {username} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'Username': username,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.UserAlert(val.Username === obj.Username)': context_output
    }
    return human_readable, entry_context, response


def get_user_machine_command():
    """Retrieves a collection of machines related to a given user ID.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    username = demisto.args().get('username')
    response = get_user_machines_request(username)
    machines_list = get_machines_list(response)
    human_readable = tableToMarkdown(f'Machines that are related to user {username}:', machines_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Username': username,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.UserMachine(val.Username === obj.Username)': context_output
    }
    return human_readable, entry_context, response


def add_remove_machine_tag_command():
    """Adds or remove tag to a specific Machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIpAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel', 'MachineTags']
    machine_id = demisto.args().get('machine_id')
    action = demisto.args().get('action')
    tag = demisto.args().get('tag')
    response = add_remove_machine_tag_request(machine_id, action, tag)
    machine_data = get_machine_data(response)
    human_readable = tableToMarkdown(f'Succeed to {action} tag to {machine_id}:', machine_data, headers=headers,
                                     removeNull=True)
    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machine_data
    }
    return human_readable, entry_context, response


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_alert_fetched_time = get_last_alert_fetched_time(last_run)
    existing_ids = last_run.get('existing_ids', [])
    latest_creation_time = last_alert_fetched_time
    filter_alerts_creation_time = create_filter_alerts_creation_time(last_alert_fetched_time)
    alerts = list_alerts_request(filter_alerts_creation_time)['value']

    incidents, new_ids, latest_creation_time = all_alerts_to_incidents(alerts, latest_creation_time, existing_ids)

    demisto.setLastRun({
        'last_alert_fetched_time': datetime.strftime(latest_creation_time, '%Y-%m-%dT%H:%M:%S'),
        'existing_ids': new_ids
    })
    demisto.incidents(incidents)


def create_filter_alerts_creation_time(last_alert_fetched_time):
    """Create filter with the last alert fetched time to send in the request.

    Args:
        last_alert_fetched_time(date): Last date and time of alert that been fetched

    Returns:
        (str). The filter of alerts creation time that will be send in the  alerts list API request
    """
    filter_alerts_creation_time = f"alertCreationTime+gt+{last_alert_fetched_time.isoformat()}"

    if not filter_alerts_creation_time.endswith('Z'):
        filter_alerts_creation_time = filter_alerts_creation_time + "Z"

    return filter_alerts_creation_time


def all_alerts_to_incidents(alerts, latest_creation_time, existing_ids):
    """Gets the alerts list and convert it to incidents.

    Args:
        alerts(list): List of alerts filtered by the first_fetch_timestamp parameter
        latest_creation_time(date):  Last date and time of alert that been fetched
        existing_ids(list): List of alerts IDs that already been fetched

    Returns:(list, list, date). Incidents list, new alerts IDs list, latest alert creation time
    """
    incidents = []
    new_ids = []
    for alert in alerts:
        alert_creation_time_for_incident = datetime.strptime(alert['alertCreationTime'][:-9], '%Y-%m-%dT%H:%M:%S')
        if should_fetch_alert(alert, existing_ids):
            incident = alert_to_incident(alert, alert_creation_time_for_incident)
            incidents.append(incident)
            if alert_creation_time_for_incident == latest_creation_time:
                new_ids.append(alert["id"])
            if alert_creation_time_for_incident > latest_creation_time:
                latest_creation_time = alert_creation_time_for_incident
                new_ids = [alert['id']]

    if not new_ids:
        new_ids = existing_ids
    return incidents, new_ids, latest_creation_time


def should_fetch_alert(alert, existing_ids):
    """ Check the alert to see if it's data stands by the conditions.

    Args:
        alert (dict): The alert data
        existing_ids (list): The existing alert's ids list

    Returns:
        True - if the alert is according to the conditions, else False
    """
    alert_status = alert['status']
    alert_severity = alert['severity']
    if alert_status in ALERT_STATUS_TO_FETCH and alert_severity in ALERT_SEVERITIES_TO_FETCH and alert['id']\
            not in existing_ids:
        return True
    return False


def get_last_alert_fetched_time(last_run):
    """Gets fetch last run and returns the last alert fetch time.

    Returns:
        (date). The date and time of the last alert that been fetched
    """
    if last_run and last_run['last_alert_fetched_time']:
        last_alert_fetched_time = datetime.strptime(last_run['last_alert_fetched_time'], '%Y-%m-%dT%H:%M:%S')
    else:
        last_alert_fetched_time, _ = parse_date_range(date_range=ALERT_TIME_TO_FETCH, date_format='%Y-%m-%dT%H:%M:%S',
                                                      utc=False, to_timestamp=False)
        last_alert_fetched_time = datetime.strptime(str(last_alert_fetched_time), '%Y-%m-%dT%H:%M:%S')

    return last_alert_fetched_time


def test_module():
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
        test_module()

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

    elif demisto.command() == 'microsoft-atp-isolate-machine':
        return_outputs(*isolate_machine_command())

    elif demisto.command() == 'microsoft-atp-unisolate-machine':
        return_outputs(*unisolate_machine_command())

    elif demisto.command() == 'microsoft-atp-get-machines':
        return_outputs(*get_machines_command())

    elif demisto.command() == 'microsoft-atp-get-file-related-machines':
        return_outputs(*get_file_related_machines_command())

    elif demisto.command() == 'microsoft-atp-get-machine-details':
        return_outputs(*get_machine_details_command())

    elif demisto.command() == 'microsoft-atp-run-antivirus-scan':
        return_outputs(*run_antivirus_scan_command())

    elif demisto.command() == 'microsoft-atp-list-alerts':
        return_outputs(*list_alerts_command())

    elif demisto.command() == 'microsoft-atp-update-alert':
        return_outputs(*update_alert_command())

    elif demisto.command() == 'microsoft-atp-advanced-hunting':
        return_outputs(*get_advanced_hunting_command())

    elif demisto.command() == 'microsoft-atp-create-alert':
        return_outputs(*create_alert_command())

    elif demisto.command() == 'microsoft-atp-get-alert-related-user':
        return_outputs(*get_alert_related_user_command())

    elif demisto.command() == 'microsoft-atp-get-alert-related-files':
        return_outputs(*get_alert_related_files_command())

    elif demisto.command() == 'microsoft-atp-get-alert-related-ips':
        return_outputs(*get_alert_related_ips_command())

    elif demisto.command() == 'microsoft-atp-get-alert-related-domains':
        return_outputs(*get_alert_related_domains_command())

    elif demisto.command() == 'microsoft-atp-list-machine-actions-details':
        return_outputs(*get_machine_action_by_id_command())

    elif demisto.command() == 'microsoft-atp-collect-investigation-package':
        return_outputs(*get_machine_investigation_package_command())

    elif demisto.command() == 'microsoft-atp-get-investigation-package-sas-uri':
        return_outputs(*get_investigation_package_sas_uri_command())

    elif demisto.command() == 'microsoft-atp-restrict-app-execution':
        return_outputs(*restrict_app_execution_command())

    elif demisto.command() == 'microsoft-atp-remove-app-restriction':
        return_outputs(*remove_app_restriction_command())

    elif demisto.command() == 'microsoft-atp-stop-and-quarantine-file':
        return_outputs(*stop_and_quarantine_file_command())

    elif demisto.command() == 'microsoft-atp-list-investigations':
        return_outputs(*get_investigations_by_id_command())

    elif demisto.command() == 'microsoft-atp-start-investigation':
        return_outputs(*start_investigation_command())

    elif demisto.command() == 'microsoft-atp-get-domain-statistics':
        return_outputs(*get_domain_statistics_command())

    elif demisto.command() == 'microsoft-atp-get-domain-alerts':
        return_outputs(*get_domain_alerts_command())

    elif demisto.command() == 'microsoft-atp-get-domain-machines':
        return_outputs(*get_domain_machine_command())

    elif demisto.command() == 'microsoft-atp-get-file-statistics':
        return_outputs(*get_file_statistics_command())

    elif demisto.command() == 'microsoft-atp-get-file-alerts':
        return_outputs(*get_file_alerts_command())

    elif demisto.command() == 'microsoft-atp-get-ip-statistics':
        return_outputs(*get_ip_statistics_command())

    elif demisto.command() == 'microsoft-atp-get-ip-alerts':
        return_outputs(*get_ip_alerts_command())

    elif demisto.command() == 'microsoft-atp-get-user-alerts':
        return_outputs(*get_user_alerts_command())

    elif demisto.command() == 'microsoft-atp-get-user-machines':
        return_outputs(*get_user_machine_command())

    elif demisto.command() == 'microsoft-atp-add-remove-machine-tag':
        return_outputs(*add_remove_machine_tag_command())
except Exception as e:
    return_error(str(e))
