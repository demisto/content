import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
from datetime import datetime, timedelta
from typing import Dict, Any
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
PARAMS = demisto.params()
SERVER = PARAMS['host'][:-1] if PARAMS['host'].endswith('/') else PARAMS['host']
BASE_URL = SERVER + '/v1.0/'
TENANT = PARAMS['tenant_id']
AUTH_AND_TOKEN_URL = PARAMS['auth_id'].split('@')
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = PARAMS.get('enc_key')
USE_SSL = not PARAMS.get('insecure', False)
if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
else:
    TOKEN_RETRIEVAL_URL = AUTH_AND_TOKEN_URL[1]
APP_NAME = 'ms-graph-security'

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
    headers = {'Accept': 'application/json'}

    dbot_response = requests.post(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        data=json.dumps({
            'app_name': APP_NAME,
            'registration_id': AUTH_ID,
            'encrypted_token': get_encrypted(TENANT, ENC_KEY)
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


def get_timestamp(time_description):
    if time_description == 'Last24Hours':
        time_delta = 1
    elif time_description == 'Last48Hours':
        time_delta = 2
    else:
        time_delta = 7
    return datetime.strftime(datetime.now() - timedelta(time_delta), '%Y-%m-%d')


def http_request(method, url_suffix, json=None, params=None):
    """
    Generic request to the graph
    """
    token = get_access_token()
    r = requests.request(
        method,
        BASE_URL + url_suffix,
        json=json,
        params=params,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    )
    if r.status_code not in {200, 204, 206}:
        return_error('Error in API call to Microsoft Graph [%d] - %s' % (r.status_code, r.reason))
    elif r.status_code == 206:  # 206 indicates Partial Content, and the reason for that will be in the Warning header
        demisto.debug(str(r.headers))
    if not r.text:
        return {}
    return r.json()


def capitalize_first_letter(string):
    return string[:1].upper() + string[1:]


''' FUNCTIONS '''


def search_alerts_command(args):
    last_modified = args.get('last_modified')
    severity = args.get('severity')
    category = args.get('category')
    vendor = args.get('vendor')
    time_from = args.get('time_from')
    time_to = args.get('time_to')
    filter_query = args.get('filter')
    alerts = search_alerts(last_modified, severity, category, vendor, time_from, time_to, filter_query)['value']
    outputs = []
    for alert in alerts:
        outputs.append({
            'ID': alert['id'],
            'Title': alert['title'],
            'Category': alert['category'],
            'Severity': alert['severity'],
            'CreatedDate': alert['createdDateTime'],
            'EventDate': alert['eventDateTime'],
            'Status': alert['status'],
            'Vendor': alert['vendorInformation']['vendor'],
            'Provider': alert['vendorInformation']['provider']
        })
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': outputs
    }
    table_headers = ['ID', 'Vendor', 'Provider', 'Title', 'Category', 'Severity', 'CreatedDate', 'EventDate', 'Status']
    entry = {
        'Type': entryTypes['note'],
        'Contents': alerts,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Microsoft Security Graph Alerts', outputs, table_headers, removeNull=True),
        'EntryContext': ec
    }
    demisto.results(entry)


def search_alerts(last_modified, severity, category, vendor, time_from, time_to, filter_query):
    filters = ''
    if last_modified:
        filters += "&modifiedDate gt '{}'".format(get_timestamp(last_modified))
    if category:
        filters += "&category eq '{}'".format(category)
    if severity:
        filters += "&severity eq '{}'".format(severity)
    if time_from:
        filters += "&createdDate gt '{}'".format(time_from)
    if time_to:
        filters += "&createdDate lt '{}'".format(time_to)
    if filter_query:
        filters += "&{}".format(filter_query)
    cmd_url = 'security/alerts/?$filter=' + filters[1:]
    response = http_request('GET', cmd_url)
    return response


def get_alert_details_command(args):
    alert_id = args.get('alert_id')
    fields_to_include = args.get('fields_to_include')
    if fields_to_include:
        fields_list = fields_to_include.split(',')
    else:
        fields_list = []

    show_all_fields = True if 'All' in fields_list else False

    alert_details = get_alert_details(alert_id)

    hr = '## Microsoft Security Graph Alert Details - {}\n'.format(alert_id)

    basic_properties_title = 'Basic Properties'
    basic_properties = {
        'ActivityGroupName': alert_details['activityGroupName'],
        'AssignedTo': alert_details['assignedTo'],
        'AzureTenantID': alert_details['azureTenantId'],
        'Category': alert_details['category'],
        'ClosedDate': alert_details['closedDateTime'],
        'Confidence': alert_details['confidence'],
        'CreatedDate': alert_details['createdDateTime'],
        'Description': alert_details['description'],
        'EventDate': alert_details['eventDateTime'],
        'LastModifiedDate': alert_details['eventDateTime'],
        'Severity': alert_details['severity'],
        'Status': alert_details['status'],
        'Title': alert_details['title']
    }
    hr += tableToMarkdown(basic_properties_title, basic_properties, removeNull=True)

    if 'CloudAppStates' in fields_list or show_all_fields:
        cloud_apps_states = alert_details['cloudAppStates']
        if cloud_apps_states:
            cloud_apps_hr = []
            for state in cloud_apps_states:
                cloud_apps_hr.append({
                    'DestinationSerivceIP': state['destinationServiceIp'],
                    'DestinationSerivceName': state['destinationServiceName'],
                    'RiskScore': state['riskScore']
                })
            cloud_apps_title = 'Cloud Application States for Alert'
            hr += tableToMarkdown(cloud_apps_title, cloud_apps_hr, removeNull=True)

    if 'CustomerComments' in fields_list or show_all_fields:
        comments = alert_details['comments']
        if comments:
            comments_hr = '### Customer Provided Comments for Alert\n'
            for comment in comments:
                comments_hr += '- {}\n'.format(comment)
            hr += comments_hr

    if 'FileStates' in fields_list or show_all_fields:
        file_states = alert_details['fileStates']
        if file_states:
            file_states_hr = []
            for state in file_states:
                file_state = {
                    'Name': state['name'],
                    'Path': state['path'],
                    'RiskScore': state['riskScore']
                }
                file_hash = state.get('fileHash')
                if file_hash:
                    file_state['FileHash'] = file_hash['hashValue']
                file_states_hr.append(file_state)
            file_states_title = 'File Security States for Alert'
            hr += tableToMarkdown(file_states_title, file_states_hr, removeNull=True)

    if 'HostStates' in fields_list or show_all_fields:
        host_states = alert_details['hostStates']
        if host_states:
            host_states_hr = []
            for state in host_states:
                host_state = {
                    'Fqdn': state['fqdn'],
                    'NetBiosName': state['netBiosName'],
                    'OS': state['os'],
                    'PrivateIPAddress': state['privateIpAddress'],
                    'PublicIPAddress': state['publicIpAddress']
                }
                aad_joined = state.get('isAzureAadJoined')
                if aad_joined:
                    host_state['IsAsureAadJoined'] = aad_joined
                aad_registered = state.get('isAzureAadRegistered')
                if aad_registered:
                    host_state['IsAsureAadRegistered'] = aad_registered
                risk_score = state.get('riskScore')
                if risk_score:
                    host_state['RiskScore'] = risk_score
                host_states_hr.append(host_state)
            host_states_title = 'Host Security States for Alert'
            hr += tableToMarkdown(host_states_title, host_states_hr, removeNull=True)

    if 'MalwareStates' in fields_list or show_all_fields:
        malware_states = alert_details['malwareStates']
        if malware_states:
            malware_states_hr = []
            for state in malware_states:
                malware_states_hr.append({
                    'Category': state['category'],
                    'Familiy': state['family'],
                    'Name': state['name'],
                    'Severity': state['severity'],
                    'WasRunning': state['wasRunning']
                })
            malware_states_title = 'Malware States for Alert'
            hr += tableToMarkdown(malware_states_title, malware_states_hr, removeNull=True)

    if 'NetworkConnections' in fields_list or show_all_fields:
        network_connections = alert_details['networkConnections']
        if network_connections:
            network_connections_hr = []
            for connection in network_connections:
                connection_hr = {}
                for key, value in connection.items():
                    if value or value is False:
                        connection_hr[capitalize_first_letter(key)] = value
                network_connections_hr.append(connection_hr)
            network_connections_title = 'Network Connections for Alert'
            hr += tableToMarkdown(network_connections_title, network_connections_hr, removeNull=True)

    if 'Processes' in fields_list or show_all_fields:
        processes = alert_details['processes']
        if processes:
            processes_hr = []
            for process in processes:
                process_hr = {}
                for key, value in process.items():
                    if value or value is False:
                        process_hr[capitalize_first_letter(key)] = value
                processes_hr.append(process_hr)
            processes_title = 'Processes for Alert'
            hr += tableToMarkdown(processes_title, processes_hr, removeNull=True)

    if 'Triggers' in fields_list or show_all_fields:
        triggers = alert_details['triggers']
        if triggers:
            triggers_hr = []
            for trigger in triggers:
                triggers_hr.append({
                    'Name': trigger['name'],
                    'Type': trigger['type'],
                    'Value': trigger['value']
                })
            triggers_title = 'Triggers for Alert'
            hr += tableToMarkdown(triggers_title, triggers_hr, removeNull=True)

    if 'UserStates' in fields_list or show_all_fields:
        user_states = alert_details['userStates']
        if user_states:
            user_states_hr = []
            for state in user_states:
                state_hr = {}
                for key, value in state.items():
                    if value or value is False:
                        state_hr[capitalize_first_letter(key)] = value
                user_states_hr.append(state_hr)
            user_states_title = 'User Security States for Alert'
            hr += tableToMarkdown(user_states_title, user_states_hr, removeNull=True)

    if 'VendorInformation' in fields_list or show_all_fields:
        vendor_information = alert_details['vendorInformation']
        if vendor_information:
            vendor_info_hr = {
                'Provider': vendor_information['provider'],
                'ProviderVersion': vendor_information['providerVersion'],
                'SubProvider': vendor_information['subProvider'],
                'Vendor': vendor_information['vendor']
            }
            vendor_info_title = 'Vendor Information for Alert'
            hr += tableToMarkdown(vendor_info_title, vendor_info_hr, removeNull=True)

    if 'VulnerabilityStates' in fields_list or show_all_fields:
        vulnerability_states = alert_details['vulnerabilityStates']
        if vulnerability_states:
            vulnerability_states_hr = []
            for state in vulnerability_states:
                vulnerability_states_hr.append({
                    'CVE': state['cve'],
                    'Severity': state['severity'],
                    'WasRunning': state['wasRunning']
                })
            vulnerability_states_title = 'Vulnerability States for Alert'
            hr += tableToMarkdown(vulnerability_states_title, vulnerability_states_hr, removeNull=True)

    if 'RegistryKeys' in fields_list or show_all_fields:
        registry_keys = alert_details['registryKeyStates']
        if registry_keys:
            registry_keys_hr = []
            for r_key in registry_keys:
                r_key_hr = {}
                for key, value in r_key.items():
                    if value or value is False:
                        r_key_hr[capitalize_first_letter(key)] = value
                registry_keys_hr.append(r_key_hr)
            registry_keys_title = 'Registry Keys for Alert'
            hr += tableToMarkdown(registry_keys_title, registry_keys_hr, removeNull=True)

    context = {
        'ID': alert_details['id'],
        'Title': alert_details['title'],
        'Category': alert_details['category'],
        'Severity': alert_details['severity'],
        'CreatedDate': alert_details['createdDateTime'],
        'EventDate': alert_details['eventDateTime'],
        'Status': alert_details['status'],
        'Vendor': alert_details['vendorInformation']['vendor'],
        'Provider': alert_details['vendorInformation']['provider']
    }
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': context
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': alert_details,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }
    demisto.results(entry)


def get_alert_details(alert_id):
    cmd_url = 'security/alerts/' + alert_id
    response = http_request('GET', cmd_url)
    return response


def update_alert_command(args):
    alert_id = args.get('alert_id')
    vendor_information = args.get('vendor_information')
    provider_information = args.get('provider_information')
    assigned_to = args.get('assigned_to')
    closed_date_time = args.get('closed_date_time')
    comments = args.get('comments')
    feedback = args.get('feedback')
    status = args.get('status')
    tags = args.get('tags')
    if all(v is None for v in [assigned_to, closed_date_time, comments, feedback, status, tags]):
        return_error('No data to update was provided')
    update_alert(alert_id, vendor_information, provider_information,
                 assigned_to, closed_date_time, comments, feedback, status, tags)
    context = {
        'ID': alert_id
    }
    if status:
        context['Status'] = status
    ec = {
        'MsGraph.Alert(val.ID && val.ID === obj.ID)': context
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Alert {} has been successfully updated.'.format(alert_id),
        'EntryContext': ec
    }
    demisto.results(entry)


def update_alert(alert_id, vendor_information, provider_information,
                 assigned_to, closed_date_time, comments, feedback, status, tags):
    cmd_url = '/security/alerts/' + alert_id
    data: Dict[str, Any] = {
        'vendorInformation': {
            'provider': provider_information,
            'vendor': vendor_information
        }
    }
    if assigned_to:
        data['assignedTo'] = assigned_to
    if closed_date_time:
        data['closedDateTime'] = closed_date_time
    if comments:
        data['comments'] = [comments]
    if feedback:
        data['feedback'] = feedback
    if status:
        data['status'] = status
    if tags:
        data['tags'] = [tags]
    http_request('PATCH', cmd_url, json=data)


def get_users_command():
    users = get_users()['value']
    outputs = []
    for user in users:
        outputs.append({
            'Name': user['displayName'],
            'Title': user['jobTitle'],
            'Email': user['mail'],
            'ID': user['id']
        })
    ec = {
        'MsGraph.User(val.ID && val.ID === obj.ID)': outputs
    }
    table_headers = ['Name', 'Title', 'Email', 'ID']
    entry = {
        'Type': entryTypes['note'],
        'Contents': users,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Microsoft Graph Users', outputs, table_headers, removeNull=True),
        'EntryContext': ec
    }
    demisto.results(entry)


def get_users():
    cmd_url = 'users'
    response = http_request('GET', cmd_url)
    return response


def get_user_command():
    user_id = demisto.args().get('user_id')
    raw_user = get_user(user_id)
    user = {
        'Name': raw_user['displayName'],
        'Title': raw_user['jobTitle'],
        'Email': raw_user['mail'],
        'ID': raw_user['id']
    }
    ec = {
        'MsGraph.User(val.ID && val.ID === obj.ID)': user
    }
    table_headers = ['Name', 'Title', 'Email', 'ID']
    entry = {
        'Type': entryTypes['note'],
        'Contents': raw_user,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Microsoft Graph User ' + user_id, user, table_headers, removeNull=True),
        'EntryContext': ec
    }
    demisto.results(entry)


def get_user(user_id):
    cmd_url = 'users/' + user_id
    response = http_request('GET', cmd_url)
    return response


def test_function():
    token = get_access_token()
    response = requests.get(
        BASE_URL + 'users',
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        params={'$select': 'displayName'},
        verify=USE_SSL
    )
    try:
        data = response.json() if response.text else {}
        if not response.ok:
            return_error(f'API call to MS Graph Security failed. Please check authentication related parameters.'
                         f' [{response.status_code}] - {demisto.get(data, "error.message")}')

        demisto.results('ok')

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'API call to MS Graph Security failed, could not parse result. '
                     f'Please check authentication related parameters. [{response.status_code}]')


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        test_function()

    elif demisto.command() == 'msg-search-alerts':
        search_alerts_command(demisto.args())

    elif demisto.command() == 'msg-get-alert-details':
        get_alert_details_command(demisto.args())

    elif demisto.command() == 'msg-update-alert':
        update_alert_command(demisto.args())

    elif demisto.command() == 'msg-get-users':
        get_users_command()

    elif demisto.command() == 'msg-get-user':
        get_user_command()

except Exception as e:
    return_error(str(e))
