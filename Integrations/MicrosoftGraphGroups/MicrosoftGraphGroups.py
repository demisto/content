from CommonServerPython import *

'''IMPORTS'''
import requests
from datetime import datetime
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
BASE_URL = demisto.getParam('url').rstrip('/') + '/v1.0/'
TENANT = demisto.getParam('tenant_id')
AUTH_AND_TOKEN_URL = demisto.getParam('auth_id').split('@')
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = demisto.getParam('enc_key')
USE_SSL = not demisto.params().get('insecure', False)

''' CONSTANTS '''
if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = 'https://us-central1-oproxy-dev.cloudfunctions.net/'
    'ms_graph_groups_dev_ProvideAccessTokenFunction'  # disable-secrets-detection
# TOKEN_RETRIEVAL_URL = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
else:
TOKEN_RETRIEVAL_URL = AUTH_AND_TOKEN_URL[1]
BLOCK_ACCOUNT_JSON = '{"accountEnabled": false}'
UNBLOCK_ACCOUNT_JSON = '{"accountEnabled": true}'
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-groups'


def camel_case_to_readable(text):
    """
    'camelCase' -> 'Camel Case'
    """
    if text == 'id':
        return 'ID'
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_outputs(groups_data):
    """
    Parse user data as received from Microsoft Graph API into Demisto's conventions
    """
    if isinstance(groups_data, list):
        groups_readable, groups_outputs = [], []
        for group_data in groups_data:
            group_readable = {camel_case_to_readable(k): v for k, v in group_data.items() if k != '@odata.context'}
            groups_readable.append(group_readable)
            groups_outputs.append({k.replace(' ', ''): v for k, v in group_readable.copy().items()})

        return groups_readable, groups_outputs

    else:
        group_readable = {camel_case_to_readable(k): v for k, v in groups_data.items() if k != '@odata.context'}
        # if '@removed' in groups_data:
        #     group_readable['Status'] = 'deleted'
        user_outputs = {k.replace(' ', ''): v for k, v in group_readable.copy().items()}

        return group_readable, user_outputs


def epoch_seconds():
    """
    Return the number of seconds for return current date.
    """
    return int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds())


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


def http_request(method, url_suffix, params=None, body=None):
    """
    Generic request to Microsoft Graph
    """
    token = get_access_token()
    response = requests.request(
        method,
        BASE_URL + url_suffix,
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        params=params,
        data=body,
        verify=USE_SSL,
    )
    try:
        data = response.json() if response.text else {}
        if not response.ok:
            return_error(f'API call to MS Graph failed [{response.status_code}] - {demisto.get(data, "error.message")}')
        elif response.status_code == 206:  # 206 indicates Partial Content, reason will be in the warning header
            demisto.debug(str(response.headers))

        return data

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'Error in API call to Microsoft Graph, could not parse result [{response.status_code}]')


def test_function():
    token = get_access_token()
    response = requests.get(
        BASE_URL + 'groups',
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        params={'$orderby': 'displayName'},
        verify=USE_SSL
    )
    try:
        data = response.json() if response.text else {}
        if not response.ok:
            return_error(f'API call to MS Graph failed. Please check authentication related parameters.'
                         f' [{response.status_code}] - {demisto.get(data, "error.message")}')

        demisto.results('ok')

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'API call to MS Graph failed, could not parse result. '
                     f'Please check authentication related parameters. [{response.status_code}]')


def list_groups_command():
    order_by = demisto.getArg('order_by')
    groups = list_groups(order_by)

    readable, outputs = parse_outputs(groups['value'])
    human_readable = tableToMarkdown(name="Groups:", t=readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail'],
                                     removeNull=True)
    entry_context = {'MSGraphGroups.Groups(val.ID == obj.ID)': outputs}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=groups)


def list_groups(order_by):
    params = {'$orderby': order_by} if order_by else {}
    groups = http_request('GET', f'groups', params=params)

    return groups


def get_group_command():
    id_ = demisto.getArg('id')
    group = get_group(id_)

    readable, outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name="Groups:", t=readable, removeNull=True)
    entry_context = {'MSGraphGroups.Groups(val.ID == obj.ID)': outputs}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=group)


def get_group(id_):
    group = http_request('GET', f'groups/{id_}')

    return group


def create_group_command():
    required_properties = {
        'displayName': demisto.getArg('display_name'),
        'mailNickname': demisto.getArg('mail_nickname'),
        'mailEnabled': demisto.getArg('mail_enabled') == 'true',
        'securityEnabled': demisto.getArg('security_enabled')
    }

    # create the group
    group = create_group(required_properties)

    # display the new group and it's properties
    group_readable, group_outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name=f"{required_properties['displayName']} was created successfully:",
                                     t=group_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Security Enabled', 'Mail Enabled'],
                                     removeNull=True)
    entry_context = {'MSGraphGroups.Groups(val.ID == obj.ID)': group_outputs}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=group)


def create_group(properties):
    group = http_request('POST', 'groups', body=json.dumps(properties))
    return group


def delete_group_command():
    group_id = demisto.getArg('group_id')
    delete_group(group_id)

    return_outputs(readable_output=f'Group: "{group_id}" was deleted successfully.', outputs=NO_OUTPUTS)


def delete_group(group_id):
    #  If successful, this method returns 204 No Content response code.
    #  It does not return anything in the response body.
    http_request('DELETE ', f'groups/{group_id}')


def get_delta_command():
    properties = demisto.getArg('properties')
    groups_data = get_delta(properties)
    headers = list(set([camel_case_to_readable(p) for p in argToList(properties)] + ['ID']))

    groups_readable, groups_outputs = parse_outputs(groups_data)
    human_readable = tableToMarkdown(name='All Graph Users', headers=headers, t=groups_readable, removeNull=True)
    entry_context = {'MSGraphGroups.Groups(val.ID == obj.ID)': groups_outputs}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=groups_data)


def get_delta(properties):
    users = http_request('GET', 'users/delta', params={'$select': properties}).get('value')
    return users


def list_members_command():
    group_id = demisto.getArg('group_id')
    members = list_members(group_id)

    members_readable, members_outputs = parse_outputs(members['value'])
    human_readable = tableToMarkdown(name=f'Group {group_id} members:', t=members_readable,
                                     # headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail'],
                                     removeNull=True)
    entry_context = {'MSGraphGroups.Members(val.ID == obj.ID)': members_outputs}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=members)


def list_members(group_id):
    members = http_request('GET', f'groups/{group_id}/members')

    return members


def add_member_command():
    group_id = demisto.getArg('group_id')
    user_id = demisto.getArg('user_id')
    required_properties = {
        "@odata.id": f'https://graph.microsoft.com/v1.0/users/{user_id}'}
    add_member(group_id, required_properties)

    # display the new member and it's properties
    member_readable, member_outputs = parse_outputs(required_properties)
    human_readable = tableToMarkdown(name=f"{member_id} was added successfully:", t=member_readable,
                                     removeNull=True)
    entry_context = {'MSGraphUser(val.ID == obj.ID)': member_outputs}
    return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=required_properties)


def add_member(group_id, properties):
    #  If successful, this method returns 204 No Content response code.
    #  It does not return anything in the response body.
    http_request('POST', f'groups/{group_id}/members/$ref', body=json.dumps(properties))


def remove_member_command():
    group_id = demisto.getArg('group_id')
    user_id = demisto.getArg('user_id')
    required_properties = {
        "@odata.id": f'https://graph.microsoft.com/v1.0/users/{user_id}'}
    remove_member(group_id, required_properties)

    return_outputs(readable_output=f'User {user_id} was removed successfully.', outputs=NO_OUTPUTS)


def remove_member(group_id, properties):
    #  If successful, this method returns 204 No Content response code.
    #  It does not return anything in the response body.
    http_request('DELETE ', f'groups/{group_id}/members/$ref', body=json.dumps(properties))


try:
    handle_proxy()

    # COMMANDS
    if demisto.command() == 'test-module':
        test_function()

    # Groups
    elif demisto.command() == 'msgraph-groups-list-groups':
        list_groups_command()
    elif demisto.command() == 'msgraph-groups-get-group':
        get_group_command()
    elif demisto.command() == 'msgraph-groups-create-group':
        create_group_command()
    elif demisto.command() == 'msgraph-groups-delete-group':
        delete_group_command()
    elif demisto.command() == 'msgraph-groups-get-group-delta':
        get_delta_command()

    # Members
    elif demisto.command() == 'msgraph-groups-list-members':
        list_members_command()
    elif demisto.command() == 'msgraph-groups-add-member':
        add_member_command()
    elif demisto.command() == 'msgraph-groups-remove-member':
        remove_member_command()



except Exception as ex:
    return_error(str(ex))
