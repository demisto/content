import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import requests
from datetime import datetime

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
BASE_URL = demisto.getParam('host').rstrip('/') + '/v1.0/'
TENANT = demisto.getParam('tenant')
TOKEN = demisto.getParam('token')
HEADERS = {"Authorization": TOKEN, "Accept": "application/json"}
USE_SSL = not demisto.params().get('unsecure', False)

''' CONSTANTS '''
DEMISTOBOT = "https://demistobot.demisto.com/msg-user-token"
PRODUCT = "MicrosoftGraphUser"
BLOCK_ACCOUNT_JSON = '{"accountEnabled": false}'
UNBLOCK_ACCOUNT_JSON = '{"accountEnabled": true}'
NO_OUTPUTS = {}


def camel_case_to_readable(text):
    """
    'camelCase' -> 'Camel Case'
    """
    if text == 'id':
        return 'ID'
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_outputs(users_data):
    """
    Parse user data as received from Microsoft Graph API into Demisto's conventions
    """
    if isinstance(users_data, list):
        users_readable, users_outputs = [], []
        for user_data in users_data:
            user_readable = {camel_case_to_readable(k): v for k, v in user_data.items() if k != '@removed'}
            if '@removed' in user_data:
                user_readable['Status'] = 'deleted'
            users_readable.append(user_readable)
            users_outputs.append({k.replace(' ', ''): v for k, v in user_readable.copy().items()})

        return users_readable, users_outputs

    else:
        user_readable = {camel_case_to_readable(k): v for k, v in users_data.items() if k != '@removed'}
        if '@removed' in users_data:
            user_readable['Status'] = 'deleted'
        user_outputs = {k.replace(' ', ''): v for k, v in user_readable.copy().items()}

        return user_readable, user_outputs


def epoch_seconds():
    """
    Return the number of seconds for return current date.
    """
    return int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds())


def get_token(refresh_token=False):
    """
    Check if we have a valid token and if not get one
    """
    ctx = demisto.getIntegrationContext()
    if {'token', 'stored', 'expires'} <= set(ctx) and not refresh_token:
        if epoch_seconds() - ctx.get('stored') < ctx.get('expires'):
            return ctx.get('token')
    response = requests.get(
        DEMISTOBOT,
        headers=HEADERS,
        params={"tenant": TENANT, "product": PRODUCT},
        verify=USE_SSL,
    )
    data = response.json()
    if not response.ok:
        return_error(f'API call to MS Graph failed [{data.get("status")} {data.get("title")}] - {data.get("detail")}')

    demisto.setIntegrationContext({
        'token': data.get('token'),
        'stored': epoch_seconds(),
        'expires': data.get('expires', 3600) - 30
    })
    return data.get('token')


def http_request(method, url_suffix, params=None, body=None, do_not_refresh_token=False):
    """
    Generic request to Microsoft Graph
    """
    token = get_token()
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
            if demisto.get(data, "error.message") == 'InvalidAuthenticationToken' and not do_not_refresh_token:
                get_token(refresh_token=True)  # try refreshing the token only once (avoid endless loop)
                return http_request(method, url_suffix, params, body, do_not_refresh_token=True)
            return_error(f'API call to MS Graph failed [{response.status_code}] - {demisto.get(data, "error.message")}')
        elif response.status_code == 206:  # 206 indicates Partial Content, reason will be in the warning header
            demisto.debug(str(response.headers))

        return data

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'Error in API call to Microsoft Graph, could not parse result [{response.status_code}]')


def test_function():
    token = get_token()
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
            return_error(f'API call to MS Graph failed. Please check authentication related parameters.'
                         f' [{response.status_code}] - {demisto.get(data, "error.message")}')

        demisto.results('ok')

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(f'API call to MS Graph failed, could not parse result. '
                     f'Please check authentication related parameters. [{response.status_code}]')


def terminate_user_session_command():
    user = demisto.getArg('user')
    terminate_user_session(user)

    return_outputs(readable_output=f'user: "{user}" session has been terminated successfully', outputs=NO_OUTPUTS)


def terminate_user_session(user):
    http_request('PATCH', f'users/{user}', body=BLOCK_ACCOUNT_JSON)


def unblock_user_command():
    user = demisto.getArg('user')
    unblock_user(user)

    return_outputs(
        readable_output=f'"{user}" unblocked. It might take several minutes for the changes to take affect across '
        'all applications.',
        outputs=NO_OUTPUTS
    )


def unblock_user(user):
    http_request('PATCH', f'users/{user}', body=UNBLOCK_ACCOUNT_JSON)


def delete_user_command():
    user = demisto.getArg('user')
    delete_user(user)

    return_outputs(readable_output=f'user: "{user}" was deleted successfully', outputs=NO_OUTPUTS)


def delete_user(user):
    http_request('DELETE ', f'users/{user}')


def create_user_command():
    required_properties = {
        'accountEnabled': demisto.getArg('account_enabled'),
        'displayName': demisto.getArg('display_name'),
        'onPremisesImmutableId': demisto.getArg('on_premises_immutable_id'),
        'mailNickname': demisto.getArg('mail_nickname'),
        'passwordProfile': {
            "forceChangePasswordNextSignIn": 'true',
            "password": demisto.getArg('password')
        },
        'userPrincipalName': demisto.getArg('user_principal_name')
    }
    other_properties = {}
    for key_value in demisto.getArg('other_properties').split(','):
        key, value = key_value.split('=', 2)
        other_properties[key] = value

    # create the user
    required_properties.update(other_properties)
    create_user(required_properties)

    # display the new user and it's properties
    user = required_properties.get('userPrincipalName')
    user_data = get_user(user, '*')
    user_readable, user_outputs = parse_outputs(user_data)
    human_readable = tableToMarkdown(name=f"{user} was created successfully:", t=user_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': user_outputs}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=user_data)


def create_user(properties):
    http_request('POST', 'users', body=json.dumps(properties))


def update_user_command():
    user = demisto.getArg('user')
    updated_fields = demisto.getArg('updated_fields')

    update_user(user, updated_fields)
    get_user_command()


def update_user(user, updated_fields):
    body = {}
    for key_value in updated_fields.split(','):
        field, value = key_value.split('=', 2)
        body[field] = value
    http_request('PATCH', f'users/{user}', body=json.dumps(body))


def get_delta_command():
    properties = demisto.getArg('properties') + ',userPrincipalName'
    users_data = get_delta(properties)
    headers = list(set([camel_case_to_readable(p) for p in argToList(properties)] + ['ID', 'User Principal Name']))

    users_readable, users_outputs = parse_outputs(users_data)
    hr = tableToMarkdown(name='All Graph Users', headers=headers, t=users_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': users_outputs}
    return_outputs(readable_output=hr, outputs=outputs, raw_response=users_data)


def get_delta(properties):
    users = http_request('GET', 'users/delta', params={'$select': properties}).get('value')
    return users


def get_user_command():
    user = demisto.getArg('user')
    properties = demisto.args().get('properties', '*')
    user_data = get_user(user, properties)

    user_readable, user_outputs = parse_outputs(user_data)
    human_readable = tableToMarkdown(name=f"{user} data", t=user_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': user_outputs}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=user_data)


def get_user(user, properties):
    user_data = http_request('GET ', f'users/{user}', params={'$select': properties})
    user_data.pop('@odata.context', None)

    return user_data


def list_users_command():
    properties = demisto.args().get('properties', 'id,displayName,jobTitle,mobilePhone,mail')
    users_data = list_users(properties)

    users_readable, users_outputs = parse_outputs(users_data)
    human_readable = tableToMarkdown(name='All Graph Users', t=users_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': users_outputs}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=users_data)


def list_users(properties):
    users = http_request('GET', 'users', params={'$select': properties}).get('value')
    return users


try:
    handle_proxy()

    # COMMANDS
    if demisto.command() == 'test-module':
        test_function()

    elif demisto.command() == 'msgraph-user-terminate-session':
        terminate_user_session_command()

    elif demisto.command() == 'msgraph-user-unblock':
        unblock_user_command()

    elif demisto.command() == 'msgraph-user-update':
        update_user_command()

    elif demisto.command() == 'msgraph-user-delete':
        delete_user_command()

    elif demisto.command() == 'msgraph-user-create':
        create_user_command()

    elif demisto.command() == 'msgraph-user-get-delta':
        get_delta_command()

    elif demisto.command() == 'msgraph-user-get':
        get_user_command()

    elif demisto.command() == 'msgraph-user-list':
        list_users_command()


except Exception as ex:
    return_error(str(ex))
    raise
