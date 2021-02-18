import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Dict

# disable insecure warnings

requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
BLOCK_ACCOUNT_JSON = '{"accountEnabled": false}'
UNBLOCK_ACCOUNT_JSON = '{"accountEnabled": true}'
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-user'


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


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed,
                 redirect_uri, auth_code):
        grant_type = AUTHORIZATION_CODE if self_deployed else CLIENT_CREDENTIALS
        resource = None if self_deployed else ''
        self.ms_client = MicrosoftClient(tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                                         base_url=base_url, verify=verify, proxy=proxy, self_deployed=self_deployed,
                                         redirect_uri=redirect_uri, auth_code=auth_code, grant_type=grant_type,
                                         resource=resource)

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def terminate_user_session(self, user):
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{user}',
            data=BLOCK_ACCOUNT_JSON,
            resp_type="text"
        )

    #  Using resp_type=text to avoid parsing error.
    def unblock_user(self, user):
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{user}',
            data=UNBLOCK_ACCOUNT_JSON,
            resp_type="text"
        )

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def delete_user(self, user):
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=f'users/{user}',
            resp_type="text"
        )

    def create_user(self, properties):
        self.ms_client.http_request(
            method='POST',
            url_suffix='users',
            json_data=properties)

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def update_user(self, user, updated_fields):
        body = {}
        for key_value in updated_fields.split(','):
            field, value = key_value.split('=', 2)
            body[field] = value
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{user}',
            json_data=body,
            resp_type="text")

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def password_change_user(self, user: str, password: str, force_change_password_next_sign_in: bool,
                             force_change_password_with_mfa: bool):
        body = {
            "passwordProfile":
                {
                    "forceChangePasswordNextSignIn": force_change_password_next_sign_in,
                    "forceChangePasswordNextSignInWithMfa": force_change_password_with_mfa,
                    "password": password
                }
        }
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{user}',
            json_data=body,
            resp_type="text")

    def get_delta(self, properties):
        users = self.ms_client.http_request(
            method='GET',
            url_suffix='users/delta',
            params={'$select': properties})
        return users.get('value', '')

    def get_user(self, user, properties):
        user_data = self.ms_client.http_request(
            method='GET',
            url_suffix=f'users/{user}',
            params={'$select': properties})
        user_data.pop('@odata.context', None)
        return user_data

    def list_users(self, properties, page_url):
        if page_url:
            response = self.ms_client.http_request(method='GET', url_suffix='users', full_url=page_url)
        else:
            response = self.ms_client.http_request(method='GET', url_suffix='users', params={'$select': properties})
        next_page_url = response.get('@odata.nextLink')
        users = response.get('value')
        return users, next_page_url

    def get_direct_reports(self, user):
        res = self.ms_client.http_request(
            method='GET',
            url_suffix=f'users/{user}/directReports')

        res.pop('@odata.context', None)
        return res.get('value', [])

    def get_manager(self, user):
        manager_data = self.ms_client.http_request(
            method='GET',
            url_suffix=f'users/{user}/manager')
        manager_data.pop('@odata.context', None)
        manager_data.pop('@odata.type', None)
        return manager_data

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def assign_manager(self, user, manager):
        manager_ref = "{}users/{}".format(self.ms_client._base_url, manager)
        body = {"@odata.id": manager_ref}
        self.ms_client.http_request(
            method='PUT',
            url_suffix=f'users/{user}/manager/$ref',
            json_data=body,
            resp_type="text"
        )


def test_function(client, _):
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
       """
    response = 'ok'
    if demisto.params().get('self_deployed', False):
        response = '```✅ Success!```'
        if demisto.command() == 'test-module':
            # cannot use test module due to the lack of ability to set refresh token to integration context
            # for self deployed app
            raise Exception("When using a self-deployed configuration, "
                            "Please enable the integration and run the !msgraph-user-test command in order to test it")
        if not demisto.params().get('auth_code') or not demisto.params().get('redirect_uri'):
            raise Exception("You must enter an authorization code in a self-deployed configuration.")

    client.ms_client.http_request(method='GET', url_suffix='users/')
    return response, None, None


def terminate_user_session_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    client.terminate_user_session(user)
    human_readable = f'user: "{user}" session has been terminated successfully'
    return human_readable, None, None


def unblock_user_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    client.unblock_user(user)
    human_readable = f'"{user}" unblocked. It might take several minutes for the changes to take affect across all ' \
                     f'applications. '
    return human_readable, None, None


def delete_user_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    client.delete_user(user)
    human_readable = f'user: "{user}" was deleted successfully'
    return human_readable, None, None


def create_user_command(client: MsGraphClient, args: Dict):
    required_properties = {
        'accountEnabled': args.get('account_enabled'),
        'displayName': args.get('display_name'),
        'onPremisesImmutableId': args.get('on_premises_immutable_id'),
        'mailNickname': args.get('mail_nickname'),
        'passwordProfile': {
            "forceChangePasswordNextSignIn": 'true',
            "password": args.get('password')
        },
        'userPrincipalName': args.get('user_principal_name')
    }
    other_properties = {}
    if args.get('other_properties'):
        for key_value in args.get('other_properties', '').split(','):
            key, value = key_value.split('=', 2)
            other_properties[key] = value
        required_properties.update(other_properties)

    # create the user
    client.create_user(required_properties)

    # display the new user and it's properties
    user = required_properties.get('userPrincipalName')
    user_data = client.get_user(user, '*')
    user_readable, user_outputs = parse_outputs(user_data)
    human_readable = tableToMarkdown(name=f"{user} was created successfully:", t=user_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': user_outputs}
    return human_readable, outputs, user_data


def update_user_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    updated_fields = args.get('updated_fields')

    client.update_user(user, updated_fields)
    return get_user_command(client, args)


def change_password_user_command(client: MsGraphClient, args: Dict):
    user = str(args.get('user'))
    password = str(args.get('password'))
    force_change_password_next_sign_in = args.get('force_change_password_next_sign_in', 'true') == 'true'
    force_change_password_with_mfa = args.get('force_change_password_with_mfa', False) == 'true'

    client.password_change_user(user, password, force_change_password_next_sign_in, force_change_password_with_mfa)
    human_readable = f'User {user} password was changed successfully.'
    return human_readable, {}, {}


def get_delta_command(client: MsGraphClient, args: Dict):
    properties = args.get('properties', '') + ',userPrincipalName'
    users_data = client.get_delta(properties)
    headers = list(set([camel_case_to_readable(p) for p in argToList(properties)] + ['ID', 'User Principal Name']))

    users_readable, users_outputs = parse_outputs(users_data)
    human_readable = tableToMarkdown(name='All Graph Users', headers=headers, t=users_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': users_outputs}
    return human_readable, outputs, users_data


def get_user_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    properties = args.get('properties', '*')
    user_data = client.get_user(user, properties)

    user_readable, user_outputs = parse_outputs(user_data)
    human_readable = tableToMarkdown(name=f"{user} data", t=user_readable, removeNull=True)
    outputs = {'MSGraphUser(val.ID == obj.ID)': user_outputs}
    return human_readable, outputs, user_data


def list_users_command(client: MsGraphClient, args: Dict):
    properties = args.get('properties', 'id,displayName,jobTitle,mobilePhone,mail')
    next_page = args.get('next_page', None)
    users_data, result_next_page = client.list_users(properties, next_page)
    users_readable, users_outputs = parse_outputs(users_data)
    metadata = None
    outputs = {'MSGraphUser(val.ID == obj.ID)': users_outputs}

    if result_next_page:
        metadata = "To get further results, enter this to the next_page parameter:\n" + str(result_next_page)

        # .NextPage.indexOf(\'http\')>=0 : will make sure the NextPage token will always be updated because it's a url
        outputs['MSGraphUser(val.NextPage.indexOf(\'http\')>=0)'] = {'NextPage': result_next_page}

    human_readable = tableToMarkdown(name='All Graph Users', t=users_readable, removeNull=True, metadata=metadata)

    return human_readable, outputs, users_data


def get_direct_reports_command(client: MsGraphClient, args: Dict):
    user = args.get('user')

    raw_reports = client.get_direct_reports(user)

    reports_readable, reports = parse_outputs(raw_reports)
    human_readable = tableToMarkdown(name=f"{user} - direct reports", t=reports_readable, removeNull=True)
    outputs = {
        'MSGraphUserDirectReports(val.Manager == obj.Manager)': {
            'Manager': user,
            'Reports': reports
        }
    }

    return human_readable, outputs, raw_reports


def get_manager_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    manager_data = client.get_manager(user)
    manager_readable, manager_outputs = parse_outputs(manager_data)
    human_readable = tableToMarkdown(name=f"{user} - manager", t=manager_readable, removeNull=True)
    outputs = {
        'MSGraphUserManager(val.User == obj.User)': {
            'User': user,
            'Manager': manager_outputs
        }
    }
    return human_readable, outputs, manager_data


def assign_manager_command(client: MsGraphClient, args: Dict):
    user = args.get('user')
    manager = args.get('manager')
    client.assign_manager(user, manager)
    human_readable = f'A manager was assigned to user "{user}". It might take several minutes for the changes ' \
                     'to take affect across all applications.'
    return human_readable, None, None


def main():
    params: dict = demisto.params()
    url = params.get('host', '').rstrip('/') + '/v1.0/'
    tenant = params.get('tenant_id')
    auth_and_token_url = params.get('auth_id', '')
    enc_key = params.get('enc_key')
    verify = not params.get('insecure', False)
    self_deployed: bool = params.get('self_deployed', False)
    redirect_uri = params.get('redirect_uri', '')
    auth_code = params.get('auth_code', '')
    proxy = params.get('proxy', False)

    commands = {
        'msgraph-user-test': test_function,
        'test-module': test_function,
        'msgraph-user-unblock': unblock_user_command,
        'msgraph-user-terminate-session': terminate_user_session_command,
        'msgraph-user-update': update_user_command,
        'msgraph-user-change-password': change_password_user_command,
        'msgraph-user-delete': delete_user_command,
        'msgraph-user-create': create_user_command,
        'msgraph-user-get-delta': get_delta_command,
        'msgraph-user-get': get_user_command,
        'msgraph-user-list': list_users_command,
        'msgraph-direct-reports': get_direct_reports_command,
        'msgraph-user-get-manager': get_manager_command,
        'msgraph-user-assign-manager': assign_manager_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client: MsGraphClient = MsGraphClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key,
                                              app_name=APP_NAME, base_url=url, verify=verify, proxy=proxy,
                                              self_deployed=self_deployed, redirect_uri=redirect_uri,
                                              auth_code=auth_code)
        human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
        return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
