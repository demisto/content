import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from urllib.parse import quote
import urllib3
from MicrosoftApiModule import *  # noqa: E402
from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES

# disable insecure warnings

urllib3.disable_warnings()

''' CONSTANTS '''
BLOCK_ACCOUNT_JSON = '{"accountEnabled": false}'
UNBLOCK_ACCOUNT_JSON = '{"accountEnabled": true}'
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-user'
INVALID_USER_CHARS_REGEX = re.compile(r'[%&*+/=?`{|}]')
API_VERSION: str = 'v1.0'


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


def create_account_outputs(users_outputs: (list[dict[str, Any]] | dict[str, Any])) -> list:
    if not isinstance(users_outputs, list):
        users_outputs = [users_outputs]

    accounts = []
    for user_outputs in users_outputs:
        accounts.append({
            'Type': 'Azure AD',
            'DisplayName': user_outputs.get('DisplayName'),
            'Username': user_outputs.get('UserPrincipalName'),
            'JobTitle': user_outputs.get('JobTitle'),
            'Email': {'Address': user_outputs.get('Mail')},
            'TelephoneNumber': user_outputs.get('MobilePhone'),
            'ID': user_outputs.get('ID'),
            'Office': user_outputs.get('OfficeLocation')
        })

    return accounts


def get_unsupported_chars_in_user(user: Optional[str]) -> set:
    """
    Extracts the invalid user characters found in the provided string.
    """
    if not user:
        return set()
    return set(INVALID_USER_CHARS_REGEX.findall(user))


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed,
                 redirect_uri, auth_code, handle_error, azure_cloud: AzureCloud, certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None,
                 managed_identities_client_id: Optional[str] = None
                 ):
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        resource = None if self_deployed else ''
        client_args = {
            'tenant_id': tenant_id,
            'auth_id': auth_id,
            'enc_key': enc_key,
            'app_name': app_name,
            'base_url': base_url,
            'verify': verify,
            'proxy': proxy,
            'self_deployed': self_deployed,
            'redirect_uri': redirect_uri,
            'auth_code': auth_code,
            'grant_type': grant_type,
            'resource': resource,
            'certificate_thumbprint': certificate_thumbprint,
            'private_key': private_key,
            'azure_cloud': azure_cloud,
            'managed_identities_client_id': managed_identities_client_id,
            'managed_identities_resource_uri': Resources.graph,
            'command_prefix': "msgraph-user",
        }
        self.ms_client = MicrosoftClient(**client_args)
        self.handle_error = handle_error

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def disable_user_account_session(self, user):
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{quote(user)}',
            data=BLOCK_ACCOUNT_JSON,
            resp_type="text"
        )

    #  Using resp_type=text to avoid parsing error.
    def unblock_user(self, user):
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{quote(user)}',
            data=UNBLOCK_ACCOUNT_JSON,
            resp_type="text"
        )

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def delete_user(self, user):
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=f'users/{quote(user)}',
            resp_type="text"
        )

    def create_user(self, properties):
        self.ms_client.http_request(
            method='POST',
            url_suffix='users',
            json_data=properties)

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def update_user(self, user: str, updated_fields: str, delimiter: str = ','):
        body = {}
        for key_value in updated_fields.split(delimiter):
            field, value = key_value.split('=', 2)
            body[field] = value
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'users/{quote(user)}',
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
            url_suffix=f'users/{quote(user)}',
            json_data=body,
            resp_type="text")

    def get_delta(self, properties):
        users = self.ms_client.http_request(
            method='GET',
            url_suffix='users/delta',
            params={'$select': properties})
        return users.get('value', '')

    def get_user(self, user, properties):
        try:
            user_data = self.ms_client.http_request(
                method='GET',
                url_suffix=f'users/{quote(user)}',
                params={'$select': properties})
            user_data.pop('@odata.context', None)
            return user_data
        except NotFoundError as e:
            LOG(f'User {user} was not found')
            return {'NotFound': e.message}
        except Exception as e:
            raise e

    def list_users(self, properties, page_url, filters):
        if page_url:
            response = self.ms_client.http_request(method='GET', url_suffix='users', full_url=page_url)
        else:
            response = self.ms_client.http_request(method='GET', url_suffix='users',
                                                   headers={"ConsistencyLevel": "eventual"},
                                                   params={'$filter': filters, '$select': properties, "$count": "true"})

        next_page_url = response.get('@odata.nextLink')
        users = response.get('value')
        return users, next_page_url

    def get_direct_reports(self, user):
        res = self.ms_client.http_request(
            method='GET',
            url_suffix=f'users/{quote(user)}/directReports')

        res.pop('@odata.context', None)
        return res.get('value', [])

    def get_manager(self, user):
        manager_data = self.ms_client.http_request(
            method='GET',
            url_suffix=f'users/{quote(user)}/manager')
        manager_data.pop('@odata.context', None)
        manager_data.pop('@odata.type', None)
        return manager_data

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def assign_manager(self, user, manager):
        manager_ref = f"{self.ms_client._base_url}users/{manager}"
        body = {"@odata.id": manager_ref}
        self.ms_client.http_request(
            method='PUT',
            url_suffix=f'users/{quote(user)}/manager/$ref',
            json_data=body,
            resp_type="text"
        )

    #  If successful, this method returns 204 No Content response code.
    #  Using resp_type=text to avoid parsing error.
    def revoke_user_session(self, user):
        self.ms_client.http_request(
            method='POST',
            url_suffix=f'users/{quote(user)}/revokeSignInSessions',
            resp_type="text"
        )
    
    #  If successful, this method returns 200
    def list_tap_policy(self, user_id, policy_id):
        url_suffix = f'users/{quote(user_id)}/authentication/temporaryAccessPassMethods'
        if policy_id:
            url_suffix += f'/{quote(policy_id)}'
        
        res = self.ms_client.http_request(
            method='GET',
            url_suffix=url_suffix
        )
        if policy_id:
            return res
        return res.get('value', [])

        
    #  If successful, this method returns 201
    def create_tap_policy(self, user_id, body):
        url_suffix = f'users/{quote(user_id)}/authentication/temporaryAccessPassMethods'
        res = self.ms_client.http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=body
        )
        return res
    
    #  If successful, this method returns 204 - no content
    def delete_tap_policy(self, user_id, policy_id):
        url_suffix = f'users/{quote(user_id)}/authentication/temporaryAccessPassMethods/{quote(policy_id)}'
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=url_suffix,
            resp_type="text"
        )

def suppress_errors_with_404_code(func):
    def wrapper(client: MsGraphClient, args: dict):
        try:
            return func(client, args)
        except NotFoundError as e:
            if client.handle_error:
                if (user := args.get("user", '___')) in str(e):
                    human_readable = f'#### User -> {user} does not exist'
                    return human_readable, None, None
                elif (manager := args.get('manager', '___')) in str(e):
                    human_readable = f'#### Manager -> {manager} does not exist'
                    return human_readable, None, None
                elif "The specified user could not be found." in str(e.message):
                    user = args.get('user', '___')
                    human_readable = f'#### User -> {user} does not exist'
                    return human_readable, None, None
            raise
    return wrapper


def test_function(client, _):
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
       """
    response = 'ok'
    if demisto.params().get('self_deployed', False):
        if demisto.command() == 'test-module':
            if client.ms_client.grant_type != CLIENT_CREDENTIALS:
                # cannot use test module due to the lack of ability to set refresh token to integration context
                # for self deployed app
                raise Exception("When using a self-deployed configuration with authorization code and redirect uri, "
                                "Please enable the integration and run the !msgraph-user-test command in order to test it")
        else:
            response = '```✅ Success!```'

    client.ms_client.http_request(method='GET', url_suffix='users/')
    return response


@suppress_errors_with_404_code
def disable_user_account_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    client.disable_user_account_session(user)
    human_readable = f'user: "{user}" account has been disabled successfully.'
    
    return CommandResults(
        readable_output=human_readable
    )

@suppress_errors_with_404_code
def unblock_user_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    client.unblock_user(user)
    human_readable = f'"{user}" unblocked. It might take several minutes for the changes to take effect across all ' \
                     f'applications. '

    return CommandResults(
        readable_output=human_readable
    )


@suppress_errors_with_404_code
def delete_user_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    client.delete_user(user)
    human_readable = f'user: "{user}" was deleted successfully.'
    
    return CommandResults(
        readable_output=human_readable
    )


def create_user_command(client: MsGraphClient, args: dict):
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
    accounts = create_account_outputs(user_outputs)
    outputs = {
        'MSGraphUser': user_outputs,
        'Account': accounts[0] if accounts else []
    }
    
    return CommandResults(
        outputs=outputs,
        readable_output=human_readable,
        raw_response=user_data
    )


@suppress_errors_with_404_code
def update_user_command(client: MsGraphClient, args: dict):
    user: str = args['user']
    updated_fields: str = args['updated_fields']
    delimiter: str = args.get('updated_fields_delimiter', ',')

    client.update_user(user, updated_fields, delimiter)
    return get_user_command(client, args)


@suppress_errors_with_404_code
def change_password_user_command(client: MsGraphClient, args: dict):
    user = str(args.get('user'))
    password = str(args.get('password'))
    force_change_password_next_sign_in = args.get('force_change_password_next_sign_in', 'true') == 'true'
    force_change_password_with_mfa = args.get('force_change_password_with_mfa', False) == 'true'

    client.password_change_user(user, password, force_change_password_next_sign_in, force_change_password_with_mfa)
    human_readable = f'User {user} password was changed successfully.'
  
    return CommandResults(
        outputs={},
        readable_output=human_readable,
        raw_response={}
    )

def get_delta_command(client: MsGraphClient, args: dict):
    properties = args.get('properties', '') + ',userPrincipalName'
    users_data = client.get_delta(properties)
    headers = list(set([camel_case_to_readable(p) for p in argToList(properties)] + ['ID', 'User Principal Name']))

    users_readable, users_outputs = parse_outputs(users_data)
    human_readable = tableToMarkdown(name='All Graph Users', headers=headers, t=users_readable, removeNull=True)

    return CommandResults(
        outputs_prefix='MSGraphUser',
        outputs=users_outputs,
        readable_output=human_readable,
        raw_response=users_data
    )

def get_user_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    properties = args.get('properties', '*')
    try:
        user_data = client.get_user(user, properties)
    except DemistoException as e:
        if 'Bad request. Please fix the request before retrying' in e.args[0]:
            invalid_chars = get_unsupported_chars_in_user(user)
            if len(invalid_chars) > 0:
                error = f'Request failed because the user contains unsupported characters: {invalid_chars}\n{str(e)}'
                return error, {}, error
        raise e

    # In case the request returned a 404 error display a proper message to the war room
    if user_data.get('NotFound', ''):
        error_message = user_data.get('NotFound')
        human_readable = f'### User {user} was not found.\nMicrosoft Graph Response: {error_message}'
        return human_readable, {}, error_message

    user_readable, user_outputs = parse_outputs(user_data)
    accounts = create_account_outputs(user_outputs)
    human_readable = tableToMarkdown(name=f"{user} data", t=user_readable, removeNull=True)
    outputs = {
        'MSGraphUser': user_outputs,
        'Account': accounts[0] if accounts else []
    }
    
    return CommandResults(
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=human_readable,
        raw_response=user_data
    )


def list_users_command(client: MsGraphClient, args: dict):
    properties = args.get('properties', 'id,displayName,jobTitle,mobilePhone,mail')
    next_page = args.get('next_page', None)
    filters = args.get('filter', None)
    users_data, result_next_page = client.list_users(properties, next_page, filters)
    users_readable, users_outputs = parse_outputs(users_data)
    accounts = create_account_outputs(users_outputs)
    metadata = None
    
    outputs = {
        'MSGraphUser': users_outputs,
        'Account': accounts
    }
    
    if result_next_page:
        metadata = "To get further results, enter this to the next_page parameter:\n" + str(result_next_page)

        # .NextPage.indexOf(\'http\')>=0 : will make sure the NextPage token will always be updated because it's a url
        # outputs['MSGraphUser(val.NextPage.indexOf(\'http\')>=0)'] = {'NextPage': result_next_page}
        outputs['MSGraphUser'].insert(0, {'NextPage': result_next_page})
    human_readable = tableToMarkdown(name='All Graph Users', t=users_readable, removeNull=True, metadata=metadata)
    
    return CommandResults(
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=human_readable,
        raw_response=users_data
    )


@suppress_errors_with_404_code
def get_direct_reports_command(client: MsGraphClient, args: dict):
    user = args.get('user')

    raw_reports = client.get_direct_reports(user)

    reports_readable, reports = parse_outputs(raw_reports)
    human_readable = tableToMarkdown(name=f"{user} - direct reports", t=reports_readable, removeNull=True)
    outputs = {
            'Manager': user,
            'Reports': reports
    }
    return CommandResults(
        outputs_prefix='MSGraphUserDirectReports',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=human_readable,
        raw_response=raw_reports
    )
    

@suppress_errors_with_404_code
def get_manager_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    manager_data = client.get_manager(user)
    manager_readable, manager_outputs = parse_outputs(manager_data)
    human_readable = tableToMarkdown(name=f"{user} - manager", t=manager_readable, removeNull=True)
    outputs = {
            'User': user,
            'Manager': manager_outputs
    }
    
    return CommandResults(
        outputs_prefix='MSGraphUserManager',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=human_readable,
        raw_response=manager_data
    )


@suppress_errors_with_404_code
def assign_manager_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    manager = args.get('manager')
    client.assign_manager(user, manager)
    human_readable = f'A manager was assigned to user "{user}". It might take several minutes for the changes ' \
                     'to take affect across all applications.'

    return CommandResults(
        outputs_key_field='ID',
        readable_output=human_readable
    )


@suppress_errors_with_404_code
def revoke_user_session_command(client: MsGraphClient, args: dict):
    user = args.get('user')
    client.revoke_user_session(user)
    human_readable = f'User: "{user}" sessions have been revoked successfully.'

    return CommandResults(
        outputs_key_field='ID',
        readable_output=human_readable
    )

@suppress_errors_with_404_code
def get_tap_policy_list_command(client: MsGraphClient, args: dict):
    user_id = args.get('user_id')
    policy_id = args.get('policy_id', None)
    client_tap_data = client.list_tap_policy(user_id, policy_id)
    tap_readable, tap_policy_output = parse_outputs(client_tap_data)
    
    # change HR from ID to Policy ID
    if isinstance(tap_readable, list) and tap_readable:
        tap_readable_dict = tap_readable[0]
    else:
        tap_readable_dict = tap_readable

    if isinstance(tap_readable_dict, dict):
        tap_readable_dict['Policy ID'] = tap_readable_dict.pop('ID', None)
    headers = ['Policy ID', 'Start Date Time' , 'Lifetime In Minutes', 'Is Usable Once', 'Is Usable', 'Method Usability Reason']
    
    human_readable = tableToMarkdown(name='All TAP Policy Users', headers=headers, t=tap_readable_dict, removeNull=True)

    return CommandResults(
        outputs_prefix='MSGraphUser.TAPPolicy',
        outputs_key_field='ID',
        outputs=tap_policy_output,
        readable_output=human_readable,
        raw_response=client_tap_data
    )

@suppress_errors_with_404_code
def create_tap_policy_command(client: MsGraphClient, args: dict):
    user_id = args.get('user_id')
    zip_password = args.get('zip_password')
    lifetime_in_minutes = arg_to_number(args.get('lifetime_in_minutes'))
    is_usable_once = argToBoolean(args.get('is_usable_once', False))
    start_time = args.get('start_time', None)
    start_time_iso = arg_to_datetime(start_time, required=False)
    
    fields = {
    'lifetimeInMinutes': lifetime_in_minutes,
    'isUsableOnce': is_usable_once,
    'startDateTime': start_time_iso.strftime("%Y-%m-%dT%H:%M:%S.000Z") if start_time_iso is not None else None
}
    body = dict(fields.items())
    res = client.create_tap_policy(user_id, body)
    
    if zip_password:
        generated_password = res.get('temporaryAccessPass')
        return_results(
            create_zip_with_password(generated_password=generated_password, zip_password=zip_password)
        )
    human_readable = f'Temporary Access Pass Authentication methods policy {user_id} was successfully created'
    _, tap_policy_output = parse_outputs(res)
    
    return CommandResults(
        outputs_prefix='MSGraphUser.TAPPolicy',
        outputs_key_field='ID',
        outputs=tap_policy_output,
        readable_output=human_readable
    )

@suppress_errors_with_404_code
def delete_tap_policy_command(client: MsGraphClient, args: dict):
    user_id = args.get('user_id')
    policy_id = args.get('policy_id')
    client.delete_tap_policy(user_id, policy_id)
    human_readable = f'Temporary Access Pass Authentication methods policy {policy_id} was successfully deleted'
    
    return CommandResults(
    outputs_key_field='ID',
    readable_output=human_readable
    )


def create_zip_with_password(generated_password: str, zip_password: str):
    """
    Create a zip file with a password.
    The function returns a zip file to the war room, and calls this script recursively using polling.

    Args:
        args (dict): The arguments passed to the script.
        generated_password (str): The password to encrypt.
        zip_password (str): The password to use for encrypting the zip file.
    """
    text_file_name = 'TAPPolicyPass.txt'
    zip_file_name = 'TAPPolicyInfo.zip'

    try:
        with open(text_file_name, 'w') as text_file:
            text_file.write(generated_password)

        demisto.debug(f'zipping {text_file_name=}')
        with AESZipFile(zip_file_name, mode='w', compression=ZIP_DEFLATED, encryption=WZ_AES) as zf:
            zf.pwd = bytes(zip_password, 'utf-8')
            zf.write(text_file_name)

        with open(zip_file_name, 'rb') as zip_file:
            zip_content = zip_file.read()

    except Exception as e:
        raise DemistoException(f'Could not generate zip file. Error:\n{str(e)}')

    finally:
        for file_name in (text_file_name, zip_file_name):
            if os.path.exists(file_name):
                os.remove(file_name)

    return_results(fileResult(zip_file_name, zip_content))

def main():
    params: dict = demisto.params()
    azure_cloud = get_azure_cloud(params, 'MicrosoftGraphUser')
    url = urljoin(azure_cloud.endpoints.microsoft_graph_resource_id, f'/{API_VERSION}/')
    tenant = params.get('creds_tenant_id', {}).get('password', '') or params.get('tenant_id', '')
    auth_and_token_url = params.get('creds_auth_id', {}).get('password', '') or params.get('auth_id', '')
    enc_key = params.get('creds_enc_key', {}).get('password', '') or params.get('enc_key', '')
    verify = not params.get('insecure', False)
    redirect_uri = params.get('redirect_uri', '')
    auth_code = params.get('creds_auth_code', {}).get('password', '') or params.get('auth_code', '')
    proxy = params.get('proxy', False)
    handle_error = argToBoolean(params.get('handle_error', 'true'))
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier', '') or params.get('certificate_thumbprint', '')
    private_key = (replace_spaces_in_credential(params.get('creds_certificate', {}).get('password', ''))
                   or params.get('private_key', ''))
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get('self_deployed', False) or managed_identities_client_id is not None

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        if self_deployed and auth_code and not redirect_uri:
            raise DemistoException('Please provide both Application redirect URI and Authorization code '
                                   'for Authorization Code flow, or None for the Client Credentials flow')
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

    commands = {
        'msgraph-user-test': test_function,
        'test-module': test_function,
        'msgraph-user-unblock': unblock_user_command,
        'msgraph-user-terminate-session': disable_user_account_command,
        'msgraph-user-account-disable': disable_user_account_command,
        'msgraph-user-update': update_user_command,
        'msgraph-user-change-password': change_password_user_command,
        'msgraph-user-delete': delete_user_command,
        'msgraph-user-create': create_user_command,
        'msgraph-user-get-delta': get_delta_command,
        'msgraph-user-get': get_user_command,
        'msgraph-user-list': list_users_command,
        'msgraph-direct-reports': get_direct_reports_command,
        'msgraph-user-get-manager': get_manager_command,
        'msgraph-user-assign-manager': assign_manager_command,
        'msgraph-user-session-revoke': revoke_user_session_command,
        'msgraph-user-tap-policy-list': get_tap_policy_list_command,
        'msgraph-user-tap-policy-create': create_tap_policy_command,
        'msgraph-user-tap-policy-delete': delete_tap_policy_command,
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client: MsGraphClient = MsGraphClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key,
                                              app_name=APP_NAME, base_url=url, verify=verify, proxy=proxy,
                                              self_deployed=self_deployed, redirect_uri=redirect_uri,
                                              auth_code=auth_code, handle_error=handle_error,
                                              certificate_thumbprint=certificate_thumbprint,
                                              private_key=private_key, azure_cloud=azure_cloud,
                                              managed_identities_client_id=managed_identities_client_id)
        if command == 'msgraph-user-generate-login-url':
            return_results(generate_login_url(client.ms_client))
        elif command == 'msgraph-user-auth-reset':
            return_results(reset_auth())
        elif command == 'msgraph-user-tap-policy-delete':
            return_results(delete_tap_policy_command(client, demisto.args()))
        elif command == 'msgraph-user-tap-policy-create':
            return_results(create_tap_policy_command(client, demisto.args()))
        elif command == 'msgraph-user-tap-policy-list':
            return_results(get_tap_policy_list_command(client, demisto.args()))
        elif command == 'msgraph-user-session-revoke':
            return_results(revoke_user_session_command(client, demisto.args()))
        elif command == 'msgraph-user-assign-manager':
            return_results(assign_manager_command(client, demisto.args()))
        elif command == 'msgraph-user-get-manager':
            return_results(get_manager_command(client, demisto.args()))
        elif command == 'msgraph-direct-reports':
            return_results(get_direct_reports_command(client, demisto.args()))
        elif command == 'msgraph-user-list':
            return_results(list_users_command(client, demisto.args()))
        elif command == 'msgraph-user-get':
            return_results(get_user_command(client, demisto.args()))
        elif command == 'msgraph-user-get-delta':
            return_results(get_delta_command(client, demisto.args()))
        elif command == 'msgraph-user-create':
            return_results(create_user_command(client, demisto.args()))
        elif command == 'msgraph-user-delete':
            return_results(delete_user_command(client, demisto.args()))
        elif command == 'msgraph-user-update':
            return_results(update_user_command(client, demisto.args()))
        elif command == 'msgraph-user-account-disable':
            return_results(disable_user_account_command(client, demisto.args()))
        elif command == 'msgraph-user-unblock':
            return_results(unblock_user_command(client, demisto.args()))
        elif command == 'msgraph-user-test':
            return_results(test_function(client, demisto.args()))
        elif command == 'test-module':
            return_results(test_function(client, demisto.args()))
        else:
            human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
