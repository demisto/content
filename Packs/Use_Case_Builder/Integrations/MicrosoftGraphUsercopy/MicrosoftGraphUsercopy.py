import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401



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

    def risky_user(self):
        riskusers = self.ms_client.http_request(
            method='GET',
            url_suffix='/identityProtection/riskyUsers')
        return riskusers.get('value', '')

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
        try:
            user_data = self.ms_client.http_request(
                method='GET',
                url_suffix=f'users/{user}',
                params={'$select': properties})
            user_data.pop('@odata.context', None)
            return user_data
        except NotFoundError as e:
            LOG(f'User {user} was not found')
            return {'NotFound': e.message}
        except Exception as e:
            raise e

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


def risky_user_command(client: MsGraphClient, args: Dict):
    user_data = client.risky_user()
    if user_data.get('NotFound', ''):
        error_message = user_data.get('NotFound')
        human_readable = f'\nMicrosoft Graph Response: {error_message}'
        return human_readable, {}, error_message



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

    # In case the request returned a 404 error display a proper message to the war room
    if user_data.get('NotFound', ''):
        error_message = user_data.get('NotFound')
        human_readable = f'### User {user} was not found.\nMicrosoft Graph Response: {error_message}'
        return human_readable, {}, error_message

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
        'msgraph-risky-user': risky_user_command,
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



### GENERATED CODE ###
# This code was inserted in place of an API module.import traceback




import requests
import re
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple, List, Optional


class Scopes:
    graph = 'https://graph.microsoft.com/IdentityRiskEvent.Read.All'
    security_center = 'https://api.securitycenter.windows.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = '(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/IdentityRiskEvent.Read.All',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope; A scope to add to the headers. Else will get self.scope.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message



if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
