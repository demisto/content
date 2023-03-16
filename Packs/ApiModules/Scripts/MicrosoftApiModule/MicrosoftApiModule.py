# pylint: disable=E9010, E9011
import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import re
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple, List, Optional


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'
    security_center_apt_service = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
    management_azure = 'https://management.azure.com/.default'


class Resources:
    graph = 'https://graph.microsoft.com/'
    security_center = 'https://api.securitycenter.microsoft.com/'
    management_azure = 'https://management.azure.com/'
    manage_office = 'https://manage.office.com/'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'
TOKEN_RETRIEVAL_ENDPOINTS = {
    'com': 'https://login.microsoftonline.com',
    'gcc-high': 'https://login.microsoftonline.us',
    'dod': 'https://login.microsoftonline.us',
    'de': 'https://login.microsoftonline.de',
    'cn': 'https://login.chinacloudapi.cn',
}
GRAPH_ENDPOINTS = {
    'com': 'https://graph.microsoft.com',
    'gcc-high': 'https://graph.microsoft.us',
    'dod': 'https://dod-graph.microsoft.us',
    'de': 'https://graph.microsoft.de',
    'cn': 'https://microsoftgraph.chinacloudapi.cn'
}
GRAPH_BASE_ENDPOINTS = {
    'https://graph.microsoft.com': 'com',
    'https://graph.microsoft.us': 'gcc-high',
    'https://dod-graph.microsoft.us': 'dod',
    'https://graph.microsoft.de': 'de',
    'https://microsoftgraph.chinacloudapi.cn': 'cn'
}

# Azure Managed Identities
MANAGED_IDENTITIES_TOKEN_URL = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01'
MANAGED_IDENTITIES_SYSTEM_ASSIGNED = 'SYSTEM_ASSIGNED'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: Optional[str] = '',
                 token_retrieval_url: str = '{endpoint}/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 refresh_token_param: Optional[str] = '',
                 auth_code: str = '',
                 scope: str = '{graph_endpoint}/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 timeout: Optional[int] = None,
                 azure_ad_endpoint: str = '{endpoint}',
                 endpoint: str = 'com',
                 certificate_thumbprint: Optional[str] = None,
                 retry_on_rate_limit: bool = False,
                 private_key: Optional[str] = None,
                 managed_identities_client_id: Optional[str] = None,
                 managed_identities_resource_uri: Optional[str] = None,
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            refresh_token: The current used refresh token.
            refresh_token_param: The refresh token from the integration's parameters (i.e instance configuration).
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
            certificate_thumbprint: Certificate's thumbprint that's associated to the app
            private_key: Private key of the certificate
            managed_identities_client_id: The Azure Managed Identities client id
            managed_identities_resource_uri: The resource uri to get token for by Azure Managed Identities
            retry_on_rate_limit: If the http request returns with a 429 - Rate limit reached response,
                                 retry the request using a scheduled command.
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        self.endpoint = endpoint
        self.retry_on_rate_limit = retry_on_rate_limit
        if retry_on_rate_limit and (429 not in self._ok_codes):
            self._ok_codes = self._ok_codes + (429,)
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
            self.refresh_token_param = refresh_token_param

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id,
                                                                  endpoint=TOKEN_RETRIEVAL_ENDPOINTS[self.endpoint])
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope.format(graph_endpoint=GRAPH_ENDPOINTS[self.endpoint])
            self.redirect_uri = redirect_uri
            if certificate_thumbprint and private_key:
                try:
                    import msal  # pylint: disable=E0401
                    self.jwt = msal.oauth2cli.assertion.JwtAssertionCreator(
                        private_key,
                        'RS256',
                        certificate_thumbprint
                    ).create_normal_assertion(audience=self.token_retrieval_url, issuer=self.client_id)
                except ModuleNotFoundError:
                    raise DemistoException('Unable to use certificate authentication because `msal` is missing.')
            else:
                self.jwt = None

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint.format(endpoint=TOKEN_RETRIEVAL_ENDPOINTS[self.endpoint])
        self.timeout = timeout  # type: ignore

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

        # for Azure Managed Identities purpose
        self.managed_identities_client_id = managed_identities_client_id
        self.managed_identities_resource_uri = managed_identities_resource_uri

    def is_command_executed_from_integration(self):
        ctx = demisto.callingContext.get('context', {})
        executed_commands = ctx.get('ExecutedCommands', [{'moduleBrand': 'Scripts'}])

        if executed_commands:
            return executed_commands[0].get('moduleBrand', "") != 'Scripts'

        return True

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', overwrite_rate_limit_retry=False, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
            overwrite_rate_limit_retry : Skip rate limit retry
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs and not self._ok_codes:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)

        if self.timeout:
            kwargs['timeout'] = self.timeout

        should_http_retry_on_rate_limit = self.retry_on_rate_limit and not overwrite_rate_limit_retry
        if should_http_retry_on_rate_limit and not kwargs.get('error_handler'):
            kwargs['error_handler'] = self.handle_error_with_metrics

        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        if should_http_retry_on_rate_limit and self.is_command_executed_from_integration():
            self.create_api_metrics(response.status_code)
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

        if should_http_retry_on_rate_limit and response.status_code == 429 and is_demisto_version_ge('6.2.0'):
            command_args = demisto.args()
            ran_once_flag = command_args.get('ran_once_flag')
            demisto.info(f'429 MS rate limit for command {demisto.command()}, where ran_once_flag is {ran_once_flag}')
            # We want to retry on rate limit only once
            if ran_once_flag:
                try:
                    error_message = response.json()
                except Exception:
                    error_message = 'Rate limit reached on retry - 429 Response'
                demisto.info(f'Error in retry for MS rate limit - {error_message}')
                raise DemistoException(error_message)

            else:
                demisto.info(f'Scheduling command {demisto.command()}')
                command_args['ran_once_flag'] = True
                return_results(self.run_retry_on_rate_limit(command_args))
                sys.exit(0)

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

        if self.auth_type == OPROXY_AUTH_TYPE:
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

    def _raise_authentication_error(self, oproxy_response: requests.Response):
        """
        Raises an exception for authentication error with the Oproxy server.
        Args:
            oproxy_response: Raw response from the Oproxy server to parse.
        """
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

    def _oproxy_authorize_build_request(self, headers: Dict[str, str], content: str,
                                        scope: Optional[str] = None, resource: str = ''
                                        ) -> requests.Response:
        """
        Build the Post request sent to the Oproxy server.
        Args:
            headers: The headers of the request.
            content: The content for the request (usually contains the refresh token).
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.

        Returns: The response from the Oproxy server.

        """
        return requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope,
                'resource': resource
            },
            verify=self.verify
        )

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
        oproxy_response = self._oproxy_authorize_build_request(headers, content, scope, resource)

        if not oproxy_response.ok:
            # Try to send request to the Oproxy server with the refresh token from the integration parameters
            # (instance configuration).
            # Relevant for cases where the user re-generated his credentials therefore the refresh token was updated.
            if self.refresh_token_param:
                demisto.error('Error in authentication: Oproxy server returned error, perform a second attempt'
                              ' authorizing with the Oproxy, this time using the refresh token from the integration'
                              ' parameters (instance configuration).')
                content = self.refresh_token_param
                oproxy_second_try_response = self._oproxy_authorize_build_request(headers, content, scope, resource)

                if not oproxy_second_try_response.ok:
                    demisto.error('Authentication failure from server (second attempt - using refresh token from the'
                                  ' integration parameters: {} {} {}'.format(oproxy_second_try_response.status_code,
                                                                             oproxy_second_try_response.reason,
                                                                             oproxy_second_try_response.text))
                    self._raise_authentication_error(oproxy_response)

                else:  # Second try succeeded
                    oproxy_response = oproxy_second_try_response

            else:  # no refresh token for a second auth try
                self._raise_authentication_error(oproxy_response)

        # Oproxy authentication succeeded
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
        if self.managed_identities_client_id:

            if not self.multi_resource:
                return self._get_managed_identities_token()

            expires_in = -1  # init variable as an int
            for resource in self.resources:
                access_token, expires_in, refresh_token = self._get_managed_identities_token(resource=resource)
                self.resource_to_access_token[resource] = access_token
            return '', expires_in, refresh_token

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
            if self.multi_resource:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_client_credentials(
                        resource=resource)
                    self.resource_to_access_token[resource] = access_token
                return '', expires_in, refresh_token
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None,
                                                    resource: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope: A scope to add to the headers. Else will get self.scope.
            resource: A resource to add to the headers. Else will get self.resource.
        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource or resource:
            data['resource'] = resource or self.resource  # type: ignore

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

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

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

    def _get_managed_identities_token(self, resource=None):
        """
        Gets a token based on the Azure Managed Identities mechanism
        in case user was configured the Azure VM and the other Azure resource correctly
        """
        try:
            # system assigned are restricted to one per resource and is tied to the lifecycle of the Azure resource
            # see https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
            use_system_assigned = (self.managed_identities_client_id == MANAGED_IDENTITIES_SYSTEM_ASSIGNED)
            resource = resource or self.managed_identities_resource_uri

            demisto.debug('try to get Managed Identities token')

            params = {'resource': resource}
            if not use_system_assigned:
                params['client_id'] = self.managed_identities_client_id

            response_json = requests.get(MANAGED_IDENTITIES_TOKEN_URL, params=params, headers={'Metadata': 'True'}).json()
            access_token = response_json.get('access_token')
            expires_in = int(response_json.get('expires_in', 3595))
            if access_token:
                return access_token, expires_in, ''

            err = response_json.get('error_description')
        except Exception as e:
            err = f'{str(e)}'

        return_error(f'Error in Microsoft authorization with Azure Managed Identities: {err}')

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

    def run_retry_on_rate_limit(self, args_for_next_run: dict):
        return CommandResults(readable_output="Rate limit reached, rerunning the command in 1 min",
                              scheduled_command=ScheduledCommand(command=demisto.command(), next_run_in_seconds=60,
                                                                 args=args_for_next_run))

    def handle_error_with_metrics(self, res):
        self.create_api_metrics(res.status_code)
        self.client_error_handler(res)

    def create_api_metrics(self, status_code):
        execution_metrics = ExecutionMetrics()
        ok_codes = (200, 201, 202, 204, 206)

        if not execution_metrics.is_supported() or demisto.command() in ['test-module', 'fetch-incidents']:
            return
        if status_code == 429:
            execution_metrics.quota_error += 1
        elif status_code in ok_codes:
            execution_metrics.success += 1
        else:
            execution_metrics.general_error += 1
        return_results(execution_metrics.metrics)

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
    def get_encrypted(content: str, key: Optional[str]) -> str:
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


def get_azure_managed_identities_client_id(params: dict) -> Optional[str]:
    """"extract the Azure Managed Identities from the demisto params

    Args:
        params (dict): the demisto params

    Returns:
        Optional[str]: if the use_managed_identities are True
        the managed_identities_client_id or MANAGED_IDENTITIES_SYSTEM_ASSIGNED
        will return, otherwise - None

    """
    auth_type = params.get('auth_type') or params.get('authentication_type')
    if params and (argToBoolean(params.get('use_managed_identities') or auth_type == 'Azure Managed Identities')):
        client_id = params.get('managed_identities_client_id', {}).get('password')
        return client_id or MANAGED_IDENTITIES_SYSTEM_ASSIGNED
    return None


def generate_login_url(client: MicrosoftClient) -> CommandResults:

    assert client.tenant_id \
        and client.scope \
        and client.client_id \
        and client.redirect_uri, 'Please make sure you entered the Authorization configuration correctly.'

    login_url = f'https://login.microsoftonline.com/{client.tenant_id}/oauth2/v2.0/authorize?' \
                f'response_type=code&scope=offline_access%20{client.scope.replace(" ", "%20")}' \
                f'&client_id={client.client_id}&redirect_uri={client.redirect_uri}'

    result_msg = f"""### Authorization instructions
1. Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.
    """
    return CommandResults(readable_output=result_msg)
