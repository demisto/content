import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
from urllib.parse import urlparse
from urllib.parse import parse_qs

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:
    """
    API Client to communicate with AzureRiskyUsers.
    """

    def __init__(self, client_id: str, verify: bool, proxy: bool):
        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=client_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url='https://graph.microsoft.com/v1.0',
            verify=verify,
            proxy=proxy,
            scope='https://graph.microsoft.com/IdentityRiskyUser.Read.All '
                  'IdentityRiskEvent.ReadWrite.All IdentityRiskyUser.Read.All '
                  'IdentityRiskyUser.ReadWrite.All offline_access')

    def risky_users_list(self, risk_state: str, risk_level: str, limit: int,
                         skip_token: str = None) -> dict:
        """
        List risky users.

        Args:
            risk_state (str): Risk State to retrieve.
            risk_level (str): Specify to get only results with the same Risk Level.
            limit (int): Limit of results to retrieve.
            skip_token (str): Skip token.

        Returns:
            response (dict): API response from AzureRiskyUsers.
        """
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$filter': build_query_filter(risk_state, risk_level)})

        return self.ms_client.http_request(method='GET',
                                           url_suffix="identityProtection/riskyUsers",
                                           params=params)

    def risky_user_get(self, id: str) -> dict:
        """
        Get risky user by ID.

        Args:
            id (str): Risky user ID to get.

        return:
            Response (dict): API response from AzureRiskyUsers.
        """
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'identityProtection/riskyUsers'
                                                      f'/{id}')

    def risk_detections_list(self, risk_state: str, risk_level: str, limit: int,
                             skip_token: str = None) -> dict:
        """
        Get a list of the Risk Detection objects and their properties.

        Args:
            risk_state (str): Risk State to retrieve.
            risk_level (str): Specify to get only results with the same Risk Level.
            limit (int): Limit of results to retrieve.
            skip_token (int): Skip token.

        return:
            Response (dict): API response from AzureRiskyUsers.
        """
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$filter': build_query_filter(risk_state, risk_level)})

        return self.ms_client.http_request(method='GET',
                                           url_suffix="/identityProtection/riskDetections",
                                           params=params)

    def risk_detection_get(self, id: str) -> dict:
        """
        Read the properties and relationships of a riskDetection object.

        Args:
            id (str): ID of risk detection to retrieve.

        Return:
            Response (dict): API response from AzureRiskyUsers.
        """
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'/identityProtection/riskDetections/'
                                                      f'{id}')


def build_query_filter(risk_state: str, risk_level: str) -> str:
    """
    Build query filter for API call, in order to get filtered results.

    Args:
        risk_state (str): Wanted risk state for filter.
        risk_level (str): Wanted risk level for filter.

    Returns:
        str: Query filter string for API call.
    """
    if risk_state and risk_level:
        return f"riskState eq '{risk_state}' and riskLevel eq '{risk_level}'"
    elif risk_state:
        return f"riskState eq '{risk_state}'"
    elif risk_level:
        return f"riskLevel eq '{risk_level}'"
    else:
        return None


def create_event_or_incident_output(item: Dict,
                                    table_headers: List[str]) -> Dict[str, Optional[Any]]:
    """
    Create the complete output dictionary for events or incidents.

    Args:
        item (dict): A source dictionary from the API response.
        table_headers (list(str)): The table headers to be used when creating initial data.

    Returns:
        object_data (dict(str)): The output dictionary.
    """
    alert_data = {field: item.get(field) for field in table_headers}
    return remove_empty_elements(alert_data)


def risky_users_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List all risky users.
    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit = args['limit']
    page = arg_to_number(args['page'])
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    skip_token = None
    readable_message = f'Risky Users List\nCurrent page size: {limit}\nShowing page {page} out others that may exist'

    if page > 1:
        offset = int(limit) * (page - 1)
        raw_response = client.risky_users_list(risk_state,
                                               risk_level,
                                               offset)

        next_link = raw_response.get('@odata.nextLink')
        if not next_link:
            return CommandResults(outputs_prefix='AzureRiskyUsers.RiskyUser',
                                  outputs_key_field='id',
                                  outputs=[],
                                  readable_output=readable_message,
                                  raw_response=[])
        else:
            parsed_url = urlparse(next_link)
            skip_token = parse_qs(parsed_url.query)['$skiptoken'][0]

    raw_response = client.risky_users_list(risk_state,
                                           risk_level,
                                           limit,
                                           skip_token)

    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']

    outputs = raw_response.get('value')

    table_outputs = [create_event_or_incident_output(item, table_headers)
                     for item in outputs]

    readable_output = tableToMarkdown(name=f'Risky Users List\n'
                                           f'Current page size: {args["limit"]}\n'
                                           f'Showing page {args["page"]} out others that may exist',
                                      t=table_outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskyUser',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=raw_response)


def risky_user_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get a risky user by ID.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    raw_response = client.risky_user_get(args.get('id'))

    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']

    outputs = create_event_or_incident_output(raw_response, table_headers)

    readable_output = tableToMarkdown(name=f'Found Risky User With ID: {raw_response.get("id")}',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskyUser',
                          outputs_key_field='id',
                          outputs=raw_response,
                          readable_output=readable_output,
                          raw_response=raw_response)


def risk_detections_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve a list of the Risk-Detection objects and their properties.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit = args['limit']
    page = arg_to_number(args['page'])
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    skip_token = None
    readable_message = f'Risk Detections List\nCurrent page size: {limit}\nShowing page {page} out others that may exist'

    if page > 1:
        offset = int(limit) * (page - 1)
        raw_response = client.risk_detections_list(risk_state,
                                                   risk_level,
                                                   offset)

        next_link = raw_response.get('@odata.nextLink')
        if not next_link:
            return CommandResults(outputs_prefix='AzureRiskyUsers.RiskDetection',
                                  outputs_key_field='id',
                                  outputs=[],
                                  readable_output=readable_message,
                                  raw_response=[])
        else:
            parsed_url = urlparse(next_link)
            skip_token = parse_qs(parsed_url.query)['$skiptoken'][0]

    raw_response = client.risk_detections_list(risk_state,
                                               risk_level,
                                               limit,
                                               skip_token)

    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'riskDetail', 'lastUpdatedDateTime',
                     'ipAddress']

    outputs = raw_response.get('value')
    table_outputs = [create_event_or_incident_output(item, table_headers)
                     for item in outputs]

    readable_output = tableToMarkdown(name=f'Risk Detections List\n'
                                           f'Current page size: {args["limit"]}\n'
                                           f'Showing page {args["page"]} out others that may exist',
                                      t=table_outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskDetection',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=raw_response)


def risk_detection_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Read the properties and relationships of a riskDetection object.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    raw_response = client.risk_detection_get(args.get('id'))
    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'ipAddress',
                     'detectionTimingType', 'lastUpdatedDateTime', 'location']
    outputs = create_event_or_incident_output(raw_response, table_headers)

    readable_output = tableToMarkdown(name=f'Found Risk Detection with ID: '
                                           f'{raw_response.get("id")}',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskDetection',
                          outputs_key_field='id',
                          outputs=raw_response,
                          readable_output=readable_output,
                          raw_response=raw_response)


# Authentication Functions


def start_auth(client) -> CommandResults:
    result = client.ms_client.start_auth('!azure-risky-users-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client) -> str:
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_connection(client) -> str:
    client.ms_client.get_access_token()
    return 'Success!'


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-risky-users-auth-start** to start' \
           ' the authentication process.'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    client_id = params.get('client_id')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            verify=verify_certificate,
            proxy=proxy)

        commands = {'azure-risky-users-auth-start': start_auth,
                    'azure-risky-users-auth-complete': complete_auth,
                    'azure-risky-users-auth-test': test_connection,
                    'azure-risky-users-list': risky_users_list_command,
                    'azure-risky-user-get': risky_user_get_command,
                    'azure-risky-users-risk-detections-list': risk_detections_list_command,
                    'azure-risky-users-risk-detection-get': risk_detection_get_command}

        if command == 'test-module':
            return_results('The test module is not functional, '
                           'run the azure-risky-users-auth-start command instead.')
        elif command in commands.keys():
            if args:
                return_results(commands[command](client, args))
            else:
                return_results(commands[command](client))
        elif command == 'azure-risky-users-auth-reset':
            return_results(reset_auth())

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


### GENERATED CODE ###
# This code was inserted in place of an API module.import traceback
import requests
import re
import base64
from typing import Dict, Tuple, List, Optional


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'


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


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
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
        Microsoft Client class that implements logic to authenticate with oproxy
        or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url,
             otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id,
             otherwise (oproxy) it's the auth id and may also contain the token url
            enc_key: If self deployed it's the client secret,
             otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources
             (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                # guardrails-disable-line
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(
                tenant_id=tenant_id)
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
            raise DemistoException('Failed to parse json object from response: {}'.format(
                response.content), exception)

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
                    access_token, expires_in, refresh_token = self._oproxy_authorize(
                        resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(
                    scope=scope)

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
                demisto.error(
                    'Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get(
                'Function-Execution-Id')
            demisto.info(
                f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
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
            response = requests.post(
                self.token_retrieval_url, data, verify=self.verify)
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
            response = requests.post(
                self.token_retrieval_url, data, verify=self.verify)
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
            'scope': self.scope
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
            response = requests.post(self.token_retrieval_url,
                                     data=data,
                                     verify=self.verify)
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
        # for testing we allow setting the refresh token directly
        if self.auth_code.startswith(refresh_prefix):
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
            aes_gcm = enc_key
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
        set_integration_context(
            {'device_code': response_json.get('device_code')})
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


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
