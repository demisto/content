import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple

# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line


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
                 resource: str = '',
                 verify: bool = True,
                 self_deployed: bool = False,
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

    def http_request(self, *args, resp_type='json', headers=None, return_empty_response=False, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        token = self.get_access_token()
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if headers:
            default_headers.update(headers)

        response = super()._http_request(   # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))

        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

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

    def get_access_token(self):
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        refresh_token = integration_context.get('current_refresh_token', '')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            access_token, expires_in, refresh_token = self._oproxy_authorize()
        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(refresh_token)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        integration_context = {
            'access_token': access_token,
            'current_refresh_token': refresh_token,
            'valid_until': time_now + expires_in,
        }

        demisto.setIntegrationContext(integration_context)
        return access_token

    def _oproxy_authorize(self) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.

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
                'encrypted_token': self.get_encrypted(content, self.enc_key)
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

    def _get_self_deployed_token(self, refresh_token: str = ''):
        if self.grant_type == AUTHORIZATION_CODE:
            return self._get_self_deployed_token_auth_code(refresh_token)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials()

    def _get_self_deployed_token_client_credentials(self) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        if self.scope:
            data['scope'] = self.scope
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

    def _get_self_deployed_token_auth_code(self, refresh_token: str = '') -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'resource': self.resource,
            'redirect_uri': self.redirect_uri
        }
        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
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
        # refresh_token = response_json.get('refresh_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

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
            calling_context = demisto.callingContext.get('context', {})  # type: ignore[attr-defined]
            brand_name = calling_context.get('IntegrationBrand', '')
            instance_name = calling_context.get('IntegrationInstance', '')
            headers['X-Content-Version'] = CONTENT_RELEASE_VERSION
            headers['X-Content-Name'] = brand_name or instance_name or 'Name not found'
            if hasattr(demisto, 'demistoVersion'):
                demisto_version = demisto.demistoVersion()
                headers['X-Content-Server-Version'] = '{}-{}'.format(demisto_version.get('version'),
                                                                     demisto_version.get("buildNumber"))
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers
