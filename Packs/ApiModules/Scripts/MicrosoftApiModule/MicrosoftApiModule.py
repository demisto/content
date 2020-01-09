import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import base64
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'


class MicrosoftClient(BaseClient):

    def __init__(self, tenant_id: str = '', auth_id: str = '', enc_key: str = '',
                 token_retrieval_url: str = '', app_name: str = '', refresh_token: str = '',
                 client_id: str = '', client_secret: str = '', scope: str = '', resource: str = '', app_url: str = '',
                 verify: bool = True, auth_type: str = OPROXY_AUTH_TYPE, *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        self.auth_type = auth_type
        self.app_url = app_url
        self.tenant_id = tenant_id
        self.auth_id = auth_id
        self.enc_key = enc_key
        self.token_retrieval_url = token_retrieval_url
        self.app_name = app_name
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.resource = resource
        self.verify = verify

    @classmethod
    def from_oproxy(cls, auth_id_and_token_url: str, enc_key: str, app_name: str,
                    tenant_id: str = '', refresh_token: str = '', *args, **kwargs):
        """
        Args:
            auth_id_and_token_url: Authentication ID and the oproxy url to use
            enc_key: Encryption key
            app_name: The application name in oproxy
            tenant_id: The tenant ID
            refresh_token: The current refresh token
        Returns:
            An instance of Microsoft Client with oproxy authentication.
        """
        auth_id_and_token_retrieval_url = auth_id_and_token_url.split('@')
        auth_id = auth_id_and_token_retrieval_url[0]
        if len(auth_id_and_token_retrieval_url) != 2:
            token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
        else:
            token_retrieval_url = auth_id_and_token_retrieval_url[1]

        return cls(tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key,  # type: ignore[misc]
                   token_retrieval_url=token_retrieval_url, auth_type=OPROXY_AUTH_TYPE,
                   app_name=app_name, refresh_token=refresh_token, *args, **kwargs)

    @classmethod
    def from_self_deployed(cls, tenant_id: str, client_id: str, client_secret: str, scope: str = '', resource: str = '',
                           app_url: str = '', *args, **kwargs):
        """
        Args:
            tenant_id: The self deployed tenant ID
            client_id: The self deployed client ID
            client_secret: The self deployed client secret
            scope: The self deployed application scope
            resource: The self deployed application resource
            app_url: The self deployed application request URL
        Returns:
            An instance of Microsoft Client with self deployed application authentication.
        """
        return cls(tenant_id=tenant_id, client_id=client_id,  # type: ignore[misc]
                   client_secret=client_secret, auth_type=SELF_DEPLOYED_AUTH_TYPE,
                   scope=scope, resource=resource, app_url=app_url, *args, **kwargs)

    def http_request(self, *args, **kwargs) -> requests.Response:
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Returns:
            requests.Response: The http response
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]

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
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        refresh_token = ''
        if auth_type == OPROXY_AUTH_TYPE:
            access_token, expires_in, refresh_token = self._oproxy_authorize()
        else:
            access_token, expires_in = self._get_self_deployed_token()
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        integration_context = {
            'access_token': access_token,
            'valid_until': time_now + expires_in,
        }

        if refresh_token:
            integration_context['current_refresh_token'] = refresh_token
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

    def _get_self_deployed_token(self) -> Tuple[str, int]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token and its expiry.
        """
        if not self.app_url:
            url = f'https://login.windows.net/{self.tenant_id}/oauth2/token'
        else:
            url = self.app_url
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }

        if self.scope:
            data['scope'] = self.scope
        if self.resource:
            data['resource'] = self.resource

        body: dict = {}
        try:
            response = requests.post(url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            body = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = body.get('access_token', '')
        expires_in = int(body.get('expires_in', 3595))

        return access_token, expires_in

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
            enc_key = base64.b64decode(enc_key)
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
