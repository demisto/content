from CommonServerPython import *
import demistomock as demisto
import requests
import base64
from typing import Union, Dict, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'


class MicrosoftClient(BaseClient):

    def __init__(self, auth_type: str, tenant_id: str = '', auth_id: str = '', enc_key: str = '',
                 token_retrieval_url: str = '', app_name: str = '', refresh_token: str = '',
                 client_id: str = '', client_secret: str = '', scope: str = '', resource: str = '', app_url: str = '',
                 verify: bool = True, *args, **kwargs):
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore
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
        self.use_ssl = verify

    @classmethod
    def from_oproxy(cls, auth_id: str, enc_key: str, token_retrieval_url: str, app_name: str,
                    tenant_id: str = '', refresh_token: str = '', *args, **kwargs):

        return cls(OPROXY_AUTH_TYPE, tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key,  # type: ignore
                   token_retrieval_url=token_retrieval_url,
                   app_name=app_name, refresh_token=refresh_token, *args, **kwargs)

    @classmethod
    def from_self_deployed(cls, tenant_id: str, client_id: str, client_secret: str, scope: str = '', resource: str = '',
                           app_url: str = '', *args, **kwargs):
        return cls(SELF_DEPLOYED_AUTH_TYPE, tenant_id=tenant_id, client_id=client_id,  # type: ignore
                   client_secret=client_secret,
                   scope=scope, resource=resource, app_url=app_url, *args, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self._get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore

    @staticmethod
    def camel_case_to_readable(cc: Union[str, Dict], fields_to_drop: List[str] = None) -> Union[str, Dict]:
        """
        'camelCase' -> 'Camel Case' (text or dictionary keys)

        Args:
            cc: either a dictionary or a text to transform
            fields_to_drop: keys to drop from input dictionary

        Returns:
            A Camel Cased string of Dict.
        """
        if fields_to_drop is None:
            fields_to_drop = []
        if isinstance(cc, str):
            if cc == 'id':
                return 'ID'
            return ''.join(' ' + char if char.isupper() else char.strip() for char in cc).strip().title()

        elif isinstance(cc, Dict):
            return {MicrosoftClient.camel_case_to_readable(field): value for field, value in cc.items()
                    if field not in fields_to_drop}
        return cc

    @staticmethod
    def snakecase_to_camelcase(sc: Union[str, Dict], fields_to_drop: List[str] = None) -> Union[str, Dict]:
        """
        'snake_case' -> 'snakeCase' (text or dictionary keys)

        Args:
            sc: either a dictionary or a text to transform
            fields_to_drop: keys to drop from input dictionary

        Returns:
            A connectedCamelCased string of Dict.
        """
        if fields_to_drop is None:
            fields_to_drop = []
        if isinstance(sc, str):
            return ''.join([word.title() for word in sc.split('_')])

        elif isinstance(sc, Dict):
            return {MicrosoftClient.snakecase_to_camelcase(field): value for field, value in sc.items()
                    if field not in fields_to_drop}
        return sc

    def _get_access_token(self):
        """
        Obtains access and refresh token from Oproxy server. Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        :return: Access token that will be added to authorization header
        :rtype: ``str``
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

    def _oproxy_authorize(self):
        content = self.refresh_token or self.tenant_id
        oproxy_response = requests.post(
            self.token_retrieval_url,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key)
            },
            verify=self.use_ssl
        )

        if oproxy_response.status_code not in {200, 201}:
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

        return (parsed_response.get('access_token'), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token'))

    def _get_self_deployed_token(self):
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
        else:
            data['resource'] = self.resource

        body: dict = {}
        try:
            response = requests.post(url, data, verify=self.use_ssl)
            if response.status_code != 200:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            body = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = body.get('access_token')
        expires_in = int(body.get('expires_on', 3595))

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
            if isinstance(error, dict):
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
            d = datetime.utcnow()
        return int((d - datetime.utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.

        :type content: ``str``
        :param content: Content to encrypt

        :type key: ``str``
        :param key: encryption key from Oproxy

        :return: Encrypted content
        :rtype: ``timestamp``
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.

            :type string: ``str``
            :param string: String to encrypt

            :type enc_key: ``str``
            :param enc_key: Encryption key

            :return: Encrypted value
            :rtype: ``bytes``
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
