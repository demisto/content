from CommonServerPython import *
from CommonServerUserPython import *
import jwt
import uuid

from Packs.Base.Scripts.CommonServerPython.CommonServerPython import DemistoException

TOKEN_EXPIRATION_TIME = 60  # In minutes. This value must be a maximum of only an hour (according to Okta's documentation).
TOKEN_RENEWAL_TIME_LIMIT = 60  # In seconds. The minimum time before the token expires to renew it.
OAUTH_URL = '/oauth_token.do'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


class ServiceNowClient(BaseClient):

    def __init__(self, credentials: dict, use_oauth: bool = False, use_jwt: bool = False, client_id: str = '',
                 client_secret: str = '', url: str = '', jwt_key_id: str = '', jwt_key: str = '', jwt_sub: str = '',
                 verify: bool = False, proxy: bool = False, headers: dict = None):
        """
        ServiceNow Client class. The class can use either basic authorization with username and password, or OAuth2.
        Args:
            - credentials: the username and password given by the user.
            - client_id: the client id of the application of the user.
            - client_secret - the client secret of the application of the user.
            - url: the instance url of the user, i.e: https://<instance>.service-now.com.
                   NOTE - url should be given without an API specific suffix as it is also used for the OAuth process.
            - verify: Whether the request should verify the SSL certificate.
            - proxy: Whether to run the integration using the system proxy.
            - headers: The request headers, for example: {'Accept`: `application/json`}. Can be None.
            - use_oauth: a flag indicating whether the user wants to use OAuth 2.0 or basic authorization.
        """
        self.auth = None
        self.use_oauth = use_oauth
        self.use_jwt = use_jwt
        # if user selected the `Use OAuth`/`Use JWT`  box use OAuth authorization, else use basic authorization
        if self.use_oauth or self.use_jwt:
            self.client_id = client_id
            self.client_secret = client_secret
            self.jwt_key_id = jwt_key_id
            self.jwt_key = jwt_key
            self.jwt_sub = jwt_sub
        else:
            self.username = credentials.get('identifier')
            self.password = credentials.get('password')
            self.auth = (self.username, self.password)

        if '@' in client_id:  # for use in OAuth test-playbook
            self.client_id, refresh_token = client_id.split('@')
            set_integration_context({'refresh_token': refresh_token})

        self.base_url = url
        super().__init__(base_url=self.base_url, verify=verify, proxy=proxy, headers=headers, auth=self.auth)  # type
        # : ignore[misc]

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, return_empty_response=False, auth=None, timeout=None):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            if self.use_oauth or self.use_jwt:  # add a valid access token to the headers when using OAuth
                access_token = self.get_access_token() if self.use_oauth else self.get_jwt_token()
                self._headers.update({
                    'Authorization': 'Bearer ' + access_token
                })
            res = super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, resp_type='response',
                                        headers=headers, json_data=json_data, params=params, data=data, files=files,
                                        ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth,
                                        timeout=timeout)
            if res.status_code in [200, 201]:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)

            if res.status_code in [401]:
                if self.use_oauth:
                    if demisto.getIntegrationContext().get('expiry_time', 0) <= date_to_timestamp(datetime.now()):
                        access_token = self.get_access_token() if self.use_oauth else self.get_jwt_token()
                        self._headers.update({
                            'Authorization': 'Bearer ' + access_token
                        })
                        return self.http_request(method, url_suffix, full_url=full_url, params=params)
                    try:
                        err_msg = f'Unauthorized request: \n{str(res.json())}'
                    except ValueError:
                        err_msg = f'Unauthorized request: \n{str(res)}'
                    raise DemistoException(err_msg)
                else:
                    raise Exception(f'Authorization failed. Please verify that the username and password are correct.'
                                    f'\n{res}')

        except Exception as e:
            if self._verify and 'SSL Certificate Verification Failed' in e.args[0]:
                return_error('SSL Certificate Verification Failed - try selecting \'Trust any certificate\' '
                             'checkbox in the integration configuration.')
            raise DemistoException(e.args[0])

    def login(self, username: str, password: str):
        """
        Generate a refresh token using the given client credentials and save it in the integration context.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password,
            'grant_type': 'password'
        }
        try:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            res = super()._http_request(method='POST', url_suffix=OAUTH_URL, resp_type='response', headers=headers,
                                        data=data)
            try:
                res = res.json()
            except ValueError as exception:
                raise DemistoException('Failed to parse json object from response: {}'.format(res.content), exception)
            if 'error' in res:
                return_error(
                    f'Error occurred while creating an access token. Please check the Client ID, Client Secret '
                    f'and that the given username and password are correct.\n{res}')
            if res.get('refresh_token'):
                refresh_token = {
                    'refresh_token': res.get('refresh_token')
                }
                set_integration_context(refresh_token)
        except Exception as e:
            return_error(f'Login failed. Please check the instance configuration and the given username and password.\n'
                         f'{e.args[0]}')

    def generate_servicenow_oauth_token(self, oauth_data: dict = {}) -> str:
        ok_codes = (200, 201, 401)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {**oauth_data} if oauth_data else {}
        data.update({
            "client_id": self.client_id,
            "client_secret": self.client_secret
        })

        try:
            res = super()._http_request(method='POST', url_suffix=OAUTH_URL, resp_type='response', headers=headers,
                                        data=data, ok_codes=ok_codes)
            try:
                res = res.json()
            except ValueError as exception:
                raise DemistoException('Failed to parse json object from response: {}'.format(res.content),
                                       exception)
            if 'error' in res:
                raise DemistoException(
                    f'Error occurred while creating an access token. Please check the Client ID, Client Secret '
                    f'and try to run again the login command to generate a new refresh token as it '
                    f'might have expired.\n{res}')
            expiry_time = date_to_timestamp(datetime.now(), date_format=TIME_FORMAT) + res.get('expires_in', 0) * 1000 - 10
            access_token = res.get('access_token')
            if access_token:
                new_token = {
                    'access_token': access_token,
                    'refresh_token': res.get('refresh_token', None),
                    'expiry_time': expiry_time
                }
                set_integration_context(new_token)
            return access_token
        except Exception as e:
            raise DemistoException(
                f'Error occurred while creating an access token {e.args[0]}. Please check the instance configuration.')

    def get_access_token(self):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the client id, client secret and refresh token.
        """
        previous_token = get_integration_context() or {}
        data = {}
        # Check if there is an existing valid access token
        if ('expiry_time' in previous_token and 'access_token' in previous_token and
            previous_token['expiry_time'] > date_to_timestamp(datetime.now())):
            return previous_token.get('access_token')
        else:
            # Check if a refresh token exists. If not, raise an exception indicating to call the login function first.
            if previous_token.get('refresh_token'):
                data['refresh_token'] = previous_token.get('refresh_token')
                data['grant_type'] = 'refresh_token'
            else:
                raise Exception('Could not create an access token. User might be not logged in. Try running the'
                                ' oauth-login command first.')
            access_token = self.generate_servicenow_oauth_token()
            return access_token

    def get_jwt_token(self):
        """
        Generate a JWT token to use for OAuth authentication.
        Args:
            client_id (str): The client's id.
            jwt_key_id (str): The URL to key id for the JWT token (for the 'aud', 'iss' claim).
            jwt_key (str): The key to use for the JWT token (for the 'aud' claim).
            jwt_sub (str): The bla to use for the JWT token (UPN of the requested AD service user.
        Returns:
            str: The JWT token.
        """
        integration_context = get_integration_context()
        previous_token = integration_context.get('jwt', {})
        current_time = datetime.now(timezone.utc)
        if 'access_token' in previous_token and previous_token['expiry_time'] > date_to_timestamp(current_time):
            return previous_token.get('access_token')
        demisto.debug('Access Token expiry time had passed. Creating new access token')

        header = {
            "alg": "RS256",  # Signing algorithm
            "typ": "JWT",  # Token type
            "kid": self.jwt_key_id,  # From ServiceNow
        }

        payload = {
            "sub": self.jwt_sub,  # Subject (e.g., user ID)
            "aud": self.client_id,  # self.client_id
            "iss": self.client_id,  # self.client_id
            "iat": current_time,  # Issued at
            "exp": current_time + timedelta(minutes=TOKEN_EXPIRATION_TIME),  # Expiry time 1 hour
            "jti": str(uuid.uuid4())
        }

        jwt_token = jwt.encode(payload, replace_spaces_in_credential(self.jwt_key), algorithm="RS256", headers=header)
        demisto.debug(f'####{jwt_token=}###')

        oauth_data = {'assertion': jwt_token, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}
        access_token = self.generate_servicenow_oauth_token(oauth_data)
        return access_token
