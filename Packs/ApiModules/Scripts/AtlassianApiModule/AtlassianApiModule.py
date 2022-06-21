from CommonServerPython import *
from requests_oauthlib import OAuth1

REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
AUTHORIZATION_CODE = 'authorization_code'
OAUTH1_AUTH = 'oauth1_auth'
BASIC_AUTH = 'basic_auth'
PERSONAL_ACCESS_TOKEN = "personal_access_token"


class AtlassianClient(BaseClient):

    def __init__(self, access_token: str = '', api_token: str = '', username: str = '',
                 password: str = '', consumer_key: str = '', private_key: str = '', headers: dict = {},
                 client_id: str = '', client_secret: str = '',
                 auth_code: str = '', redirect_uri: str = '', verify: bool = True, *args, **kwargs):
        """
        Atlassian Client class. It can use either basic authorization with username and password,OAuth1 or Oauth2.
        Args:
            - access_token:
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
        # todo: add inn documentation offline_access to the scope to get refresh token in the first step
        super().__init__(*args, **kwargs)
        self.auth = None
        self.access_token = None
        self.verify = verify
        if username and (api_token or password):
            self.grant_type = BASIC_AUTH
            self.auth = username, (api_token or password)
        elif consumer_key and private_key and access_token:
            self.grant_type = OAUTH1_AUTH
            headers.update({'X-Atlassian-Token': 'nocheck'})
            self.auth = OAuth1(
                client_key=consumer_key,
                rsa_key=private_key,
                signature_method='RSA-SHA1',
                resource_owner_key=access_token,
            )
        elif access_token:
            self.grant_type = PERSONAL_ACCESS_TOKEN
            self.access_token = access_token
            headers.update({'Authorization': f'Bearer {access_token}'})
        elif client_id and client_secret and auth_code and redirect_uri:
            self.token_retrieval_url = 'https://auth.atlassian.com/oauth/token'
            self.grant_type = AUTHORIZATION_CODE
            self.client_id = client_id
            self.client_secret = client_secret
            self.auth_code = auth_code
            self.redirect_uri = redirect_uri
        else:
            return_error(
                'Please provide the required Authorization information:'
                '- Basic Authentication requires user name and API token or password'
                '- OAuth 1.0 requires ConsumerKey, AccessToken and PrivateKey'
                '- Personal Access Token requires AccessToken'
                '- authorization code requires Client ID, Client Secret, authentication code and redirect uri'
            )
        self.headers = headers

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
            d = AtlassianClient._get_utcnow()
        return int((d - AtlassianClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    def get_access_token(self):

        integration_context = get_integration_context()

        refresh_token = integration_context.get('current_refresh_token', '')
        access_token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        access_token, expires_in, refresh_token = self.get_token(refresh_token)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            "access_token": access_token,
            "valid_until": valid_until,
            'current_refresh_token': refresh_token
        })

        set_integration_context(integration_context)
        return access_token

    def http_request(self, headers=None, *args, **kwargs):
        if headers:
            headers.update(self.headers)
        else:
            headers = self.headers

        if self.auth:  # basic auth or Oauth 1.0
            return requests.request(auth=self.auth, headers=headers, *args, **kwargs)
        else:  # auth code
            access_token = self.access_token or self.get_access_token()
            headers.update({"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
            return requests.request(headers=headers, *args, **kwargs)

    def get_token(self, refresh_token: str = ''):
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
        )
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
                return_error(f'Error in Atlassian authorization. Status: {response.status_code},'
                             f' body: {response.json()}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Atlassian authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = arg_to_number(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def get_auth(self):
        return self.auth

    def get_headers(self):
        return self.headers
