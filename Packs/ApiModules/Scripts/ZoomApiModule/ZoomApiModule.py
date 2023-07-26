import demistomock as demisto  # noqa: F401
import jwt
from CommonServerPython import *  # noqa: F401
from datetime import timedelta
import dateparser

''' CONSTANTS '''

OAUTH_TOKEN_GENERATOR_URL = 'https://zoom.us/oauth/token'
# The token’s time to live is 1 hour,
# two minutes were subtract for extra safety.
TOKEN_LIFE_TIME = timedelta(minutes=58)
# the lifetime for an JWT token is 90 minutes == 5400 seconds
# 400 seconds were subtract for extra safety.
JWT_LIFETIME = 5000
# maximun records that the api can return in one request
MAX_RECORDS_PER_PAGE = 300

# ERRORS
INVALID_CREDENTIALS = 'Invalid credentials. Please verify that your credentials are valid.'
INVALID_API_SECRET = 'Invalid API Secret. Please verify that your API Secret is valid.'
INVALID_ID_OR_SECRET = 'Invalid Client ID or Client Secret. Please verify that your ID and Secret is valid.'

'''CLIENT CLASS'''


class Zoom_Client(BaseClient):
    """ A client class that implements logic to authenticate with Zoom application. """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        api_secret: str | None = None,
        account_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        verify=True,
        proxy=False,
    ):
        super().__init__(base_url, verify, proxy)
        self.api_key = api_key
        self.api_secret = api_secret
        self.account_id = account_id
        self.client_id = client_id
        self.client_secret = client_secret
        is_jwt = (api_key and api_secret) and not (client_id and client_secret and account_id)
        if is_jwt:
            # the user has chosen to use the JWT authentication method (deprecated)
            self.access_token: str | None = get_jwt_token(api_key, api_secret)  # type: ignore[arg-type]
        else:
            # the user has chosen to use the OAUTH authentication method.
            try:
                self.access_token = self.get_oauth_token()
            except Exception as e:
                demisto.debug(f"Cannot get access token. Error: {e}")
                self.access_token = None

    def generate_oauth_token(self):
        """
    Generate an OAuth Access token using the app credentials (AKA: client id and client secret) and the account id

    :return: valid token
    """
        token_res = self._http_request(method="POST", full_url=OAUTH_TOKEN_GENERATOR_URL,
                                       params={"account_id": self.account_id,
                                               "grant_type": "account_credentials"},
                                       auth=(self.client_id, self.client_secret))
        return token_res.get('access_token')

    def get_oauth_token(self, force_gen_new_token=False):
        """
            Retrieves the token from the server if it's expired and updates the global HEADERS to include it

            :param force_gen_new_token: If set to True will generate a new token regardless of time passed

            :rtype: ``str``
            :return: Token
        """
        now = datetime.now()
        ctx = get_integration_context()

        if not ctx or not ctx.get('token_info').get('generation_time', force_gen_new_token):
            # new token is needed
            oauth_token = self.generate_oauth_token()
            ctx = {}
        else:
            if generation_time := dateparser.parse(
                ctx.get('token_info').get('generation_time')
            ):
                time_passed = now - generation_time
            else:
                time_passed = TOKEN_LIFE_TIME
            if time_passed < TOKEN_LIFE_TIME:
                # token hasn't expired
                return ctx.get('token_info').get('oauth_token')
            else:
                # token expired
                oauth_token = self.generate_oauth_token()

        ctx.update({'token_info': {'oauth_token': oauth_token, 'generation_time': now.strftime("%Y-%m-%dT%H:%M:%S")}})
        set_integration_context(ctx)
        return oauth_token

    def error_handled_http_request(self, method, url_suffix='', full_url=None, headers=None,
                                   auth=None, json_data=None, params=None, files=None, data=None,
                                   return_empty_response: bool = False, resp_type: str = 'json', stream: bool = False, ):

        # all future functions should call this function instead of the original _http_request.
        # This is needed because the OAuth token may not behave consistently,
        # First the func will make an http request with a token,
        # and if it turns out to be invalid, the func will retry again with a new token.
        try:
            return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                         auth=auth, json_data=json_data, params=params, files=files, data=data,
                                         return_empty_response=return_empty_response, resp_type=resp_type, stream=stream)
        except DemistoException as e:
            if ('Invalid access token' in e.message
                    or "Access token is expired." in e.message):
                self.access_token = self.generate_oauth_token()
                headers = {'authorization': f'Bearer {self.access_token}'}
                return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                             auth=auth, json_data=json_data, params=params, files=files, data=data,
                                             return_empty_response=return_empty_response, resp_type=resp_type, stream=stream)
            else:
                raise DemistoException(e.message)


''' HELPER FUNCTIONS '''


def get_jwt_token(apiKey: str, apiSecret: str) -> str:
    """
    Encode the JWT token given the api ket and secret
    """
    now = datetime.now()
    expire_time = int(now.strftime('%s')) + JWT_LIFETIME
    payload = {
        'iss': apiKey,

        'exp': expire_time
    }
    encoded = jwt.encode(payload, apiSecret, algorithm='HS256')
    return encoded
