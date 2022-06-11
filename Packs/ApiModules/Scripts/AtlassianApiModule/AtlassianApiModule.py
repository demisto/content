from CommonServerPython import *
from CommonServerUserPython import *

from requests_oauthlib import OAuth1


class AtlassianClient(BaseClient):

    def __init__(self, access_token: str = '', api_token: str = '', username: str = '',
                 password: str = '', consumer_key: str = '', private_key: str = '', headers: dict = {}):
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
        self.headers = headers
        self.access_token = access_token
        is_oauth1 = consumer_key and access_token and private_key

        if username and (password or api_token):  # basic authentication
            self.auth = username, (api_token or password)

        elif is_oauth1:  # oauth
            headers.update({'X-Atlassian-Token': 'nocheck'})
            self.auth = OAuth1(
                client_key=consumer_key,
                rsa_key=private_key,
                signature_method='RSA-SHA1',
                resource_owner_key=access_token,
            )

        elif access_token and not is_oauth1:  # bearer
            # Personal Access Token Authentication
            # HEADERS.update({'Authorization': f'Bearer {access_token}'})
            headers.update({'Authorization': f'Bearer {access_token}'})
        else:
            return_error(
                'Please provide the required Authorization information:'
                '- Basic Authentication requires user name and password or API token'
                '- OAuth 1.0 requires ConsumerKey, AccessToken and PrivateKey'
                '- Personal Access Tokens requires AccessToken'
            )
        self.headers = headers
        super().__init__(base_url=self.base_url, verify=self.use_ssl, headers=self.headers,
                         auth=self.auth)

    def get_auth(self):
        return self.auth

    def get_headers(self):
        return self.headers

    def http_request(self, method, full_url=None, headers=None, verify=False,
                     params=None, data=None, files=None):

        try:
            result = requests.request(
                method=method,
                url=full_url,
                data=data,
                auth=self.auth,
                headers=headers.update(self.headers) if headers else self.headers,
                verify=verify,
                files=files,
                params=params
            )
        except ValueError:
            raise ValueError("Could not deserialize privateKey")

        return result
