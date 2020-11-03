from CommonServerPython import *
from CommonServerUserPython import *


OAUTH_URL = '/oauth_token.do'


class ServiceNowClient(BaseClient):

    def __init__(self, params):
        """
        ServiceNow Client class. The class can use either basic authorization with username and password, or OAuth2.
        Args:
            params: The parameters that should be used to initialize the Service Now Client:
                    - Credentials - the username and password given by the user.
                    - Client Id - the client id of the application of the user.
                    - Client Secret - the client secret of the application of the user.
                    - Url - the instance url of the user, i.e: https://<instance>.service-now.com. NOTE: the url should
                            be given without an API specific suffix as it is used in the OAuth process.
                    - Insecure
                    - Proxy
                    - Headers
                    - Use OAuth - a flag indicating whether the user wants to use OAuth 2.0 or basic authorization.
        """
        self.use_oauth = params.get('use_oauth')
        if self.use_oauth:  # if user selected the `Use OAuth` box use OAuth authorization, else use basic authorization
            self.client_id = params.get('client_id')
            self.client_secret = params.get('client_secret')
        else:
            self.username = params.get('credentials', {}).get('identifier')
            self.password = params.get('credentials', {}).get('password')
            self._auth = (self.username, self.password)

        self.base_url = params.get('url')
        super().__init__(base_url=self.base_url, verify=not params.get('insecure', False),
                         ok_codes=tuple(), proxy=params.get('proxy', False), headers=params.get('headers'))  # type: ignore[misc]

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, return_empty_response=False, auth=None):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            res = super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, resp_type='response',
                                        headers=headers, json_data=json_data, params=params, data=data, files=files,
                                        ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth)
            if res.status_code in [200, 201]:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)

            if res.status_code in [401]:
                if self.use_oauth:
                    if demisto.getIntegrationContext().get('expiry_time', 0) <= date_to_timestamp(datetime.now()):
                        access_token = self.get_access_token()
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
                    raise res

        except Exception as e:
            if 'SSL Certificate Verification Failed' in e.args[0]:
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
            res = self.http_request('POST', url_suffix=OAUTH_URL, data=data, headers=headers)
            if 'error' in res:
                return_error(
                    f'Error occurred while creating an access token. Please check the Client ID, Client Secret '
                    f'and that the given username and password are correct.\n{res}')
            if res.get('access_token'):
                expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                expiry_time += res.get('expires_in') * 1000 - 10
                new_token = {
                    'access_token': res.get('access_token'),
                    'refresh_token': res.get('refresh_token'),
                    'expiry_time': expiry_time
                }
                demisto.setIntegrationContext(new_token)
        except Exception as e:
            return_error(f'Login failed. Please check the instance configuration and the given username and password.'
                         f'\n\n{e.args[0]}')

    def get_access_token(self):
        """
        Get an access token that was previously created if it is still valid, else, generate a new access token from
        the client id, client secret and refresh token.
        """
        previous_token = demisto.getIntegrationContext()

        # Check if there is an existing valid access token
        if previous_token.get('access_token') and previous_token.get('expiry_time') > date_to_timestamp(datetime.now()):
            access_token = previous_token.get('access_token')
        else:
            data = {'client_id': self.client_id,
                    'client_secret': self.client_secret}

            # Check if a refresh token exists. If not, raise an exception indicating to call the login function first.
            if previous_token.get('refresh_token'):
                data['refresh_token'] = previous_token.get('refresh_token')
                data['grant_type'] = 'refresh_token'
            else:
                raise Exception('Could not create an access token. Maybe the user is not logged in. Try running the'
                                ' !servicenow-login command.')

            try:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                res = self.http_request('POST', url_suffix=OAUTH_URL, data=data, headers=headers)
                if 'error' in res:
                    return_error(
                        f'Error occurred while creating an access token. Please check the Client ID, Client Secret '
                        f'and that the refresh token is not expired.\n{res}')
                if res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                    expiry_time += res.get('expires_in', 0) * 1000 - 10
                    new_token = {
                        'access_token': res.get('access_token'),
                        'refresh_token': res.get('refresh_token'),
                        'expiry_time': expiry_time
                    }
                    demisto.setIntegrationContext(new_token)
                    access_token = res.get('access_token')
            except Exception as e:
                return_error(f'Error occurred while creating an access token. Please check the instance configuration.'
                             f'\n\n{e.args[0]}')
        return access_token
