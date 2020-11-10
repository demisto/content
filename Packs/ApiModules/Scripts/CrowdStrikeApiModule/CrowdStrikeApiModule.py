from CommonServerPython import *
from CommonServerUserPython import *


class CrowdStrikeClient(BaseClient):

    def __init__(self, params):
        """
        CrowdStrike Client class that implements OAuth2 authentication.
        Args:
            params: Demisto params
        """
        credentials = params.get('credentials', {})
        self._client_id = credentials.get('identifier')
        self._client_secret = credentials.get('password')
        super().__init__(base_url=demisto.params().get('server_url', 'https://api.crowdstrike.com/'),
                         verify=not params.get('insecure', False), ok_codes=tuple(),
                         proxy=params.get('proxy', False))  # type: ignore[misc]
        self._token = self._generate_token()
        self._headers = {'Authorization': 'bearer ' + self._token}

    @staticmethod
    def _error_handler(res: requests.Response):
        """
        Converting the errors of the API to a string, in case there are no error, return an empty string
        :param res: the request's response
        :return: None
        """
        err_msg = 'Error in API call [{}] - {}\n'.format(res.status_code, res.reason)
        try:
            # Try to parse json error response
            error_entry = res.json()
            errors = error_entry.get('errors', [])
            err_msg += '\n'.join(f"{error.get('code')}: {error.get('message')}" for  # pylint: disable=no-member
                                 error in errors)
            if 'Failed to issue access token - Not Authorized' in err_msg:
                err_msg = err_msg.replace('Failed to issue access token - Not Authorized',
                                          'Client Secret is invalid.')
            elif 'Failed to generate access token for clientID' in err_msg:
                err_msg = err_msg.replace('Failed to generate access token for clientID=', 'Client ID (')
                if err_msg.endswith('.'):
                    err_msg = err_msg[:-1]
                err_msg += ') is invalid.'
            raise DemistoException(err_msg)
        except ValueError:
            err_msg += '\n{}'.format(res.text)
            raise DemistoException(err_msg)

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False, auth=None):
        """A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type full_url: ``str``
        :param full_url:
            Bypasses the use of self._base_url + url_suffix. This is useful if you need to
            make a request to an address outside of the scope of the integration
            API.

        :type headers: ``dict``
        :param headers: Headers to send in the request. If None, will use self._headers.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :type data: ``dict``
        :param data: The data to send in a 'POST' request.

        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.

        :type files: ``dict``
        :param files: The file data to send in a 'POST' request.

        :type timeout: ``float`` or ``tuple``
        :param timeout:
            The amount of time (in seconds) that a request will wait for a client to
            establish a connection to a remote machine before a timeout occurs.
            can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).

        :type ok_codes: ``tuple``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204). If you specify
            "None", will use self._ok_codes.

        :type return_empty_response: ``bool``
        :param return_empty_response: Indicates whether we are expecting empty response (like 204) or not.

        :return: Depends on the resp_type parameter
        :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     json_data=json_data, params=params, data=data, files=files, timeout=timeout,
                                     ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth,
                                     error_handler=self._error_handler)

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request('POST', '/oauth2/token', data=body, auth=(self._client_id, self._client_secret))
        return token_res.get('access_token')

    def check_quota_status(self) -> dict:
        """Checking the status of the quota
        :return: http response
        """
        url_suffix = "/falconx/entities/submissions/v1?ids="
        return self.http_request('GET', url_suffix)
