from CommonServerPython import *
from CommonServerUserPython import *
import requests


class CrowdStrikeClient(BaseClient):

    def __init__(self, params):
        """
        CrowdStrike Client class that implements OAuth2 authentication.
        Args:
            params: Demisto params
        """
        self._verify = not params.get('insecure', False)
        self._username = params.get('credentials', {}).get('identifier')
        self._password = params.get('credentials', {}).get('password')
        self._proxy = params.get('proxy', False)
        self._base_url = "https://api.crowdstrike.com/"
        self._ok_codes = tuple()  # type: ignore[var-annotated]
        self._session = requests.Session()
        self._token = self._generate_token()
        self._headers = {'Authorization': 'bearer ' + self._token}
        if not self._proxy:
            self._session.trust_env = False

        # super().__init__(base_url=self._base_url, verify=self._verify, *args, **kwargs)  # type: ignore[misc]

    @staticmethod
    def _handle_errors(errors: list) -> str:
        """
        Converting the errors of the API to a string, in case there are no error, return an empty string
        :param errors: each error is a dict with the keys code and message
        :return: errors converted to single str
        """
        return '\n'.join(f"{error['code']}: {error['message']}" for error in errors)

    def _is_status_code_valid(self, response, ok_codes=None):
        """If the status code is OK, return 'True'.

        :type response: ``requests.Response``
        :param response: Response from API after the request for which to check the status.

        :type ok_codes: ``tuple`` or ``list``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204). If you specify
            "None", will use response.ok.

        :return: Whether the status of the response is valid.
        :rtype: ``bool``
        """
        # Get wanted ok codes
        status_codes = ok_codes if ok_codes else self._ok_codes
        if status_codes:
            return response.status_code in status_codes
        return response.ok

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False):
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
        try:
            # Replace params if supplied
            address = full_url if full_url else urljoin(self._base_url, url_suffix)
            headers = headers if headers else self._headers
            # Execute
            res = self._session.request(
                method,
                address,
                verify=self._verify,
                params=params,
                data=data,
                json=json_data,
                files=files,
                headers=headers,
                timeout=timeout,
            )
            # Handle error responses gracefully
            if not self._is_status_code_valid(res, ok_codes):
                try:
                    # Try to parse json error response
                    error_entry = res.json()
                    err_msg = self._handle_errors(error_entry.get("errors"))
                    raise DemistoException(err_msg)
                except ValueError:
                    err_msg += '\n{}'.format(res.text)
                    raise DemistoException(err_msg)

            is_response_empty_and_successful = (res.status_code == 204)
            if is_response_empty_and_successful and return_empty_response:
                return res

            try:
                return res.json()
            except ValueError as exception:
                raise DemistoException("Failed to parse json object from response:" + str(res.content), exception)
        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.SSLError as exception:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ConnectionError as exception:
            # Get originating Exception in Exception chain
            error_class = str(exception.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                      'Verify that the server URL parameter' \
                      ' is correct and that you have access to the server from your host.' \
                .format(err_type, exception.errno, exception.strerror)
            raise DemistoException(err_msg, exception)

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            'client_id': self._username,
            'client_secret': self._password
        }

        byte_creds = f'{self._username}:{self._password}'.encode('utf-8')

        headers = {
            'Authorization': f'Basic {base64.b64encode(byte_creds).decode()}'
        }
        token_res = self.http_request('POST', '/oauth2/token', data=body, headers=headers)
        return token_res.get('access_token')

    def check_quota_status(
            self
    ) -> dict:
        """Creating the needed arguments for the http request
        :return: http response
        """
        url_suffix = "/falconx/entities/submissions/v1?ids="
        return self.http_request("Get", url_suffix)
