from CommonServerPython import *

''' IMPORTS '''

import urllib.parse
import httplib2
from google.auth import exceptions
from contextlib import contextmanager
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from typing import List, Dict, Any, Tuple, Optional

''' CONSTANTS '''

COMMON_MESSAGES: Dict[str, str] = {
    'TIMEOUT_ERROR': 'Connection Timeout Error - potential reasons might be that the Server URL parameter'
                     ' is incorrect or that the Server is not accessible from your host. Reason: {}',
    'HTTP_ERROR': 'HTTP Connection error occurred. Status: {}. Reason: {}',
    'TRANSPORT_ERROR': 'Transport error occurred. Reason: {}',
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured Service Account JSON. Reason: {}',
    'BAD_REQUEST_ERROR': 'An error occurred while fetching/submitting the data. Reason: {}',
    'TOO_MANY_REQUESTS_ERROR': 'Too many requests please try after sometime. Reason: {}',
    'INTERNAL_SERVER_ERROR': 'The server encountered an internal error. Reason: {}',
    'AUTHORIZATION_ERROR': 'Request has insufficient privileges. Reason: {}',
    'JSON_PARSE_ERROR': 'Unable to parse JSON string. Please verify the JSON is valid.',
    'NOT_FOUND_ERROR': 'Not found. Reason: {}',
    'UNKNOWN_ERROR': 'An error occurred. Status: {}. Reason: {}',
    'PROXY_ERROR': 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is'
                   ' selected, try clearing the checkbox.',
    'REFRESH_ERROR': 'Failed to generate/refresh token. Subject email or service account credentials'
                     ' are invalid. Reason: {}',
    'BOOLEAN_ERROR': 'The argument {} must be either true or false.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'UNEXPECTED_ERROR': 'An unexpected error occurred.',
}


class GSuiteClient:
    """
    Client to use in integration with powerful http_request.
    """

    def __init__(self, service_account_dict: Dict[str, str], proxy: bool, verify: bool,
                 base_url: str = '', headers: Optional[Dict[str, str]] = None,
                 user_id: str = ''):
        self.headers = headers
        try:
            self.credentials = service_account.Credentials.from_service_account_info(info=service_account_dict)
        except Exception:
            raise ValueError(COMMON_MESSAGES['JSON_PARSE_ERROR'])
        self.proxy = proxy
        self.verify = verify
        self.authorized_http: Any = None
        self.base_url = base_url
        self.user_id = user_id

    def set_authorized_http(self, scopes: List[str], subject: Optional[str] = None, timeout: int = 60) -> None:
        """
        Set the http client from given subject and scopes.

        :param scopes: List of scopes needed to make request.
        :param subject: To link subject with credentials.
        :param timeout: Timeout value for request.

        :return: None.
        """
        self.credentials = self.credentials.with_scopes(scopes)
        if subject:
            self.credentials = self.credentials.with_subject(subject)
        authorized_http = AuthorizedHttp(credentials=self.credentials,
                                         http=GSuiteClient.get_http_client(self.proxy, self.verify, timeout=timeout))
        self.authorized_http = authorized_http

    def http_request(self, url_suffix: str = None, params: Optional[Dict[str, Any]] = None,
                     method: str = 'GET',
                     body: Optional[Dict[str, Any]] = None, full_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Makes an API call to URL using authorized HTTP.

        :param url_suffix: url_suffix of url.
        :param params: Parameters to pass in request url.
        :param method: Method to use while making http request.
        :param body: Request body.
        :param full_url: URL to consider for request when given url_suffix will be ignored.

        :return: response json.
        :raises DemistoException: If there is issues while making the http call.
        """
        encoded_params = f'?{urllib.parse.urlencode(params)}' if params else ''

        url = full_url

        if url_suffix:
            url = urljoin(self.base_url, url_suffix)

        url = f'{url}{encoded_params}'

        body = json.dumps(body) if body else None

        with GSuiteClient.http_exception_handler():
            response = self.authorized_http.request(headers=self.headers, method=method, uri=url, body=body)
            return GSuiteClient.validate_and_extract_response(response)

    @staticmethod
    def handle_http_error(error: httplib2.socks.HTTPError) -> None:
        """
        Handle and raise DemistoException with respective message.

        :param error: HTTPError object.

        :return: None
        :raises DemistoException: raise DemistoException with respective error message.
        """
        if error.args and isinstance(error.args[0], tuple):
            error_status, error_msg = error.args[0][0], error.args[0][1].decode()
            if error_status == 407:  # Proxy Error
                raise DemistoException(COMMON_MESSAGES['PROXY_ERROR'])
            raise DemistoException(COMMON_MESSAGES['HTTP_ERROR'].format(error_status, error_msg))
        raise DemistoException(error)

    @staticmethod
    @contextmanager
    def http_exception_handler():
        """
        Exception handler for handling different exceptions while making http calls.

        :return: None
        :raises DemistoException: If there is any other issues while making the http call.
        """
        try:
            yield
        except httplib2.socks.HTTPError as error:
            GSuiteClient.handle_http_error(error)
        except exceptions.TransportError as error:
            if 'proxyerror' in str(error).lower():
                raise DemistoException(COMMON_MESSAGES['PROXY_ERROR'])
            raise DemistoException(COMMON_MESSAGES['TRANSPORT_ERROR'].format(error))
        except exceptions.RefreshError as error:
            if error.args:
                raise DemistoException(COMMON_MESSAGES['REFRESH_ERROR'].format(error.args[0]))
            raise DemistoException(error)
        except TimeoutError as error:
            raise DemistoException(COMMON_MESSAGES['TIMEOUT_ERROR'].format(error))
        except Exception as error:
            raise DemistoException(error)

    @staticmethod
    def get_http_client(proxy: bool, verify: bool, timeout: int = 60) -> httplib2.Http:
        """
        Validate proxy and prepares Http object.

        :param proxy: Boolean indicates whether to use proxy or not.
        :param verify: Boolean indicates whether to use ssl certification.
        :param timeout: Timeout value for request.

        :return: ProxyInfo object.
        :raises DemistoException: If there is any other issues while preparing proxy.
        """
        proxy_info = {}
        proxies = handle_proxy()
        if proxy:
            https_proxy = proxies['https']
            if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
                https_proxy = 'https://' + https_proxy
            parsed_proxy = urllib.parse.urlparse(https_proxy)
            proxy_info = httplib2.ProxyInfo(
                proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                proxy_host=parsed_proxy.hostname,
                proxy_port=parsed_proxy.port,
                proxy_user=parsed_proxy.username,
                proxy_pass=parsed_proxy.password)

        return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=not verify, timeout=timeout)

    @staticmethod
    def validate_and_extract_response(response: Tuple[httplib2.Response, Any]) -> Dict[str, Any]:
        """
        Prepares an error message based on status code and extract a response.

        :param response: Tuple containing httplib2.Response and content.

        :return: response extracted json.
        :raises DemistoException: If there is any other issues parsing response.
        """
        if response[0].status == 200 or response[0].status == 204:
            return GSuiteClient.safe_load_non_strict_json(response[1])

        status_code_message_map = {
            400: COMMON_MESSAGES['BAD_REQUEST_ERROR'],
            401: COMMON_MESSAGES['AUTHENTICATION_ERROR'],
            403: COMMON_MESSAGES['AUTHORIZATION_ERROR'],
            404: COMMON_MESSAGES['NOT_FOUND_ERROR'],
            429: COMMON_MESSAGES['TOO_MANY_REQUESTS_ERROR'],
            500: COMMON_MESSAGES['INTERNAL_SERVER_ERROR']
        }

        try:
            # Depth details of error.
            demisto.debug(response[1].decode() if type(response[1]) is bytes else response[1])
            message = GSuiteClient.safe_load_non_strict_json(response[1]).get('error', {}).get('message', '')
        except ValueError:
            message = COMMON_MESSAGES['UNEXPECTED_ERROR']

        if response[0].status in status_code_message_map:
            raise DemistoException(status_code_message_map[response[0].status].format(message))
        else:
            raise DemistoException(COMMON_MESSAGES['UNKNOWN_ERROR'].format(response[0].status, message))

    @staticmethod
    def safe_load_non_strict_json(json_string: str) -> Dict[str, Any]:
        """
        Loads the JSON with non-strict mode.

        :param json_string: json string to parse.

        :return: Parsed dictionary.
        :raises ValueError: If there is any other issues while parsing json.
        """
        try:
            if json_string:
                return json.loads(json_string, strict=False)
            return {}
        except ValueError:
            raise ValueError(COMMON_MESSAGES['JSON_PARSE_ERROR'])

    @staticmethod
    def validate_set_boolean_arg(args: Dict[str, Any], arg: str, arg_name: Optional[str] = None) -> None:
        """
        Set and validate boolean arguments.

        :param args: dictionary containing arguments.
        :param arg: key containing boolean arg.
        :param arg_name: In case of arg name is different in command to set in exception.

        :return: None
        :raises ValueError: if boolean arg value is invalid.
        """
        if arg in args:
            try:
                args[arg] = argToBoolean(args[arg])
            except ValueError:
                raise ValueError(COMMON_MESSAGES['BOOLEAN_ERROR'].format(arg_name if arg_name else arg))

    @staticmethod
    def remove_empty_entities(d):
        """
        Recursively remove empty lists, empty dicts, or None elements from a dictionary.

        :param d: Input dictionary.
        :return: Dictionary with all empty lists, and empty dictionaries removed.
        """

        def empty(x):
            return x is None or x == {} or x == [] or x == ''

        if not isinstance(d, (dict, list)):
            return d
        elif isinstance(d, list):
            return [value for value in (GSuiteClient.remove_empty_entities(value) for value in d) if not empty(value)]
        else:
            return {key: value for key, value in ((key, GSuiteClient.remove_empty_entities(value))
                                                  for key, value in d.items()) if not empty(value)}

    @staticmethod
    def validate_get_int(max_results: Optional[str], message: str, limit: int = 0) -> Optional[int]:
        """
        Validate and convert string max_results to integer.

        :param max_results: max results in string.
        :param message: Message to display when exception raised.
        :param limit: If max_results > limit raise the exception.

        :return: int max_results
        :raises ValueError: if max_results is not a integer and < 0.
        """
        if max_results:
            try:
                max_results_int = int(max_results)
                if max_results_int <= 0:
                    raise ValueError
                if limit and max_results_int > limit:
                    raise ValueError
                return max_results_int
            except ValueError:
                raise ValueError(message)
        return None

    @staticmethod
    def strip_dict(args: Dict[str, str]) -> Dict[str, str]:
        """
        Remove leading and trailing white spaces from dictionary values and remove empty entries.

        :param args: Arguments dict.
        :return: Dictionary with whitespaces and empty entries removed.
        """
        return {key: value.strip() for (key, value) in args.items() if value and value.strip()}
