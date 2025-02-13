import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Dict, List
import json
from base64 import b64encode

CONTENT_TYPE_MAPPER = {
    "json": "application/json",
    "xml": "text/xml",
    "form": "application/x-www-form-urlencoded",
    "data": "multipart/form-data"
}

RAW_RESPONSE = 'raw_response'


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool):

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def http_request(self, method: str, full_url: str = '', headers: dict = None, resp_type: str = RAW_RESPONSE,
                     params: dict = None, data: str = None, timeout: int = 10, retries: int = 0,
                     status_list_to_retry: list = None, allow_redirects: bool = True,
                     backoff_factor: int = 5):
        try:
            res = self._http_request(
                method=method,
                full_url=full_url,
                headers=headers,
                params=params,
                timeout=timeout,
                resp_type=resp_type,
                status_list_to_retry=status_list_to_retry,
                retries=retries,
                data=data,
                error_handler=self._generic_error_handler,
                allow_redirects=allow_redirects,
                backoff_factor=backoff_factor
            )
        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)
        return res

    @staticmethod
    def _generic_error_handler(res: requests.Response):
        status_code = res.status_code
        if status_code == 400:
            raise DemistoException(f"Bad request. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 401:
            raise DemistoException(f"Unauthorized. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 403:
            raise DemistoException(f"Invalid permissions. Status code: {status_code}. "
                                   f"Origin response from server: {res.text}")

        if status_code == 404:
            raise DemistoException(f"The server has not found anything matching the request URI. Status code:"
                                   f" {status_code}. Origin response from server: {res.text}")
        if status_code == 500:
            raise DemistoException(f"Internal server error. Status code: {status_code}."
                                   f" Origin response from server: {res.text}")

        if status_code == 502:
            raise DemistoException(f"Bad gateway. Status code: {status_code}. Origin response from server: {res.text}")


def create_headers(headers: Dict, request_content_type_header: str, response_content_type_header: str) \
        -> Dict[str, str]:
    """
    Create a dictionary of headers. It will map the header if it exists in the CONTENT_TYPE_MAPPER.
    Args:
        headers: The headers the user insert.
        request_content_type_header: The content type header.
        response_content_type_header: The response type header.

    Returns:
        A dictionary of headers to send in the request.
    """
    if request_content_type_header in CONTENT_TYPE_MAPPER.keys():
        request_content_type_header = CONTENT_TYPE_MAPPER[request_content_type_header]
    if response_content_type_header in CONTENT_TYPE_MAPPER.keys():
        response_content_type_header = CONTENT_TYPE_MAPPER[response_content_type_header]
    if request_content_type_header and not headers.get('Content-Type'):
        headers['Content-Type'] = request_content_type_header
    if response_content_type_header and not headers.get('Accept'):
        headers['Accept'] = response_content_type_header

    return headers


def get_parsed_response(res, resp_type: str) -> Any:
    try:
        resp_type = resp_type.lower()
        if resp_type == 'json':
            res = res.json()
        elif resp_type == 'xml':
            res = json.loads(xml2json(res.content))
        else:
            res = res.text
        return res
    except ValueError as exception:
        raise DemistoException('Failed to parse json object from response: {}'
                               .format(res.content), exception)


def format_status_list(status_list: list) -> List[int]:
    """
    Get a status list and format it to a range of status numbers.
    Example:
        given: ['400-404',500,501]
        return: [400,401,402,403,500,501]
    Args:
        status_list: The given status list.
    Returns:
        A list of statuses to retry.
    """
    final_status_list = []
    for status in status_list:
        # Checks if the status is a range of statuses
        if '-' in status:
            range_numbers = status.split('-')
            status_range = list(range(int(range_numbers[0]), int(range_numbers[1]) + 1))
            final_status_list.extend(status_range)
        elif status.isdigit():
            final_status_list.append(int(status))
    return final_status_list


def build_outputs(parsed_res, res: requests.Response) -> Dict:
    return {'ParsedBody': parsed_res,
            'Body': res.text,
            'StatusCode': res.status_code,
            'StatusText': res.reason,
            'URL': res.url,
            'Headers': dict(res.headers)}


def parse_headers(headers: str) -> Dict:
    """
        Parsing headers from str type to dict.
        The allowed format are:
        1. {"key": "value"}
        2. "key": "value"
    """
    if not headers.startswith('{') and not headers.endswith('}'):
        headers = '{' + headers + '}'
    try:
        headers_dict = json.loads(headers)
    except json.decoder.JSONDecodeError:
        raise DemistoException("Make sure the headers are in one of the allowed formats.")
    return headers_dict


def main():
    params = demisto.params()
    cred = params.get('auth_credentials', {})
    uName = cred.get('identifier', '')

    if demisto.command() == 'test-module':
        return_results("The http request will use stored credentials labeled: " + uName)
    if demisto.command() == 'http_request':
        args = demisto.args()
        method = args.get('method', '')
        full_url = args.get('url', '')
        body = args.get('body', '')
        request_content_type = args.get('request_content_type', '')
        response_content_type = args.get('response_content_type', '')
        parse_response_as = args.get('parse_response_as', RAW_RESPONSE)
        params = params.get('params', {})
        headers = args.get('headers', {})
        authType = args.get('authType', {})
        passw = cred.get('password', {})
        token = b64encode(f"{uName}:{passw}".encode('utf-8')).decode("ASCII")

        if isinstance(headers, str):
            headers = parse_headers(headers)
        if authType == ('Bearer'):
            token = passw
        if authType != ('N/A'):
            headers["Authorization"] = authType + ' ' + token
        headers = create_headers(headers, request_content_type, response_content_type)

        save_as_file = args.get('save_as_file', 'no')
        file_name = args.get('filename', 'http-file')
        timeout = arg_to_number(args.get('timeout', 10))
        timeout_between_retries = args.get('timeout_between_retries', 5)
        retry_count = arg_to_number(args.get('retry_count', 3))
        proxy = argToBoolean(args.get('proxy', False))
        verify = argToBoolean(not args.get('unsecure', False))

        client = Client(base_url=full_url, verify=verify, proxy=proxy)
        kwargs = {
            'method': method,
            'full_url': full_url,
            'headers': headers,
            'data': body,
            'timeout': timeout,
            'params': params,
            'backoff_factor': timeout_between_retries
        }

        retry_on_status = args.get('retry_on_status', None)
        raise_on_status = True if retry_on_status else False
        retry_status_list = format_status_list(argToList(retry_on_status))

        if raise_on_status:
            kwargs.update({
                'retries': retry_count,
                'status_list_to_retry': retry_status_list,
                'raise_on_status': raise_on_status
            })
        try:
            enable_redirect = argToBoolean(args.get('enable_redirect', True))

            if not enable_redirect:
                kwargs.update({
                    'allow_redirects': enable_redirect
                })

            res = client.http_request(**kwargs)
            parsed_res = get_parsed_response(res, parse_response_as)

            if save_as_file == 'yes':
                return_results(fileResult(file_name, res.content))

            outputs = build_outputs(parsed_res, res)

            return_results(CommandResults(
                readable_output=f"Sent a {method} request to {full_url}",
                outputs_prefix='HttpRequest.Response',
                outputs=outputs,
                raw_response={'data': parsed_res}
            ))
        except Exception as e:
            return_error(f'Failed to execute HttpV2 script. Error: {str(e)}')

# if demisto.command() == 'long-running-execution':
  # Should have here an endless loop


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
