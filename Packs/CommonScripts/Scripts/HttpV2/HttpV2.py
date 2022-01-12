"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback

CONTENT_TYPE_MAPPER = {
    "json": "application/json",
    "xml": "text/xml",
    "form": "application/x-www-form-urlencoded",
    "data": "multipart/form-data"
}


class Client(BaseClient):
    def __init__(self, base_url: str, auth: tuple, verify: bool, proxy: bool):

        super().__init__(base_url=base_url, auth=auth, verify=verify, proxy=proxy)

    def http_request(self, method: str, full_url: str = '', headers=None, resp_type='raw response', params=None,
                     data=None, timeout=10, retries=0, status_list_to_retry=None, enable_redirect=False,
                     raise_on_status=False):
        try:
            res = self._http_request(
                method=method,
                full_url=full_url,
                headers=headers,
                params=params,
                timeout=timeout,
                resp_type=resp_type,
                status_list_to_retry=status_list_to_retry,
                raise_on_redirect=enable_redirect,
                raise_on_status=raise_on_status,
                retries=retries,
                data=data,
                error_handler=self._generic_error_handler
            )
        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)
        return res

    @staticmethod
    def _generic_error_handler(res):
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


def create_headers(headers, request_content_type_header, response_content_type_header):
    if request_content_type_header in CONTENT_TYPE_MAPPER.keys():
        request_content_type_header = CONTENT_TYPE_MAPPER[request_content_type_header]
    if response_content_type_header in CONTENT_TYPE_MAPPER.keys():
        response_content_type_header = CONTENT_TYPE_MAPPER[response_content_type_header]
    if request_content_type_header and not headers.get('Content-Type'):
        headers['Content-Type'] = request_content_type_header
    if response_content_type_header and not headers.get('Accept'):
        headers['Accept'] = response_content_type_header

    return headers


def save_res_to_file(res, file_name):
    return return_results(fileResult(file_name, res))


def get_status_list(status_list):
    final_status_list = []
    for status in status_list:
        range_numbers = status.split('-')
        if len(range_numbers) == 1:
            final_status_list.append(int(range_numbers[0]))
        else:
            status_range = list(range(int(range_numbers[0]), int(range_numbers[1]) + 1))
            final_status_list.extend(status_range)
    print(final_status_list)
    return final_status_list


''' MAIN FUNCTION '''


def main(args: Dict):
    method = args.get('method', '')
    url = args.get('url', '')
    body = args.get('body', '')
    request_content_type = args.get('request_content_type', '')
    response_content_type = args.get('response_content_type', '')
    parse_response_as = args.get('parse_response_as', 'raw response')
    headers = args.get('headers', {})
    headers = create_headers(headers, request_content_type, response_content_type)
    auth = tuple(argToList(args.get('basic_auth', None)))
    # username = args.get('username', '')
    # password = args.get('password', '')
    save_as_file = args.get('save_as_file', 'no')
    file_name = args.get('filename', 'http-file')
    enable_redirect = argToBoolean(args.get('enable_redirect', False))
    timeout = arg_to_number(args.get('timeout', ''))
    retry_on_status = args.get('retry_on_status', None)
    raise_on_status = True if retry_on_status else False
    retry_status_list = get_status_list(argToList(retry_on_status))
    retry_count = arg_to_number(args.get('retry_count', 3))
    proxy = argToBoolean(args.get('proxy', False))
    verify = argToBoolean(not args.get('unsecure', False))

    client = Client(base_url=url, auth=auth, verify=verify, proxy=proxy)

    if enable_redirect or raise_on_status:
        res = client.http_request(method=method, full_url=url, headers=headers, data=body, timeout=timeout,
                                  retries=retry_count, enable_redirect=enable_redirect, resp_type=parse_response_as,
                                  status_list_to_retry=retry_status_list, raise_on_status=raise_on_status)
    else:
        res = client.http_request(method=method, full_url=url, headers=headers, data=body, timeout=timeout,
                                  resp_type=parse_response_as)

    if save_as_file == 'yes':
        save_res_to_file(res, file_name)

    return res


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
