import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""


import traceback
import xml.etree.ElementTree as ET
from typing import Any, Dict


class Client(BaseClient):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):

        super().__init__(base_url=base_url, auth=(username, password), verify=verify, proxy=proxy)

    def http_request(self, method: str, full_url: str = '', headers=None, resp_type='json', params=None,
                     data=None, timeout=10, retries=0, return_empty_response=False,
                     status_list_to_retry=None, enable_redirect=False, raise_on_status=False):
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
        if res.status_code == 400:
            raise DemistoException(f"Bad request. Origin response from server: {res.text}")

        if res.status_code == 401:
            raise DemistoException(f"Unauthorized. Origin response from server: {res.text}")

        if res.status_code == 403:
            raise DemistoException(f"Invalid permissions. Origin response from server: {res.text}")

        if res.status_code == 404:
            raise DemistoException(f"The server has not found anything matching the request URI. Origin response from"
                                   f" server: {res.text}")
        if res.status_code == 500:
            raise DemistoException(f"Internal server error. Origin response from server: {res.text}")

        if res.status_code == 502:
            raise DemistoException(f"Bad gateway. Origin response from server: {res.text}")


def create_headers(headers_input, content_type, res_type):
    headers = headers_input
    if content_type and not headers.get('Content-Type'):
        headers['Content-Type'] = content_type
    if res_type and not headers.get('Accept'):
        headers['Accept'] = res_type
    print(headers)
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
    return final_status_list


''' MAIN FUNCTION '''


def main(args: Dict):
    method = args.get('method', '')
    url = args.get('url', '')
    body = args.get('body', '')
    new1 = ET.tostring(body, encoding='unicode')
    print(f"Body length {len(body)}")
    print(body)
    print(new1)
    request_content_type = args.get('request_content_type', '')
    response_content_type = args.get('response_content_type', '')
    headers = args.get('headers', {})
    headers = create_headers(headers, request_content_type, response_content_type)
    username = args.get('username', '')
    password = args.get('password', '')
    save_as_file = args.get('save_as_file', 'no')
    file_name = args.get('filename', 'http-file')
    enable_redirect = args.get('enable_redirect', False)
    timeout = int(args.get('timeout', ''))
    retry_on_status = args.get('retry_on_status', [])
    retry_status_list = get_status_list(argToList(retry_on_status))
    retry_count = int(args.get('retry_count', 3))
    log_error_on_status = args.get('log_error_on_status', False)
    proxy = args.get('proxy', False)
    verify = not args.get('unsecure', False)

    client = Client(base_url=url, username=username, password=password, verify=verify, proxy=proxy)
    print(enable_redirect)
    if enable_redirect is True:
        res = client.http_request(method=method, full_url=url, headers=headers, data=body, timeout=timeout,
                                  retries=retry_count, enable_redirect=enable_redirect, resp_type=response_content_type)
    elif retry_status_list:
        res = client.http_request(method=method, full_url=url, headers=headers, data=body, timeout=timeout,
                                  retries=retry_count, resp_type='response',
                                  status_list_to_retry=retry_status_list, raise_on_status=True)
    else:
        res = client.http_request(method=method, full_url=url, headers=headers, data=new1, timeout=timeout,
                                  resp_type='response')
    print(res)

    if save_as_file == 'yes':
        save_res_to_file(res, file_name)
    return CommandResults(readable_output='human_readable',
                          outputs='http',
                          outputs_prefix='httpv2',
                          raw_response=res,
                          )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
