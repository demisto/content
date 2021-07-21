"""

"""
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50

# map_types = {'ASN': [None, None],
#             'BITCOIN_ADDRESS': [DBotScoreType.CRYPTOCURRENCY, Common.Cryptocurrency],
#             'CVE': [DBotScoreType.CVE, Common.CVE],
#             'DOMAIN': [DBotScoreType.DOMAIN, Common.Domain],
#             'EMAIL': [DBotScoreType.EMAIL, Common.EMAIL],
#             'FILE_HASH_MD5': [DBotScoreType.FILE, Common.File],
#             'FILE_HASH_SHA1': [DBotScoreType.FILE, Common.File],
#             'FILE_HASH_SHA256': [DBotScoreType.FILE, Common.File],
#             'IPv4': [DBotScoreType.IP, Common.IP],
#             'IPv6': [DBotScoreType.IP, Common.IP],
#             'MAC_ADDRESS': [None, None],
#             'MITRE_ATT&CK': [None, None],
#             'URL': [DBotScoreType.URL, Common.URL],
#             'YARA_RULE': [None, None]}

MAP_IOCS = {
    'BITCOIN_ADDRESS': DBotScoreType.CRYPTOCURRENCY,
    'CVE': DBotScoreType.CVE,
    'DOMAIN': DBotScoreType.DOMAIN,
    'EMAIL': DBotScoreType.EMAIL,
    'FILE_HASH_MD5': DBotScoreType.FILE,
    'FILE_HASH_SHA1': DBotScoreType.FILE,
    'FILE_HASH_SHA256': DBotScoreType.FILE,
    'IPv4': DBotScoreType.IP,
    'IPv6': DBotScoreType.IP,
    'URL': DBotScoreType.URL}

# IOCs we don't create indicator obj for them are ["YARA, MITER, MAC_ADD, ASN]

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    """

    @logger
    def __init__(self, headers, verify=False, proxy=False):
        url = 'https://api.iocparser.com'
        super().__init__(url, headers=headers, verify=verify, proxy=proxy)

    def ioc_from_url(self, url: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a URL

        :type url: ``str``
        :param url: The URL from which the IOCs will be extracted

        :return: The HTTP response returned by the API
        :rtype: ``Dict[str, Any]``
        """

        data = {'url': url, 'public': False}
        return self._http_request(
            method='POST',
            url_suffix='/url',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data),
            return_empty_response=True
        )

    def ioc_from_text(self, text: str, keys: list = None) -> Dict[str, Any]:
        data = {'data': text}
        if keys:
            data['keys'] = keys
        return self._http_request(
            method='POST',
            url_suffix='/text',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data)
        )

    # TODO the api gets raw text not as dict
    def ioc_from_raw_text(self, raw_text: str, keys: list = None) -> Dict[str, Any]:
        data = {}
        if keys:
            data['keys'] = keys
        return self._http_request(
            method='POST',
            url_suffix='/raw',
            headers={'Content-Type': 'text/plain'},
            data=json.dumps(data)
        )

    def ioc_from_twitter(self, user_name: str, keys: list = None) -> Dict[str, Any]:
        data = {'data': user_name}
        if keys:
            data['keys'] = keys
        return self._http_request(
            method='POST',
            url_suffix='/twitter',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data)
        )


''' HELPER FUNCTIONS '''


def list_to_upper_case(lst: List[str]) -> List[str]:
    return list(map(lambda x: x.upper(), lst))


def process_response(response_data: Dict[str, List], keys: List[str]) -> None:
    """
    Creates indicators from the IOCs extracted from the response of the API and returns them as a list

    :type response_data: ``Dict[str, List]``
    :param response_data: The data key from the API's response

    :type keys: ``List[str]``
    :param keys: IOC Types to return
    """

    keys_list = list(response_data.keys())
    for ioc_type in keys_list:
        if ioc_type not in keys or not response_data[ioc_type]:
            del response_data[ioc_type]


def limit_response(response_data: Dict[str, List], limit: int) -> Dict[str, List]:
    limited_response = {}
    for ioc_type, iocs in response_data.items():
        for ioc in iocs:
            if limit > 0:
                if not limited_response.get(ioc_type):
                    limited_response[ioc_type] = []
                limited_response.get(ioc_type).append(ioc)
                limit -= 1
    return limited_response


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    :type client: ``Client``
    :param client: IOCParser client to use


    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    response = client.ioc_from_url('https://pastebin.com/iMzrRXbJ')
    if (response.get('status') == 'fail') or (response.get('status') == 'error') or (response.get('status') is None):
        return 'Failed to connect with the API'
    return 'ok'


def ioc_from_url_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns the results of the Parse IOCs from URL API call
    Args:
        client: IOCParser client to use
        args: All command arguments, url and keys (if specified)

    Returns:
        CommandResults object containing the results of the parse from url as
        returned from the API and its readable output

    """
    url = args.get('url')
    keys = argToList(args.get('keys'))
    limit = args.get('limit')
    if not keys:
        keys = ['ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1',
                'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&CK', 'URL', 'YARA_RULE']
    keys = list_to_upper_case(keys)

    if not url:
        raise ValueError('url not specified')

    response = client.ioc_from_url(url)
    try:
        response_data = response.get('data')
    except Exception:
        raise Exception('The response from the API is empty')

    process_response(response_data, keys)
    if limit:
        response_data = limit_response(response_data, int(limit))
    if not response_data:
        raise Exception('The response from the API is empty')

    command_results = []
    outputs = {'url': url, 'Results': []}
    for key, values in response_data.items():
        for value in values:
            outputs['Results'].append({'type': key, 'value': value})
    for ioc_type, iocs in response_data.items():
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type} for {url}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromUrl',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


def ioc_from_text_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    pass


def ioc_from_raw_text_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    pass


def ioc_from_twitter_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    pass


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions

    :return:
    :rtype:
    """

    try:
        command = demisto.command()
        params = demisto.params()
        args = demisto.args()
        verify = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        headers = {
        }
        client = Client(headers, verify, proxy)

        if command == 'ioc-parser-parse-url':
            return_results(ioc_from_url_command(client, args))
        elif command == 'ioc-parser-parse-text':
            return_results(ioc_from_text_command(client, args))
        elif command == 'ioc-parser-parse-raw-text':
            return_results(ioc_from_raw_text_command(client, args))
        elif command == 'ioc-parser-parse-twitter':
            return_results(ioc_from_twitter_command(client, args))
        elif command == 'test-module':
            return_results(test_module(client))

    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
