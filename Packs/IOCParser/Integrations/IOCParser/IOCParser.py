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
# What to do with FILE_NAME

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
            data=json.dumps(data)
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


def create_dbot_score_obj(indicator: str, indicator_type: str) -> Common.DBotScore:
    """
    Creates a DBotScore object with the given parameters (and score as None)

    :type indicator: ``str``
    :param indicator: The indicator

    :type indicator_type: ``str``
    :param indicator_type: the indicator type

    :return: DBotScore object
    :rtype: ``Common.DBotScore``
    """

    return Common.DBotScore(
        indicator=indicator,
        indicator_type=MAP_IOCS.get(indicator_type),
        integration_name='IOCParser',
        score=Common.DBotScore.NONE
    )


def create_indicator_obj_list(response_data: Dict[str, List], keys) -> (List, Dict):
    """
    Creates indicators from the IOCs extracted from the response of the API and returns them as a list

    :type response_data: ``Dict[str, List]``
    :param response_data: The data key from the API's response

    :return: List with all indicator object that was created according to
    :rtype: ``Common.DBotScore``
    """

    indicators = []
    only_to_warroom = {}
    for indicator_type, indicators_list in response_data.items():
        if indicator_type not in keys:
            continue
        if indicator_type not in MAP_IOCS.keys():
            only_to_warroom[indicator_type] = indicators_list
        for indicator in indicators_list:
            dbot_score = create_dbot_score_obj(indicator, indicator_type)
            context_outputs = {indicator_type: indicator}
            indicator_obj = None
            if indicator_type == 'ASN':
                break
            elif indicator_type == 'FILE_NAME':
                break
            elif indicator_type == 'BITCOIN_ADDRESS':
                indicator_obj = Common.Cryptocurrency(address=indicator, address_type='bitcoin', dbot_score=dbot_score)
            elif indicator_type == 'CVE':
                indicator_obj = Common.CVE(id=indicator, cvss=None, published=None, modified=None, description=None)
            elif indicator_type == 'DOMAIN':
                indicator_obj = Common.Domain(domain=indicator, dbot_score=dbot_score)
            elif indicator_type == 'EMAIL':
                indicator_obj = Common.EMAIL(address=indicator, dbot_score=dbot_score)
            elif indicator_type == 'FILE_HASH_MD5':
                indicator_obj = Common.File(md5=indicator, dbot_score=dbot_score)
            elif indicator_type == 'FILE_HASH_SHA1':
                indicator_obj = Common.File(sha1=indicator, dbot_score=dbot_score)
            elif indicator_type == 'FILE_HASH_SHA256':
                indicator_obj = Common.File(sha256=indicator, dbot_score=dbot_score)
            elif indicator_type == 'IPv4' or indicator_type == 'IPv6':
                indicator_obj = Common.IP(ip=indicator, dbot_score=dbot_score)
            elif indicator_type == 'MAC_ADDRESS':
                break
            elif indicator_type == 'MITRE_ATT&CK':
                break
            elif indicator_type == 'URL':
                indicator_obj = Common.URL(url=indicator, dbot_score=dbot_score)
            elif indicator_type == 'YARA_RULE':
                break
            indicators.append((indicator_obj, context_outputs))

    return indicators, only_to_warroom


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    :type client: ``Client``
    :param client: IOCParser client to use


    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    response = client.ioc_from_url('https://pastebin.com/iMzrRXbJ', ['URL'])
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
    keys = args.get('keys')

    if not url:
        raise ValueError('url not specified')

    command_results = []

    response = client.ioc_from_url(url, keys)
    response_data = response.get('data')

    indicators, only_to_warroom = create_indicator_obj_list(response_data, keys)

    for indicator, d in indicators:
        command_results.append(CommandResults(
            #readable_output=readable_output,
            outputs_prefix='IOCParser.parseFromUrl',
            indicator=indicator,
            outputs=d,
            #raw_response=response
        ))
    readable_output = tableToMarkdown(
        'Parse from URL Results',
        remove_empty_elements(response_data),
        headerTransform=string_to_table_header,
    )

    command_results.append(CommandResults(
        readable_output=readable_output,
        raw_response=response
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
