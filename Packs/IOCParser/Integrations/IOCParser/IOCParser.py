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

KEYS = ['ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1',
        'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&CK', 'URL', 'YARA_RULE']


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

    def ioc_from_text(self, text: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a JSON text

        :type text: ``str``
        :param text: The JSON from which the IOCs will be extracted

        :return: The HTTP response returned by the API
        :rtype: ``Dict[str, Any]``
        """
        data = {'data': text}
        return self._http_request(
            method='POST',
            url_suffix='/text',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data),
            return_empty_response=True
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
            data=json.dumps(data),
            return_empty_response=True
        )

    def ioc_from_twitter(self, user_name: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a twitter account

        :type user_name: ``str``
        :param user_name: The twitter account from which the IOCs will be extracted

        :return: The HTTP response returned by the API
        :rtype: ``Dict[str, Any]``
        """
        data = {'data': user_name}
        return self._http_request(
            method='POST',
            url_suffix='/twitter',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data),
            return_empty_response=True
        )


''' HELPER FUNCTIONS '''


def list_to_upper_case(lst: List[str]) -> List[str]:
    """
    Upper case every string in the list

    :type lst: ``List``
    :param lst: The list we want to upper case

    :return: The upper cased list
    :rtype: ``List``
    """
    return list(map(lambda x: x.upper(), lst))


def remove_unwanted_keys(response_data: Dict[str, List], keys: List[str]) -> None:
    """
    Removes all keys that were not specified by the user as the desired keys to return

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
    """
    Trims the result from the API according to limit parameter

    :type response_data: ``Dict[str, List]``
    :param response_data: The data key from the API's response

    :type limit: ``int``
    :param limit: maximum number of results to return


    :return: New dictionary with at most "limit" results
    :rtype: Dict[str, List]
    """

    limited_response = {}
    for ioc_type, iocs in response_data.items():
        for ioc in iocs:
            if limit > 0:
                if not limited_response.get(ioc_type):
                    limited_response[ioc_type] = []
                limited_response.get(ioc_type).append(ioc)
                limit -= 1
    return limited_response


def process_response(response: Dict[str, Any], keys: List[str], limit: int) -> Dict[str, List]:
    """


    :type response: ``Dict[str, Any]``
    :param response: The data key from the API's response

    :type keys: ``List[str]``
    :param keys: IOC Types to return

    :type limit: ``int``
    :param limit: maximum number of results to return

    :return:
    :rtype: Dict[str, List]
    """

    try:
        response_data = response.get('data')
    except Exception:
        raise Exception('The response from the API is empty')

    remove_unwanted_keys(response_data, keys)
    if limit is not None:
        response_data = limit_response(response_data, int(limit))
    if not response_data:
        raise Exception('The response from the API is empty from limit')
    return response_data


def unite_all_tweets_into_dict(twitter_response: Dict[str, Any]) -> None:
    # The data for this response is a list of "responses", for each tweet of the user
    """
    Unites all data from every tweet to a single dictionary

    :type twitter_response: ``Dict[str, List]``
    :param twitter_response: The data key from the API's response
    """

    try:
        response_data = twitter_response.get('data')
    except Exception:
        raise Exception('The response from the API is empty')

    united_data = {}
    for tweet in response_data:
        for ioc_type, iocs in tweet.get('data').items():
            for ioc in iocs:
                if not united_data.get(ioc_type):
                    united_data[ioc_type] = []
                united_data.get(ioc_type).append(ioc)

    twitter_response['data'] = united_data


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    :type client: ``Client``
    :param client: IOCParser client to use


    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    response = client.ioc_from_url('https://pastebin.com/iMzrRXbJ')
    if (response.get('status') == 'fail') \
            or (response.get('status') == 'error') \
            or (response.get('status') is None):
        return 'Failed to connect with the API'
    return 'ok'


def ioc_from_url_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns the results of the Parse IOCs from URL API call
    Args:
        client: IOCParser client to use
        args: All command arguments, ulr, limit and keys (if specified)

    Returns:
        CommandResults object containing the results of the parse from url as
        returned from the API and its readable output

    """
    url = args.get('url')
    keys = argToList(args.get('keys'))
    limit = args.get('limit')
    if not keys:
        keys = KEYS
    keys = list_to_upper_case(keys)

    if not url:
        raise ValueError('url not specified')

    response = client.ioc_from_url(url)

    response_data = process_response(response, keys, limit)

    command_results = []
    outputs = {'url': url, 'Results': []}
    for key, values in response_data.items():
        for value in values:
            outputs['Results'].append({'type': key, 'value': value})
    for ioc_type, iocs in response_data.items():
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type} from {url}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromUrl',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


def ioc_from_text_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        Returns the results of the Parse IOCs from text API call
        Args:
            client: IOCParser client to use
            args: All command arguments, text, limit and keys (if specified)

        Returns:
            CommandResults object containing the results of the parse from
            text (in JSON format) as returned from the API and its readable output

        """
    data = args.get('data')
    keys = argToList(args.get('keys'))
    limit = args.get('limit')
    if not keys:
        keys = KEYS
    keys = list_to_upper_case(keys)

    if not data:
        raise ValueError('text not specified')

    response = client.ioc_from_text(data)

    response_data = process_response(response, keys, limit)

    command_results = []
    outputs = {'data': data, 'Results': []}
    for key, values in response_data.items():
        for value in values:
            outputs['Results'].append({'type': key, 'value': value})
    for ioc_type, iocs in response_data.items():
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromText',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


def ioc_from_raw_text_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    pass


def ioc_from_twitter_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        Returns the results of the Parse IOCs from twitter account API call
        Args:
            client: IOCParser client to use
            args: All command arguments, data, limit and keys (if specified)

        Returns:
            CommandResults object containing the results of the parse from
            twitter account as returned from the API and its readable output
    """

    twitter_account = args.get('data')
    keys = argToList(args.get('keys'))
    limit = args.get('limit')
    if not keys:
        keys = KEYS
    keys = list_to_upper_case(keys)

    if not twitter_account:
        raise ValueError('twitter user name not specified')

    twitter_response = client.ioc_from_twitter(twitter_account)
    unite_all_tweets_into_dict(twitter_response)
    response_data = process_response(twitter_response, keys, limit)

    command_results = []
    outputs = {'data': twitter_account, 'Results': []}
    for key, values in response_data.items():
        for value in values:
            outputs['Results'].append({'type': key, 'value': value})
    for ioc_type, iocs in response_data.items():
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type} from {twitter_account}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromTwitter',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command function
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
