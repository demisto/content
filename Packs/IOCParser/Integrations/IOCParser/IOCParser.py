"""
Cortex XSOAR Integration for IOC Parser.
"""
from CommonServerPython import *

import json
import urllib3
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

KEYS = ['ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1',
        'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&CK', 'URL', 'YARA_RULE']
URL = 'https://api.iocparser.com'


''' CLIENT CLASS '''


class Client(BaseClient):

    @logger
    def __init__(self, verify=False, proxy=False):
        url = URL
        super().__init__(url, verify=verify, proxy=proxy)

    def ioc_from_url(self, url: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a URL.
        Args:
            url: The URL from which the IOCs will be extracted

        Returns:
            The HTTP response returned by the API
        """

        data = {'url': url, 'public': False}
        return self._http_request(
            method='POST',
            url_suffix='/url',
            headers={'Content-Type': 'application/json'},
            # The API requires the data to be a string in json format
            data=json.dumps(data),
            return_empty_response=True
        )

    def ioc_from_json_text(self, text: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a JSON text.
        Args:
            text: The JSON from which the IOCs will be extracted

        Returns:
            The HTTP response returned by the API
        """

        data = {'data': text}
        return self._http_request(
            method='POST',
            url_suffix='/text',
            headers={'Content-Type': 'application/json'},
            # The API requires the data to be a string in json format
            data=json.dumps(data),
            return_empty_response=True
        )

    def ioc_from_raw_text(self, raw_text: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a raw text.
        Args:
            raw_text: The raw text from which the IOCs will be extracted

        Returns:
            The HTTP response returned by the API
        """

        return self._http_request(
            method='POST',
            url_suffix='/raw',
            headers={'Content-Type': 'text/plain'},
            # The API requires the data to be a string
            data=raw_text,
            return_empty_response=True
        )

    def ioc_from_twitter(self, user_name: str) -> Dict[str, Any]:
        """
        Extracts all IOCs from a twitter account
        Args:
            user_name: The twitter account from which the IOCs will be extracted

        Returns:
            The HTTP response returned by the API
        """

        data = {'data': user_name}
        return self._http_request(
            method='POST',
            url_suffix='/twitter',
            headers={'Content-Type': 'application/json'},
            # The API requires the data to be a string in json format
            data=json.dumps(data),
            return_empty_response=True
        )


''' HELPER FUNCTIONS '''


def list_to_upper_case(lst: List[str]) -> List[str]:
    """
    Upper case every string in the list
    Args:
        lst: The list we want to upper case

    Returns:
        The upper cased list
    """

    return [s.upper() for s in lst]


def remove_unwanted_keys(response_data: Dict[str, List], keys: List[str]) -> None:
    """
    Removes all keys that were not specified by the user as the desired keys to return

    Args:
        response_data: Dictionary of an IOC as key and a list of all IOCs from this type as value
        keys: IOC Types to return
    """

    keys_list = list(response_data.keys())
    for ioc_type in keys_list:
        if ioc_type not in keys or not response_data[ioc_type]:
            del response_data[ioc_type]


def limit_response(response_data: Dict[str, List], limit: int) -> Dict[str, List]:
    """
    Trims the result from the API according to limit parameter.
    Args:
        response_data: Dictionary of an IOC as key and a list of all IOCs from this type as value
        limit: maximum number of results to return

    Returns:
        New dictionary with at most "limit" results
    """

    limited_response = {}
    for ioc_type, iocs in response_data.items():
        limited_response[ioc_type] = []
        for ioc in iocs:
            if limit > 0:
                limited_response.get(ioc_type).append(ioc)
                limit -= 1
            else:
                return limited_response
    return limited_response


def process_response(response: Dict[str, Any], keys: List[str], limit: int) -> Dict[str, List]:
    """
    Args:
        response: The data key from the API's response
        keys: IOC Types to return
        limit: maximum number of results to return

    Returns:

    """

    if not response:
        raise ValueError('The response from the API is empty.')
    response_data = response.get('data')
    remove_unwanted_keys(response_data, keys)
    if limit is not None:
        response_data = limit_response(response_data, limit)
    return response_data


def unite_all_tweets_into_dict(twitter_response: Dict[str, Any]) -> None:
    # The data for this response is a list of "responses", for each tweet of the user
    """

    Args:
        twitter_response: A dictionary that represents the response
    """

    try:
        response_data = twitter_response.get('data')
    except Exception:
        raise ValueError('The response from the API is empty')

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
    Tests API connectivity.
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Args:
        client: IOCParser client to use

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    try:
        client.ioc_from_url('https://pastebin.com/iMzrRXbJ')
    except Exception as e:
        return f'Failed to connect with the API. Error: {str(e)}'
    return 'ok'


def ioc_from_url_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Returns the results of the Parse IOCs from URL API call.
    Args:
        client: IOCParser client to use.
        args: All command arguments, url, limit, keys (if specified).

    Returns:
        CommandResults object containing the results of the parse from url as
        returned from the API and its readable output.
    """

    url = args.get('url')
    keys = list_to_upper_case(argToList(args.get('keys'))) or KEYS
    limit = arg_to_number(args.get('limit'))
    try:
        response = client.ioc_from_url(url)
    except DemistoException as e:
        raise ValueError(str(e))

    response_data = process_response(response, keys, limit)
    if not response_data:
        raise ValueError('There is no information about the requested keys')
    command_results = []
    outputs = {'url': url, 'Results': []}
    for ioc_type, iocs in response_data.items():
        for ioc in iocs:
            outputs['Results'].append({'type': ioc_type, 'value': ioc})
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type} from {url}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromUrl',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


def ioc_from_json_text_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        Returns the results of the Parse IOCs from text API call.
        Args:
            client: IOCParser client to use.
            args: All command arguments, text, limit, and keys (if specified).

        Returns:
            CommandResults object containing the results of the parse from
            text (in JSON format) as returned from the API and its readable output.
    """

    data = args.get('data')
    try:
        a_json = json.loads(data)
    except ValueError as e:
        raise ValueError(f'Data should be in JSON format. Error: {str(e)}')
    keys = list_to_upper_case(argToList(args.get('keys'))) or KEYS
    limit = arg_to_number(args.get('limit'))

    try:
        response = client.ioc_from_json_text(data)
    except DemistoException as e:
        raise ValueError(str(e))
    response_data = process_response(response, keys, limit)
    if not response_data:
        raise ValueError('There is no information about the requested keys')
    command_results = []
    outputs = {'data': data, 'Results': []}
    for ioc_type, iocs in response_data.items():
        for ioc in iocs:
            outputs['Results'].append({'type': ioc_type, 'value': ioc})
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromJSONText',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


def ioc_from_raw_text_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        Returns the results of the Parse IOCs from raw text API call
        Args:
            client: IOCParser client to use
            args: All command arguments, text, limit, and keys (if specified).

        Returns:
            CommandResults object containing the results of the parse from
            text (in JSON format) as returned from the API and its readable output
    """

    raw_text = args.get('data')
    file = args.get('entry_id')
    if raw_text:
        if file:
            raise ValueError('Both data and entry id were inserted - please insert only one.')
        data = raw_text

    elif file:
        demisto.debug('getting the path of the file from its entry id')
        result = demisto.getFilePath(args.get('entry_id'))
        if not result:
            raise ValueError('No file was found for given entry id')
        file_path, file_name = result['path'], result['name']
        if not file_name.endswith('.txt'):
            raise ValueError('File should be in txt format.')
        with open(file_path, 'r') as f:
            data = f.read()
        f.close()

    else:
        raise ValueError('Neither data nor entry id specified.')
    keys = list_to_upper_case(argToList(args.get('keys'))) or KEYS
    limit = arg_to_number(args.get('limit'))
    try:
        response = client.ioc_from_raw_text(data)
    except DemistoException as e:
        raise ValueError(str(e))
    response_data = process_response(response, keys, limit)
    if not response_data:
        raise ValueError('There is no information about the requested keys')
    command_results = []
    outputs = {'data': data, 'Results': []}
    for ioc_type, iocs in response_data.items():
        for ioc in iocs:
            outputs['Results'].append({'type': ioc_type, 'value': ioc})
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'results for {ioc_type}', iocs, headers=ioc_type),
            outputs_prefix=f'IOCParser.parseFromRawText',
            outputs=outputs
        ))

    command_results.append(CommandResults(
        raw_response=response_data
    ))

    return command_results


def ioc_from_twitter_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        Returns the results of the Parse IOCs from twitter account API call
        Args:
            client: IOCParser client to use
            args: All command arguments, data, limit, and keys (if specified).

        Returns:
            CommandResults object containing the results of the parse from
            twitter account as returned from the API and its readable output
    """

    twitter_account = args.get('data')
    keys = list_to_upper_case(argToList(args.get('keys'))) or KEYS
    limit = arg_to_number(args.get('limit'))
    try:
        twitter_response = client.ioc_from_twitter(twitter_account)
    except DemistoException as e:
        raise ValueError('Could not find this twitter account') from e
    unite_all_tweets_into_dict(twitter_response)
    response_data = process_response(twitter_response, keys, limit)
    if not response_data:
        raise ValueError('There is no information about the requested keys')
    command_results = []
    outputs = {'data': twitter_account, 'Results': []}
    for ioc_type, iocs in response_data.items():
        for ioc in iocs:
            outputs['Results'].append({'type': ioc_type, 'value': ioc})
        command_results.append(CommandResults(
                readable_output=tableToMarkdown(f'results for {ioc_type} from {twitter_account}',
                                                iocs,
                                                headers=ioc_type),
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
        client = Client(verify=verify, proxy=proxy)

        if command == 'ioc-parser-parse-url':
            return_results(ioc_from_url_command(client, args))
        elif command == 'ioc-parser-parse-text':
            return_results(ioc_from_json_text_command(client, args))
        elif command == 'ioc-parser-parse-raw-text':
            return_results(ioc_from_raw_text_command(client, args))
        elif command == 'ioc-parser-parse-twitter':
            return_results(ioc_from_twitter_command(client, args))
        elif command == 'test-module':
            return_results(test_module(client))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command. '
                     f'Error: {str(e)}\n{traceback.format_exc()}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
