import json
import traceback
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


''' CLIENT CLASS '''


class XSOARClient(BaseClient):
    """Client class to interact with the XSOAR API"""

    def get_lists(self):
        return self._http_request(
            method='GET',
            url_suffix='/lists'
        )

    def save_list(self, list_data, list_version, xsoar_block_list_name):
        return self._http_request(
            method='POST',
            url_suffix='/lists/save',
            json_data={
                'id': xsoar_block_list_name,
                'name': xsoar_block_list_name,
                'data': json.dumps(list_data),
                'version': list_version
            }
        )


class NetskopeClient(BaseClient):
    """Client class to interact with the Netskope API"""

    def update_url_list(self, api_key, list_contents):
        return self._http_request(
            method='GET',
            url_suffix='/updateUrlList',
            params={
                'token': api_key,
                'name': xsoar_url_block_list_name,
                'list': ','.join(list_contents)
            }
        )

    def update_filehash_list(self, api_key, list_contents):
        return self._http_request(
            method='GET',
            url_suffix='/updateFileHashList',
            params={
                'token': api_key,
                'name': xsoar_filehash_block_list_name,
                'list': ','.join(list_contents)
            }
        )


''' HELPER FUNCTIONS '''


def get_list(client, xsoar_block_list_name):
    r = client.get_lists()

    # get XSOAR List
    list_data = None
    for listt in r:
        if listt.get('name') == xsoar_block_list_name:
            list_data = listt.get('data')
            list_version = listt.get('version')
            break

    if not list_data:
        raise Exception(f'"{xsoar_block_list_name}" XSOAR List could not be found')

    # json string to dictionary
    if isinstance(list_data, str):
        list_data = json.loads(list_data)

    # get values
    key = list(list_data.keys())[0]
    list_contents = list(list_data.values())[0]

    return key, list_contents, list_version


def add_indicators(list_contents, indicator):
    # append value(s) to list
    if isinstance(indicator, str):
        if indicator not in list_contents:
            list_contents.append(indicator)
    elif isinstance(indicator, list):
        for i in indicator:
            if i not in list_contents:
                list_contents.append(i)
    else:
        return_error('"list_contents" is not type "str" or "list", not sure how that happened...')

    return list_contents


def remove_indicators(list_contents, indicator):
    # remove value(s) from list
    if isinstance(indicator, str):
        if indicator in list_contents:
            list_contents.remove(indicator)
    elif isinstance(indicator, list):
        for i in indicator:
            if i in list_contents:
                list_contents.remove(i)
    else:
        return_error('"list_contents" is not type "str" or "list", not sure how that happened...')

    return list_contents


def save_list(client, key, list_contents, list_version, xsoar_block_list_name):
    list_data = {
        key: list_contents
    }

    # save list
    r = client.save_list(list_data, list_version, xsoar_block_list_name)

    return list_data


''' COMMAND FUNCTIONS '''


def test_module(xsoar_client: XSOARClient, netskope_client: NetskopeClient, api_key: str) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :param xsoar_client: XSOAR client to use
    :param netskope_lient: Netskope client to use
    :param api_key: Netskope API key

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        key, list_contents, list_version = get_list(xsoar_client, xsoar_filehash_block_list_name)
        r = netskope_client.update_filehash_list(api_key, list_contents)
        if r.get('errorCode') == 'Authorization Error':
            return 'Netskope Authorization Error: make sure Netskope API Key is correctly set'
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            return 'XSOAR Authorization Error: make sure XSOAR API Key is correctly set'
        else:
            raise e
    return 'ok'


def add_url(client: XSOARClient, args: Dict[str, Any]) -> CommandResults:
    key, list_contents, list_version = get_list(client, xsoar_url_block_list_name)

    url = argToList(args.get('url'))
    list_contents = add_indicators(list_contents, url)

    list_data = save_list(client, key, list_contents, list_version, xsoar_url_block_list_name)

    markdown = tableToMarkdown(f'URLs added to list: "{xsoar_url_block_list_name}"', list_data)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='XSOAR',
        outputs_key_field='',
        outputs={
            'URLList': list_contents
        }
    )


def remove_url(client: XSOARClient, args: Dict[str, Any]) -> CommandResults:
    key, list_contents, list_version = get_list(client, xsoar_url_block_list_name)

    url = argToList(args.get('url'))
    list_contents = remove_indicators(list_contents, url)

    list_data = save_list(client, key, list_contents, list_version, xsoar_url_block_list_name)

    markdown = tableToMarkdown(f'URLs removed from list: "{xsoar_url_block_list_name}"', list_data)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='XSOAR',
        outputs_key_field='',
        outputs={
            'URLList': list_contents
        }
    )


def update_url_list(xsoar_client: XSOARClient, netskope_client: NetskopeClient, api_key: str) -> CommandResults:
    key, list_contents, list_version = get_list(xsoar_client, xsoar_url_block_list_name)
    r = netskope_client.update_url_list(api_key, list_contents)

    if r.get('status') == 'error':
        return_error(f'Errors: {r.get("errors")}')

    list_data = {
        key: list_contents
    }

    markdown = tableToMarkdown(f'"{xsoar_url_block_list_name}" {r.get("msg")}', list_data)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Netskope',
        outputs_key_field='',
        outputs={
            'URLList': list_contents
        }
    )


def add_filehash(client: XSOARClient, args: Dict[str, Any]) -> CommandResults:
    key, list_contents, list_version = get_list(client, xsoar_filehash_block_list_name)

    filehash = argToList(args.get('filehash'))
    list_contents = add_indicators(list_contents, filehash)

    list_data = save_list(client, key, list_contents, list_version, xsoar_filehash_block_list_name)

    markdown = tableToMarkdown(f'File hashes added to list: "{xsoar_filehash_block_list_name}"', list_data)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='XSOAR',
        outputs_key_field='',
        outputs={
            'FileHashList': list_contents
        }
    )


def remove_filehash(client: XSOARClient, args: Dict[str, Any]) -> CommandResults:
    key, list_contents, list_version = get_list(client, xsoar_filehash_block_list_name)

    filehash = argToList(args.get('filehash'))
    list_contents = remove_indicators(list_contents, filehash)

    list_data = save_list(client, key, list_contents, list_version, xsoar_filehash_block_list_name)

    markdown = tableToMarkdown(f'File hashes removed from list: "{xsoar_filehash_block_list_name}"', list_data)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='XSOAR',
        outputs_key_field='',
        outputs={
            'FileHashList': list_contents
        }
    )


def update_filehash_list(xsoar_client: XSOARClient, netskope_client: NetskopeClient, api_key: str) -> CommandResults:
    key, list_contents, list_version = get_list(xsoar_client, xsoar_filehash_block_list_name)
    r = netskope_client.update_filehash_list(api_key, list_contents)

    if r.get('status') == 'error':
        return_error(f'Errors: {r.get("errors")}')

    list_data = {
        key: list_contents
    }

    markdown = tableToMarkdown(f'"{xsoar_filehash_block_list_name}" {r.get("msg")}', list_data)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Netskope',
        outputs_key_field='',
        outputs={
            'FileHashList': list_contents
        }
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    base_url = urljoin(demisto.params().get('url'), '/api/v1')
    xsoar_api_key = demisto.params().get('xsoar_api_key')
    netskope_api_key = demisto.params().get('netskope_api_key')
    global xsoar_url_block_list_name
    xsoar_url_block_list_name = demisto.params().get('xsoar_url_block_list_name')
    global xsoar_filehash_block_list_name
    xsoar_filehash_block_list_name = demisto.params().get('xsoar_filehash_block_list_name')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    xsoar_commands = {
        'netskopev1-add-url': add_url,
        'netskopev1-remove-url': remove_url,
        'netskopev1-add-filehash': add_filehash,
        'netskopev1-remove-filehash': remove_filehash
    }

    netskope_commands = {
        'netskopev1-update-url-list': update_url_list,
        'netskopev1-update-filehash-list': update_filehash_list
    }

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    xsoar_server_url = demisto.demistoUrls().get('server')
    try:
        xsoar_client = XSOARClient(
            base_url=xsoar_server_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                'Authorization': xsoar_api_key
            }
        )

        netskope_client = NetskopeClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(xsoar_client, netskope_client, netskope_api_key)
            return_results(result)
        elif command in xsoar_commands:
            return_results(xsoar_commands[command](xsoar_client, demisto.args()))
        elif command in netskope_commands:
            return_results(netskope_commands[command](xsoar_client, netskope_client, netskope_api_key))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
