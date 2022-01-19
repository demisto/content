import traceback
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API"""

    def get_lists(self):
        return self._http_request(
            method='GET'
        )

    def get_list(self, list_id):
        return self._http_request(
            method='GET',
            url_suffix=list_id
        )

    def patch_list(self, list_id, url_list_object, action):
        return self._http_request(
            method='PATCH',
            url_suffix=f'{list_id}/{action}',
            json_data=url_list_object
        )

    def replace_url_list(self, list_id, url_list_object):
        return self._http_request(
            method='PUT',
            url_suffix=list_id,
            json_data=url_list_object
        )

    def deploy_lists(self):
        return self._http_request(
            method='POST',
            url_suffix='deploy'
        )


''' HELPER FUNCTIONS '''


def create_url_list_object(urls, type_='exact'):
    return {
        'data': {
            'urls': urls,
            'type': type_
        }
    }


def get_list_id_from_name(client, list_name):
    # get list ID from lists, filtered by list name
    lists = client.get_lists()
    list_id = [listt.get('id') for listt in lists if listt.get('name') == list_name]
    if len(list_id) == 0:
        raise Exception(f'A Netskope URL List with the name "{list_name}" does not exist')
    elif len(list_id) == 1:
        return str(list_id[0])
    else:
        raise Exception(f'Found multiple Netskope URL Lists with the name "{list_name}"')


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type Client: ``client``
    :param client: Netskope client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client._http_request(
            method='GET'
        )
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def get_lists(client: Client, args: Dict[str, Any]) -> CommandResults:
    r = client.get_lists()

    markdown = tableToMarkdown('Retrieved all applied and pending lists', r)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Netskope',
        outputs_key_field='',
        outputs={
            'URLList': r
        }
    )


def get_list(client: Client, args: Dict[str, Any]) -> CommandResults:
    list_name = args.get('list_name')

    list_id = get_list_id_from_name(client, list_name)

    r = client.get_list(list_id)

    markdown = tableToMarkdown(f'Retrieved "{list_name}" list', r)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Netskope',
        outputs_key_field='',
        outputs={
            'URLList': r
        }
    )


def add_url(client: Client, args: Dict[str, Any]) -> CommandResults:
    list_name = args.get('list_name')
    url = argToList(args.get('url'))

    if len(url) == 0:
        raise Exception('received an empty list of URLs')

    list_id = get_list_id_from_name(client, list_name)

    # create 'urls' list
    urls = []
    for u in url:
        urls.append(u)

    # append urls to list
    url_list_object = create_url_list_object(urls)
    r = client.patch_list(list_id, url_list_object, 'append')

    # apply pending changes
    client.deploy_lists()

    markdown = tableToMarkdown(f'Added "{url}" to "{r.get("name")}" list', r)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Netskope',
        outputs_key_field='',
        outputs={
            'URLList': r
        }
    )


def remove_url(client: Client, args: Dict[str, Any]) -> CommandResults:
    list_name = args.get('list_name')
    url = argToList(args.get('url'))

    if len(url) == 0:
        raise Exception('received an empty list of URLs')

    list_id = get_list_id_from_name(client, list_name)

    # get urls from list
    r = client.get_list(list_id)
    urls = r.get('data').get('urls')

    # remove urls
    urls_found = []
    urls_not_found = []
    for u in url:
        if u in urls:
            urls_found.append(u)
        else:
            urls_not_found.append(u)
    for u in urls_found:
        urls.remove(u)

    # write urls to list
    url_list_object = create_url_list_object(urls, r.get('data').get('type'))
    r = client.patch_list(list_id, url_list_object, 'replace')

    # apply pending changes
    client.deploy_lists()

    message = f'Remove URLs from "{r.get("name")}" list'
    if urls_found:
        message += f'\nRemoved: {urls_found}'
    if urls_not_found:
        message += f"\nNot found: {urls_not_found}"
    markdown = tableToMarkdown(message, r)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix='Netskope',
        outputs_key_field='',
        outputs={
            'URLList': r
        }
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('api_key')
    base_url = urljoin(demisto.params()['url'], '/api/v2/policy/urllist/')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    headers = {
        'Content-Type': 'application/json',
        'Netskope-Api-Token': api_key,
        'Accept': 'application/json'
    }

    commands = {
        'netskopev2-get-lists': get_lists,
        'netskopev2-get-list': get_list,
        'netskopev2-add-url': add_url,
        'netskopev2-remove-url': remove_url
    }

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers
        )

        if command == 'test-module':
            return_results(test_module(client))
        if command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
