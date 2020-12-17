from CommonServerPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

'''CONSTANTS'''
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


class Client(BaseClient):
    def __init__(self, input_url: str, username: str, password: str, verify_certificate: bool, proxy: bool):
        base_url = urljoin(input_url, '/api/v2/')
        headers = {
            "Content-Type": "application/json",
        }
        authentication = (username, password)
        super(Client, self).__init__(base_url=base_url,
                                     verify=verify_certificate,
                                     headers=headers,
                                     auth=authentication,
                                     proxy=proxy)

    def api_request(self, method: str, url_suffix: str, params: dict = None, data: dict = None) -> dict:
        return self._http_request(method=method, url_suffix=url_suffix, params=params, data=data)


def inventories_list(client: Client, args: dict) -> List[CommandResults]:
    command_results = []
    response = client.api_request('GET', 'inventories/', args)
    results = response.get('results')
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related')  # remove irelevant fields from output
        res.pop('summary_fields')
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.Inventory',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res),
            raw_response=res
        ))
    return command_results


def hosts_list(client: Client, args: dict) -> List[CommandResults]:
    inventory_id = args.pop('inventory_id', None)
    if inventory_id:
        url_suffix = f'inventories/{inventory_id}/hosts'
    else:
        url_suffix = 'hosts/'

    command_results = []
    response = client.api_request('GET', url_suffix, args)
    results = response.get('results')
    if not len(results):
        command_results.append(CommandResults(
            readable_output=f"No results were found for the following argument {str(args)}",
            raw_response=response
        ))
    for res in results:
        res.pop('related')  # remove irelevant fields from output
        res.pop('summary_fields')
        command_results.append(CommandResults(
            outputs_prefix='AnsibleAWX.Host',
            outputs_key_field='id',
            outputs=res,
            readable_output=tableToMarkdown(name='Results', t=res),
            raw_response=res
        ))
    return command_results


def create_host(client: Client, args: dict):
    inventory_id = args.pop('inventory_id', None)
    if inventory_id:
        url_suffix = f'inventories/{inventory_id}/hosts'
    else:
        url_suffix = 'hosts/'

    body = {'name': args.get('host_name'),
            'description': args.get('description', ''),
            'enabled': bool(args.get('enabled', 'True')),
            }

    response = client.api_request('POST', url_suffix, args)



def test_module(client: Client) -> str:

    try:
        client.api_request('inventories/', {})
        return 'ok'
    except Exception as e:
        raise DemistoException(f"Error in API call - check the input parameters. Error: {e}.")


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    commands = {
        'ansible-awx-inventories-list': inventories_list,
        'ansible-awx-hosts-list': hosts_list,
        'ansible-awx-host-create': create_host
    }

    base_url = params.get("url")

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    username = params.get("username")
    password = params.get("password")

    try:

        client = Client(
            input_url=base_url,
            username=username,
            password=password,
            verify_certificate=verify_certificate,
            proxy=proxy)

        command = demisto.command()

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
