import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify: bool, api_key: str = ""):
        headers = {
            'Authorization': 'prm-key ' + api_key
        }
        super().__init__(base_url=base_url, verify=verify, headers=headers)

    def get_accounts_list(self, params):
        result = self._http_request(method="GET", url_suffix="/account", params=params, headers=self._headers)
        return result

    def get_accounts_id(self, id, params):
        result = self._http_request(method="GET", url_suffix=f"/account/{id}", params=params,  headers=self._headers)
        return result


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        res = client.get_accounts_list({})
        if res.get('success'):
            message = 'ok'
    except DemistoException as e:
        raise e
    return message


def impartner_get_account_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    query = args.get('query', None)
    fields = args.get('fields', None)
    filter = args.get('filter', None)
    orderby = args.get('orderby', None)
    skip = args.get('skip', None)
    take = args.get('take', None)
    all_fields = args.get('all_fields', None)
    if all_fields == "TRUE":
        fields = ""
    params = assign_params(q=query, fields=fields, filter=filter, orderby=orderby, skip=skip, take=take)

    # Call the Client function and get the raw response
    result = client.get_accounts_list(params)
    parsed_result = result.get('data', '')
    readable_output = tableToMarkdown('List of account ID\'s', parsed_result.get('results'))
    return CommandResults(
        outputs_prefix='Impartner.Accounts.List',
        readable_output=readable_output,
        outputs_key_field='Impartner.Accounts.list.results.id',
        outputs=parsed_result)


def impartner_get_account_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    id = args.get('id', None)
    fields = args.get('fields', None)
    all_fields = args.get('all_fields', None)
    if all_fields == "true":
        fields = ""
    params = assign_params(fields=fields)
    # Call the Client function and get the raw response
    result = client.get_accounts_id(id, params)
    parsed_result = result.get('data', '')
    readable_list = {'name': parsed_result['name'], 'ID': parsed_result['id'], 'link': parsed_result['recordLink'],
                     'PST Engineer': parsed_result['tech_BD_Assigned_for_XSOAR__cf']}
    readable_output = tableToMarkdown('Account Details', readable_list,
                                      ['name', 'ID', 'link', 'PST Engineer'],
                                      headerTransform=pascalToSpace, removeNull=False)

    return CommandResults(
        outputs_prefix='Impartner.Account',
        readable_output=readable_output,
        outputs_key_field='Impartner.Account.id',
        outputs=parsed_result,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/objects/v1/')
    verify_certificate = not demisto.params().get('insecure', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'impartner-get-account-list':
            return_results(impartner_get_account_list_command(client, demisto.args()))
        elif demisto.command() == 'impartner-get-account-id':
            return_results(impartner_get_account_id_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
