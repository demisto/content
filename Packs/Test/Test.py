"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
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

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
register_module_line('Drift', 'start', __line__())



''' CONSTANTS '''
API_ENDPOINT = 'https://driftapi.com'


class Client(BaseClient):

    def test(self):
        url_suffix = '/users/list'
        self._http_request('GET', url_suffix=url_suffix)

    def post_contact(self, email: dict = None):
        url_suffix = '/contacts'
        res = self._http_request('POST', url_suffix=url_suffix, json_data=email)
        return res

    def get_contact(self, contact_id: str = None, email: str = None):
        url_suffix = '/contacts'
        params = dict()
        if contact_id:
            url_suffix = f"{url_suffix}/{contact_id}"
        elif email:
            params['email'] = email
        res = self._http_request(
            'GET',
            url_suffix=url_suffix,
            params=params
        )
        return res.get('data', [])

    def patch_contact(self, contact_id: str = None, attributes: dict = None):
        url_suffix = f"/contacts/{contact_id}"
        res = self._http_request(
            'PATCH',
            url_suffix=url_suffix,
            json_data=attributes
        )
        return res

    def delete_contact(self, contact_id: str = None):
        url_suffix = f"/contacts/{contact_id}"
        res = self._http_request(
            'DELETE',
            url_suffix=url_suffix,
            resp_type='response',
            ok_codes=[200, 202])
        return res


def test_module(client: Client):
    client.test()
    return_results('ok')


def post_contact_command(client, args):
    email = {
        'attributes': {
            'email': args.get('email')
        }
    }
    res = client.post_contact(email=email)
    command_results = CommandResults(
        outputs_prefix='Drift.Contacts',
        outputs_key_field=['id'],
        outputs=res,
        readable_output=tableToMarkdown('Contact:', res)
    )
    return command_results


def get_contact_command(client, args):
    email = args.get('email')
    contact_id = args.get('id')
    if not email and not contact_id:
        return_error("Please provide one of the ID or Email")
    res = client.get_contact(email=email, contact_id=contact_id)
    command_results = CommandResults(
        outputs_prefix='Drift.Contacts',
        outputs_key_field=['id'],
        outputs=res,
        readable_output=tableToMarkdown('Contact:', res)
    )
    return_results(command_results)


def patch_contact_command(client, args):
    contact_id = args.get('id')
    attributes = {
        'attributes': args.get('attributes')
    }
    res = client.patch_contact(contact_id=contact_id, attributes=attributes)
    command_results = CommandResults(
        outputs_prefix='Drift.Contacts',
        outputs_key_field=['id'],
        outputs=res,
        readable_output=tableToMarkdown('Contact:', res)
    )
    return_results(command_results)


def delete_contact_command(client, args):
    contact_id = args.get('id')
    client.delete_contact(contact_id=contact_id)
    command_results = CommandResults(
        readable_output=f"Contact ID {contact_id} was deleted."
    )
    return_results(command_results)


def main():
    params = demisto.params()
    args = demisto.args()
    credentials = params.get('access_token')
    access_token = credentials.get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    commands = {
        'drift-post-contact': post_contact_command,
        'drift-get-contact': get_contact_command,
        'drift-update-contact': patch_contact_command,
        'drift-delete-contact': delete_contact_command
    }

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        client = Client(
            API_ENDPOINT,
            verify_certificate,
            proxy,
            headers=headers
        )

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            commands[command](client, args)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('Drift', 'end', __line__())
