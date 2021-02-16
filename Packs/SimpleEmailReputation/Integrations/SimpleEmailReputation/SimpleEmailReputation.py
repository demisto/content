import traceback
from typing import Any, Dict, List

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get_email_reputation(self, email: str) -> Dict[str, Any]:
        """Gets the email reputation using the API endpoint

        :type email: ``str``
        :param email: email address to get the reputation for

        :return: dict containing the email reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/' + email,
        )


''' COMMAND FUNCTIONS '''


def email_reputation_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """email command: Returns email reputation for a list of emails

    :type client: ``Client``
    :param Client: client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['email']`` is a list of emails or a single email

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains emails

    :rtype: ``CommandResults``
    """

    emails = argToList(args.get('email'))
    if len(emails) == 0:
        raise ValueError('Email(s) not specified')

    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for email
    command_results: List[CommandResults] = []

    for email in emails:
        em_data = client.get_email_reputation(email)
        em_data['email'] = email

        readable_output = tableToMarkdown('Simple Email Reputation', em_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='Emailrep.email',
            outputs_key_field=em_data['email'],
            outputs=em_data
        ))
    return command_results


def test_module(client: Client):
    client.get_email_reputation('test@test.com')
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'])

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Key': f'{api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            res = test_module(client)
            return_results(res)

        elif demisto.command() == 'emailrep-get-reputation':
            return_results(email_reputation_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
