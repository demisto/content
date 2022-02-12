import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the Postmark Spamcheck API
    """
    def __init__(self, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def spamcheck(self, email: str, options: str) -> dict:
        """Get spam score of EML file
        Returns the spam score result returned by the Postmark Spamcheck API as a dictionary.

        :type email: ``str``
        :param email: EML file to be sent to the Postmark Spamcheck API
        :type options: ``str``
        :param options: Must either be "long" for a full report of processing rules, or "short" for a score request.

        :return: Spam score result returned by the Postmark Spamcheck API as dict
        :rtype: ``dict``
        """
        return self._http_request(method='POST', url_suffix='filter', data={'email': email, 'options': options},
                                  resp_type='json', ok_codes=(200,))


''' COMMAND FUNCTIONS '''


def test_module_command(client):
    """
    Tests Postmark Spamcheck API connectivity
    """
    result = client.spamcheck(email='', options='short')
    if result:
        return 'ok'


def spamcheck_command(client: Client, file_path: str, args: dict) -> dict:
    """Returns the spam score result returned by the Postmark Spamcheck API as a dictionary.

    :type client: ``Client``
    :param client: Instance of Client class to interact with the Postmark Spamcheck API
    :type file_path: ``str``
    :param file_path: File path to EML file in XSOAR
    :type args: ``dict``
    :param args: Command arguments

    :return: Spam score result returned by the Postmark Spamcheck API as dict
    :rtype: ``dict``
    """
    if not file_path:
        raise ValueError('entry file path not found')

    email = open(file_path, "rb").read()
    short = args.get('short', False)

    if short:
        options = 'short'
    else:
        options = 'long'

    response = client.spamcheck(email=email, options=options)

    if not response and not response.get('success'):
        raise Exception('Failed submitting mail to Postmark Spamcheck API: %s\n' % file_path)
    else:
        return response


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('base_url')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = Client(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module_command(client))
        elif command == 'postmark-spamcheck':
            entry_id = args.get('entryid')
            file_path = demisto.getFilePath(entry_id).get('path')
            result = spamcheck_command(client=client, file_path=file_path, args=args)
            result['entryid'] = entry_id
            command_results = CommandResults(
                readable_output=tableToMarkdown('Postmark - Spamcheck', result, metadata='Spamcheck completed'
                                                , removeNull=True),
                outputs_prefix='Postmark.Spamcheck',
                outputs_key_field='entryid',
                outputs=result
            )
            return_results(command_results)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
