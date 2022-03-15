import shlex
import subprocess
import traceback
from typing import Dict, Any

import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


LOGIN_VICTORY_MESSAGE = '''# Congratulations
![](https://raw.githubusercontent.com/demisto/content/EscapeRoomMaterials/Packs/EscapeRoomTier2/images/access_MrBurns.gif')
Oh, password policy. It's one of these annoying buzzwords. We prefer to call it an unrequested security surplus.

You freed my Smithers from the cold chains of the password policy prison.
I shall grant you a present, check the context.

And now Smithers, Release the hounds!
'''


def get_server_url():
    args = shlex.split('ip route show')
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, _ = p.communicate()

    match = re.match('default via (.*) dev', stdout.decode('utf-8'))
    if not match:
        raise ValueError('could not find server URL')

    demisto_urls = demisto.demistoUrls()
    if 'acc_Tier2' in demisto_urls['server']:
        return f'https://{match.group(1)}/acc_Tier2'

    return f'https://{match.group(1)}'



def hint(args: Dict[str, Any]) -> CommandResults:
    text = args.get('text', '')

    result: Dict[str, Union[int, str]] = {
        'ID': 1,
    }
    if text and text.istitle():
        result['Clue'] = 'next step is already set in the proper page.'
        result['Filter'] = 'is:python -is:integration tags:XSOAR'

    else:
        result['Clue'] = "next step is... oh wait! you don't deserve a hint, your input was wrong"

    return CommandResults(
        outputs_prefix=f'Hints.{text}',
        outputs_key_field='',
        outputs=result,
    )


def check_login(args):
    _ = args
    server = get_server_url()
    user_name = 'smithers'
    password = '1234'

    try:
        client = demisto_client.configure(base_url=server, username=user_name,
                                          password=password, verify_ssl=False)
        client.generic_request(path='/health', method='GET')

        return CommandResults(readable_output=LOGIN_VICTORY_MESSAGE, outputs={'MrBurns.Present': 'hello'})
    except ApiException as exc:  # pylint: disable=W0703
        return_error(exc.body)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    command = demisto.command()
    commands = {
        'hint': hint,
        'check-login': check_login,
    }

    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            return_results('ok')

        elif command in commands:
            return_results(commands[command](demisto.args()))

    # Log exceptions and return errors
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}', error=exc)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
