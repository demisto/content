
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any


def hint(args: Dict[str, Any]) -> CommandResults:
    text = args.get('text', '')

    result = {
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


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            return_results('ok')

        elif demisto.command() == 'hint':
            return_results(hint(demisto.args()))

    # Log exceptions and return errors
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(exc)}', error=exc)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
