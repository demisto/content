import demistomock as demisto
from CommonServerPython import *

from typing import Dict, Any
import traceback


HINT = '''
Demisto has 7 letters
XSOAR has 5 letters
What is the password
'''

''' COMMAND FUNCTION '''

def set_indicator_hint(indicator_id):
    demisto.execute


def hint_command(args: Dict[str, Any]) -> CommandResults:
    demisto.info(f'''
\n\n
args:
{args}

demisto class:
{dir(demisto)}

Calling context:
{demisto.callingContext}
\n\n
    ''')

    markdown = ''

    return CommandResults(
        readable_output=markdown,
        # outputs=outputs,
        # outputs_key_field=None
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(hint_command(demisto.args()))
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenLayoutButtonPasswordHint. Error: {str(exc)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
