import traceback
from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *

# update the hint field with the following value:
# ╔═══════════════════════════════════════╗
# ║                                       ║
# ║    ╔═════════════════════════════╗    ║
# ║    ║ ╔═════════════════════════╗ ║    ║
# ║    ║ ║  Demisto has 7 letters  ║ ║    ║
# ║    ║ ║  XSOAR has 5 letters    ║ ║    ║
# ║    ║ ║  What is the password   ║ ║    ║
# ║    ║ ╚═════════════════════════╝ ║    ║
# ║    ╚═════════════════════════════╝    ║
# ║                                       ║
# ╚═══════════════════════════════════════╝


# COMMAND FUNCTION #


def set_indicator_hint(indicator_id):
    res = demisto.executeCommand('setIndicator', {
        'id': indicator_id,
        'customFields': {
            'userpswdhint': '![](https://user-images.githubusercontent.com/30797606/'
                            '100021906-ee631480-2dea-11eb-8c47-bb3691053435.png)',
        },
    })

    if is_error(res):
        demisto.error(f'oylo!\n{res}\n\n')


def hint_command(args: Dict[str, Any]) -> CommandResults:
    indicator_id = dict_safe_get(args, ['indicator', 'id'])
    set_indicator_hint(indicator_id)

    # return blank string to avoid additional text in the execute notification.
    return CommandResults(readable_output=' ')


# MAIN FUNCTION #


def main():
    try:
        return_results(hint_command(demisto.args()))
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenLayoutButtonPasswordHint. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
