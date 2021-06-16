import traceback
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def get_entry_details(entry_id: str) -> Dict[str, str]:

    entry_id_details = demisto.executeCommand("getEntries", {})

    username = entry_id_details[len(entry_id_details) - 2]['Metadata']['user']

    user_email = demisto.executeCommand("getUserByUsername", {"username": username})

    return {'email': user_email[0]['Contents']['email']}


''' COMMAND FUNCTION '''


def get_entry_details_command(args: Dict[str, Any]) -> CommandResults:

    entry_id = args.get('entryid')

    result = get_entry_details(entry_id)

    return CommandResults(
        outputs_prefix='entryid',
        outputs_key_field='email',
        outputs=result
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_entry_details_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
