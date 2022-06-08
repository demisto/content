import traceback
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def add_journal_entry(args):

    demisto.debug(f'Args - {args}')

    incident_id = args.get('incident_id')
    details = args.get('details')
    private_details = args.get('private_details')

    json_args = {
        "Details": details
    }

    if private_details:
        json_arg['PrivateNoteDetails'] = private_details

    command_args = {
        "type": "incident",
        "public_id": incident_id,
        "related_type": "JournalNote",
        "json": json_args
    }

    demisto.debug(f'Command args - {command_args}')
    return execute_command("cherwell-create-related-business-object", command_args)


''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def add_journal_entry_command(args: Dict[str, Any]) -> CommandResults:

    # Call the standalone function and get the raw response
    result = add_journal_entry(args)

    return CommandResults(
        outputs_prefix='Cherwell.Journal',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(add_journal_entry_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute add_journal_entry_command. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
