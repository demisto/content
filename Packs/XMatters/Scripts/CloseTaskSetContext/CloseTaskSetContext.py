import demistomock as demisto
from CommonServerPython import *
from typing import Dict, Any
import traceback


''' COMMAND FUNCTION '''


def close_task_set_context(args: Dict[str, Any]) -> CommandResults:
    entry_id_or_tag = args.get('entry_id')
    context_key = args.get('context_key')
    comments = args.get('comments')
    demisto.executeCommand("taskComplete", {"id": entry_id_or_tag, "comments": comments})

    if not entry_id_or_tag:
        raise ValueError('entry_id not specified')
    if not context_key:
        raise ValueError('context_key not specified')

    result = {
        context_key: comments
    }

    return CommandResults(
        outputs_key_field=context_key,
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(close_task_set_context(demisto.args()))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute close_task_set_context. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
