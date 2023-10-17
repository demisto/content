import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any
import traceback
import random

''' COMMAND FUNCTION '''


def shuffle_list_command(args: Dict[str, Any]) -> CommandResults:

    l = argToList(args.get('list', []))
    n = arg_to_number(args.get("elements_to_return", 3))
    o = args.get("output_path", "ShuffledList")

    shuffled = random.sample(l, n)

    markdown = tableToMarkdown(
        f"Shuffled List",
        shuffled,
        removeNull=True,
        headers=["Value"]
    )

    return CommandResults(
        outputs_prefix=o,
        outputs=shuffled,
        readable_output=markdown
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(shuffle_list_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
