import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import demistomock as demisto
from CommonServerPython import *
from typing import Any


def shuffle_list(args: dict[str, Any]) -> CommandResults:
    input_list = args.get("input_list", [])

    if not isinstance(input_list, list):
        return_error("The input provided is not a list")

    try:
        shuffled_list = input_list[:]
        import random
        random.shuffle(shuffle_list)

        return CommandResults(
            outputs_prefix='ShuffledList',
            outputs=shuffled_list
        )

    except Exception as e:
        return_error(f"Error shuffling list {input_list}: {str(e)}")


def main():
    try:
        return_results(shuffle_list(demisto.args()))
    except Exception as e:
        return_error(f"Error shuffling list: {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
