import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def basescript_dummy(dummy: str) -> Dict[str, str]:
    """Returns a simple python dict with the information provided
    in the input (dummy).
    :type dummy: ``str``
    :param dummy: string to add in the dummy dict that is returned
    :return: dict as {"dummy": dummy}
    :rtype: ``str``
    """

    return {"dummy": dummy}


''' COMMAND FUNCTION '''


def basescript_dummy_command(args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', 'example dummy')

    if not dummy:
        raise ValueError('dummy not specified')

    result = basescript_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseScript',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(basescript_dummy_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
