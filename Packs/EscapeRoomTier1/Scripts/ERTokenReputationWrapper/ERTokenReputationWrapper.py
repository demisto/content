import traceback
from typing import Any, Dict

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

# COMMAND FUNCTION #


def validate_password(password):
    if password != 'What':
        raise ValueError('Invalid password')


def run_reputation_script(args: Dict[str, Any]) -> CommandResults:
    password = args.get('password')
    validate_password(password)
    args.update({
        'execution-password': password,
        'token': dict_safe_get(args, ['indicator', 'value']),
        'indicator_id': dict_safe_get(args, ['indicator', 'id']),
    })
    demisto.info(f'\n\n{args}\n\n')
    return demisto.executeCommand('ERTokenReputation', args)


# MAIN FUNCTION #


def main():
    try:
        return_results(run_reputation_script(demisto.args()))
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenReputationWrapper. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
