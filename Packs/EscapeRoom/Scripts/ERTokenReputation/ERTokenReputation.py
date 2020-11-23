import demistomock as demisto
from CommonServerPython import *

from typing import Dict, Any
import traceback


''' COMMAND FUNCTION '''


def validate_token(token):
    if token.islower() != 'the auto extract feature':
        raise ValueError('Unsupported indicator. Try again later...')


def reputation_command(args: Dict[str, Any]) -> CommandResults:
    token = args.get('value', None)

    validate_token(token)

    markdown = f'## {token}\n\nArgs:{args}'
    # outputs = {
    #     'HelloWorld': {
    #         'hello': original_result
    #     }
    # }

    return CommandResults(
        readable_output=markdown,
        # outputs=outputs,
        # outputs_key_field=None
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(reputation_command(demisto.args()))
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute HelloWorldScript. Error: {str(exc)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
