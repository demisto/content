import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import

import uuid


''' STANDALONE FUNCTION '''


def generate_random_uuid() -> str:
    return str(uuid.uuid4())


''' COMMAND FUNCTION '''


def generate_random_uuid_command() -> CommandResults:
    outputs = {
        'GeneratedUUID': generate_random_uuid()
    }

    return CommandResults(
        readable_output=f'## Random UUID Generated: {outputs["GeneratedUUID"]}',
        outputs=outputs,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(generate_random_uuid_command())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GenerateRandomUUID. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
