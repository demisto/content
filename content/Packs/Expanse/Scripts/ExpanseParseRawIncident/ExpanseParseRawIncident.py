import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


import json


def parse_raw(raw_json):
    data = json.loads(raw_json)
    outputs = {
        'expanse_raw_json_event': data
    }
    readable_outputs = tableToMarkdown('Event Information', data)

    return (
        readable_outputs,
        outputs,
        raw_json
    )


def main():
    try:
        return_outputs(*parse_raw(demisto.args().get('expanse_raw_json_event', '')))
    except Exception as ex:
        return_error(f'Failed to execute ExpanseParseRawIncident. Error: {str(ex)}')


if __name__ in ('__builtin__', 'builtins'):
    main()
