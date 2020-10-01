import re

import demistomock as demisto
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, Tuple


def check_field(field_value, regex=None):
    if regex:
        if re.match(regex, field_value):
            return True
    else:
        if field_value:
            return True
    return False


def poll_field(args: Dict[str, Any]) -> Tuple[str, dict, dict]:

    field = args.get('field')
    regex = args.get('regex')
    ignore_case = argToBoolean(args.get('ignore_case', 'False'))
    regex_ignore_case_flag = re.IGNORECASE if ignore_case else 0
    regex = re.compile(regex, regex_ignore_case_flag) if regex else None

    incident = demisto.incidents()[0]

    data = {
        'field': field,
        'exists': False
    }

    if field in incident:
        data['exists'] = check_field(incident.get(field), regex)

    else:
        custom_fields = incident.get('CustomFields', {})
        if field in custom_fields:
            data['exists'] = check_field(custom_fields.get(field), regex)

    context = {
        'CheckFieldValue(val.field == obj.field)': data
    }

    human_readable = 'The field exists.' if data['exists'] else 'The field does not exist.'
    return human_readable, context, data


def main():
    try:
        return_outputs(*poll_field(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CheckFieldValue script. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
