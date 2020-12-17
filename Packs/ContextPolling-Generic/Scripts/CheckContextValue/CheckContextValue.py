import re
from typing import Any, Dict, Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def check_key(field_value, regex=None):
    if regex:
        if re.match(regex, field_value):
            return True
    else:
        if field_value:
            return True
    return False


def poll_field(args: Dict[str, Any]) -> Tuple[str, dict, dict]:

    key = args.get('key').split(".")
    regex = args.get('regex')
    ignore_case = argToBoolean(args.get('ignore_case', 'False'))
    regex_ignore_case_flag = re.IGNORECASE if ignore_case else 0
    regex = re.compile(regex, regex_ignore_case_flag) if regex else None

    context = demisto.context()
    for k in key:
        try:
            context = context.get(k, {})
        except Exception:
            context = None
            break

    data = {
        'key': '.'.join(key),
        'exists': False
    }

    if context:
        data['exists'] = check_key(context, regex)

    context_value = {
        'CheckContextKey(val.key == obj.key)': data
    }

    human_readable = 'The key exists.' if data['exists'] else 'The key does not exist.'
    return human_readable, context_value, data


def main():
    try:
        return_outputs(*poll_field(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CheckFieldValue script. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
