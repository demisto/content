from typing import Dict

from CommonServerPython import *


def check_key(field_value, regex=None):
    if regex:
        if re.search(regex, field_value):
            return True
    else:
        if field_value:
            return True
    return False


def poll_field(args: Dict[str, Any]) -> CommandResults:
    keys_list = args.get('key', '').split(".")
    regex = args.get('regex')
    ignore_case = argToBoolean(args.get('ignore_case', 'False'))

    regex_ignore_case_flag = re.IGNORECASE if ignore_case else 0
    regex = re.compile(regex, regex_ignore_case_flag) if regex else None

    context = dict_safe_get(demisto.context(), keys_list)

    data = {
        'key': '.'.join(keys_list),
        'exists': False
    }

    if context:
        data['exists'] = check_key(context, regex)

    command_results = CommandResults(
        outputs_key_field='key',
        outputs_prefix='CheckContextKey',
        outputs=data,
        readable_output='The key exists.' if data['exists'] else 'The key does not exist.',
        raw_response=data
    )
    return command_results


def main():
    try:
        return_results(poll_field(demisto.args()))
    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CheckFieldValue script. Error: {str(err)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
