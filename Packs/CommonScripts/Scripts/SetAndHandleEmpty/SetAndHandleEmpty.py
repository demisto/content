import demistomock as demisto
from CommonServerPython import *
from typing import Text


def get_value(value, stringify=False):
    if stringify:
        return str(value)
    elif not value or not isinstance(value, (Text, bytes, bytearray)):
        return value
    else:
        try:
            return json.loads(value)
        except (json.decoder.JSONDecodeError, TypeError):
            return value


def main():
    args = demisto.args()
    value = args.get('value')
    key = args.get('key')
    force = args.get('force') == 'true'
    value = get_value(value, args.get('stringify') == 'true')
    if value or force:
        human_readable = f'Key {key} set'
        context_entry = {key: value}
    else:
        human_readable = 'value is None'
        context_entry = {}

    if args.get('append') == 'false' and context_entry:
        demisto.executeCommand('DeleteContext', {'key': key})

    return_results(CommandResults(
        readable_output=human_readable,
        outputs=context_entry,
    ))


if __name__ in ('__builtin__', 'builtins'):
    main()
