import demistomock as demisto
from CommonServerPython import *


def main():
    args = demisto.args()
    value = args.get('value')
    key = args.get('key')
    context_entry = {}
    if value:
        human_readable = f'Key {key} set'
        stringify = args.get('stringify') == 'true'
        if not stringify:
            try:
                context_entry = {key: json.loads(value)}
            except json.decoder.JSONDecodeError:
                stringify = True
        if stringify:
            context_entry = {key: value}
    else:
        human_readable = 'value is None'
    if args.get('append') == 'false' and context_entry:
        demisto.executeCommand('DeleteContext', {'key': key})

    return_outputs(human_readable, context_entry)


if __name__ in ('__builtin__', 'builtins'):
    main()
