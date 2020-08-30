import demistomock as demisto
from CommonServerPython import *


def main():
    args = demisto.args()
    value = args.get('value')
    context_entry = {}
    if value:
        human_readable = 'Key ' + args.get('key') + ' set'
        stringify = args.get('stringify') == 'true'
        if not stringify:
            try:
                context_entry = {args.get('key'): json.loads(value)}
            except json.decoder.JSONDecodeError:
                stringify = True
        if stringify:
            context_entry = {args.get('key'): value}
    else:
        human_readable = 'value is None'
    return_outputs(human_readable, context_entry)


if __name__ in ('__builtin__', 'builtins'):
    main()
