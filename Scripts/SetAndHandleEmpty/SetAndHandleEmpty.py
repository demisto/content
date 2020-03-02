import demistomock as demisto
from CommonServerPython import *


def main():
    args = demisto.args()
    value = args.get('value')
    if value:
        human_readable = 'Key ' + args.get('key') + ' set'
        context_entry = {args.get('key'): value}
    else:
        context_entry = {}
        human_readable = 'value is None'
    return_outputs(human_readable, context_entry)


if __name__ in ('__builtin__', 'builtins'):
    main()
