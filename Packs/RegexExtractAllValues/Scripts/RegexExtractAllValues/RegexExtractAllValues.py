import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()

    results = []
    value = args.get('value')
    if value:
        regex_flags = 0
        for flag in argToList(args.get('flags', '')):
            if flag in ('dotall', 's'):
                regex_flags |= re.DOTALL
            elif flag in ('multiline', 'm'):
                regex_flags |= re.MULTILINE
            elif flag in ('ignorecase', 'i'):
                regex_flags |= re.IGNORECASE
            elif flag in ('unicode', 'u'):
                regex_flags |= re.UNICODE
            else:
                raise ValueError(f'Unknown flag: {flag}')

        pattern = re.compile(r'{}'.format(args['regex']), flags=regex_flags)
        matches = re.findall(pattern, value)
        if matches:
            for m in matches:
                results.extend([v for v in (m if isinstance(m, tuple) else [m])])

    demisto.results(results)


if __name__ in ('__builtin__', 'builtins'):
    main()
