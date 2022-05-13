import demistomock as demisto  # noqa: F401
import regex
from CommonServerPython import *  # noqa: F401


def main():
    match_target = demisto.args()['value']

    re_flags = regex.V1
    error_if_no_match = False
    unpack_matches = False

    try:

        if demisto.args()['multi_line'].lower() == 'true':
            re_flags |= regex.MULTILINE

        if demisto.args()['ignore_case'].lower() == 'true':
            re_flags |= regex.IGNORECASE

        if demisto.args()['period_matches_newline'].lower() == 'true':
            re_flags |= regex.DOTALL

        if demisto.args()['error_if_no_match'].lower() == 'true':
            error_if_no_match = True

        if demisto.args()['unpack_matches'].lower() == 'true':
            unpack_matches = True

    except KeyError:
        pass

    regex_pattern = regex.compile(r'{}'.format(demisto.args()['regex']), flags=re_flags)

    try:
        matches = regex.findall(regex_pattern, match_target)

        if error_if_no_match is False or len(matches) != 0:
            if unpack_matches and matches:
                results = []
                for m in matches:
                    results.extend([v for v in (m if isinstance(m, tuple) else [m]) if v])
            else:
                results = matches

            demisto.results(results)
        else:
            return_error('No results found')

    except Exception:
        raise


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
