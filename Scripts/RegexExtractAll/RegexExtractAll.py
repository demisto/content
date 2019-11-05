import demistomock as demisto
from CommonServerPython import *
import regex as re


def main():
    match_target = demisto.args()['value']

    re_flags = re.V1
    error_if_no_match = False

    try:

        if demisto.args()['multi_line'].lower() == 'true':
            re_flags |= re.MULTILINE

        if demisto.args()['ignore_case'].lower() == 'true':
            re_flags |= re.IGNORECASE

        if demisto.args()['period_matches_newline'].lower() == 'true':
            re_flags |= re.DOTALL

        if demisto.args()['error_if_no_match'].lower() == 'true':
            error_if_no_match = True

    except KeyError:
        pass

    regex_pattern = re.compile(r'{}'.format(demisto.args()['regex']), flags=re_flags)

    try:
        matches = re.findall(regex_pattern, match_target)

        if error_if_no_match is False or len(matches) != 0:
            demisto.results(matches)
        else:
            return_error('No results found')

    except Exception:
        raise


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
