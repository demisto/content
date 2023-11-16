import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_regex_matches(args):
    match_target = args['value']
    capture_groups = args.get('groups')
    dict_keys = args.get('keys')
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
    regex_pattern = re.compile(r'{}'.format(args['regex']), regex_flags)
    if capture_groups:
        capture_groups = capture_groups.split(',')
        # Validating groups input to be integers
        if not all(x.isdigit() for x in capture_groups):
            raise ValueError('Error: groups must be integers')

    if dict_keys:
        dict_keys = dict_keys.split(',')

    pattern_match = re.search(regex_pattern, match_target)
    matches = []
    if pattern_match:
        for i in pattern_match.groups():
            matches.append(i)

    if capture_groups:
        for j in capture_groups:
            if len(matches) - 1 < int(j):
                raise ValueError('Error: Regex group (' + j + ') out of range')
        matches = [matches[int(x)] for x in capture_groups]

    if dict_keys:
        if len(dict_keys) != len(matches):
            raise ValueError('Error: Number of keys does not match number of items')
        else:
            dict_matches = dict(zip(dict_keys, matches))
            return dict_matches
    return matches


def main():
    matches: str | list = []
    args = demisto.args()
    try:
        matches = get_regex_matches(args)
    except Exception as e:
        demisto.error(f'Error in RegexGroups script: {str(e)}')
    finally:
        # empty list is not supported
        if not matches:
            matches = ''
        return_results(matches)


if __name__ in ('__builtin__', 'builtins'):
    main()
