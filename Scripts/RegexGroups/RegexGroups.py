import demistomock as demisto
from CommonServerPython import *
match_target = demisto.args()['value']
regex_pattern = re.compile(r'{}'.format(demisto.args()['regex']))
capture_groups = demisto.args().get('groups')
dict_keys = demisto.args().get('keys')

if capture_groups:
    capture_groups = capture_groups.split(',')
    # Validating groups input to be integers
    if not all(x.isdigit() for x in capture_groups):
        raise ValueError('Error: groups must be integers')

if dict_keys:
    dict_keys = dict_keys.split(',')
try:
    pattern_match = re.search(regex_pattern, match_target)
    matches = []
    if pattern_match:
        for i in pattern_match.groups():
            matches.append(i)

    if capture_groups:
        matches = [matches[int(x)] for x in capture_groups]

    if dict_keys:
        if len(dict_keys) != len(matches):
            raise ValueError('Error: Number of keys does not match number of items')
        else:
            matches = dict(zip(dict_keys, matches))

    demisto.results(matches)

except Exception:
    raise
