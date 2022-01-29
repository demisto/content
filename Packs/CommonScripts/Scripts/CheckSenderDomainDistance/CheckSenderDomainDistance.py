import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def levenshtein(s1, s2):
    l1 = len(s1)
    l2 = len(s2)
    matrix = [range(l1 + 1)] * (l2 + 1)
    for zz in range(l2 + 1):
        matrix[zz] = range(zz, zz + l1 + 1)
    for zz in range(0, l2):
        for sz in range(0, l1):
            if s1[sz] == s2[zz]:
                matrix[zz + 1][sz + 1] = min(matrix[zz + 1][sz] + 1, matrix[zz][sz + 1] + 1, matrix[zz][sz])
            else:
                matrix[zz + 1][sz + 1] = min(matrix[zz + 1][sz] + 1, matrix[zz][sz + 1] + 1, matrix[zz][sz] + 1)
    return matrix[l2][l1]


res = []
found = False

domains = argToList(demisto.get(demisto.args(), 'domain'))
if not domains:
    res.append({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
               'Contents': 'Unable to extract domain from arguments'})
else:
    sender = demisto.get(demisto.args(), 'sender')
    if sender:
        parts = sender.split('@')
        if len(parts) == 2:
            if not parts[1] in domains:
                distances = []
                for domain in domains:
                    distance = levenshtein(domain, parts[1])
                    distances.append(distance)
                    closeDistance = demisto.get(demisto.args(), 'distance')
                    closeDistanceInt = int(closeDistance) if closeDistance else 3
                    if distance > 0 and distance < closeDistanceInt:
                        res.append({'Type': entryTypes['note'], 'ContentsFormat': formats['text'],
                                   'Contents': 'Domain ' + parts[1] + ' is suspiciously close to ' + domain})
                        found = True
                if len(distances) > 0:
                    # Override the context on each run
                    demisto.setContext('LevenshteinDistance', distances if len(distances) > 1 else distances[0])
        else:
            res.append({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                       'Contents': 'Unable to extract domain from sender - ' + sender})
    else:
        res.append({'Type': entryTypes['error'], 'ContentsFormat': formats['text'], 'Contents': 'Unable to find sender in email'})
if found:
    res.append('yes')
else:
    res.append('no')
demisto.results(res)
