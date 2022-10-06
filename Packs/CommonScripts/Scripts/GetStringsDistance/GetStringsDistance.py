import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def levenshtein(s1, s2):
    l1 = len(s1)
    l2 = len(s2)
    matrix = [list(range(l1 + 1))] * (l2 + 1)
    for zz in range(l2 + 1):
        matrix[zz] = list(range(zz, zz + l1 + 1))
    for zz in range(0, l2):
        for sz in range(0, l1):
            if s1[sz] == s2[zz]:
                matrix[zz + 1][sz + 1] = min(matrix[zz + 1][sz] + 1, matrix[zz][sz + 1] + 1, matrix[zz][sz])
            else:
                matrix[zz + 1][sz + 1] = min(matrix[zz + 1][sz] + 1, matrix[zz][sz + 1] + 1, matrix[zz][sz] + 1)
    return matrix[l2][l1]


found = False


def main():
    res = []

    close_distance = demisto.get(demisto.args(), 'distance')
    close_distance_int = int(close_distance) if close_distance else 3

    compare_string = argToList(demisto.get(demisto.args(), 'compareString'))
    if not compare_string:
        res.append({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                    'Contents': 'Unable to extract compareString from arguments'})
    else:
        input_string = demisto.get(demisto.args(), 'inputString')
        if input_string:
            distances = []
            for cur_string in compare_string:
                levenshtein_distance = levenshtein(cur_string, input_string)
                distances.append(
                    {
                        'StringA': input_string,
                        'StringB': cur_string,
                        'LevenshteinDistance': levenshtein_distance,
                        'TooClose': 0 < levenshtein_distance < close_distance_int
                    })
            res.append(
                {
                    'Type': entryTypes['note'],
                    'Contents': {'Distances': distances},
                    'ContentsFormat': formats['json'],
                    'HumanReadable': tblToMd('Distances', distances, ['StringA', 'StringB', 'LevenshteinDistance', 'TooClose']),
                    'ReadableContentsFormat': formats['markdown']
                })

        else:
            res.append(
                {
                    'Type': entryTypes['error'],
                    'ContentsFormat': formats['text'],
                    'Contents': 'Unable to extract inputString - ' + input_string
                })

        demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
