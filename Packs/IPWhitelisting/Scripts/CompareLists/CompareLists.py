import demistomock as demisto
from CommonServerPython import *

def main():
    left = argToList(demisto.args().get('left'))
    right = argToList(demisto.args().get('right'))

    out = {
        'ListCompare':
            {
                'LeftOnly': [x for x in left if x not in right],
                'RightOnly': [x for x in right if x not in left],
                'Both': [x for x in left if x in right]
            }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': json.dumps(out),
        'HumanReadable': 'Set comparisons in Context.',
        'EntryContext': out
    })
    
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()