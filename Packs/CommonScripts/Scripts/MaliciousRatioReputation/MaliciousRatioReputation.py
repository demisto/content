import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_indicator_from_value(indicator_value):
    try:
        res = demisto.executeCommand("findIndicators", {'value': indicator_value})
        indicator = res[0]['Contents'][0]
        return indicator
    except:
        pass


indicator_value = demisto.args()['input']
indicator = get_indicator_from_value(indicator_value)
if indicator:
    res = demisto.executeCommand("maliciousRatio", {'value': indicator['value']})
    try:
        mr_score = res[0]['Contents'][0]['maliciousRatio']
        if mr_score > float(demisto.args()['threshold']):
            ec = {}
            ec['DBotScore'] = {
                'Type': indicator['indicator_type'].lower(),
                'Score': 2,  # suspicious
                'Vendor': 'DBot-MaliciousRatio',
                'Indicator': indicator['value']
            }
            entry = {
                'Type': entryTypes['note'],
                'EntryContext': ec,
                'Contents': ec['DBotScore']['Score'],
                'ContentsFormat': formats['text'],
                'HumanReadable': 'Malicious ratio for %s is %.2f' % (indicator['value'], mr_score),
                'ReadableContentsFormat': formats['markdown']
            }
            demisto.results(entry)
    except:
        pass
