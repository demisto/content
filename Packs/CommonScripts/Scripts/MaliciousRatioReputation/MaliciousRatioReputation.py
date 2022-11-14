import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_indicator_from_value(indicator_value):
    try:
        res = demisto.executeCommand("findIndicators", {'value': indicator_value})
        indicator = res[0]['Contents'][0]
        return indicator
    except Exception:
        pass


def get_indicator_result(indicator):
    res = demisto.executeCommand("maliciousRatio", {'value': indicator['value']})

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
        return entry


def main():
    indicator_value = demisto.args().get('input')
    indicator = get_indicator_from_value(indicator_value)
    if indicator:
        try:
            demisto.results(get_indicator_result(indicator))
        except Exception:
            pass


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
