import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

REPUTATIONS = {
    0: 'None',
    1: 'Good',
    2: 'Suspicious',
    3: 'Bad'
}


def get_indicator_from_value(indicator_value):
    try:
        if not indicator_value:
            return None
        res = demisto.executeCommand("findIndicators", {'value': indicator_value})
        indicator = res[0]['Contents'][0]
        return indicator
    except Exception:
        pass


def get_ssdeep_related_indicators(ssdeep_indicator):
    related_indicators = [ssdeep_indicator]
    for inv_id in ssdeep_indicator['investigationIDs']:
        try:
            res = demisto.executeCommand("getContext", {"id": inv_id})
            context = res[0]['Contents']['context']
            file_obj = demisto.dt(context, "File(val.SSDeep == '%s')" % ssdeep_indicator['value'])
            if file_obj is None:
                file_obj = {}
            elif type(file_obj) is list:
                file_obj = file_obj[0]
            related_indicators.append(get_indicator_from_value(file_obj.get('MD5')))
            related_indicators.append(get_indicator_from_value(file_obj.get('SHA1')))
            related_indicators.append(get_indicator_from_value(file_obj.get('SHA256')))
        except Exception:
            continue
    related_indicators = [x for x in related_indicators if x is not None]
    return related_indicators


def main():
    ssdeep_value = demisto.args().get('input')
    current_incident_id = demisto.investigation().get('id')
    res = demisto.executeCommand('similarSsdeep', {
        'value': ssdeep_value,
        'daysTimeFrame': int(demisto.args().get('timeFrameDays', '1')),
        'threshold': int(demisto.args().get('threshold', '50'))
    })
    ssdeep_indicators = [x['indicator'] for x in res[0]['Contents']]
    ssdeep_indicator = get_indicator_from_value(ssdeep_value)
    if not ssdeep_indicator:
        # make the current ssdeep part of the current invastigation
        ssdeep_indicator = {
            'investigationIDs': [current_incident_id],
            'score': 0
        }
    else:
        # make sure the current ssdeep part of the current invastigation
        if ssdeep_indicator.get('investigationIDs') is None:
            ssdeep_indicator['investigationIDs'] = [current_incident_id]
        elif current_incident_id not in ssdeep_indicator['investigationIDs']:
            ssdeep_indicator['investigationIDs'].append(current_incident_id)

    ssdeep_indicators.append(ssdeep_indicator)
    related_indicators = []
    for i in ssdeep_indicators:
        related_indicators += get_ssdeep_related_indicators(i)

    max_score = max([x.get('score') for x in related_indicators])
    max_score_indicator = next(x for x in related_indicators if x.get('score', 0) == max_score)
    if max_score > ssdeep_indicator.get('score', 0) and max_score > 1:
        entry = {
            'Type': entryTypes['note'],
            'HumanReadable': 'Similarity to %s %s:%s' % (
                REPUTATIONS[max_score_indicator['score']], max_score_indicator['indicator_type'], max_score_indicator['value']),
            'ReadableContentsFormat': formats['markdown'],
            'Contents': max_score,
            'ContentsFormat': formats['text']
        }
        ec = {'DBotScore': {
            'Indicator': ssdeep_value,
            'Type': 'ssdeep',
            'Vendor': 'DBot',
            'Score': max_score
        }}
        entry['EntryContext'] = ec
        demisto.results(entry)
    else:
        demisto.results(ssdeep_indicator.get('score', 0))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
