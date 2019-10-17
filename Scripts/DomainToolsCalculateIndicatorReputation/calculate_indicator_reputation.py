from CommonServerPython import *


def find_indicator_reputation():
    create_date = demisto.args().get('create_date', None)
    response = demisto.executeCommand('CalculateAge', {'create_date': create_date})
    domain_age = response[0]['Contents'].get('age')
    proximity_score = int(demisto.args().get('proximity_score', 0))
    threat_profile_score = int(demisto.args().get('threat_profile_score', 0))
    proximity_score_threshold = int(demisto.args().get('proximity_score_threshold', 70))
    age_threshold = int(demisto.args().get('age_threshold', 7))
    threat_profile_score_threshold = int(demisto.args().get('threat_profile_score_threshold', 70))

    if proximity_score > proximity_score_threshold or threat_profile_score > threat_profile_score_threshold:
        return 'Bad'
    elif domain_age < age_threshold and (
            proximity_score < proximity_score_threshold or threat_profile_score < threat_profile_score_threshold):
        return 'Suspicious'
    else:
        return 'Good'


def main():
    domain_name = demisto.args().get('domain_name', None)
    reputation = find_indicator_reputation()
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {'reputation': reputation},
        'HumanReadable': '{} has a {} Risk Reputation'.format(domain_name, reputation),
        'EntryContext': {}
    })


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
