from DomainToolsCalculateIndicatorReputation.calculate_indicator_reputation import main, find_indicator_reputation
from CommonServerPython import *


def test_find_indicator_reputation_bad(mocker):
    def execute_command(name, args=None):
        return [
            {
                'Contents': {'age': 2}
            }
        ]

    mocker.patch.object(demisto, 'args', return_value={'proximity_score': 69,
                                                       'threat_profile_score': 71,
                                                       'create_date': '2019-09-09'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    result = find_indicator_reputation()
    assert result == 'Bad'


def test_find_indicator_reputation_suspicious(mocker):
    def execute_command(name, args=None):
        return [
            {
                'Contents': {'age': 2}
            }
        ]

    mocker.patch.object(demisto, 'args', return_value={'proximity_score': 69,
                                                       'threat_profile_score': 68,
                                                       'create_date': '2019-09-09'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    result = find_indicator_reputation()
    assert result == 'Suspicious'


def test_find_indicator_reputation_good(mocker):
    def execute_command(name, args=None):
        return [
            {
                'Contents': {'age': 8}
            }
        ]

    mocker.patch.object(demisto, 'args', return_value={'proximity_score': 69,
                                                       'threat_profile_score': 68,
                                                       'create_date': '2019-09-09'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    result = find_indicator_reputation()
    assert result == 'Good'


def test_calculate_indicator_reputation(mocker):
    def execute_command(name, args=None):
        return [
            {
                'Contents': {'age': 8}
            }
        ]

    mocker.patch.object(demisto, 'args', return_value={'proximity_score': 69,
                                                       'threat_profile_score': 68,
                                                       'create_date': '2019-09-09',
                                                       'domain_name': 'demisto.com'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    mocker.patch
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['ContentsFormat'] == formats['json']
    assert results[0]['Contents'] == {'reputation': 'Good'}
    assert results[0]['HumanReadable'] == 'demisto.com has a Good Risk Reputation'
    assert results[0]['EntryContext'] == {}
