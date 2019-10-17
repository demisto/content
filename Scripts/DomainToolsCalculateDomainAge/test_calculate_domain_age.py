from DomainToolsCalculateDomainAge.calculate_domain_age import main, find_age
from CommonServerPython import *


def test_find_age():
    create_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    result = find_age(create_date)
    assert result == 1


def test_calculate_age(mocker):
    create_date = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
    mocker.patch.object(demisto, 'args', return_value={'create_date': create_date})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['create_date'] == create_date

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['ContentsFormat'] == formats['json']
    assert results[0]['Contents'] == {'age': 2}
    assert results[0]['HumanReadable'] == '2 days old'
    assert results[0]['EntryContext'] == {}
