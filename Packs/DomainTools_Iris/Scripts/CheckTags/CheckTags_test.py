from CommonServerPython import *
from CheckTags import main


def test_check_tags_tags_match(mocker):
    domain_tags = [{'label': 'mal1'}, {'label': 'cool1'}]
    malicious_tags = '["mal1", "cool2"]'
    mocker.patch.object(demisto, 'args', return_value={'incident_id': 1,
                                                       'domain_tags': domain_tags,
                                                       'malicious_tags': malicious_tags})
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['ContentsFormat'] == formats['json']
    assert results[0]['Contents'] is None
    assert results[0]['HumanReadable'] == 'No matching tags found.'
    assert results[0]['EntryContext'] == {}


def test_check_tags_tags_dont_match(mocker):
    domain_tags = [{'label': 'mal1'}, {'label': 'cool1'}]
    malicious_tags = '["mal2", "cool2"]'
    mocker.patch.object(demisto, 'args', return_value={'incident_id': 1,
                                                       'domain_tags': domain_tags,
                                                       'malicious_tags': malicious_tags})
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['ContentsFormat'] == formats['json']
    assert results[0]['Contents'] is None
    assert results[0]['HumanReadable'] == 'No matching tags found.'
    assert results[0]['EntryContext'] == {}
