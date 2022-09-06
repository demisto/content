import demistomock as demisto
from CommonServerPython import * # noqa: F401


def test_main(mocker):
    from PrintErrorEntry import main

    # test custom fields with short names
    mocker.patch.object(demisto, 'args', return_value={
        'message': 'this is error'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results['Contents'] == 'this is error'
    assert results['Type'] == EntryType.ERROR
