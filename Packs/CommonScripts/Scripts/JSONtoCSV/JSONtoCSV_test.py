from CommonServerPython import *


def test_main(mocker):
    from JSONtoCSV import main

    mocker.patch.object(demisto, 'args', return_value={
        'entryid': 'something@something'
    })
    mocker.patch.object(demisto, 'executeCommand', return_value=[
        {"Contents": [
            {"Test": "value"},
            {"Test": "value2"}
        ]}
    ])
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args
    assert results[0][0] == 'Test\r\nvalue\r\nvalue2'
