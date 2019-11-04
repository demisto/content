import demistomock as demisto


def test_main(mocker):
    from SecondsToString import main

    mocker.patch.object(demisto, 'args', return_value={
        'value': '90122'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == '1d 1h 2m 2s'

    mocker.patch.object(demisto, 'args', return_value={
        'value': 90122
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == '1d 1h 2m 2s'

    mocker.patch.object(demisto, 'args', return_value={
        'value': '86401'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == '1d 1s'

    mocker.patch.object(demisto, 'args', return_value={
        'value': 14401
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == '4h 1s'
