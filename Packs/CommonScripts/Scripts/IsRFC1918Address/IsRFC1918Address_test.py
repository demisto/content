import demistomock as demisto


def test_main(mocker):
    from IsRFC1918Address import main

    mocker.patch.object(demisto, 'args', return_value={'value': '172.16.0.1'})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is True

    mocker.patch.object(demisto, 'args', return_value={'value': '8.8.8.8'})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is False

    mocker.patch.object(demisto, 'args', return_value={'value': None, 'left': '8.8.8.8'})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is False
