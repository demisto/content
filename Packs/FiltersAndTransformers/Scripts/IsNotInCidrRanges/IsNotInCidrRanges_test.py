import demistomock as demisto


def test_main(mocker):
    from IsNotInCidrRanges import main

    mocker.patch.object(demisto, 'args', return_value={
        'left': '172.16.0.1',
        'right': '10.0.0.0/8,192.168.0.0/16'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is True

    mocker.patch.object(demisto, 'args', return_value={
        'left': '10.5.5.5',
        'right': '10.0.0.0/8,192.168.0.0/16'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args
    assert results[0][0] is False
