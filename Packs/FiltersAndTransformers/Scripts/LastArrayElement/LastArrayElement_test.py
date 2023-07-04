import demistomock as demisto


def test_main(mocker):
    from LastArrayElement import main

    mocker.patch.object(demisto, 'args', return_value={
        'value': [1, 2, 3]
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert isinstance(results, int)
    assert results == 3

    mocker.patch.object(demisto, 'args', return_value={
        'value': 3
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert isinstance(results, int)
    assert results == 3

    mocker.patch.object(demisto, 'args', return_value={
        'value': [1, 2, [1, 2, 3]]
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert isinstance(results, list)
    assert results[2] == 3

    mocker.patch.object(demisto, 'args', return_value={
        'value': None
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert isinstance(results, list)
    assert results == []
