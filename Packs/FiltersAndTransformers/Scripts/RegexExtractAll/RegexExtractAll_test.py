import demistomock as demisto


def test_main(mocker):
    from RegexExtractAll import main

    # test basic functionality
    with open('TestData/data.txt', 'r') as f:
        test_data = f.read()

    mocker.patch.object(demisto, 'args', return_value={
        'value': test_data,
        'regex': r'\b[A-Za-z0-9._%=+\p{L}-]+@[A-Za-z0-9\p{L}.-]+\.[A-Za-z]{2,}\b',
        'multi_line': 'false',
        'ignore_case': 'false',
        'period_matches_newline': 'false',
        'error_if_no_match': 'false',
        'unpack_matches': 'false'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 3
    assert results[0] == 'test@test.com'
    assert results[1] == 'testtrainee@test.com'
    assert results[2] == 'testtrainee@test.com'

    # test case insensitive
    mocker.patch.object(demisto, 'args', return_value={
        'value': test_data,
        'regex': r'\bTEST[A-Za-z@.]+\b',
        'multi_line': 'false',
        'ignore_case': 'true',
        'period_matches_newline': 'false',
        'error_if_no_match': 'false',
        'unpack_matches': 'false'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 3
    assert results[0] == 'test@test.com'
    assert results[1] == 'testtrainee@test.com'
    assert results[2] == 'testtrainee@test.com'

    # test unpack matches
    mocker.patch.object(demisto, 'args', return_value={
        'value': test_data,
        'regex': r'([A-Za-z@.]+@([A-Za-z@.]+))',
        'multi_line': 'false',
        'ignore_case': 'true',
        'period_matches_newline': 'false',
        'error_if_no_match': 'false',
        'unpack_matches': 'true'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert len(results) == 6
    assert results[0] == 'test@test.com'
    assert results[1] == 'test.com'
    assert results[2] == 'testtrainee@test.com'
    assert results[3] == 'test.com'
    assert results[4] == 'testtrainee@test.com'
    assert results[5] == 'test.com'
