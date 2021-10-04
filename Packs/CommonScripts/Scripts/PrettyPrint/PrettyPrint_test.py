import demistomock as demisto


def test_main(mocker):

    from PrettyPrint import main

    test_obj = {
        'string': 'abc',
        'number': 123,
        'boolean': True,
        'list': ['x', 'y', 'z']
    }

    mocker.patch.object(demisto, 'args', return_value={
        'value': test_obj,
    })

    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]

    assert results == "{'boolean': True, 'list': ['x', 'y', 'z'], 'number': 123, 'string': 'abc'}"
