import demistomock as demisto


def test_main__error(mocker):
    """
    Given: Invalid regex flags passed as argument
    When: Calling the main function
    Then: Results should be called once and return an empty str
    """
    from RegexGroups import main
    args = {
        'flags': 'invalidflag',
        'value': 'test'
    }
    results_mock = mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'args', return_value=args)
    main()
    assert results_mock.call_count == 1
    assert results_mock.call_args[0][0] == ''


def test_main__no_match(mocker):
    """
    Given: No matching regex passed as argument
    When: Calling the main function
    Then: Results should be called once and return empty str
    """
    from RegexGroups import main
    args = {
        'value': 'test',
        'regex': '.*'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    results_mock = mocker.patch.object(demisto, 'results')
    main()
    assert results_mock.call_count == 1
    assert results_mock.call_args[0][0] == ''


def test_main__match(mocker):
    """
    Given: A regex that matches the input value
    When: Calling the main function
    Then: Results should be called once and return matched groups
    """
    from RegexGroups import main
    args = {
        'value': 'test',
        'regex': '(.*)'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    results_mock = mocker.patch.object(demisto, 'results')
    main()
    assert results_mock.call_count == 1
    assert results_mock.call_args[0][0] == ['test']
