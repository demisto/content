import demistomock as demisto


def test_DisplayHTML(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the DisplayHTML script.
    Then:
        - Validating calling to 'demisto.results' once with the right arguments.
    """
    from DisplayHTML import main
    mocker.patch.object(demisto, 'args', return_value={'html': 'html', 'markAsNote': 'True', "header": "header"})
    results_mock = mocker.patch.object(demisto, 'results')
    main()
    results_mock.assert_called_once()
    results = results_mock.call_args[0][0]
    assert results == {'Contents': '<h1>header</h1></br>html',
                       'ContentsFormat': 'html',
                       'Note': True,
                       'Type': 1}
