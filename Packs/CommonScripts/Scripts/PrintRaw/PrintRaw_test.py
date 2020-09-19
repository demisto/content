import demistomock as demisto


def test_main(mocker):
    from PrintRaw import main

    # test custom fields with short names
    mocker.patch.object(demisto, 'args', return_value={
        'value': '\tthat was a tab  \n\n\nthree newlines\tafter another tab\n'
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == r"'\tthat was a tab  \n\n\nthree newlines\tafter another tab\n'"
