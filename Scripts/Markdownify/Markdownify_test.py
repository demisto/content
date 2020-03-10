import demistomock as demisto


def test_main(mocker):
    from Markdownify import main
    mocker.patch.object(demisto, 'args', return_value={
        'html': '<a href="http://demisto.com">Demisto</a>'
    })
    mocker.patch.object(demisto, 'results')
    result_entry = main()
    assert '[Demisto](http://demisto.com)' in result_entry['HumanReadable']
