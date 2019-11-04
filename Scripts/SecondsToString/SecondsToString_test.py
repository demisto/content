import demistomock as demisto


def test_main(mocker):
    from SecondsToString import main

    mocker.patch.object(demisto, 'results')
    results = main(value='90122')
    assert results == '1d 1h 2m 2s'

    mocker.patch.object(demisto, 'results')
    results = main(value=90122)
    assert results == '1d 1h 2m 2s'

    mocker.patch.object(demisto, 'results')
    results = main('86401')
    assert results == '1d 1s'

    mocker.patch.object(demisto, 'results')
    results = main(14401)
    assert results == '4h 1s'
