import demistomock as demisto
from FormatURL import main


def test_formatter(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': 'https://www.test.com'})
    mocker.patch.object(demisto, 'results')

    main()

    results = demisto.results.call_args[0]

    assert results[0]['Contents'] == ['https://www.test.com']


def test_failed_formatter(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': 'https://@www.test.com'})
    mocker.patch.object(demisto, 'results')

    main()

    results = demisto.results.call_args[0]

    assert results[0]['Contents'] == ['']
