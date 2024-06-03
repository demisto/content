import demistomock as demisto
import FormatURL


def test_formatter(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': 'https://www.test.com'})
    mocker.patch.object(demisto, 'results')

    FormatURL.main()

    results = demisto.results.call_args[0]
    # print(f'test_formatter, {results=}')
    # print(f'test_formatter, {type(results[0])=}')
    # print(f"test_formatter, {type(results[0]['Contents'])=}")

    assert results[0]['Contents'][0] == 'https://www.test.com'
    assert results[0]['Contents'] == ['https://www.test.com']


def test_failed_formatter(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': 'https://@www.test.com'})
    mocker.patch.object(demisto, 'results')

    FormatURL.main()

    results = demisto.results.call_args[0]

    assert results[0]['Contents'] == ['']


def test_bad(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': 1})
    return_error = mocker.patch.object(FormatURL, 'return_error')
    FormatURL.main()
    assert return_error.called_once
