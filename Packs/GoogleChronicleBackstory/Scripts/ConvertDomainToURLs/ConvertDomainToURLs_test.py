from unittest.mock import patch
import demistomock as demisto

import ConvertDomainToURLs

ARGS = {'domains': "demo.com"}


def test_main_success(mocker):
    """
        When main function is called, get_entry_context should be called.
    """

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(ConvertDomainToURLs, 'get_entry_context',
                        return_value={})
    ConvertDomainToURLs.main()
    assert ConvertDomainToURLs.get_entry_context.called


@patch('ConvertDomainToURLs.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(ConvertDomainToURLs, 'get_entry_context', side_effect=Exception)
    with capfd.disabled():
        ConvertDomainToURLs.main()

    mock_return_error.assert_called_once_with('Error occurred while extracting Domain(s):\n')


def test_get_entry_context_success():
    """
        When get_entry_context function is called then it should return converted URLs.
    """

    converted_urls = ConvertDomainToURLs.get_entry_context(ARGS.get('domains'), True)
    assert {'DomainToURL': ['http://demo.com', 'https://demo.com']} == converted_urls
