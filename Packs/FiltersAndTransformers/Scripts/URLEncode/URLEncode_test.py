from URLEncode import *
import demistomock as demisto


def test_URLEncode(mocker):
    """
    Given
    - a valid url to encode.
    - safe_character argument is set to default value: '/'.
    - ignore_safe_character argument is set to default value: 'false'.
    When
    - call URLEncode transformer.
    Then
    - the url is encoded except for the '/' character.
    """
    mocker.patch.object(demisto, 'args', return_value={'value': 'https://www.google.com/'})
    mocked_return_results = mocker.patch('URLEncode.return_results')
    main()
    mocked_return_results.assert_called_once_with('https%3A//www.google.com/')


def test_URLEncode_without_safe_character(mocker):
    """
    Given
    - a valid url to encode.
    - safe_character argument is set to default value: '/'.
    - ignore_safe_character argument is set to: 'true'.
    When
    - call URLEncode transformer.
    Then
    - the entire url is encoded including the default '/' character.
    """
    mocker.patch.object(demisto, 'args', return_value={'value': 'https://www.google.com/', 'ignore_safe_character': 'true'})
    mocked_return_results = mocker.patch('URLEncode.return_results')
    main()
    mocked_return_results.assert_called_once_with('https%3A%2F%2Fwww.google.com%2F')


def test_URLEncode_with_safe_character(mocker):
    """
    Given
    - a valid url to encode.
    - safe_character argument is set to: '@'.
    - ignore_safe_character argument is set to default value: 'false'.
    When
    - call URLEncode transformer.
    Then
    - the url is encoded except for the '@' character.
    """
    mocker.patch.object(demisto, 'args', return_value={'value': 'https://www.@google@com/', 'safe_character': '@'})
    mocked_return_results = mocker.patch('URLEncode.return_results')
    main()
    mocked_return_results.assert_called_once_with('https%3A%2F%2Fwww.@google@com%2F')


def test_URLEncode_fail(mocker):
    """
    Given
    - an exception is raised.
    When
    - call URLEncode transformer.
    Then
    - return_error function is called with the relevant error message.
    """
    mocker.patch.object(demisto, 'args', return_value={'value': 'https://www.google.com/'})
    mocker.patch('URLEncode.return_results', side_effect=Exception("Mocked error"))
    mocked_return_error = mocker.patch('URLEncode.return_error')
    main()
    mocked_return_error.assert_called_once()
