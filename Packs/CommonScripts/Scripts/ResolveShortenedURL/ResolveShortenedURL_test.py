import demistomock as demisto
import urllib.request
from unittest.mock import patch, MagicMock
import ResolveShortenedURL


def test_resolve_un_shortened_url(mocker):
    """
     Given:
         - The script args.
     When:
         - Running the main with a URL that can be unshortened.
     Then:
         - Validating calling to 'demisto.results' once with the right arguments.
     """
    args = {'url': 'https://test/example'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mock_response = MagicMock()
    content = {'success': True, 'resolved_url': 'test', 'requested_url': 'test', 'usage_count': 'test'}
    excepted_args = {'Type': 1, 'Contents': ['test'], 'ContentsFormat': 'json',
                     'HumanReadable': '### Shorten URL results\n|Resolved URL|Shortened URL|Usage count|\n'
                                      '|---|---|---|\n| test | test | test |\n', 'EntryContext': {'URL.Data': ['test']}}
    with patch.object(urllib.request, 'urlopen', return_value=mock_response):
        mocker.patch("json.loads", return_value=content)
        execute_mock = mocker.patch.object(demisto, 'results')
        ResolveShortenedURL.main()
        assert execute_mock.call_count == 1
        assert execute_mock.call_args[0][0] == excepted_args


def test_resolve_shortened_url(mocker):
    """
     Given:
         - The script args.
     When:
         - Running the main with a URL that cannot be unshortened.
     Then:
         - Validating calling to 'demisto.results' once with the relevant massage.
     """
    args = {'url': 'https://test.com'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mock_response = MagicMock()
    content = {'success': False}
    with patch.object(urllib.request, 'urlopen', return_value=mock_response):
        mocker.patch("json.loads", return_value=content)
        execute_mock = mocker.patch.object(demisto, 'results')
        ResolveShortenedURL.main()
        assert execute_mock.call_count == 1
        assert execute_mock.call_args[0][0] == 'Provided URL could not be un-shortened'
