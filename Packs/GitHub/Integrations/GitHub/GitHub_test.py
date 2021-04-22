import demistomock as demisto


def mock_http_request_for_search(method, url_suffix, params=None, data=None):
    return {"items": []}


def test_search_issue(mocker):
    """
    Given:
        There are 200 issues to fetch from GitHub
    When:
        search_command is running
    Then:
        Assert that the arguments are what we expected
    """

    mocker.patch.object(demisto, 'params', return_value={"token": "123456"})
    mocker.patch.object(demisto, 'args', return_value={"query": "hello", "limit": 200})
    mocker.patch.object(demisto, 'results', return_value={"q": "hello", "per_page": 100})
    mocker.patch('GitHub.http_request', side_effect=mock_http_request_for_search)
    from GitHub import search_command

    search_command()

    assert demisto.results() == {"q": "hello", "per_page": 100}
