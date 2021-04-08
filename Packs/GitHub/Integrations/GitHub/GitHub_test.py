import demistomock as demisto


def mock_http_request_for_search(method, url_suffix, params=None, data=None):
    return params


def test_search_issue(mocker):
    """
    Given:
        There are 50 issues to fetch from GitHub
    When:
        search_command is running
    Then:
        Assert that the arguments are what we expected
    """
    query = 'hello'
    limit = 50
    mocker.patch.object(demisto, 'params', return_value={"token": "123456"})
    mocker.patch('GitHub.http_request', side_effect=mock_http_request_for_search)
    from GitHub import search_issue

    params_for_request = search_issue(query, limit)

    assert params_for_request == {"q": query, "per_page": limit}
