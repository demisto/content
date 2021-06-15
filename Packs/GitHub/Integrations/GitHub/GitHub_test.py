from GitHub import main, BASE_URL, list_branch_pull_requests
import demistomock as demisto
import json
import pytest


MOCK_PARAMS = {
    'user': 'test',
    'repository': 'hello-world',
    'token': 'testtoken'
}


def load_test_data(json_path):
    with open(json_path, mode='r') as f:
        return json.load(f)


def test_search_code(requests_mock, mocker):
    raw_response = load_test_data('./test_data/search_code_response.json')
    requests_mock.get(f'{BASE_URL}/search/code?q=create_artifacts%2borg%3ademisto&page=0&per_page=10',
                      json=raw_response)

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'query': 'create_artifacts+org:demisto',
        'limit': '10'
    })
    mocker.patch.object(demisto, 'command', return_value='GitHub-search-code')
    mocker.patch.object(demisto, 'results')

    main()

    results = demisto.results.call_args[0][0]
    assert results['Contents'] == raw_response
    assert len(results['EntryContext']['GitHub.CodeSearchResults(val.html_url && val.html_url == obj.html_url)']) == 7
    assert 'Repository Name' in results['HumanReadable']


def test_list_branch_pull_requests_command(requests_mock):
    test_list_branch_pull_requests_command_response = load_test_data(
        './test_data/get-branch-pull-requests-response.json')
    requests_mock.get('https://api.github.com/repos/demisto/content/pulls?head=demisto:Update-Docker-Image',
                      json=test_list_branch_pull_requests_command_response['response'])
    formatted_outputs = list_branch_pull_requests(branch_name='Update-Docker-Image', repository='content',
                                                  organization='demisto')
    assert formatted_outputs == test_list_branch_pull_requests_command_response['expected']


def mock_http_request(method, url_suffix, params=None, data=None, headers=None, is_raw_response=False):
    if url_suffix == "/search/issues":
        return {"items": [{"repository_url": "", "limit": params.get("per_page")}]}
    elif url_suffix == "/orgs/demisto/teams/content/members" and params.get('page') == 1:
        return [{"login": 'test1', 'id': '12345'}]
    elif url_suffix == "/orgs/demisto/teams/content/members" and params.get('page') == 2:
        return []


SEARCH_CASES = [
    (200, 100),
    (40, 40)
]

LIST_TEAM_MEMBERS_CASES = [
    (200, {'page': 1, 'per_page': 100}),
    (40, {'page': 1, 'per_page': 40})
]


@pytest.mark.parametrize('limit, expected_result', SEARCH_CASES)
def test_search_command(mocker, limit, expected_result):
    """
    Given:
        There are some issues to fetch from GitHub
    When:
        search_command is running
    Then:
        Assert that the limit <= 100
    """
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'query': 'Hello',
        'limit': limit
    })
    mocker.patch('GitHub.http_request', side_effect=mock_http_request)
    mocker_output = mocker.patch('GitHub.return_outputs')
    from GitHub import search_command

    search_command()

    assert mocker_output.call_args.args[2].get('items')[0].get('limit') == expected_result


@pytest.mark.parametrize('maximum_users, expected_result1', LIST_TEAM_MEMBERS_CASES)
def test_list_team_members_command(mocker, maximum_users, expected_result1):
    """
    Given:
        when we want to list the team members and to limit the number of users to return
    When:
        list_team_members_command is running
    Then:
        Assert that the number of users in single page is compatible with the maximum_users number and with the github
        page size limit
    """
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'organization': 'demisto',
        'team_slug': 'content',
        'maximum_users': maximum_users
    })
    mock_list_members = mocker.patch('GitHub.http_request', side_effect=mock_http_request)
    from GitHub import list_team_members_command

    list_team_members_command()

    url_suffix = '/orgs/demisto/teams/content/members'
    mock_list_members.call_args_list[0]('GET', url_suffix, expected_result1)
