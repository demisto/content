import json
import pytest
from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "file_path, expected_encoded_file_path",
    (
        pytest.param("./CheckFileCommand", "./CheckFileCommand"),
        pytest.param("test/test_file.py", "test%2Ftest_file.py"),
        pytest.param("./test/test_file.py", "./test%2Ftest_file.py"),
        pytest.param("./test%2Ftest_file.py", "./test%2Ftest_file.py"),
        pytest.param("test%2Ftest_file.py", "test%2Ftest_file.py"),
    ),
)
def test_encode_file_path_if_needed(file_path, expected_encoded_file_path):
    """
        Given:
            - A file path
        When:
            - Running the helper method encode_file_path_if_needed, which dictates if a file path
            should be encoded or not.
        Then:
            - Check if the returned file path was indeed encoded, or did not need encoding.
        """
    from GitLabv2 import encode_file_path_if_needed
    encoded_file_path = encode_file_path_if_needed(file_path)
    assert encoded_file_path == expected_encoded_file_path


ARGS_CASES = [
    (2, -1, False,  # The page_size value must be equal to 1 or bigger.
     {'error': 'limit and page arguments must be positive'}  # expected
     ),
    (-5, 11, False,  # The page_size value must be equal to 1 or bigger.
     {'error': 'limit and page arguments must be positive'}  # expected
     ),
    (1, 1, True,  # Good Case
     {'limit': 1, 'per_page': 1, 'page_number': 1}),  # expected
    (120, 1, True,  # Good Case
     {'limit': 120, 'per_page': 100, 'page_number': 1})  # expected
]


@pytest.mark.parametrize('limit, page_number, isGoodCase, expected_results', ARGS_CASES)
def test_check_args(limit, page_number, isGoodCase, expected_results):
    """
        Given:
            - A command's arguments:
                1. limit: total number of results.
                2. page_number: The number of page to retrieve results from.
                3. isGoodCase: is the test case is with valid arguments.
                3. expected_results: what we expect to get.
        When:
            - running commands that has pagination
        Then:
            - checking that if the parameters < 1 , exception is thrown
        """
    from GitLabv2 import validate_pagination_values
    from CommonServerPython import DemistoException

    if isGoodCase:
        res_limit, res_per_page, res_page_number = validate_pagination_values(limit, page_number)
        assert res_limit == expected_results['limit']
        assert res_per_page == expected_results['per_page']
        assert res_page_number == expected_results['page_number']

    else:
        with pytest.raises(DemistoException) as e:
            validate_pagination_values(limit, page_number)
        assert str(e.value) == expected_results['error']


ARGS_CHECK_LIMIT_GROUP_PROJECT = [
    ({'group_id': '39882308', 'limit': '2'},  # params
     'results',  # client result section from commands_test_data.jason
     2  # excpeted
     ),
    ({'group_id': '39882308', 'limit': '1'},  # params
     'project1',  # client result section from commands_test_data.jason
     1  # excpeted
     )
]


def test_create_issue_command(mocker):
    """
    Given:
        All relevant arguments for the command
    When:
        Running the add_issue_to_project_board_command function.
    Then:
        Assert the message returned is as expected.
    """
    from GitLabv2 import Client, create_issue_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    params = {'title': 'title_test', 'description': 'desc_test', 'labels': 'label1'}
    expected_result = {'iid': 114, 'title': 'title_test', 'description': 'desc_test',
                       'state': 'opened', 'created_at': "'2022-10-06T14:45:38.004Z'",
                       'updated_at': "'2022-10-06T14:45:38.004Z'", 'author': {'name': 'name'}}
    expected_hr = '### Created Issue\n' \
                  '|Iid|Title|Description|CreatedAt|CreatedBy|UpdatedAt|State|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| 114 | title_test | desc_test | \'2022-10-06T14:45:38.004Z\' | ' \
                  'name | \'2022-10-06T14:45:38.004Z\' | opened |\n'

    ret_value = util_load_json('test_data/commands_test_data.json').get('issue_client')
    mocker.patch.object(Client, '_http_request', return_value=ret_value)
    result = create_issue_command(client, params)
    assert result.raw_response == expected_result
    assert result.readable_output == expected_hr


def test_branch_create_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a branch_create_command
    Then:
        - check if the results of creation a branch.
    """
    from GitLabv2 import Client, branch_create_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    params = {'branch': 'branchExample', 'ref': 'ref', 'partial_response': 'false'}
    expected_hr = '### Created Branch\n' \
                  '|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|\n' \
                  '|---|---|---|---|---|---|\n' \
                  '| branchExample | f9d0bf17 | test1 | 2022-07-27T13:09:50.000+00:00 | false | false |\n'
    ret_value = util_load_json('test_data/commands_test_data.json').get('create_branch')
    mocker.patch.object(Client, '_http_request', return_value=ret_value)
    result = branch_create_command(client, params)
    assert result.raw_response == ret_value
    assert result.readable_output == expected_hr


def test_issue_update_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a issue_update_command
    Then:
        - check if the results of ypdating an issue is valid
    """
    from GitLabv2 import Client, issue_update_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    params = {'title': 'title_test', 'description': 'desc_test', 'labels': 'label1'}
    expected_result = {'iid': 114, 'title': 'title_test', 'description': 'desc_test',
                       'state': 'opened', 'created_at': "'2022-10-06T14:45:38.004Z'",
                       'updated_at': "'2022-10-06T14:45:38.004Z'", 'author': {'name': 'name'}}
    expected_hr = '### Update Issue\n' \
                  '|Iid|Title|Description|CreatedAt|CreatedBy|UpdatedAt|State|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| 114 | title_test | desc_test | \'2022-10-06T14:45:38.004Z\' |' \
                  ' name | \'2022-10-06T14:45:38.004Z\' | opened |\n'

    ret_value = util_load_json('test_data/commands_test_data.json').get('issue_client')
    mocker.patch.object(Client, '_http_request', return_value=ret_value)
    result = issue_update_command(client, params)
    assert result.raw_response == expected_result
    assert result.readable_output == expected_hr


def test_get_version_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a get_version_command
    Then:
        - check if the results of version and reversion returns are valid.
    """
    from GitLabv2 import Client, version_get_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_version = util_load_json('test_data/commands_test_data.json').get('get_version')
    mocker.patch.object(Client, '_http_request', return_value=response_version)
    result = version_get_command(client, {})
    expected_raw_result = {'version': '15.5.0-pre', 'revision': '6146b2240b0'}
    expected_hr = 'GitLab version 15.5.0-pre\n reversion: 6146b2240b0 '
    assert result.raw_response == expected_raw_result
    assert result.readable_output == expected_hr


def test_group_project_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a group_project_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, group_project_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'group_id': 112, 'limit': 2}
    response_client = util_load_json('test_data/commands_test_data.json').get('get_group_project')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = group_project_list_command(client, args)
    expected_hr = '### List Group Projects\n' \
                  '|Id|Name|Description|Path|\n' \
                  '|---|---|---|---|\n' \
                  '| 1 | ProjectTest1 | test1 | learn-gitlab1 |\n' \
                  '| 2 | ProjectTest2 | test2 | learn-gitlab2 |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_get_project_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a get_project_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, get_project_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2}
    response_client = util_load_json('test_data/commands_test_data.json').get('get_project_list')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = get_project_list_command(client, args)
    expected_hr = '### List Projects\n' \
                  '|Id|Name|Description|Path|\n' \
                  '|---|---|---|---|\n' \
                  '| 1 | LearnGitLab1 | description1 | /learn-gitlab1 |\n' \
                  '| 2 | LearnGitLab2 | description2 | /learn-gitlab2 |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


ARGS_BRANCHES = [
    ({'branch_name': '1-test', 'limit': '1'},  # args single branch
     'get_branches_single',  # result from json
     '### Branch details\n'
     '|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|\n'
     '|---|---|---|---|---|---|\n'
     '| 1-test | f9d0bf17 | test1 | 2022-07-27T13:09:50.000+00:00 | false | false |\n'
     ),
    ({'limit': '2'},  # args list
     'get_branches',
     '### List Branches\n'
     '|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|\n'
     '|---|---|---|---|---|---|\n'
     '| 1-test | f9d0bf17 | test1 | 2022-07-27T13:09:50.000+00:00 | false | false |\n'
     '| 2-test | d9177263 | test2 | 2022-07-18T12:19:47.000+00:00 | false | false |\n'
     )
]


@pytest.mark.parametrize('args, result_key_json, expected_results', ARGS_BRANCHES)
def test_branch_list_command(mocker, args, result_key_json, expected_results):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a branch_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, branch_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get(result_key_json)
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = branch_list_command(client, args)
    assert result.readable_output == expected_results


ARGS_COMMITS = [
    ({'commit_id': 'a1', 'limit': '1'},  # args single branch
     'commit_single_request',
     'get_commit_single',  # result from json
     '### Commit details\n'
     '|Title|Message|ShortId|Author|CreatedAt|\n'
     '|---|---|---|---|---|\n'
     '| commit1 | message1 | a1 | demo1 | 2022-07-26T11:28:03.000+00:00 |\n'
     ),
    ({'limit': '2'},  # args list
     'commit_list_request',
     'get_commits',
     '### List Commits\n'
     '|Title|Message|ShortId|Author|CreatedAt|\n'
     '|---|---|---|---|---|\n'
     '| commit1 | message1 | a1 | demo1 | 2022-07-26T11:28:03.000+00:00 |\n'
     '| commit2 | message2 | b2 | demo2 | 2022-07-26T11:28:03.000+00:00 |\n'
     '| commit3 | message3 | c3 | demo3 | 2022-07-26T11:28:03.000+00:00 |\n'
     )
]


@pytest.mark.parametrize('args, client_function, result_key_json, expected_results', ARGS_COMMITS)
def test_commit_list_command(mocker, args, client_function, result_key_json, expected_results):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a commit_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, commit_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get(result_key_json)
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = commit_list_command(client, args)
    assert result.readable_output == expected_results


def test_merge_request_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a merge_request_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, merge_request_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2, 'sort': 'asc'}
    response_client = util_load_json('test_data/commands_test_data.json').get('list_merge_request')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = merge_request_list_command(client, args)
    expected_hr = '### List Merge requests\n' \
                  '|Iid|CreatedAt|CreatedBy|Status|\n' \
                  '|---|---|---|---|\n' \
                  '| 5 | 2022-10-02T10:11:27.506Z | Test Account | opened |\n' \
                  '| 6 | 2022-10-02T10:11:27.506Z | Test Account | opened |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_group_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a merge_request_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, group_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 1}
    response_client = util_load_json('test_data/commands_test_data.json').get('list_groups')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = group_list_command(client, args)
    expected_hr = '### List Groups\n' \
                  '|Id|Name|Path|Description|CreatedAt|Visibility|\n' \
                  '|---|---|---|---|---|---|\n' \
                  '| 55694272 | demistoTest | demistotest1 | exaple unit test | 2022-07-18T12:19:46.363Z | private |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_issue_note_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a merge_request_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, issue_note_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2, 'issue_iid': 4}
    response_client = util_load_json('test_data/commands_test_data.json').get('list_issue_note')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = issue_note_list_command(client, args)
    expected_hr = '### List Issue notes\n' \
                  '|Id|Author|Text|CreatedAt|UpdatedAt|\n' \
                  '|---|---|---|---|---|\n' \
                  '| 112 | user test | body1 | 2022-07-27T10:47:38.028Z | 2022-07-27T10:47:38.032Z |\n' \
                  '| 113 | user test | body2 | 2022-07-27T10:47:38.028Z | 2022-07-27T10:47:38.032Z |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_merge_request_note_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a merge_request_note_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, merge_request_note_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2, 'sort': 'asc', 'merge_request_iid': 123}
    response_client = util_load_json('test_data/commands_test_data.json').get('list_merge_request_note')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = merge_request_note_list_command(client, args)
    expected_hr = '### List Merge Issue Notes\n'\
                  '|Id|Text|CreatedAt|UpdatedAt|\n' \
                  '|---|---|---|---|\n' \
                  '| 115 | body11 | 2022-10-02T08:48:43.674Z | 2022-10-02T08:48:43.676Z |\n' \
                  '| 112 | body12 | 2022-10-02T08:48:43.588Z | 2022-10-02T08:48:43.591Z |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_group_member_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a group_member_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, group_member_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2}

    response_client = util_load_json('test_data/commands_test_data.json').get('list_group_members')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = group_member_list_command(client, args)
    expected_hr = '### List Group Members\n' \
                  '|Id|Name|UserName|MembershipState|ExpiresAt|\n' \
                  '|---|---|---|---|---|\n' \
                  '| 126 | Test Account | test2 | active | 2032-10-02T08:44:38.826Z |\n' \
                  '| 116 | Test Account | test2 | active | 2032-10-02T08:44:38.826Z |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_project_user_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a group_member_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLabv2 import Client, project_user_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 3}
    response_client = util_load_json('test_data/commands_test_data.json').get('list_project_user')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = project_user_list_command(client, args)
    expected_hr = '### List Users\n'\
                  '|Id|UserName|Name|State|WebLink|\n'\
                  '|---|---|---|---|---|\n'\
                  '| 123 | test1 | Test Account | active | web_url1 |\n'\
                  '| 345 | test2 | Test Account | active | web_url2 |\n'\
                  '| 678 | test3 | Test Account | active | web_url3 |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


ARGS_FOR_UPDATE = [
    (
        {'arg1': 'not in optinal_params', 'arg2': 'not in optinal_params'}, ['optinal_param'],  # args
        False,  # not valid case
        {'e': 'At least one of arguments is required for the request to be successful\n'}  # expected result
    ),
    (
        {}, ['optinal_param'],  # expected result, # args - Invalid Case
        False,  # not valid case
        {'e': 'At least one of arguments is required for the request to be successful\n'}  # expected result
    ),
    (
        {'arg1': 'not in optinal_params'}, [],  # args - Invalid Case
        False,  # not valid case
        {'e': 'At least one of arguments is required for the request to be successful\n'}  # expected result
    ),
    (
        {'optinal_param': 'exist', 'arg2': 'not in optinal_params'}, ['optinal_param'],
        True,  # valid case
        {'optinal_param': 'exist'}  # expected result
    )
]


@pytest.mark.parametrize('args, optinal_params, isGoodCase, expected_results', ARGS_FOR_UPDATE)
def test_check_args_for_update(args, optinal_params, isGoodCase, expected_results):
    """
    Given:
        - optinal params, arguments
    When:
        - running update commands
    Then:
        - checking that at least one argument from optinal params is in args.
    """
    from GitLabv2 import check_args_for_update
    from CommonServerPython import DemistoException

    if isGoodCase:
        res = check_args_for_update(args, optinal_params)
        assert res == expected_results

    else:
        with pytest.raises(DemistoException) as e:
            check_args_for_update(args, optinal_params)
        assert str(e.value) == expected_results['e']


def test_file_get_command(mocker):
    """
    Given:
        - optinal params, arguments
    When:
        - running file_get_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import Client, file_get_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 3}
    response_client = util_load_json('test_data/commands_test_data.json').get('file')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = file_get_command(client, args)
    expected_hr = '### Get File\n' \
                  '|FileName|FilePath|Ref|ContentSha|CommitId|LastCommitId|Size|\n' \
                  '|---|---|---|---|---|---|---|\n' \
                  '| example-file | .example-file | test-1 | 7ff1d80f | f9d0b | f9d0b | 1024 |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


CASE_FILE_CREATE = [
    ({},  # args
     'You must specify either the "file_content" and "file_path" or the "entry_id" of the file.'),
    ({'file_content': 'example', 'branch': 'main', 'commit_msg': 'unit'},  # args
     'File created successfully.'  # results
     )

]


@pytest.mark.parametrize('args, expected_results', CASE_FILE_CREATE)
def test_file_create_command(mocker, args, expected_results):
    """
    Given:
        - optinal params, arguments
    When:
        - running file_create_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import Client, file_create_command
    from CommonServerPython import DemistoException
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    if len(args) == 0:
        with pytest.raises(DemistoException) as e:
            file_create_command(client, args)
        assert str(e.value) == expected_results
    else:
        response_client = util_load_json('test_data/commands_test_data.json').get('create_file')
        mocker.patch.object(Client, '_http_request', return_value=response_client)
        result = file_create_command(client, args)
        assert result.readable_output == expected_results


CASE_FILE_UPDATE = [
    ({},  # args
     'You must specify either the "file_content" and "file_path" or the "entry_id" of the file.'),
    ({'file_path': 'example', 'branch': 'main', 'commit_msg': 'unit', 'file_content': 'update'},  # args
     'File updated successfully.'  # results
     )

]


@pytest.mark.parametrize('args, expected_results', CASE_FILE_UPDATE)
def test_file_update_command(mocker, args, expected_results):
    """
    Given:
        - optinal params, arguments
    When:
        - running file_update_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import Client, file_update_command
    from CommonServerPython import DemistoException
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    if len(args):
        response_client = util_load_json('test_data/commands_test_data.json').get('create_file')
        mocker.patch.object(Client, '_http_request', return_value=response_client)
        result = file_update_command(client, args)
        assert result.readable_output == expected_results
    else:
        with pytest.raises(DemistoException) as e:
            file_update_command(client, args)
        assert str(e.value) == expected_results


ARGS_PAGINATION = [
    ({'limit': 3, 'page_number': 1},
     3),
    ({'limit': 50, 'page_number': 1},
     50),
    ({'limit': 101, 'page_number': 1},
     101)
]


@pytest.mark.parametrize('args, expected_results', ARGS_PAGINATION)
def test_check_pagintion(mocker, args, expected_results):
    """
    Given:
        - optinal params, arguments
    When:
        - running commands that contains limit, page_number args.
    Then:
        - checking that the response is according pagination
    """
    from GitLabv2 import Client, response_according_pagination
    mocker.patch.object(Client, 'project_user_list_request', return_value={"response_client"})
    result = response_according_pagination(Client.project_user_list_request, args['limit'], args['page_number'], {}, None)
    assert len(result) == expected_results


def test_get_raw_file_command(mocker):
    """
    Given:
        - optinal params, arguments
    When:
        - running get_raw_file_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import Client, get_raw_file_command
    import CommonServerPython
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'ref': 'main', 'file_path': 'unit'}
    response_client = util_load_json('test_data/commands_test_data.json').get('raw_file')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    mocker.patch.object(CommonServerPython, 'fileResult', return_value="/command_examples.txt")
    result = get_raw_file_command(client, args)
    expected_hr = '### Raw file\n' \
                  '|path|reference|content|\n' \
                  '|---|---|---|\n' \
                  '| unit |  | I am a file. |\n'
    assert result[0].raw_response == response_client
    assert result[0].readable_output == expected_hr


ARGS_VERIFY_ID = [
    (-10,
     'Project with project_id -10 does not exist'),
    (10,
     'Project with project_id 10 does not exist'),
    (-1,
     'Project with project_id -1 does not exist')
]


@pytest.mark.parametrize('project_id, expected_results', ARGS_VERIFY_ID)
def test_verify_project_id(mocker, project_id, expected_results):
    """
    Given:
        - optinal project_id
    When:
        - running verify_project_id
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import Client, verify_project_id
    from CommonServerPython import DemistoException
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get('get_project_list')
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    with pytest.raises(DemistoException) as e:
        verify_project_id(client, project_id)
    assert str(e.value) == expected_results


def test_code_search_command(mocker):
    """
    Given:
        - optinal params, arguments
    When:
        - running code_search_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import Client, code_search_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    expected_raw = ' search via unit test\n'
    response_client = util_load_json('test_data/commands_test_data.json').get('search_code')
    args = {'search': 'unit', 'limit': '1'}
    mocker.patch.object(Client, '_http_request', return_value=response_client)
    result = code_search_command(client, args)
    assert result.raw_response[0]['data'] == expected_raw


def test_gitlab_pipelines_schedules_list_command(mocker):
    """
    Given:
        - client and demisto args
    When:
        - calling the gitlab_pipelines_schedules_list_command
    Then:
        - validate that the command results returns properly
    """
    from GitLabv2 import (Client, gitlab_pipelines_schedules_list_command)
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get('pipeline_schedule')
    args = {"project_id": 1}
    expected_outputs: list[dict] = response_client['expected_outputs']
    expected_prefix: str = response_client['expected_prefix']
    expected_key_field: str = response_client['expected_key_field']
    mocker.patch.object(Client, '_http_request', return_value=response_client['mock_response'])
    command_result = gitlab_pipelines_schedules_list_command(client, args)
    assert command_result.outputs_prefix == expected_prefix
    assert command_result.outputs == expected_outputs
    assert command_result.outputs_key_field == expected_key_field


def test_gitlab_pipelines_list_command(mocker):
    """
    Given:
        - client and demisto args
    When:
        - calling the gitlab_pipelines_list_command
    Then:
        - validate that the command results returns properly
    """
    from GitLabv2 import (Client, gitlab_pipelines_list_command)
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get('pipeline')
    args = {"project_id": "3"}
    expected_outputs: list[dict] = response_client['expected_outputs']
    expected_prefix: str = response_client['expected_prefix']
    expected_key_field: str = response_client['expected_key_field']
    mocker.patch.object(Client, '_http_request', return_value=response_client['mock_response'])
    command_result = gitlab_pipelines_list_command(client, args)
    assert command_result.outputs_prefix == expected_prefix
    assert command_result.outputs == expected_outputs
    assert command_result.outputs_key_field == expected_key_field


def test_gitlab_jobs_list_command(mocker):
    """
    Given:
        - client and demisto args
    When:
        - calling the gitlab_jobs_list_command
    Then:
        - validate that the command results returns properly
    """
    from GitLabv2 import (Client, gitlab_jobs_list_command)
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get('jobs')
    args = {
        "project_id": "4",
        "pipeline_id": "12"
    }
    expected_outputs: list[dict] = response_client['expected_outputs']
    expected_prefix: str = response_client['expected_prefix']
    expected_key_field: str = response_client['expected_key_field']
    mocker.patch.object(Client, '_http_request', return_value=response_client['mock_response'])
    command_result = gitlab_jobs_list_command(client, args)
    assert command_result.outputs_prefix == expected_prefix
    assert command_result.outputs == expected_outputs
    assert command_result.outputs_key_field == expected_key_field


def test_gitlab_artifact_get_command(mocker):
    """
    Given:
        - client and demisto args
    When:
        - calling the gitlab_artifact_get_command
    Then:
        - validate that the command results returns properly
    """
    from GitLabv2 import (Client, gitlab_artifact_get_command)
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get('artifact-get')
    args = {
        "project_id": "45",
        "job_id": "32",
        "artifact_path_suffix": "artifacts/failed_tests.txt"}
    expected_outputs: list[dict] = response_client['expected_outputs']
    expected_prefix: str = response_client['expected_prefix']
    expected_key_field: str = response_client['expected_key_field']
    mocker.patch.object(Client, '_http_request', return_value=response_client['mock_response'])
    command_result = gitlab_artifact_get_command(client, args)
    assert command_result.outputs_prefix == expected_prefix
    assert command_result.outputs == expected_outputs
    assert command_result.outputs_key_field == expected_key_field


@pytest.mark.parametrize('error_message, expected_result', [('this is an error', False),
                                                            ("Failed to parse json object"
                                                                "from response: <!DOCTYPE html>\n<html class=)", True)])
def test_check_for_html_in_error(error_message, expected_result):
    from GitLabv2 import check_for_html_in_error
    assert check_for_html_in_error(error_message) == expected_result


ARGS_FOR_PARTIAL_RESPONSE = [
    (
        [], "",  # args empty both
        []
    ),
    (
        [{
            "name": "Test",
            "commit": {
                "id": "7d",
                "short_id": "7d",
                "created_at": "2022-10-11T09:05:11.000+00:00",
                "parent_ids": [
                    "01"
                ],
                "title": "title",
                "message": "delete file via playbook",
                "author_name": "Test Account",
                "author_email": "test@dem.com",
                "authored_date": "2022-10-11T09:05:11.000+00:00",
                "committer_name": "Test Account",
                "committer_email": "test@dem.com",
                "committed_date": "2022-10-11T09:05:11.000+00:00",
                "trailers": {},
                "web_url": "url"
            },
            "merged": 'false',
            "protected": 'false'
        }], "",  # args empty object_name
        [{}]
    ),
    (
        [], {"Branch"},  # args empty response
        []
    ),
    (
        [
            {
                "name": "Test",
                "commit": {
                    "id": "7d",
                    "short_id": "7d",
                    "created_at": "2022-10-11T09:05:11.000+00:00",
                    "parent_ids": [
                        "01"
                    ],
                    "title": "titleCommit",
                    "message": "delete file via playbook",
                    "author_name": "Test Account",
                    "author_email": "test@dem.com",
                    "authored_date": "2022-10-11T09:05:11.000+00:00",
                    "committer_name": "Test Account",
                    "committer_email": "test@dem.com",
                    "committed_date": "2022-10-11T09:05:11.000+00:00",
                    "trailers": {},
                    "web_url": "url"
                },
                "merged": 'false',
                "protected": 'false'
            }], "Branch",  # branch
        [{'name': 'Test', 'commit': {'id': '7d', 'short_id': '7d', "title": "titleCommit",
          'committed_date': '2022-10-11T09:05:11.000+00:00', 'author_name': 'Test Account'},
          'merged': 'false', 'protected': 'false'}]
    )
]


@pytest.mark.parametrize('response, object_name, expected_response', ARGS_FOR_PARTIAL_RESPONSE)
def test_partial_response(response, object_name, expected_response):
    """
    Given:
        - API response.
        - object_name (Branch, Issue etc).
        - expected_response after filtering.
    When:
        - running partial_response
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import partial_response
    result = partial_response(response, object_name)
    assert result == expected_response


ARGS_ISO_CHECK = [
    (None, True, None),
    ('7 days', True, '2022-10-31T15:11:11.704807'),
    ('7 months', True, '2022-04-07T15:11:11.704807')
]


@freeze_time('2022-11-07T15:11:11.704807')
@pytest.mark.parametrize('arg, isValidDate, expected_response', ARGS_ISO_CHECK)
def test_return_date_arg_as_iso(arg, isValidDate, expected_response):
    """
    Given:
        - arg representing time stamp
    When:
        - running return_date_arg_as_iso
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from GitLabv2 import return_date_arg_as_iso
    from CommonServerPython import DemistoException
    if isValidDate:
        result = return_date_arg_as_iso(arg)
        assert result == expected_response
    else:
        with pytest.raises(DemistoException) as e:
            return_date_arg_as_iso(arg)

        assert str(e.value) == expected_response


@pytest.mark.parametrize('trigger_token, args, expected_result', [
    ('', {}, util_load_json('test_data/commands_test_data.json').get('trigger_pipeline1')),
    (1111, {'project_id': 2222, 'ref_branch': 'test'},
     util_load_json('test_data/commands_test_data.json').get('trigger_pipeline2'))
])
def test_trigger_pipeline(mocker, trigger_token, args, expected_result):
    """
    Given:
        - client and demisto args
            - case 1 - client without trigger token.
            - case 2 - client with trigger token and args with a different project ID than the instance.
    When:
        - gitlab_trigger_pipeline_command
    Then:
        - The response is as expected
            - case 1 - Throws an error about the trigger token that is missing
            - case 2 - The response is correct with the same branch and project_id as in the args.
    """
    from GitLabv2 import Client, gitlab_trigger_pipeline_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'},
                    trigger_token=trigger_token)
    expected_outputs: list[dict] = expected_result['expected_outputs']
    expected_prefix: str = expected_result['expected_prefix']
    expected_key_field: str = expected_result['expected_key_field']
    mocker.patch.object(Client, '_http_request', return_value=expected_result['mock_response'])
    mock_error = mocker.patch('GitLabv2.return_error')

    command_result = gitlab_trigger_pipeline_command(client, args)

    if not trigger_token:
        assert mock_error.call_args[0][0] == 'A trigger token is required in the integration instance configuration'
    else:
        assert command_result.outputs_prefix == expected_prefix
        assert command_result.outputs_key_field == expected_key_field
        assert command_result.outputs == expected_outputs
        assert command_result.outputs.get('ref') == args.get('ref_branch')
        assert command_result.outputs.get('project_id') == args.get('project_id')


def test_cancel_pipeline(mocker):
    """
    Given:
        - GitLab client and demisto args
    When:
        - gitlab_cancel_pipeline_command
    Then:
        - The response is as expected
    """
    from GitLabv2 import Client, gitlab_cancel_pipeline_command
    args = {'project_id': 2222, 'pipeline_id': 1}
    expected_result = util_load_json('test_data/commands_test_data.json').get('cancel_pipeline')
    client = Client(project_id=1234,
                    base_url="server_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    expected_outputs: list[dict] = expected_result['expected_outputs']
    expected_prefix: str = expected_result['expected_prefix']
    expected_key_field: str = expected_result['expected_key_field']
    mocker.patch.object(Client, '_http_request', return_value=expected_result['mock_response'])

    command_result = gitlab_cancel_pipeline_command(client, args)

    assert command_result.outputs_prefix == expected_prefix
    assert command_result.outputs_key_field == expected_key_field
    assert command_result.outputs == expected_outputs
    assert command_result.outputs.get('project_id') == int(args.get('project_id'))
    assert command_result.outputs.get('status') == 'canceled'
