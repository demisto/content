
import pytest
import demistomock as demisto

FIND_AVAILABLE_BRANCH_CASES = [
    (
        'Hi', 'bitbucket-branch-get'  # case bitbucket
    )
]

expected_branch_name = 'Hi'

mocker_bitbucket = {'Contents': 'Failed to execute bitbucket-branch-get command\nError: Error in API call [404] - '
                                'Not Found\n{"type": "error", "error": {"message": "Hi"}}', 'Type': 4}


@pytest.mark.parametrize('pack_name, command_get_branch', FIND_AVAILABLE_BRANCH_CASES)
def test_find_available_branch(pack_name, command_get_branch, mocker):
    """
    Given:
        - A pack name and a command to execute.
    When:
        - There isn't a branch name in the incident fields.
    Then:
        - Returning an available name for the new branch
    """
    from SuggestBranchName import find_available_branch
    mocker.patch.object(demisto, 'executeCommand', return_value=mocker_bitbucket)
    branch_name = find_available_branch(pack_name, command_get_branch)
    assert branch_name == expected_branch_name


RESPONSE = [{"Contents": {"value": [{"name": "Test/Test"}, {"name": "Test/Test_1"}]}}]


@pytest.mark.parametrize('pack_name, response, expected_available_branch_name', [("Test", RESPONSE, "refs/heads/Test_2")])
def test_find_available_branch_azure_devops(mocker, pack_name: str, response: list[dict], expected_available_branch_name: str):
    """
    Given:
        - A pack name
    When:
        - Two branches exist
    Then:
        - Returning an available name for the new branch
    """
    from SuggestBranchName import find_available_branch_azure_devops
    mocker.patch.object(demisto, 'executeCommand', return_value=response)
    branch_name = find_available_branch_azure_devops(pack_name)
    assert branch_name == expected_available_branch_name
