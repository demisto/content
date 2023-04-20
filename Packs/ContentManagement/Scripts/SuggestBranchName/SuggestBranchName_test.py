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
