from Utils.trigger_private_build import GET_WORKFLOW_URL, branch_has_private_build_infra_change, get_modified_files
from Utils.get_private_build_status import get_workflow_status


GET_MODIFIED_FILES_MOCKS = [['Utils/comment_on_pr.py'],
                            ['Tests/scripts/validate_premium_packs.sh'],
                            ['Tests/private_build/run_content_tests_private.py']]

DIFF_COMMAND_RES = '.circleci/config.yml\nUtils/file1.py\nUtils/tests/file2.py'


def test_branch_has_private_build_infra_change(mocker):
    """
    Given
    - A branch name.

    When
    - Running branch_has_private_build_infra_change.

    Then
    - function returns True if there are infrastructure files changes in the branch.
    """
    mocker.patch('Utils.trigger_private_build.get_modified_files', side_effect=GET_MODIFIED_FILES_MOCKS)
    not_infra_file = branch_has_private_build_infra_change()
    infra_file = branch_has_private_build_infra_change()
    infra_folder = branch_has_private_build_infra_change()
    assert not not_infra_file
    assert infra_file
    assert infra_folder


def test_get_modified_files(mocker):
    """
    Given

    When
    - Running get_modified_files.

    Then
    - function returns a list with the modified files by using git diff command.
    """
    mocker.patch('demisto_sdk.commands.common.tools.run_command', return_value=DIFF_COMMAND_RES)
    modified_files = get_modified_files()
    assert modified_files == ['.circleci/config.yml', 'Utils/file1.py', 'Utils/tests/file2.py']


def test_get_workflow_status_completed(requests_mock):
    """
    Given
    - Github token.
    - Github workflow id.

    When
    - Running get_workflow_status on completed job.

    Then
    - function returns a set with the workflow job status and job conclusion.
    """
    workflow_id = '826'
    requests_mock.get(GET_WORKFLOW_URL.format(workflow_id),
                      json={'jobs': [{'status': 'completed', 'conclusion': 'failure'}]},
                      status_code=200)

    job_status, job_conclusion, step = get_workflow_status('token', workflow_id)
    assert job_status == 'completed'
    assert job_conclusion == 'failure'


def test_get_workflow_status_in_progress(requests_mock):
    """
    Given
    - Github token.
    - Github workflow id.

    When
    - Running get_workflow_status on job in progress.

    Then
    - function returns a set with the workflow job status, job conclusion and the current step.
    """
    workflow_id = '826'
    requests_mock.get(GET_WORKFLOW_URL.format(workflow_id),
                      json={'jobs': [{'status': 'in_progress', 'steps': [{'name': 'step1', 'status': 'completed'},
                                                                         {'name': 'step2', 'status': 'completed'},
                                                                         {'name': 'step3', 'status': 'in_progress'}]}]},
                      status_code=200)

    job_status, job_conclusion, step = get_workflow_status('token', workflow_id)
    assert job_status == 'in_progress'
    assert not job_conclusion
    assert step == 'step3'
