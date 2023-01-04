from Utils.trigger_private_build import GET_WORKFLOW_URL
from Utils.get_private_build_status import get_workflow_status


GET_MODIFIED_FILES_MOCKS = [['Utils/comment_on_pr.py'],
                            ['Tests/scripts/validate_premium_packs.sh'],
                            ['Tests/private_build/run_content_tests_private.py']]

DIFF_COMMAND_RES = '.circleci/config.yml\nUtils/file1.py\nUtils/tests/file2.py'


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
