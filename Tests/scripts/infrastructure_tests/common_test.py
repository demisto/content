from pathlib import Path
from Tests.scripts.common import get_reviewer, get_person_in_charge, are_pipelines_in_order, is_pivot, get_slack_user_name, \
    was_message_already_sent, get_nearest_newer_commit_with_pipeline, get_nearest_older_commit_with_pipeline
from requests_mock import MockerCore


def test_get_person_in_charge(mocker):
    """
    Given:
        A commit with author name and title
    When:
        The function get_person_in_charge is called with that commit
    Then:
        It should return a tuple with the author name and the pull request URL and the title beginning (up to 20 characters)
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug (#123)'

    result = get_person_in_charge(commit)
    assert result == ('John Doe', 'https://github.com/demisto/content/pull/123', 'Fix a bug (#123)...')


def test_get_person_in_charge__multiple_IDs(mocker):
    """
    Given:
        A commit with author name and title, and multiple IDs in the title (common when a PR is from a contributor)
    When:
        The function get_person_in_charge is called with that commit
    Then:
        It should return the a tuple with the author name and the pull request URL, with only the last ID in the URL,
        and the title beginning (up to 20 characters)
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug (#456) (#123)'

    result = get_person_in_charge(commit)
    assert result == ('John Doe', 'https://github.com/demisto/content/pull/123', 'Fix a bug (#456) (#1...')


def test_get_person_in_charge__no_parenthesis(mocker):
    """
    Given:
        A commit with author name and title and the ID in the title is not in parenthesis
    When:
        The function get_person_in_charge is called with the commit
    Then:
        It should return the author name and the pull request URL (even if the ID was not in parenthesis)
        and the title beginning (up to 20 characters)
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug #123'

    result = get_person_in_charge(commit)
    assert result == ('John Doe', 'https://github.com/demisto/content/pull/123', 'Fix a bug #123...')


def test_get_person_in_charge__no_number_sign(mocker):
    """
    Given:
        A commit with author name and title, but no number sign (#) before the ID
    When:
        The function get_person_in_charge is called with the commit
    Then:
        It should return a tuple of None since the ID is not in the correct format
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug (123)'

    result = get_person_in_charge(commit)
    assert result == (None, None, None)


def test_pipelines_are_in_correct_order__false(mocker):
    """
    Given:
        Two pipelines that are out of order in respect to their creation time
    When:
        The function are_pipelines_in_order is called with the two pipelines
    Then:
        It should return False as the pipelines are out of order
    """
    pipeline1 = mocker.Mock()
    pipeline1.created_at = '2020-01-01T00:00:00Z'
    pipeline2 = mocker.Mock()
    pipeline2.created_at = '2020-01-02T00:00:00Z'

    result = are_pipelines_in_order(pipeline1, pipeline2)
    assert result is False


def test_pipelines_are_in_correct_order__true(mocker):
    """
    Given:
        Two pipelines that are in order in respect to their creation time
    When:
        The function are_pipelines_in_order is called with both pipelines
    Then:
        It should return True as the pipelines are in order
    """
    pipeline1 = mocker.Mock()
    pipeline1.created_at = '2020-01-02T00:00:00Z'
    pipeline2 = mocker.Mock()
    pipeline2.created_at = '2020-01-01T00:00:00Z'

    result = are_pipelines_in_order(pipeline1, pipeline2)
    assert result is True


def test_is_pivot__previously_pipeline_success_and_current_failed(mocker):
    """
    Given:
        A previously successful pipeline and a current failed pipeline
    When:
        The function is_pivot is called with both pipelines
    Then:
        It should return True since the current pipeline failed after a successful pipeline
    """
    previously_pipeline = mocker.Mock()
    previously_pipeline.status = 'success'
    current_pipeline = mocker.Mock()
    current_pipeline.status = 'failed'

    mocker.patch('Tests.scripts.common.are_pipelines_in_order', return_value=(True))

    result = is_pivot(current_pipeline, previously_pipeline)
    assert result is True


def test_is_pivot__previously_pipeline_success_and_current_success(mocker):
    """
    Given:
        A previously successful pipeline and a current successful pipeline
    When:
        The function is_pivot is called with both pipelines
    Then:
        It should return None since there is no pivot since both pipelines succeeded
    """
    previously_pipeline = mocker.Mock()
    previously_pipeline.status = 'success'
    current_pipeline = mocker.Mock()
    current_pipeline.status = 'success'

    mocker.patch('Tests.scripts.common.are_pipelines_in_order', return_value=(True))

    result = is_pivot(current_pipeline, previously_pipeline)
    assert result is None


def test_is_pivot__previously_pipeline_failed_and_current_failed(mocker):
    """
    Given:
        A previously failed pipeline and a current failed pipeline
    When:
        The function is_pivot is called with both pipelines
    Then:
        It should return None since there is no pivot since both pipelines failed
    """
    previously_pipeline = mocker.Mock()
    previously_pipeline.status = 'failed'
    current_pipeline = mocker.Mock()
    current_pipeline.status = 'failed'

    mocker.patch('Tests.scripts.common.are_pipelines_in_order', return_value=(True))

    result = is_pivot(current_pipeline, previously_pipeline)
    assert result is None


def test_is_pivot__previously_pipeline_failed_and_current_success(mocker):
    """
    Given:
        A previously failed pipeline and a current successful pipeline
    When:
        The function is_pivot is called with both pipelines
    Then:
        It should return False since there is a positive pivot, since the current pipeline succeeded after a failed pipeline
    """
    previously_pipeline = mocker.Mock()
    previously_pipeline.status = 'failed'
    current_pipeline = mocker.Mock()
    current_pipeline.status = 'success'

    mocker.patch('Tests.scripts.common.are_pipelines_in_order', return_value=(True))

    result = is_pivot(current_pipeline, previously_pipeline)
    assert result is False


def test_is_pivot__previously_pipeline_not_success_or_faild_and_current_failed(mocker):
    """
    Given:
        A previously in-progress pipeline and a current failed pipeline
    When:
        The function is_pivot is called with both pipelines
    Then:
        It should return None since there is no known pivot since the previously pipeline is not in a final state
    """
    current_pipeline = mocker.Mock()
    current_pipeline.status = 'failed'
    previously_pipeline = mocker.Mock()
    previously_pipeline.status = 'in progress'
    mocker.patch('Tests.scripts.common.are_pipelines_in_order', return_value=(True))

    result = is_pivot(current_pipeline, previously_pipeline)
    assert result is None


def test_get_reviewer__no_reviewer(requests_mock: MockerCore):
    """
    Given:
        - A URL of a PR that has no reviewers.
    When:
        - get_reviewer is called on it.
    Then:
        - It should return None.
    """
    pr_url = 'https://github.com/owner/repo/pull/123'
    response = []
    requests_mock.get('https://api.github.com/repos/owner/repo/pulls/123/reviews', json=response)

    result = get_reviewer(pr_url)
    assert result is None


def test_get_reviewer__second_reviewer_approved(requests_mock: MockerCore):
    """
    Given:
        - A URL of a PR with 2 reviewers, but only the second reviewer approved.
    When:
        - get_reviewer is called on it.
    Then:
        - It should return the second reviewer's name.
    """
    pr_url = 'https://github.com/owner/repo/pull/123'
    response = [{"Jon": "test", "state": "test", "user": {"login": "Jon"}},
                {"Jane Doe": "test", "state": "APPROVED", "user": {"login": "Jane Doe"}}]
    requests_mock.get('https://api.github.com/repos/owner/repo/pulls/123/reviews', json=response)

    result = get_reviewer(pr_url)
    assert result == "Jane Doe"


def test_get_reviewer__two_reviewers_approved(requests_mock: MockerCore):
    """
    Given:
        - A URL of a PR with two reviewers who approved.
    When:
        - get_reviewer is called on it.
    Then:
        - It should return the first reviewer's name.
    """
    pr_url = 'https://github.com/owner/repo/pull/123'
    response = [{"Jon": "test", "state": "APPROVED", "user": {"login": "Jon"}},
                {"Jane Doe": "test", "state": "APPROVED", "user": {"login": "Jane Doe"}}]
    requests_mock.get('https://api.github.com/repos/owner/repo/pulls/123/reviews', json=response)

    result = get_reviewer(pr_url)
    assert result == "Jon"


def test_get_slack_user_name__name_in_map():
    """
    Given:
        - A name that is in the mapping.
    When:
        - get_slack_user_name is called on it.
    Then:
        - It should return the mapped name.
    """
    name = "Mike"
    result = get_slack_user_name(name, str(Path(__file__).parent / 'tests_data/test_mapping.json'))
    assert result == "mike"


def test_get_slack_user_name__name_not_in_map():
    """
    Given:
        - A name that is not in the mapping.
    When:
        - get_slack_user_name is called on it.
    Then:
        - It should return the original name.
    """
    name = "Jon"
    result = get_slack_user_name(name, str(Path(__file__).parent / 'tests_data/test_mapping.json'))
    assert result == "Jon"


def test_get_slack_user_name__name_is_github_actions_bot():
    """
    Given:
        - The name 'github-actions[bot]'.
    When:
        - get_slack_user_name is called on it.
    Then:
        - It should return the owner of the docker image update bot.
    """
    name = "github-actions[bot]"
    result = get_slack_user_name(name, str(Path(__file__).parent / 'tests_data/test_mapping.json'))
    assert result == "docker images bot owner"


COMMITS = ['commit1', 'commit2', 'commit3', 'commit4', 'commit5']
PIPELINES = ['pipeline1', 'pipeline2', 'pipeline3', 'pipeline4', 'pipeline5']


def test_was_message_already_sent__was_sent_for_true_pivot(mocker):
    """
    Given:
        An index of a commit and a list of commits and pipelines with a positive pivot in newer pipelines
    When:
        The function was_message_already_sent is called with the index, commits and pipelines
    Then:
        It should return True since the message was already sent for newer pipelines
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit, pipelines: commit)
    mocker.patch('Tests.scripts.common.is_pivot', return_value=True)

    assert was_message_already_sent(2, COMMITS, PIPELINES) is True


def test_was_message_already_sent__was_sent_for_false_pivot(mocker):
    """
    Given:
        An index of a commit and a list of commits and pipelines with a negative pivot in newer pipelines
    When:
        The function was_message_already_sent is called with the index, commits and pipelines
    Then:
        It should return True since the message was already sent for newer pipelines
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit, pipelines: commit)
    mocker.patch('Tests.scripts.common.is_pivot', return_value=False)
    assert was_message_already_sent(2, COMMITS, PIPELINES) is True


def test_was_message_already_sent__was_not_sent(mocker):
    """
    Given:
        An index of a commit and a list of commits and pipelines with a no pivots in newer pipelines
    When:
        The function was_message_already_sent is called with the index, commits and pipelines
    Then:
        It should return False since the message was not sent for newer pipelines
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit, pipelines: commit)
    mocker.patch('Tests.scripts.common.is_pivot', return_value=None)
    assert was_message_already_sent(2, COMMITS, PIPELINES) is False


def test_was_message_already_sent__was_not_sent_no_pipeline(mocker):
    """
    Given:
        An index of a commit that has no pipeline and a list of commits and pipelines with a positive pivot in newer pipelines
    When:
        The function was_message_already_sent is called with the index, commits and pipelines
    Then:
        It should return False since the message was not sent for newer pipelines since current commit has no pipeline
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit, pipelines: commit)
    mocker.patch('Tests.scripts.common.is_pivot', return_value=True)
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit,
                 pipelines: None if commit == 'commit2' else commit)
    assert was_message_already_sent(2, COMMITS, PIPELINES) is False


def test_get_nearest_newer_commit__with_pipeline(mocker):
    """
    Given:
        A list of commits and pipelines, but only the first commit has a pipeline
    When:
        The function get_nearest_commit_with_pipeline is called with the list of commits,
        the index of current commit and "newer" as the direction
    Then:
        It should return the first commit since he is the closest with a pipeline,
        and a list of all commits between the first commit and the current one that are suspicious
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit,
                 pipelines: commit if commit == 'commit1' else None)
    pipeline, suspicious_commits = get_nearest_newer_commit_with_pipeline(PIPELINES, COMMITS, 3)
    assert pipeline == 'commit1'
    assert suspicious_commits == ['commit3', 'commit2']


def test_get_nearest_older_commit__with_pipeline(mocker):
    """
    Given:
        A list of commits and pipelines, but only the last commit has a pipeline
    When:
        The function get_nearest_older_commit_with_pipeline is called with the list of commits,
    Then:
        It should return the last commit since he is the closest with a pipeline,
        and a list of all commits between the last commit and the current one that are suspicious
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', side_effect=lambda commit,
                 pipelines: commit if commit == 'commit5' else None)
    pipeline, suspicious_commits = get_nearest_older_commit_with_pipeline(PIPELINES, COMMITS, 1)
    assert pipeline == 'commit5'
    assert suspicious_commits == ['commit2', 'commit3', 'commit4']


def test_get_nearest_newer_commit_with_pipeline__no_pipelines(mocker):
    """
    Given:
        A list of commits and pipelines, but no commit has a pipeline
    When:
        The function get_nearest_newer_commit_with_pipeline is called with the list of commits,
    Then:
        It should return None since no commit has a pipeline.
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', return_value='pipeline_for_commit')
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', return_value=None)
    pipeline, suspicious_commits = get_nearest_newer_commit_with_pipeline(PIPELINES, COMMITS, 2)
    assert pipeline is None
    assert suspicious_commits is None


def test_get_nearest_older_commit_with_pipeline__no_pipelines(mocker):
    """
    Given:
        A list of commits and pipelines, but no commit has a pipeline
    When:
        The function get_nearest_older_commit_with_pipeline is called with the list of commits,
    Then:
        It should return None since no commit has a pipeline.
    """
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', return_value='pipeline_for_commit')
    mocker.patch('Tests.scripts.common.get_pipeline_by_commit', return_value=None)
    pipeline, suspicious_commits = get_nearest_older_commit_with_pipeline(PIPELINES, COMMITS, 2)
    assert pipeline is None
    assert suspicious_commits is None
