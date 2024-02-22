from pathlib import Path
from Tests.scripts.common import get_reviewer, get_person_in_charge, are_pipelines_in_order, is_pivot, get_slack_user_name
from requests_mock import MockerCore


NAME_AND_PR_URL = ('John Doe', 'https://github.com/demisto/content/pull/123')


def test_get_person_in_charge(mocker):
    """
    Given:
        A commit with author name and title
    When:
        The function get_person_in_charge is called with that commit
    Then:
        It should return a tuple with the author name and the pull request URL
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug (#123)'

    result = get_person_in_charge(commit)
    assert result == NAME_AND_PR_URL


def test_get_person_in_charge__multiple_IDs(mocker):
    """
    Given:
        A commit with author name and title, and multiple IDs in the title (common when a PR is from a contributor)
    When:
        The function get_person_in_charge is called with that commit
    Then:
        It should return the a tuple with the author name and the pull request URL, with only the last ID in the URL
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug (#456) (#123)'

    result = get_person_in_charge(commit)
    assert result == NAME_AND_PR_URL


def test_get_person_in_charge__no_parenthesis(mocker):
    """
    Given:
        A commit with author name and title and the ID in the title is not in parenthesis
    When:
        The function get_person_in_charge is called with the commit
    Then:
        It should return the author name and the pull request URL even if the ID was not in parenthesis
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.title = 'Fix a bug #123'

    result = get_person_in_charge(commit)
    assert result == NAME_AND_PR_URL


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
    assert result == (None, None)


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
