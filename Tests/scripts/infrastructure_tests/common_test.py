from Tests.scripts.common import get_reviewer, get_person_in_charge, are_pipelines_in_order, is_pivot, get_slack_user_name
import pytest
from requests_mock import MockerCore


def test_get_person_in_charge(mocker):
    """
    Given a commit object
    When get_person_in_charge is called on it
    Then it should return the expected name and PR link
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.author_email = 'john@doe.com'
    commit.title = 'Merge branch \'master\' into branch-name (#123)'

    expected = ('John Doe', 'https://github.com/demisto/content/pull/123')

    result = get_person_in_charge(commit)

    assert result == expected


@pytest.mark.parametrize(('pipeline1_date, pipeline2_date, expected'),(
    pytest.param('2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z', False, id= "pipelines not in order"),
    pytest.param('2020-01-02T00:00:00Z', '2020-01-01T00:00:00Z', True, id= "pipelines in order")))
def test_are_pipelines_in_order(mocker, pipeline1_date, pipeline2_date, expected):
    """
    Given:
        - Two pipelines with their created_at dates.
    When:
        - are_pipelines_in_order is called on them.
    Then:
        - It should return the expected result.
          scenario 1: pipeline1.created_at > pipeline2.created_at -> False
          scenario 2: pipeline1.created_at < pipeline2.created_at -> True
    """
    pipeline1 = mocker.Mock()
    pipeline1.id = '1'
    pipeline1.created_at = pipeline1_date

    pipeline2 = mocker.Mock()
    pipeline2.id = '2'
    pipeline2.created_at = pipeline2_date

    result = are_pipelines_in_order(pipeline1, pipeline2)

    assert result == expected


@pytest.mark.parametrize(('pipeline1_status, pipeline2_status, expected'),(
    pytest.param('success', 'failed', True, id= "negative pivot"),
    pytest.param('failed', 'success', False, id= "positiv pivot"),
    pytest.param('success', 'success', None, id = "no change"),
    pytest.param('failed', 'in progress', None, id = "pipeline still running")))
def test_is_pivot(mocker, pipeline1_status, pipeline2_status, expected):
    """
    Given:
        - Two pipelines with their statuses.
    When:
        - Checking on status change. 
    Then:
        - It should return the expected result.
          scenario 1: pipeline1.status =='success' and pipeline2.status == 'failed' -> True
          scenario 2: pipeline1.status == 'failed' and pipeline2.status =='success' -> False
          scenario 3: pipeline1.status =='success' and pipeline2.status =='success' -> None
          scenario 4: pipeline1.status == 'failed' and pipeline2.status == 'in progress' -> None
    """
    pipeline1 = mocker.Mock()
    pipeline1.status = pipeline1_status
    pipeline2 = mocker.Mock()
    pipeline2.status = pipeline2_status

    mocker.patch('Tests.scripts.common.are_pipelines_in_order', return_value=(True))
    result = is_pivot(pipeline2, pipeline1)

    assert result == expected


@pytest.mark.parametrize(('response, expected'), (
    pytest.param([], None, id ="no reviewer"),
    pytest.param([{"Jon": "test", "state": "test", "user": {"login": "Jon"}},
      {"Jane Doe": "test", "state": "APPROVED", "user": {"login": "Jane Doe"}}], "Jane Doe", id = "one reviewer approved"),
    pytest.param([{"Jon": "test", "state": "APPROVED", "user": {"login": "Jon"}},
     {"Jane Doe": "test", "state": "APPROVED", "user": {"login": "Jane Doe"}}], "Jon", id = "2 reviewers approved"),
))
def test_get_reviewer(response, expected, requests_mock: MockerCore):
    """
    Given:
        - A PR URL.
    When:
        - get_reviewer is called on it.
    Then:
        - It should return the expected result.
        scenario 1: No reviewers -> None
        scenario 2: One reviewer who approved -> "Jane Doe"
        scenario 3: Two reviewers who approved -> the first one - "Jon"
    """
    pr_url = 'https://github.com/owner/repo/pull/123'
    requests_mock.get('https://api.github.com/repos/owner/repo/pulls/123/reviews', json=response)
    result = get_reviewer(pr_url)
    assert result == expected


@pytest.mark.parametrize(('name, expected'),( 
    pytest.param("Mike", "mike", id ="name in map"),
    pytest.param("Jon", "Jon", id = "name not in map"),
    pytest.param("github-actions[bot]", "docker images bot owner", id= "name is 'github-actions[bot]'")
))
def test_get_slack_user_name(name, expected):
    """
    Given:
        - A name and a name mapping file path.
    When:
        - get_slack_user_name is called on it.
    Then:
        - It should return the expected result.
        scenario 1: name is in the mapping -> the mapped name
        scenario 2: name is not in the mapping -> name
        scenario 3: name is 'github-actions[bot]' -> the owner of the docker image update bot.
    """
    results = get_slack_user_name(name, 'tests_data/test_mapping.json')
    assert results == expected
