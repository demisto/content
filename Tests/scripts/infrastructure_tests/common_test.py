from Tests.scripts import common
import pytest


def test_person_in_charge(mocker):
    """
    Given a commit object
    When person_in_charge is called on it
    Then it should return the expected name and PR link
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.author_email = 'john@doe.com'
    commit.title = 'Merge branch \'master\' into branch-name (#123)'

    expected = ('John Doe', 'https://github.com/demisto/content/pull/123')

    result = common.person_in_charge(commit)

    assert result == expected

@pytest.mark.parametrize('pipeline1_date, pipeline2_date, expected', [
    ('2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z', False),
    ('2020-01-02T00:00:00Z', '2020-01-01T00:00:00Z', True)])
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

    result = common.are_pipelines_in_order(pipeline1, pipeline2)

    assert result == expected


@pytest.mark.parametrize('pipeline1_status, pipeline2_status, expected', [
    ('success', 'failed', True),
    ('failed','success', False),
    ('success','success', None),
    ('failed', 'in progress', None)
    ])
def test_is_pivot(mocker, pipeline1_status, pipeline2_status, expected):
    """
    Given:
        - Two pipelines with their statuses.
    When:
        - is_pivot is called on them.
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
    
    mocker.patch.object(common, 'are_pipelines_in_order', return_value=(True))
    result = common.is_pivot(pipeline2, pipeline1)

    assert result == expected



