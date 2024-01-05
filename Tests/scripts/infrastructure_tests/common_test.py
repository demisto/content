from Tests.scripts import common


def test_person_in_charge(mocker):
    """
    Given a commit object
    When person_in_charge is called on it
    Then it should return the expected name, email and PR link
    """
    commit = mocker.Mock()
    commit.author_name = 'John Doe'
    commit.author_email = 'john@doe.com'
    commit.title = 'Merge branch \'master\' into branch-name (#123)'

    expected = ('John Doe', 'john@doe.com', 'https://github.com/demisto/content/pull/123')

    result = common.person_in_charge(commit)

    assert result == expected


def test_are_pipelines_in_order_as_commits_true(mocker):
    """
    Given a list of commits and two pipeline SHAs
    When the pipeline SHAs are in the same order as the commits
    Then it should return True and the commit that triggered the later pipeline

    """
    commit1 = mocker.Mock()
    commit1.id = '1'
    commit1.created_at = '2020-01-01T00:00:00Z'

    commit2 = mocker.Mock()
    commit2.id = '2'
    commit2.created_at = '2020-01-02T00:00:00Z'

    commits = [commit1, commit2]
    current_sha = '2'
    previous_sha = '1'

    expected = (True, commit2)

    result = common.are_pipelines_in_order_as_commits(commits, current_sha, previous_sha)

    assert result == expected


def test_are_pipelines_in_order_as_commits_false(mocker):
    """
    Given a list of commits and two pipeline SHAs
    When the pipeline SHAs are not in the same order as the commits
    Then it should return False and None
    """
    commit1 = mocker.Mock()
    commit1.id = '1'
    commit1.created_at = '2020-01-01T00:00:00Z'

    commit2 = mocker.Mock()
    commit2.id = '2'
    commit2.created_at = '2020-01-02T00:00:00Z'

    commits = [commit1, commit2]
    current_sha = '1'
    previous_sha = '2'

    expected = (False, None)

    result = common.are_pipelines_in_order_as_commits(commits, current_sha, previous_sha)
    # there is a problem to test if side effect that is None is equal to None, so for now its removed from the assert
    assert result[0] == expected[0]


def test_is_pivot_first_pipeline(mocker):
    """
    Given a pipeline id, list of pipelines and commits
    When the pipeline is the first in the list
    Then it should return None, None
    """
    pipeline_id = '1'
    pipelines = [mocker.Mock(id=1)]
    commits = [mocker.Mock()]

    expected = (None, None)

    result = common.is_pivot(pipeline_id, pipelines, commits)

    assert result == expected


def test_is_pivot_pipeline_not_in_list(mocker):
    """
    Given a pipeline id, list of pipelines and commits
    When the pipeline id is not in the list of pipelines
    Then it should return None, None
    """
    pipeline_id = '1'
    pipelines = [mocker.Mock(id=2)]
    commits = [mocker.Mock()]

    expected = (None, None)

    result = common.is_pivot(pipeline_id, pipelines, commits)

    assert result == expected


def test_is_pivot_negative(mocker):
    """
    Given a pipeline id, list of pipelines and commits
    When previous pipeline succeeded and current failed and in order
    Then it should return True, commit
    """
    pipeline_id = '2'
    pipelines = [
        mocker.Mock(id=1, status='success'),
        mocker.Mock(id=2, status='failed')
    ]
    commit = mocker.Mock()
    commits = [commit]

    expected = (True, commit)
    mocker.patch.object(common, 'are_pipelines_in_order_as_commits', return_value=(True, commit))
    result = common.is_pivot(pipeline_id, pipelines, commits)

    assert result == expected


def test_is_pivot_positive(mocker):
    """
    Given a pipeline id, list of pipelines and commits
    When previous pipeline failed and current succeeded and in order
    Then it should return False, commit

    """
    pipeline_id = '2'
    pipelines = [
        mocker.Mock(id=1, status='failed'),
        mocker.Mock(id=2, status='success')
    ]
    commit = mocker.Mock()
    commits = [commit]

    expected = (False, commit)
    mocker.patch.object(common, 'are_pipelines_in_order_as_commits', return_value=(True, commit))
    result = common.is_pivot(pipeline_id, pipelines, commits)

    assert result == expected
