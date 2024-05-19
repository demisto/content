from unittest.mock import Mock, patch

import pytest

from Utils.trigger_contribution_build import (
    cancel_active_pipelines,
    handle_contribution_prs,
)


@pytest.fixture
def mock_gitlab_project():
    return Mock()


@pytest.fixture
def mock_pipeline():
    return Mock()


@pytest.fixture
def mock_branch():
    return Mock(name="branch")


class MockIssue:
    def __init__(self, base_ref):
        self.base = Mock(ref=base_ref)
        self.number = 123


@pytest.fixture
def mock_github_issues():
    return [MockIssue("master")]


@pytest.fixture
def mock_new_pipeline():
    return Mock(web_url="http://example.com")


class mock_pull_request:
    def __init__(self, base_ref):
        self.base = Mock(ref=base_ref, return_value=base_ref)
        self.number = 123
        self.head = Mock()
        self.head.label = "label"


@pytest.fixture
def mock_args():
    return Mock()


@patch("Utils.trigger_contribution_build.logging")
def test_cancel_active_pipelines(
    mock_logging, mock_gitlab_project, mock_branch, mock_pipeline
):
    """
    Given:
        - A handled GitLab branch has one or more active pipelines.
    When:
        - Handling a GitLab branch.
    Then:
        - Cancel all active pipelines for this specific branch.
    """
    # Arrange
    mock_pipeline.id = 123
    mock_pipeline.cancel.return_value = None
    mock_gitlab_project.pipelines.list.return_value = [mock_pipeline]

    # Act
    cancel_active_pipelines(mock_gitlab_project, mock_branch)

    # Assert
    mock_pipeline.cancel.assert_called_once()
    mock_logging.info.assert_called_once_with("Canceling active pipeline: 123")


@patch("Utils.trigger_contribution_build.cancel_active_pipelines")
@patch("Utils.trigger_contribution_build.logging")
def test_handle_contribution_prs_exception_handling(
    mock_logging,
    mock_cancel_active_pipelines,
    mock_args,
    mock_github_issues,
    mock_gitlab_project,
    mock_branch,
):
    """
    Given:
        - An exception is raised.
    When:
        - Triggering a new pipeline for a given GitLab branch.
    Then:
        - Log the exception and continue to next branch.
    """
    # Arrange
    mock_branch.name = "master"
    mock_gitlab_project.branches.get.return_value = mock_branch
    mock_gitlab_project.trigger_pipeline.side_effect = Exception("Test exception")
    issue_mock = mock_github_issues[0]
    issue_mock.number = 123

    # Mocking `create_comment` and `as_pull_request` methods
    issue_mock.create_comment = Mock()
    issue_mock.as_pull_request = Mock(return_value=mock_pull_request(mock_branch.name))

    # Act
    handle_contribution_prs(mock_args, mock_github_issues, mock_gitlab_project)

    # Assertions
    mock_cancel_active_pipelines.assert_called_once_with(
        mock_gitlab_project, mock_branch
    )
    mock_logging.info.assert_any_call(
        "Trigger build for PR 123|base: master|contrib: label"
    )
    mock_logging.exception.assert_called_once_with(
        "Failed to trigger pipeline for: master. Error: Test exception"
    )
