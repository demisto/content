from typing import Any

import pytest

from Tests.scripts.github_client import GithubClient, GithubPullRequest


@pytest.fixture
def sha() -> str:
    return "mock_sha"


@pytest.fixture
def branch() -> str:
    return "mock_job_name"


@pytest.fixture
def pull_request(sha: str, branch: str, requests_mock: Any) -> GithubPullRequest:
    requests_mock.get(
        f"{GithubClient.base_url}/search/issues?q={sha}+repo:demisto/content+is:pull-request+head:{branch}+is:open",
        json={
            "total_count": 1,
            "items": [
                {"node_id": "mock_node_id", "body": "b", "comments_url": "https://comments_url"},
            ]
        },
    )
    return GithubPullRequest("mock_token", sha1=sha, branch=branch)


def test_add_comment(pull_request: GithubPullRequest, requests_mock: Any) -> None:
    req = requests_mock.post("https://comments_url")
    pull_request.add_comment("c")
    assert req.called_once


def test_edit_comment(pull_request: GithubPullRequest, requests_mock: Any) -> None:
    req = requests_mock.post(f"{GithubClient.base_url}/graphql")
    pull_request.edit_comment("c", append=True)
    assert req.called_once
