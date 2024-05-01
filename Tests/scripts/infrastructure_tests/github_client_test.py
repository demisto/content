from typing import Any

import pytest

from Tests.scripts.github_client import GithubClient, GithubPullRequest


SHA = "mock_sha"
BRANCH = "mock_branch"
COMMENTS_URL = "https://comments_url"  # disable-secrets-detection


@pytest.fixture
def pull_request(requests_mock: Any) -> GithubPullRequest:
    requests_mock.get(
        f"{GithubClient.base_url}/search/issues?q={SHA}+repo:demisto/content+is:pull-request+head:{BRANCH}+is:open",
        json={
            "total_count": 1,
            "items": [
                {
                    "node_id": "mock_node_id",
                    "body": "b",
                    "comments_url": COMMENTS_URL,
                },
            ]
        },
    )
    return GithubPullRequest("mock_token", sha1=SHA, branch=BRANCH)


def test_add_comment(pull_request: GithubPullRequest, requests_mock: Any) -> None:
    req = requests_mock.post(COMMENTS_URL)
    pull_request.add_comment("c")
    assert req.called_once


def test_edit_comment(pull_request: GithubPullRequest, requests_mock: Any) -> None:
    req = requests_mock.post(f"{GithubClient.base_url}/graphql")
    pull_request.edit_comment("c", append=True)
    assert req.called_once
