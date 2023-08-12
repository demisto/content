import requests
from Tests.scripts.utils import logging_wrapper as logging


class GithubClient:
    def __init__(
        self,
        github_token: str,
        verify: bool = False,
        fail_on_error: bool = False,
        repository: str = "demisto/content",
    ) -> None:
        self.base_url = "https://api.github.com"
        self.headers = {"Authorization": f"Bearer {github_token}"}
        self.verify = verify
        self.fail_on_error = fail_on_error
        self.repository = repository

    def handle_error(self, err: str) -> None:
        if self.fail_on_error:
            raise Exception(err)
        logging.warning(err)

    def http_request(
        self,
        method: str = "GET",
        url_suffix: str | None = None,
        params: dict | None = None,
        json_data: dict | None = None,
        full_url: str | None = None,
    ) -> dict | None:
        if url_suffix:
            full_url = f"{self.base_url}{url_suffix}"
        if not full_url:
            raise Exception("Could not make the API call - a url must be provided.")

        response = requests.request(
            method,
            full_url,
            params=params,
            json=json_data,
            headers=self.headers,
            verify=self.verify,
        )
        try:
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.handle_error(
                f"{method} request to github failed: {e}"
            )
            return None

    def graphql(
        self,
        query: str,
        variables: dict | None = None,
    ) -> dict | None:
        return self.http_request(
            "POST",
            url_suffix="/graphql",
            json_data={"query": query, "variables": variables},
        )

    def search_pulls(
        self,
        sha1: str | None = None,
        branch: str | None = None,
        is_open: bool | None = None,
    ) -> dict:
        q = []
        if sha1:
            q.append(sha1)
        q.extend([f"repo:{self.repository}", "is:pull-request"])
        if branch:
            q.append(f"head:{branch}")
        if is_open is not None:
            q.append("is:open" if is_open else "is:closed")
        return self.http_request(
            "GET",
            f"/search/issues?q={'+'.join(q)}",
        )

    def get_pull(
        self,
        sha1: str | None = None,
        branch: str | None = None,
        is_open: bool = True,
    ) -> dict:
        if not (sha1 or branch):
            self.handle_error("Did not provide enough details to get PR data.")
            return {}

        res: dict = self.search_pulls(sha1, branch, is_open)
        if not res or res.get('total_count', 0) != 1:
            self.handle_error(
                f"Could not find a pull request where {branch=}, {sha1=}, {is_open=}"
            )
            return {}
        pulls: list = res["items"]
        return pulls[0]


class GithubPullRequest(GithubClient):
    def __init__(
        self,
        github_token: str,
        verify: bool = False,
        sha1: str | None = None,
        branch: str | None = None,
        fail_on_error: bool = False,
        repository: str = "demisto/content",
    ) -> None:
        super().__init__(github_token, verify, fail_on_error, repository)
        self.data: dict = self.get_pull(sha1, branch)

    def add_comment(self, comment: str) -> None:
        """Adds a comment to the pull request.

        Args:
            comment (string): The comment text.
            branch (str): The branch name.
            sha1 (str): The commit SHA.
        """
        self.http_request(
            "POST",
            full_url=self.data.get("comments_url"),
            json_data={"body": comment},
        )

    def edit_comment(
        self,
        comment: str,
        append: bool = True,
    ) -> None:
        """Edits the first comment (AKA "body") of the pull request.

        Args:
            comment (string): The comment text.
            pull_request (dict): The pull request data ().
            append (bool, default: True): Whether to append to or override the existing comment.
        """
        if append:
            comment = f"{self.data.get('body')}\n{comment}"
        self.graphql(
            query="""
                mutation UpdateComment($nodeId: ID!, $comment: String!) {
                    updateIssueComment(input: {
                        id: $nodeId,
                        body: $comment
                    }) {
                        issueComment {
                            lastEditedAt
                        }
                    }
                }
            """,
            variables={
                "nodeId": self.data.get("node_id"),
                "comment": comment,
            },
        )
