import re
import requests
from Tests.scripts.utils import logging_wrapper as logging


class GithubClient:
    base_url = "https://api.github.com"

    def __init__(
        self,
        github_token: str,
        verify: bool = False,
        fail_on_error: bool = False,
        repository: str = "demisto/content",
    ) -> None:
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
        res = self.http_request(
            "POST",
            url_suffix="/graphql",
            json_data={"query": query, "variables": variables},
        )
        if res.get("errors"):
            self.handle_error("\n".join([e.get("message") for e in res["errors"]]))
        return res

    def search_pulls(
        self,
        sha1: str | None = None,
        branch: str | None = None,
        is_open: bool | None = None,
    ) -> dict | None:
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

        res = self.search_pulls(sha1, branch, is_open)
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
        logging.info(f"Adding a comment to pull request #{self.data.get('number')}")
        self.http_request(
            "POST",
            full_url=self.data.get("comments_url"),
            json_data={"body": comment},
        )

    def edit_comment(
        self,
        comment: str,
        append: bool = False,
        comment_tag: str | None = None,
    ) -> dict | None:
        """Edits the first comment (AKA "body") of the pull request.

        Args:
            comment (string): The comment text.
            append (bool, default: False): Whether to append to or override the existing comment.
            comment_tag (str | None): If provided, tries to find existing text wrapped by comment tags
                                      and replace it with `comment` value.
                                      If the comment tags do not exist, appends `comment` surrounded by them.
                                      
                                      Example:
                                        body = "Hello, <!-- COMMENT_TAG - START -->world<!-- COMMENT_TAG - END -->!"
                                        comment = "bye"
                                        comment_tag = "COMMENT_TAG"
                                        Results to:
                                            "Hello, <!-- COMMENT_TAG - START -->bye<!-- COMMENT_TAG - END -->!"
        """
        logging.info(f"Editing comment of pull request #{self.data.get('number')}")
        current_comment = self.data.get("body")
        updated_comment = comment

        if comment_tag:
            append = False
            tags_template = "<!-- {comment_tag} - START -->\n{comment}\n<!-- {comment_tag} - END -->"
            replace_pattern = tags_template.format(comment_tag=comment_tag, comment="(.*?)")
            if re.match(replace_pattern, current_comment):
                updated_comment = re.sub(replace_pattern, current_comment, comment)
            else:
                comment = tags_template.format(comment_tag=comment_tag, comment=comment)
                append = True
        if append:
            updated_comment = f"{self.data.get('body')}\n{comment}"
        return self.graphql(
            query="""
                mutation UpdateComment($nodeId: ID!, $comment: String!) {
                    updatePullRequest(input: {
                        pullRequestId: $nodeId,
                        body: $comment
                    }) {
                        pullRequest {
                            lastEditedAt
                        }
                    }
                }
            """,
            variables={
                "nodeId": self.data.get("node_id"),
                "comment": updated_comment,
            },
        )
