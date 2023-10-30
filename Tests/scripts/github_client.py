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
        if res and res.get("errors"):
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
        section_name: str | None = None,
    ) -> dict | None:
        """Edits the first comment (AKA "body") of the pull request.

        Args:
            comment (string): The comment text.
            append (bool, default: False): Whether to append to or override the existing comment.
            section_name (str | None): If provided, tries to find existing text wrapped by the section tags
                                       and if exists, replaces it with `comment` value. Otherwise, appends
                                       `comment` to the PR comment in a new section (i.e., wrapped by the tags).

                                       Example:
                                       body = "Hello, <!-- SECTION - START -->\nworld<!-- SECTION - END -->!"
                                       comment = "bye"
                                       section_name = "SECTION"
                                       Results to:
                                           "Hello, <!-- SECTION - START -->\nbye<!-- SECTION - END -->!"
        """
        logging.info(f"Editing comment of pull request #{self.data.get('number')}")
        current_comment = (self.data.get("body") or "").replace("\r\n", "\n")
        updated_comment = comment

        if section_name:
            append = False
            start_tag = f"<!-- {section_name} - START -->\n"
            end_tag = f"\n<!-- {section_name} - END -->"
            replace_pattern = f"({start_tag})(.*?)({end_tag})"
            if re.search(replace_pattern, current_comment, re.DOTALL):
                updated_comment = re.sub(replace_pattern, fr"\1{comment}\3", current_comment, flags=re.DOTALL)
            else:
                comment = f"{start_tag}{comment}{end_tag}"
                append = True
        if append:
            updated_comment = f"{current_comment}\n{comment}"
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
