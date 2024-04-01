from io import BytesIO
from pathlib import Path
from zipfile import ZipFile
import requests
import typer
from urllib3 import disable_warnings

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper


ORG_NAME = "demisto"
DOCS_REPO_NAME = "content-docs"
SDK_REPO_NAME = "demisto-sdk"

disable_warnings()

install_logging("create_sdk_pr.log", logger=logging_wrapper)

REPOS_API_PREFIX = "https://api.github.com/repos"


class CannotFindWorkflowError(ValueError): ...


class CannotFindArtifactError(ValueError): ...


class GitHubClient:
    def __init__(
        self,
        branch_name: str,
        github_token: str,
        organization: str,
        repo: str,
        is_draft: bool,
    ) -> None:
        self.organization = organization
        self.repo = repo
        self.branch_name = branch_name
        self.is_draft = is_draft
        self.headers = {
            "Authorization": f"Bearer {github_token}",
            "accept": "application/vnd.github+json",
        }

    @property
    def base_url(self) -> str:
        return f"{REPOS_API_PREFIX}/{self.organization}/{self.repo}"

    def get_file(self, path: Path) -> dict:
        res = requests.get(
            url=f"https://raw.githubusercontent.com/{ORG_NAME}/{DOCS_REPO_NAME}/{self.branch_name}/{path!s}",
            headers=self.headers,
        )
        res.raise_for_status()
        return res.json()

    def commit_file(self, path_in_repo: Path, content: str, commit_message: str):
        res = requests.put(
            url=f"{self.base_url}/contents/{path_in_repo!s}",
            params={
                "message": commit_message,
                "content": content,
                "branch": self.branch_name,
                "sha": self.get_file(path_in_repo)["sha"],
            },
            headers=self.headers,
        )
        res.raise_for_status()

    def create_pr(self, title: str, body: str, reviewer: str):
        create_res = requests.post(
            url=f"{self.base_url}/pulls",
            json={
                "base": "master",
                "head": self.branch_name,
                "title": title,
                "body": body,
                "draft": self.is_draft,
            },
            headers=self.headers,
        )
        create_res.raise_for_status()
        pr_number = create_res.json()["number"]

        assign_res = requests.post(
            f"{self.base_url}/pulls/{pr_number}/requested_reviewers",
            json={"reviewers": [reviewer]},
        )
        assign_res.raise_for_status()

    def get_most_recent_workflow_run_id(self, workflow_name: str) -> int:
        res = requests.get(
            url=f"{self.base_url}/actions/runs",
            params={"branch": self.branch_name},
            verify=False,  # TODO remove
        )
        res.raise_for_status()
        if res.json()["total_count"] == 0:
            raise CannotFindWorkflowError(
                f"Could not find workflows with {workflow_name=} for {self.branch_name=}"
            )

        if not (
            matching_name := sorted(
                (
                    run
                    for run in res.json()["workflow_runs"]
                    if run["name"] == workflow_name
                ),
                key=lambda run: run["created_at"],
            )
        ):
            raise ValueError(
                f"Could not find workflows with {workflow_name=} in {self.branch_name=}"
            )

        return matching_name[-1]["id"]

    def get_workflow_artifact_zip(
        self, workflow_id: int, artifact_name: str
    ) -> ZipFile:
        res = requests.get(
            url=f"{self.base_url}/actions/runs/{workflow_id}/artifacts",
            verify=False,  # TODO remove
        )
        res.raise_for_status()
        if not res.json()["total_count"]:
            raise CannotFindArtifactError(
                f"Counld not find any artifacts for {workflow_id=}"
            )
        matching_name = [
            artifact
            for artifact in res.json()["artifacts"]
            if artifact["name"] == artifact_name
        ]
        if not matching_name:
            raise CannotFindArtifactError
        if len(matching_name) != 1:
            raise CannotFindArtifactError(
                f"expected only one artifact with {artifact_name=}, found {len(matching_name)}"
            )
        file = requests.get(
            url=matching_name[0]["archive_download_url"],
            headers=self.headers,
            verify=False,  # TODO remove verify=false
        )
        file.raise_for_status()
        return ZipFile(BytesIO(file.content))


def compile_validate_docs(readme_markdown: str, checks_markdown: str) -> str:
    document_header = "\n".join(
        (
            "---",
            "id: demisto-sdk-validate",
            "title: Demisto-SDK Validate checks",
            "---",
        )
    )

    return (
        "\n\n".join((document_header, readme_markdown, checks_markdown))
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )  # required for docusaurus


def main(
    github_token: str, branch_name: str, release_owner: str, is_draft: bool
) -> None:
    # Get generated `validate` docs from the branch workflow
    sdk_client = GitHubClient(
        organization=ORG_NAME,
        repo=SDK_REPO_NAME,
        branch_name=branch_name,
        is_draft=is_draft,
        github_token=github_token,
    )

    try:
        checks_markdown_artifact_zip = sdk_client.get_workflow_artifact_zip(
            artifact_name="validation_docs",
            workflow_id=sdk_client.get_most_recent_workflow_run_id(
                workflow_name="CI - On Push"
            ),
        )
    except CannotFindArtifactError:
        raise typer.Exit(0)  # TODO log

    # Commit to content-docs
    docs_client = GitHubClient(
        organization=ORG_NAME,
        repo=DOCS_REPO_NAME,
        branch_name=branch_name,
        is_draft=is_draft,
        github_token=github_token,
    )

    docs_client.commit_file(
        path_in_repo=Path("docs/concepts/demisto-sdk-validate.md"),
        content=compile_validate_docs(
            readme_markdown=sdk_client.get_file(
                Path("demisto_sdk/commands/validate/README.md")
            )["content"],
            checks_markdown=str(
                checks_markdown_artifact_zip.read("validation_docs.md"),
                encoding="utf-8",
            ),
        ),
        commit_message=f"SDK v{branch_name} Validate docs",
    )
    docs_client.create_pr(
        title=f"SDK Validate docs: {branch_name}",
        body="Automated update of SDK validate docs",
        reviewer=release_owner,
    )


if __name__ == "__main__":
    typer.run(main)
