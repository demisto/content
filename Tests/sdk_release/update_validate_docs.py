import base64
from io import BytesIO
from pathlib import Path
from typing import Annotated
from zipfile import ZipFile
import requests
import typer
from urllib3 import disable_warnings

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logger


ORG_NAME = "demisto"
DOCS_REPO_NAME = "content-docs"
SDK_REPO_NAME = "demisto-sdk"

disable_warnings()

install_logging("update_validate_docs.log", logger=logger)

REPOS_API_PREFIX = "https://api.github.com/repos"


def decode_base64(b64: str) -> str:
    return base64.b64decode(b64).decode("utf-8")


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
        self.branch = branch_name
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
            f"{self.base_url}/contents/{path!s}",
            headers=self.headers,
        )
        res.raise_for_status()
        return res.json()

    def create_branch(self) -> None:
        sha = requests.get(
            f"{self.base_url}/branches/master",
            headers=self.headers,
        ).json()["commit"]["sha"]

        try:
            res = requests.post(
                f"{self.base_url}/git/refs",
                headers=self.headers,
                json={"ref": f"refs/heads/{self.branch}", "sha": sha},
            )
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if (
                res.status_code == 422
                and res.json()["message"] == "Reference alreay exists"
            ):
                raise ValueError("branch alredy exists") from e

    def commit_file(self, path_in_repo: Path, content: str, commit_message: str):
        res = requests.put(
            url=f"{self.base_url}/contents/{path_in_repo!s}",
            json={
                "message": commit_message,
                "content": base64.b64encode(bytes(content, encoding="utf8")).decode(
                    "utf-8"
                ),
                "branch": self.branch,
                "sha": self.get_file(path_in_repo)["sha"],
            },
            headers=self.headers,
        )
        res.raise_for_status()

    def create_pr(self, title: str, body: str, reviewer: str) -> int:
        create_res = requests.post(
            url=f"{self.base_url}/pulls",
            json={
                "base": "master",
                "head": self.branch,
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
            headers=self.headers,
        )
        assign_res.raise_for_status()
        return pr_number

    def get_most_recent_workflow_run_id(self, workflow_name: str) -> int:
        res = requests.get(
            url=f"{self.base_url}/actions/runs",
            params={"branch": self.branch},
        )
        res.raise_for_status()
        if res.json()["total_count"] == 0:
            raise CannotFindWorkflowError(
                f"Could not find workflows with {workflow_name=} for {self.branch=}"
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
                f"Could not find workflows with {workflow_name=} in {self.branch=}"
            )

        return matching_name[-1]["id"]

    def get_workflow_artifact_zip(
        self, workflow_id: int, artifact_name: str
    ) -> ZipFile:
        res = requests.get(
            url=f"{self.base_url}/actions/runs/{workflow_id}/artifacts",
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
        file = requests.get(
            url=matching_name[0]["archive_download_url"],
            headers=self.headers,
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
        "\n\n".join(
            (document_header, readme_markdown, checks_markdown.replace("\\n", "\n"))
        )
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )  # required for docusaurus


def main(
    github_token: Annotated[str, typer.Option("-t", "--github-token")],
    branch_name: Annotated[str, typer.Option("-b", "--branch-name")],
    release_owner: Annotated[str, typer.Option("-r", "--reviewer")],
    is_draft: Annotated[bool, typer.Option("-d", "--draft")],
    artifact_folder: Annotated[Path, typer.Option("-f", "--artifact-folder")],
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
        logger.warning(
            "Cannot find the artifact containing validation docs. "
            "This is OK when validations don't change between SDK releases."
        )
        raise typer.Exit(0)
    checks_markdown = checks_markdown_artifact_zip.read("validation_docs.md").decode(
        "utf-8"
    )
    # Commit to content-docs
    docs_client = GitHubClient(
        organization=ORG_NAME,
        repo=DOCS_REPO_NAME,
        branch_name=branch_name,
        is_draft=is_draft,
        github_token=github_token,
    )
    docs_client.create_branch()
    docs_client.commit_file(
        path_in_repo=Path("docs/concepts/demisto-sdk-validate.md"),
        content=compile_validate_docs(
            readme_markdown=decode_base64(
                sdk_client.get_file(Path("demisto_sdk/commands/validate/README.md"))[
                    "content"
                ]
            ),
            checks_markdown=checks_markdown,
        ),
        commit_message=f"SDK v{branch_name} Validate docs",
    )
    pr_number = docs_client.create_pr(
        title=f"SDK Validate docs: {branch_name}",
        body="Automated update of SDK validate docs",
        reviewer=release_owner,
    )

    (artifact_folder / "validate_release_notes_message.txt").write_text(
        f"SDK-Validate docs have changed, review [the content-docs PR](https://github.com/{ORG_NAME}/{DOCS_REPO_NAME}/pulls/{pr_number})"
    )


if __name__ == "__main__":
    typer.run(main)
