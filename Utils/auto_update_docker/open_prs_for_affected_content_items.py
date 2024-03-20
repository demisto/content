from dotenv import load_dotenv
from typing import Any
from git import Repo, GitCommandError, IndexFile  # pip install GitPython
from pathlib import Path
from github import Github, GithubException, Repository  # pip install PyGithub
from demisto_sdk.commands.common.handlers import DEFAULT_JSON_HANDLER as json
import os
import logging
import pathspec
import typer

logging.basicConfig(level=logging.INFO)
load_dotenv()
app = typer.Typer(no_args_is_help=True)

def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())



@app.command()
def get_affected_content_items(
    affected_content_items: str = typer.Argument(
        default="Utils/auto_update_docker/affected_content_items.json",
        help="The affected content items that will have their image tags updated",
    ),
    staging_branch: str = typer.Argument(
        default="auto",
        help="The staging branch, that will act as the base branch for the PRs",
    ),
    prs_limit: str = typer.Argument(
        default="10",
        help="The maximum number of content items to open in one PR",
    ),
):
    org_name = "demisto"
    repo_name = "content"
    remote_github_controller = Github(os.getenv("GITHUB_ACCESS_TOKEN"), verify=False)
    # Get the remote repo that is at Github
    remote_content_repo = remote_github_controller.get_repo(f"{org_name}/{repo_name}")
    # Run the script in a git-initialized repo
    repo = Repo(".")
    index = repo.index
    origin = repo.remotes.origin
    # Get current active branch
    active_branch = repo.active_branch
    logging.info(f'Checking out master\n{repo.git.checkout("master")}')
    # Pull from master
    origin.pull()

    # Check if the staging branch exists, if not, create one:
    remote_github_controller
def main():
    app()


if __name__ == "__main__":
    main()
