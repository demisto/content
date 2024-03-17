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
    batch_index: int = typer.Argument(
        default="0",
        help="The batch index",
    ),
    coverage_report: str = typer.Argument(
        default="Utils/auto_update_docker/coverage_report.json",
        help="The coverage report from last nightly",
    ),
    docker_images_latest_tag_path: str = typer.Argument(
        default="",
        help="The file that contains the docker images tag, if given an empty string, will retrieve them latest tags from dockerhub",
    ),
):
    ...

def main():
    app()


if __name__ == "__main__":
    main()
