from dotenv import load_dotenv
from typing import Any
from git import Repo, Git, Remote  # pip install GitPython
from github import Github, GithubException, Repository  # pip install PyGithub
from demisto_sdk.commands.common.handlers import DEFAULT_JSON_HANDLER as json
import yaml
import os
import logging
import math
import typer

logging.basicConfig(level=logging.INFO)
load_dotenv()
app = typer.Typer(no_args_is_help=True)
CWD = os.getcwd()

def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def create_remote_pr(
    docker_image: str,
    current_batch: int,
    number_of_batches: int,
    target_tag: str,
    head_branch: str,
    remote_content_repo: Repository.Repository,
    pr_tags: list[str],
    pr_assignees: list[str] = [],
    pr_reviewers: list[str] = [],
    base_branch: str = "master",
):
    """Create the PR with the changes in the docker tag on the remote repo.

    Args:
        docker_image (str): The docker image.
        current_batch (int): PR batch number, with respect to docker image.
        number_of_batches (int): Overall number of batches.
        target_tag (str): The docker's target tag.
        head_branch (str): The head branch, that has the committed changes.
        remote_content_repo (Repository.Repository): Remote repository.
        pr_tags (list[str]): PR tags.
        pr_assignees (list[str], optional): PR assignee/s. Defaults to [].
        pr_reviewers (list[str], optional): PR reviewer/s. Defaults to [].
        base_branch (str, optional): The base branch. Defaults to "master".
    """
    body = "Auto update docker PR"
    title = f"Auto update docker for {docker_image}:{target_tag}. Batch #{current_batch}/{number_of_batches}"
    pr = remote_content_repo.create_pull(
        title=title,
        body=body,
        base=base_branch,
        head=head_branch,
        draft=True,
    )
    # pr.add_to_labels
    pr.create_review_request(reviewers=pr_reviewers)
    logging.info(f'Requested review from {",".join(sorted(pr_reviewers))}')

    pr.add_to_assignees(*pr_assignees)
    logging.info(f'Assigned to {",".join(sorted(pr_assignees))}')

    pr.set_labels(*pr_tags)
    logging.info(f'Set labels to {",".join(sorted(pr_tags))}')


def update_content_items_docker_images_and_push(
    docker_image: str,
    content_items: list[str],
    target_tag: str,
    pr_tags: list[str],
    current_batch: int,
    number_of_batches: int,
    staging_branch: str,
    git: Git,
    remote_content_repo: Repository.Repository,
    origin: Remote,
):
    """_summary_

    Args:
        docker_image (str): The docker image.
        content_items (list[str]): Content items to update their docker images.
        target_tag (str): Target tag of docker image.
        pr_tags (list[str]): PR tags.
        current_batch (int): PR batch number, with respect to docker image.
        number_of_batches (int): Overall number of batches.
        staging_branch (str): The staging branch, which is treated as the base branch of the PR.
        git (Git): Git object to stage and commit files.
        remote_content_repo (Repository.Repository): The remote repository. Used to created PRs.
        origin (Remote): Remote object. Used to open PRs on the remote repository.
    """
    logging.info(f"Updating the following content items: {','.join(content_items)}")
    current_batch_branch_name = f"AUD-{docker_image}-{target_tag}-batch-{current_batch}"
    # Create branch off of master
    git.checkout("-b", current_batch_branch_name, "master")
    yml_content: dict[str, Any] = {}
    updated_content_items: list[str] = []
    new_docker_image = f"{docker_image}:{target_tag}"
    for content_item in content_items:
        logging.info(f"Updating docker image of {content_item} to {new_docker_image}")
        with open(content_item) as f:
            yml_content = yaml.safe_load(f)
        if "dockerimage" in yml_content:
            # For scripts
            yml_content["dockerimage"] = new_docker_image
        elif "dockerimage" in yml_content.get("script", {}):
            yml_content["script"]["dockerimage"] = new_docker_image
            # For integrations
        else:
            logging.error(f"Could not locate docker image field in YAML, skipping {content_item}")
            continue
        with open(content_item, "w") as f:
            # We use width=float("inf") so yaml.dump does not add \n to long lines
            yaml.dump(yml_content, f, sort_keys=False, width=float("inf"))
        updated_content_items.append(content_item)

    git.add(updated_content_items)
    git.commit(
        "-m",
        f"Updated docker image to {docker_image}:{target_tag}. Batch #{current_batch}/{number_of_batches}",
    )

    create_remote_branch_result = origin.push(f"+refs/heads/{current_batch_branch_name}:refs/heads/{current_batch_branch_name}")
    logging.info(f"Created remote branch {current_batch_branch_name}")
    create_remote_branch_result.raise_if_error()
    create_remote_pr(
        remote_content_repo=remote_content_repo,
        docker_image=docker_image,
        current_batch=current_batch,
        number_of_batches=number_of_batches,
        target_tag=target_tag,
        head_branch=current_batch_branch_name,
        base_branch=staging_branch,
        pr_tags=pr_tags,
    )


@app.command()
def open_prs_for_content_items(
    affected_content_items_file: str = typer.Argument(
        default="Utils/auto_update_docker/affected_content_items.json",
        help="The affected content items that will have their image tags updated, supplied as a json",
    ),
    staging_branch: str = typer.Argument(
        default="auto_update_docker_staging_branch",
        help="The staging branch, that will act as the base branch for the PRs",
    ),
    prs_limit: str = typer.Argument(
        # TODO Change to 50 later
        default="2",
        help="The maximum number of content items to open in one PR",
    ),
):
    prs_limit_int = int(prs_limit)
    affected_content_items = load_json(affected_content_items_file)
    org_name = "demisto"
    repo_name = "content"
    remote_github_controller = Github(os.getenv("GITHUB_ACCESS_TOKEN"), verify=False)
    # Get the remote repo that is at Github
    remote_content_repo = remote_github_controller.get_repo(f"{org_name}/{repo_name}")
    master_branch_name = "master"
    # Run the script in a git-initialized repo
    repo = Repo(".")
    git = repo.git
    origin = repo.remotes.origin
    # To fetch al remote branches
    origin.fetch()

    logging.info(f'Checking out master\n{repo.git.checkout("master")}')
    # Pull from master
    origin.pull()
    source_branch = remote_content_repo.get_branch(master_branch_name)
    # Check if the staging branch exists, if not, create one
    try:
        src = remote_content_repo.get_git_ref(f"heads/{staging_branch}")
        # If reached here, that means there is a remote branch with the same name as the staging branch.

        # Make staging branch up to date with master
        src.edit(sha=source_branch.commit.sha)
    except GithubException as github_exception:
        if "Branch not found" in str(github_exception):
            # We need to create remote branch that corresponds to the staging branch
            remote_content_repo.create_git_ref(ref="refs/heads/" + staging_branch, sha=source_branch.commit.sha)
        else:
            raise github_exception

    try:
        for docker_image in affected_content_items:
            image_config = affected_content_items[docker_image]
            if content_items := image_config["content_items"]:
                number_of_batches = math.ceil(len(content_items) / prs_limit_int)
                # We divide the content items to batches
                batch_start = 0
                batch_end = batch_start + prs_limit_int
                for current_batch in range(1, number_of_batches + 1):
                    logging.info(f"{current_batch=}")
                    content_items_for_batch = content_items[batch_start:batch_end]
                    update_content_items_docker_images_and_push(
                        current_batch=current_batch,
                        number_of_batches=number_of_batches,
                        docker_image=docker_image,
                        staging_branch=staging_branch,
                        git=git,
                        remote_content_repo=remote_content_repo,
                        origin=origin,
                        content_items=content_items_for_batch,
                        pr_tags=image_config["pr_tags"],
                        target_tag=image_config["target_tag"],
                    )
                    batch_start = batch_end
                    batch_end = batch_start + prs_limit_int

    except Exception as e:
        logging.error(f"Got error when opening PRs {e}")


def main():
    app()


if __name__ == "__main__":
    main()
