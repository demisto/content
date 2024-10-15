import logging
import sys
import math
import os
from collections import defaultdict
from typing import Any

import typer
import yaml
from demisto_sdk.commands.common.handlers import DEFAULT_JSON_HANDLER as json
from dotenv import load_dotenv
from git import Git, Remote, Repo  # pip install GitPython
from github import Github, GithubException, Repository  # pip install PyGithub

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
    updated_content_items: list[str],
    coverage: str,
    pr_labels: list[str] = [],
    pr_assignees: list[str] = [],
    pr_reviewers: list[str] = [],
    base_branch: str = "master",
) -> str:
    """Create the PR with the changes in the docker tag on the remote repo.

    Args:
        docker_image (str): The docker image.
        current_batch (int): PR batch number, with respect to docker image.
        number_of_batches (int): Overall number of batches.
        target_tag (str): The docker's target tag.
        head_branch (str): The head branch, that has the committed changes.
        remote_content_repo (Repository.Repository): Remote repository.
        updated_content_items (list[str]): The content items that hold the changes of their docker tag.
        pr_labels (list[str]): The PR labels.
        pr_assignees (list[str], optional): PR assignee/s. Defaults to [].
        pr_reviewers (list[str], optional): PR reviewer/s. Defaults to [].
        base_branch (str, optional): The base branch. Defaults to "master".

    Returns:
        The PR URL link.
    """
    joined_content_items = "\n".join(updated_content_items)
    body = f"Auto updated docker tags for the following content items:\n{joined_content_items}"
    title = f"{docker_image}:{target_tag} | {coverage} | PR batch #{current_batch}/{number_of_batches}"
    pr = remote_content_repo.create_pull(
        title=title,
        body=body,
        base=base_branch,
        head=head_branch,
        draft=True,
    )

    if pr_reviewers:
        pr.create_review_request(reviewers=pr_reviewers)
        logging.info(f'Requested review from {",".join(sorted(pr_reviewers))}')

    if pr_assignees:
        pr.add_to_assignees(*pr_assignees)
        logging.info(f'Assigned to {",".join(sorted(pr_assignees))}')

    if pr_labels:
        pr.set_labels(*pr_labels)
        logging.info(f'Set labels to {",".join(sorted(pr_labels))}')
    return pr.html_url


def update_content_items_docker_images_and_push(
    docker_image: str,
    content_items: list[str],
    target_tag: str,
    coverage: str,
    pr_labels: list[str],
    current_batch: int,
    number_of_batches: int,
    staging_branch: str,
    git: Git,
    remote_content_repo: Repository.Repository,
    origin: Remote,
    pr_assignees: list[str],
    pr_reviewers: list[str],
) -> dict[str, Any]:
    """Updates the content items' docker tags, and pushes the changes to a remote branch.

    Args:
        docker_image (str): The docker image.
        content_items (list[str]): Content items to update their docker images.
        target_tag (str): Target tag of docker image.
        coverage (str): The coverage of the content items in the PR batch.
        pr_labels (list[str]): The PR labels.
        current_batch (int): PR batch number, with respect to docker image.
        number_of_batches (int): Overall number of batches.
        staging_branch (str): The staging branch, which is treated as the base branch of the PR.
        git (Git): Git object to stage and commit files.
        remote_content_repo (Repository.Repository): he remote repository. Used to created PRs.
        origin (Remote):  Remote object. Used to open PRs on the remote repository.
        pr_assignees (list[str]): The PR assignees.
        pr_reviewers (list[str]): The PR reviewers.

    Returns:
        dict[str, Any]: A dictionary that holds the content items that were updated, and their PR link.
    """
    logging.info(f"Updating the following content items: {','.join(content_items)}")
    current_batch_branch_name = f"AUD-{docker_image}-{target_tag}-pr-batch-{current_batch}"
    # Create branch off of master
    git.checkout("-b", current_batch_branch_name, "master")
    yml_content: dict[str, Any] = {}
    updated_content_items: list[str] = []
    new_docker_image = f"{docker_image}:{target_tag}"
    for content_item in content_items:
        logging.info(f"Updating docker image of {content_item} to {new_docker_image}")
        with open(content_item) as f:
            yml_content = yaml.safe_load(f)
        object_to_update = {}
        if "dockerimage" in yml_content:
            # For scripts
            object_to_update = yml_content
        elif "dockerimage" in yml_content.get("script", {}):
            # For integrations
            object_to_update = yml_content["script"]

        if object_to_update["dockerimage"] != new_docker_image:
            object_to_update["dockerimage"] = new_docker_image
        else:
            # No need to update if docker image is already the target
            logging.info(f"Docker image is already the target, skipping {content_item}")
            continue
        with open(content_item, "w") as f:
            # We use width=float("inf") so yaml.dump does not add \n to long lines
            yaml.dump(yml_content, f, sort_keys=False, width=float("inf"))
        updated_content_items.append(content_item)
    if not updated_content_items:
        # No content items were updated, skipping PR creation
        return {}

    git.add(updated_content_items)
    git.commit(
        "-m",
        f"Updated docker image to {docker_image}:{target_tag}. PR batch #{current_batch}/{number_of_batches}",
    )

    push_changes_to_remote_pr = origin.push(f"+refs/heads/{current_batch_branch_name}:refs/heads/{current_batch_branch_name}")
    logging.info(f"Created remote branch {current_batch_branch_name}")
    push_changes_to_remote_pr.raise_if_error()
    pr_link = create_remote_pr(
        remote_content_repo=remote_content_repo,
        docker_image=docker_image,
        current_batch=current_batch,
        number_of_batches=number_of_batches,
        target_tag=target_tag,
        head_branch=current_batch_branch_name,
        base_branch=staging_branch,
        pr_labels=pr_labels,
        updated_content_items=updated_content_items,
        pr_assignees=pr_assignees,
        pr_reviewers=pr_reviewers,
        coverage=coverage,
    )
    return {"content_items": updated_content_items, "pr_link": pr_link}


def comma_list(raw_data: str) -> list[str]:
    return raw_data.split(",") if raw_data else []


@app.command()
def open_prs_for_content_items(
    staging_branch: str = typer.Option(
        help="The staging branch, that will act as the base branch for the PRs",
    ),
    batch_dir: str = typer.Option(
        default="",
        help="The batch directory, holds the input of the script, under the file affected_content_items.json,"
        " and the output of the current script",
    ),
    prs_limit: str = typer.Option(
        # TODO Change to 10 later
        default="10",
        help="The maximum number of content items to open in one PR",
    ),
    pr_assignees: list = typer.Option(
        default="",
        help="The PR assignees",
        parser=comma_list,
    ),
    pr_reviewers: list = typer.Option(
        default="",
        help="The PR reviewers",
        parser=comma_list,
    ),
):
    prs_limit_int = int(prs_limit)
    affected_content_items = load_json(f"{batch_dir}/affected_content_items.json")
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

    if staging_branch != master_branch_name:
        # If staging branch is the master/main branch, then no need to create or update it
        try:
            current_active_branch = repo.active_branch
            # Check if the staging branch exists, if not, create one
            remote_content_repo.get_git_ref(f"heads/{staging_branch}")
            # If reached here, that means there is a remote branch with the same name as the staging branch.

            # Checkout the staging branch
            logging.info(f"Checking out to staging branch: {staging_branch}\n{git.checkout(staging_branch)}")
            # Make staging branch up to date with master
            origin.pull(master_branch_name)
            origin.push(staging_branch)

            logging.info(f"Checking out to active branch: {current_active_branch}\n{git.checkout(current_active_branch)}")
        except GithubException as github_exception:
            # Resource not found
            if github_exception.status == 404:
                source_branch = remote_content_repo.get_branch(master_branch_name)
                # We need to create remote branch that corresponds to the staging branch
                remote_content_repo.create_git_ref(ref="refs/heads/" + staging_branch, sha=source_branch.commit.sha)
            else:
                raise github_exception

    try:
        docker_images_prs_output: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for docker_image in affected_content_items:
            image_config = affected_content_items[docker_image]
            if content_items := image_config["content_items"]:
                number_of_batches = math.ceil(len(content_items) / prs_limit_int)
                # We divide the content items to PR batches
                pr_batch_start = 0
                pr_batch_end = pr_batch_start + prs_limit_int
                for current_batch in range(1, number_of_batches + 1):
                    logging.info(f"{current_batch=}")
                    content_items_for_batch = content_items[pr_batch_start:pr_batch_end]
                    pr_content = update_content_items_docker_images_and_push(
                        current_batch=current_batch,
                        number_of_batches=number_of_batches,
                        docker_image=docker_image,
                        staging_branch=staging_branch,
                        git=git,
                        remote_content_repo=remote_content_repo,
                        origin=origin,
                        content_items=content_items_for_batch,
                        pr_labels=image_config["pr_labels"],
                        target_tag=image_config["target_tag"],
                        coverage=image_config["coverage"],
                        pr_assignees=pr_assignees,
                        pr_reviewers=pr_reviewers,
                    )
                    if pr_content:
                        docker_images_prs_output[docker_image].append(pr_content)
                    else:
                        # Not all PR batches will have updated content items
                        logging.info(
                            f"PR batch {current_batch} for {docker_image} with {content_items_for_batch = }"
                            " did not contain updates"
                        )
                    pr_batch_start = pr_batch_end
                    pr_batch_end = pr_batch_start + prs_limit_int
        if batch_dir:
            # Output the content items and PRs
            with open(f"{batch_dir}/docker_images_prs_output.json", "w") as images_prs_output:
                json.dump(docker_images_prs_output, images_prs_output)

    except Exception as e:
        logging.error(f"Got error when opening PRs {e}")
        sys.exit(1)


def main():
    app()


if __name__ == "__main__":
    main()
