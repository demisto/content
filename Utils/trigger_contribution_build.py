#!/usr/bin/env python3
import argparse
import logging
import os

import urllib3
from github import Github, GithubException
from github.Issue import Issue
from github.PaginatedList import PaginatedList
from gitlab import Gitlab
from gitlab.exceptions import GitlabError
from gitlab.v4.objects.branches import ProjectBranch
from gitlab.v4.objects.projects import Project
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()

DEFAULT_CI_PIPELINE_SOURCE = "contrib"
GITLAB_DEFAULT_PROJECT_ID = 1061
CONTRIBUTION_PRS_QUERY = 'is:pull-request state:open label:ready-for-instance-test label:Contribution label:"External PR"'
GITLAB_PROJECT_ID = os.getenv("CI_PROJECT_ID") or GITLAB_DEFAULT_PROJECT_ID
GITLAB_SERVER_URL = os.getenv("CI_SERVER_URL", "https://gitlab.xdr.pan.local")  # disable-secrets-detection
GITHUB_TRIGGER_BUILD_LABEL = "ready-for-instance-test"


class COMMENT_MESSAGES:
    build_request_accepted: str = "For the Reviewer: Trigger build request has been accepted for this contribution PR."
    build_triggered: str = "For the Reviewer: Successfully created a pipeline in GitLab with url: {url}"
    build_trigger_failed: str = "For the Reviewer: Could not create a pipeline in GitLab for branch name: {branch}. \
    The branch was not found in the GitLab project."


def arguments_handler() -> argparse.Namespace:
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Trigger contribution build.")
    parser.add_argument("--github-token", help="Github API token")
    parser.add_argument("--gitlab-api-token", help="Gitlab API token")
    parser.add_argument("--gitlab-trigger-token", help='Gitlab trigger token')
    return parser.parse_args()


def cancel_active_pipelines(gitlab_project: Project, branch: ProjectBranch) -> None:
    """Find and cancel all currently active pipelines for a given GitLab branch.

    Args:
        gitlab_project (Project): GitLab Project object.
        branch (ProjectBranch): Gitlab branch object.
    """
    pipelines = gitlab_project.pipelines.list(ref=branch.name, status="running")
    if pipelines:
        for pipeline in pipelines:
            logging.info(f"Canceling active pipeline: {pipeline.id}")
            pipeline.cancel()


def handle_contribution_prs(args, github_issues: PaginatedList[Issue], gitlab_project: Project) -> None:
    """Given a list of github issues (PRs), create new pipelines for their mirrored GitLab branches.
    Older active pipelines for each branch will be canceled.

    Args:
        args (Namespace): Script arguments.
        github_issues (PaginatedList[Issue]): List of GitHub PRs returned from the contribution PRs query.
        gitlab_project (Project): GitLab project object.
    """
    for issue in github_issues:
        try:
            issue.create_comment(COMMENT_MESSAGES.build_request_accepted)
            # casting to PR object due to Module limitation (Issue object does not have a `branch name` attribute).
            pull_request = issue.as_pull_request()

            # the branch the contributor wants to commit into (starts with 'demisto:')
            github_branch_name = pull_request.base.ref

            # get the GitLab branch object corresponding to the GitHub branch
            if branch := gitlab_project.branches.get(github_branch_name):
                logging.info(
                    f"Trigger build for PR {pull_request.number}|base: {pull_request.base.ref}|contrib: {pull_request.head.label}"
                )

                cancel_active_pipelines(gitlab_project, branch)

                variables = {
                    "CONTRIB_BRANCH": pull_request.head.label,
                    "PULL_REQUEST_NUMBER": str(pull_request.number),
                    "PR_NUMBER": str(pull_request.number),
                    "CI_COMMIT_BRANCH": pull_request.base.ref,
                    "CI_PIPELINE_SOURCE": "contrib",
                    "CONTRIB_REPO": pull_request.head.repo.name,
                    "BASE_BRANCH": pull_request.base.ref,
                }
                new_pipeline = gitlab_project.trigger_pipeline(
                    ref=pull_request.base.ref,
                    token=args.gitlab_trigger_token,
                    variables=variables,
                )

                logging.info(f"New pipeline triggered successfully: {new_pipeline.web_url}")
                issue.create_comment(COMMENT_MESSAGES.build_triggered.format(url=new_pipeline.web_url))

            else:
                logging.info(f"No branch was found in the GitLab project with the name: {github_branch_name}.\
                             New pipeline was not created.")
                issue.create_comment(COMMENT_MESSAGES.build_trigger_failed.format(branch=github_branch_name))

            pull_request.remove_from_labels(GITHUB_TRIGGER_BUILD_LABEL)

        except Exception as e:
            logging.exception(f"Failed to trigger pipeline for: {github_branch_name}. Error: {e}")


def main():
    install_logging("trigger_contribution_build.log")
    args: argparse.Namespace = arguments_handler()

    try:
        github_client = Github(login_or_token=args.github_token)
        gitlab_client = Gitlab(oauth_token=args.gitlab_api_token, url=GITLAB_SERVER_URL, ssl_verify=False)

        github_issues: PaginatedList[Issue] = github_client.search_issues(query=CONTRIBUTION_PRS_QUERY)
        gitlab_project: Project = gitlab_client.projects.get(GITLAB_PROJECT_ID)
    except GithubException as e:
        logging.exception(f"Failed to initialize Github client: {e}")
    except GitlabError as e:
        logging.exception(f"Failed to initialize GitLab client: {e}")
    except Exception as e:
        logging.exception(f"Failed to initialize necessary variables related to GitHub or Gitlab: {e}")

    logging.info("Successfully initiated Github and Gitlab clients.")
    handle_contribution_prs(args=args, github_issues=github_issues, gitlab_project=gitlab_project)


if __name__ == "__main__":
    main()
