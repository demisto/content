#!/usr/bin/env python3
import argparse
import os
from collections import namedtuple

import urllib3
from github import Github
from github.Issue import Issue
from github.PaginatedList import PaginatedList
from gitlab import Gitlab
from gitlab.v4.objects.branches import ProjectBranch
from gitlab.v4.objects.projects import Project

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
            print(f"Canceling active pipeline: {pipeline.id}")
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

        issue.create_comment(COMMENT_MESSAGES.build_request_accepted)
        # Casting to PR object due to Module limitation (Issue object does not have a `branch name` attribute).
        pull_request = issue.as_pull_request()
        github_branch_name = pull_request.base.ref

        # TODO: remove this specific if statement when done testing
        if github_branch_name == "contrib/samuelFain_master-1":  # noqa: SIM102

            # get the corresponding GitLab branch object corresponding to the GitHub branch
            if branch := gitlab_project.branches.get(github_branch_name):
                print(f'--- Handling branch: {branch.name}. ---')

                cancel_active_pipelines(gitlab_project, branch)

                variables = {
                    "CONTRIB_BRANCH": branch.name,
                    "PULL_REQUEST_NUMBER": str(pull_request.number),
                    "CI_COMMIT_BRANCH": branch.name,
                    "CI_PIPELINE_SOURCE": "contrib",
                }
                new_pipeline = gitlab_project.trigger_pipeline(
                    ref=branch.name, token=args.gitlab_trigger_token, variables=variables
                )

                print(f"New pipeline triggered: {new_pipeline.web_url}")
                issue.create_comment(COMMENT_MESSAGES.build_triggered.format(url=new_pipeline.web_url))

            else:
                print(f"No branch was found with the name: {github_branch_name}. New pipeline was not created.")
                issue.create_comment(COMMENT_MESSAGES.build_trigger_failed.format(branch=github_branch_name))

            pull_request.remove_from_labels(GITHUB_TRIGGER_BUILD_LABEL)


def main():
    args: argparse.Namespace = arguments_handler()

    github_client = Github(login_or_token=args.github_token)
    gitlab_client = Gitlab(oauth_token=args.gitlab_api_token, url=GITLAB_SERVER_URL, ssl_verify=False)

    github_issues: PaginatedList[Issue] = github_client.search_issues(query=CONTRIBUTION_PRS_QUERY)
    gitlab_project: Project = gitlab_client.projects.get(GITLAB_PROJECT_ID)

    handle_contribution_prs(args=args, github_issues=github_issues, gitlab_project=gitlab_project)


if __name__ == "__main__":
    main()
