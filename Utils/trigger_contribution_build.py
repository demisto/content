#!/usr/bin/env python3
import argparse
import os
from collections import namedtuple

import urllib3
from github import Github
from github.Issue import Issue
from github.PaginatedList import PaginatedList
from gitlab import Gitlab
from gitlab.v4.objects.merge_requests import ProjectMergeRequestManager
from gitlab.v4.objects.projects import Project

urllib3.disable_warnings()

CONTRIBUTION_PRS_QUERY = 'is:pull-request state:open label:ready-for-instance-test label:Contribution label:"External PR"'

GITLAB_PROJECT_ID = os.getenv("CI_PROJECT_ID") or 1061
GITLAB_SERVER_URL = os.getenv(
    "CI_SERVER_URL", "https://gitlab.xdr.pan.local"
)  # disable-secrets-detection
GITHUB_TRIGGER_BUILD_LABEL = "ready-for-instance-test"

MESSAGES = namedtuple(
    "MESSAGES",
    ["build_request_accepted", "build_triggered"],
)
COMMENT_MESSAGES = MESSAGES(
    "For the Reviewer: Trigger build request has been accepted for this contribution PR.",
    "For the Reviewer: Successfully created a pipeline in GitLab with url: {url}",
)


def arguments_handler() -> argparse.Namespace:
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Trigger contribution build.")
    parser.add_argument("--github-token", help="Github api token")
    parser.add_argument("--gitlab-api-token", help="Gitlab api token")
    parser.add_argument("--gitlab-trigger-token", help='Gitlab trigger token')
    return parser.parse_args()


def handle_issues(github_issues: PaginatedList[Issue], gitlab_merge_requests: ProjectMergeRequestManager):
    ...


def main():
    args = arguments_handler()

    github_client = Github(login_or_token=args.github_token)
    gitlab_client = Gitlab(oauth_token=args.gitlab_api_token, url=GITLAB_SERVER_URL, ssl_verify=False)

    github_issues: PaginatedList[Issue] = github_client.search_issues(CONTRIBUTION_PRS_QUERY)
    gitlab_project: Project = gitlab_client.projects.get(GITLAB_PROJECT_ID)

    # TODO: for testing only - remove
    for issue in github_issues:
        # Print some basic information about the issue
        print("Title:", issue.title)
        print("URL:", issue.html_url)
        print("Created By:", issue.user.login)
        print("Labels:", [label.name for label in issue.labels])
        print("-------------------------------------")

    for issue in github_issues:
        issue.create_comment(COMMENT_MESSAGES.build_request_accepted)

        pull_request = issue.as_pull_request() # Get the github pull request object
        branch_name = pull_request.head.ref

        # TODO: remove this specific if statement when done testing
        if branch_name == "test-pr/add-trigger-contribution-build-job":  # noqa: SIM102

            # get the GitLab branch object matching the GitHub branch
            if branch := gitlab_project.branches.get(branch_name):

                print('branch:', branch)

                # find all active pipelines for this branch and cancel them
                pipelines = gitlab_project.pipelines.list(
                    ref=branch.name, status="running"
                )
                if pipelines:
                    for pipeline in pipelines:
                        print(f"Canceling active pipeline: {pipeline.id}")
                        pipeline.cancel()

                new_pipeline = gitlab_project.trigger_pipeline(
                    ref=branch.name,
                    token=args.gitlab_trigger_token,  # FIX: need trigger token here!
                )

                print(f"New pipeline triggered: {new_pipeline.web_url}")

        else:
            print("No branch was found with the name:", branch_name)

        issue.create_comment(COMMENT_MESSAGES.build_triggered)
        issue.remove_from_labels(GITHUB_TRIGGER_BUILD_LABEL)


if __name__ == "__main__":
    main()
