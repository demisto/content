#!/usr/bin/env python3
import argparse
import json
import os
import sys
from collections import namedtuple
from github import Github
from gitlab import Gitlab
from github.Issue import Issue
from github.PaginatedList import PaginatedList
import requests
import urllib3

urllib3.disable_warnings()

FIND_CONTRIBUTION_PRS_QUERY = 'is:pull-request state:open label:ready-for-instance-test label:Contribution -label:"Interanl PR"'

# OWNER = "demisto"
# REPO = "content"
GITLAB_PROJECT_ID = os.getenv("CI_PROJECT_ID") or 1061
GITLAB_SERVER_URL = os.getenv(
    "CI_SERVER_URL", "https://gitlab.xdr.pan.local"
)  # disable-secrets-detection
GITHUB_TRIGGER_BUILD_LABEL = "ready-for-instance-test"
# GITHUB_SEARCH_REQUEST_ENDPOINT = "https://api.github.com/search/issues"
# GITHUB_GET_PR_ENDPOINT = "https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
# GITHUB_DELETE_LABEL_ENDPOINT = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/labels/{label_name}"
# GITHUB_POST_COMMENT_ENDPOINT = "https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
# GITHUB_QUERY_LABELS = {
#     "label": ["Contribution", GITHUB_TRIGGER_BUILD_LABEL],
#     "-label": ["Internal PR"],
# }
# GITLAB_TRIGGER_PIPELINE_ENDPOINT = (
#     "https://gitlab.com/api/v4/projects/{project_id}/trigger/pipeline"
# )

MESSAGES = namedtuple(
    "MESSAGES",
    ["build_request_accepted", "build_triggered", "cant_trigger_build"],
)
COMMENT_MESSAGES = MESSAGES(
    "For the Reviewer: Trigger build request has been accepted for this contribution PR.",
    "For the Reviewer: Successfully created a pipeline in GitLab with url: {url}",
    "For the Reviewer: Build was not triggered for this PR since a current pipeline already running.", # TODO: remove
)


# def get_contribution_prs(headers: dict[str, str]):
#     """Get all contribution PRs with the relevant labels using a query.

#     Args:
#         headers (dict[str, str]): GitHub API request headers.

#     Returns:
#         list[dict]: A list of prs matching the query sent in params.
#     """
#     query_labels = " ".join(
#         [
#             f'{label}:"{item}"'
#             for label, lst in GITHUB_QUERY_LABELS.items()
#             for item in lst
#         ]
#     ).strip()

#     params = {"q": "is:pr state:open " + f"{query_labels}"}

#     response = requests.get(
#         GITHUB_SEARCH_REQUEST_ENDPOINT, headers=headers, params=params
#     )

#     if response.status_code == 200:
#         return response.json()
#     else:
#         print(
#             f"Trigger contribution build script failed with request status code: {response.status_code}"
#         )
#         sys.exit(1)


# def delete_label_from_contribution_pr(headers: dict[str, str], pr: dict) -> None:
#     """Deletes the "ready-for-instance-test" label from a contribution PR.

#     Args:
#         headers (dict[str, str]): GitHub API request headers.
#         pr (dict): Dictionary representing a contribution PR.
#     """
#     issue_number = str(pr.get("number"))

#     response = requests.delete(
#         GITHUB_DELETE_LABEL_ENDPOINT.format(
#             owner=OWNER,
#             repo=REPO,
#             issue_number=issue_number,
#             label_name=GITHUB_TRIGGER_BUILD_LABEL,
#         ),
#         headers=headers,
#     )
#     title = pr.get("title")
#     if response.status_code == 200:
#         print(
#             f"{GITHUB_TRIGGER_BUILD_LABEL} label removed for PR number: {title}, issue number: {issue_number}"
#         )
#     else:
#         print(
#             f"Could not remove {GITHUB_TRIGGER_BUILD_LABEL} label for PR number: {title}, issue number: {issue_number}"
#         )


# def post_comment_to_contribution_pr(
#     headers: dict[str, str], pr: dict, message: str
# ) -> None:
#     """Posts a comment on a contribution PR based on a given message.

#     Args:
#         headers (dict[str, str]): GitHub API request headers.
#         pr (dict): Dictionary representing a contribution PR.
#         message (str): Message to comment.
#     """
#     issue_number = str(pr.get("number"))
#     json_data = {"body": message}

#     requests.post(
#         GITHUB_POST_COMMENT_ENDPOINT.format(
#             owner=OWNER,
#             repo=REPO,
#             issue_number=issue_number,
#             label_name=GITHUB_TRIGGER_BUILD_LABEL,
#             body=message,
#         ),
#         headers=headers,
#         data=json.dumps(json_data),
#     )


# def trigger_build_for_contribution_pr(headers: dict[str, str], branch_name: str):
#     """ Trigger pipeline for a contribution PR in GitLab.

#     Args:
#         headers (dict[str, str]):  GitLab API request headers.
#         branch_name (str): PR branch name
#     """
#     response = requests.post(
#         GITLAB_TRIGGER_PIPELINE_ENDPOINT.format(project_id=GITLAB_PROJECT_ID),
#         headers=headers,
#         data={"ref": branch_name},
#     )

#     if response.status_code == 201:
#         print("Pipeline triggered successfully.")
#     else:
#         print(f"Failed to trigger pipeline. Status code: {response.status_code}")


# def get_merge_request_iid(headers: dict[str, str], project_id, branch_name):
#     url = f"GITLAB_API_URL/projects/{project_id}/merge_requests?source_branch={branch_name}&state=opened"

#     response = requests.get(url, headers=headers)
#     if response.status_code == 200:
#         merge_requests = response.json()
#         if merge_requests:
#             return merge_requests[0]["iid"]  # Assuming the first MR is the latest one
#         else:
#             print("No open merge requests found for the branch.")
#             return None
#     else:
#         print(f"Failed to fetch merge requests. Status code: {response.status_code}")
#         return None


# def is_pipeline_running(headers: dict[str, str], project_id, merge_request_iid):
#     url = "{GITLAB_API_URL}/projects/{project_id}/merge_requests/{merge_request_iid}/pipelines"

#     response = requests.get(url, headers=headers)
#     if response.status_code == 200:
#         pipelines = response.json()
#         for pipeline in pipelines:
#             if pipeline["status"] == "running":
#                 return True
#         return False
#     else:
#         print(f"Failed to fetch pipelines. Status code: {response.status_code}")
#         return None


# def check_running_pipeline(headers: dict[str, str], branch_name: str):
#     merge_request_iid = get_merge_request_iid(headers, GITLAB_PROJECT_ID, branch_name)
#     if merge_request_iid is not None:
#         running = is_pipeline_running(headers, GITLAB_PROJECT_ID, merge_request_iid)
#         if running is not None:
#             if running:
#                 print(
#                     "Pipeline is running for the latest merge request associated with the branch."
#                 )
#             else:
#                 print(
#                     "No pipeline is running for the latest merge request associated with the branch."
#                 )


def arguments_handler() -> argparse.Namespace:
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Trigger contribution build.")
    parser.add_argument("--github-token", help="Github api token")
    parser.add_argument("--gitlab-api-token", help="Gitlab api token")
    return parser.parse_args()


def get_branch_name(headers: dict[str, str], pr: dict) -> str | None:
#     """Get branch name (also known as 'ref') of a GitHub PR.
#     This helper function is needed since the response returned from `get_contribution_prs` function
#     do not contain this information which is needed for the GitLab requests.

#     Args:
#         headers (dict[str, str]):  GitHub API request headers.
#         pr (dict): Dictionary representing a contribution PR.

#     Returns:
#         str | None: branch name if request was successful, None otherwise.
#     """
#     issue_number = str(pr.get("number"))

#     response = requests.get(
#         GITHUB_GET_PR_ENDPOINT.format(owner=OWNER, repo=REPO, pr_number=issue_number),
#         headers=headers,
#     ).json()

#     if response.status_code == 200:
#         return response.get("head", {}).get("ref")
#     else:
#         print("")  # TODO: add error message
#         return None


def main():
    args = arguments_handler()

    # github_headers = {
    #     "Content-Type": "application/json",
    #     "Authorization": f"Bearer {args.github_token}",
    # }

    # gitlab_headers = {
    #     "Content-Type": "application/json",
    #     "Authorization": f"Bearer {args.gitlab_api_token}",
    # }

    github_client = Github(login_or_token=args.github_token)
    gitlab_client = Gitlab(oauth_token=args.gitlab_api_token, url=GITLAB_SERVER_URL)

    github_issues: PaginatedList[Issue] = github_client.search_issues(FIND_CONTRIBUTION_PRS_QUERY)
    gitlab_merge_requests = gitlab_client.projects.get(GITLAB_PROJECT_ID).mergerequests

    for issue in github_issues:
        issue.create_comment(COMMENT_MESSAGES.build_request_accepted)

        pull_request = issue.as_pull_request() # Get the github pull request object
        branch_name = pull_request.head.ref

        if branch_name == 'test-pr/add-trigger-contribution-build-job': # TODO: remove this if statement when done testing
            # TODO: transfer if statement logic below to a helper function
            if merge_requests := gitlab_merge_requests.list(source_branch=branch_name):
                # Assuming there's only one MR for a branch
                mr = merge_requests[0] #FIX: fix `getitem` error

                # Get pipelines for the MR
                pipelines = mr.pipelines.list()

                if pipelines:
                    # Get the most recent pipeline
                    latest_pipeline = pipelines[0]

                    if latest_pipeline.status == 'running':
                        print(f"Pipeline is running for MR {mr.iid}. Cancelling current pipeline...")

                        # Cancel the current pipeline
                        latest_pipeline.cancel()

                        print("Current pipeline cancelled. Triggering a new pipeline...")

                        # Trigger a new pipeline
                        new_pipeline = mr.trigger_pipeline()

                        print("New pipeline triggered.")
                    else:
                        print(f"No running pipeline found for MR {mr.iid}. Triggering a new pipeline...")

                        # Trigger a new pipeline
                        new_pipeline = mr.trigger_pipeline()

                        print("New pipeline triggered.")
                else:
                    print(f"No pipeline found for MR {mr.iid}. Triggering a new pipeline...")

                    # Trigger a new pipeline
                    new_pipeline = mr.trigger_pipeline()

                    print("New pipeline triggered.")
            else:
                print("No Merge Requests found for the branch:", branch_name)

        issue.create_comment(COMMENT_MESSAGES.build_triggered)
        issue.remove_from_labels(GITHUB_TRIGGER_BUILD_LABEL)


    # response = get_contribution_prs(github_headers)

    # if items := response.get("items"):
    #     pr_numbers: list[str] = []
    #     for pr in items:
    #         if str(pr.get("number")) == "33308":  # TODO: if statement for testing only
    #             post_comment_to_contribution_pr(
    #                 github_headers, pr, COMMENT_MESSAGES.build_request_accepted
    #             )
    #             if not (branch_name := get_branch_name(github_headers, pr)):
    #                 continue
    #             check_running_pipeline(gitlab_headers, branch_name)
    #             trigger_build_for_contribution_pr(github_headers, branch_name)
    #             delete_label_from_contribution_pr(github_headers, pr)
    #             post_comment_to_contribution_pr(
    #                 github_headers, pr, COMMENT_MESSAGES.build_triggered
    #             )
    #             pr_numbers.append(str(pr.get("number")))
    #     print(f"Build triggered for the following contribution PRs: {pr_numbers}")
    # else:
    #     print("No contribution PRs builds were trigger.")
    #     return


if __name__ == "__main__":
    main()
