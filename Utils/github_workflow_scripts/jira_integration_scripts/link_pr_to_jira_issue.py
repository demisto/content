import argparse
import re
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JIRA_PATH_FOR_REGEX = "https:\/\/jira-hq.paloaltonetworks.local\/browse\/"
JIRA_FIXED_ISSUE_REGEX = f"fixes: ({JIRA_PATH_FOR_REGEX}([A-Z][A-Z0-9]+-[0-9]+))\s?"
JIRA_RELATED_ISSUE_REGEX = f"relates: ({JIRA_PATH_FOR_REGEX}([A-Z][A-Z0-9]+-[0-9]+))\s?"
GENERIC_WEBHOOK_NAME = "GenericWebhook_link_pr_to_jira"
JIRA_GITHUB_INTEGRATION_INSTANCE_URL = "https://content-gold.paloaltonetworks.com/instance/" \
                                       f"execute/{GENERIC_WEBHOOK_NAME}"


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Linking GitHub PR to Jira Issue.')
    parser.add_argument('-l', '--pr_link', help='The PR url.')
    parser.add_argument('-n', '--pr_num', help='The PR number.')
    parser.add_argument('-t', '--pr_title', help='The PR Title.')
    parser.add_argument('-b', '--pr_body', help='the content of the PR description.')
    parser.add_argument('-m', '--is_merged', help='boolean. Whether the PR was merged or not.')
    parser.add_argument('-u', '--username', help='The instance username.')
    parser.add_argument('-s', '--password', help='The instance password.')

    return parser.parse_args()


def find_fixed_issue_in_body(body_text, is_merged):
    """
    Getting the issues url in the PR's body as part of `fixing: <issue>` format.
    Return list of issues found: [{"link": link, "id": issue_id}]
    """
    fixed_jira_issues = re.findall(JIRA_FIXED_ISSUE_REGEX, body_text)
    related_jira_issue = re.findall(JIRA_RELATED_ISSUE_REGEX, body_text)

    # If a PR is not merged, we just add its link to all the  link to the issues using Gold.
    # If the PR is merged, we only send issues that should be closed by it.
    fixed_issue = [{"link": link, "id": issue_id} for link, issue_id in fixed_jira_issues]
    related_issue = []
    if not is_merged:
        related_issue = [{"link": link, "id": issue_id} for link, issue_id in related_jira_issue]
    return fixed_issue + related_issue


def trigger_generic_webhook(options):
    pr_link = options.pr_link
    pr_title = options.pr_title
    pr_body = options.pr_body
    is_merged = options.is_merged
    pr_num = options.pr_num
    username = options.username
    password = options.password

    issues_in_pr = find_fixed_issue_in_body(pr_body, is_merged)

    body = {
        "name": GENERIC_WEBHOOK_NAME,
        "raw_json": {
            "PullRequestNum": pr_num,
            "closeIssue": is_merged,  # whether to close the fixed issue in Jira
            "PullRequestLink": pr_link,  # will be used to add to jira issue's fields
            "PullRequestTitle": f"{pr_title} ({pr_link})",  # will be used in comment of attaching jira issue.
            "JiraIssues": issues_in_pr
        },
    }

    # post to Content Gold
    res = requests.post(JIRA_GITHUB_INTEGRATION_INSTANCE_URL, json=body, auth=(username, password))

    if res.status_code != 200:
        print(
            f"Trigger playbook for Linking GitHub PR to Jira Issue failed. Post request to Content"
            f" Gold has status code of {res.status_code}")
        sys.exit(1)


def main():
    options = arguments_handler()
    trigger_generic_webhook(options)


if __name__ == "__main__":
    main()
