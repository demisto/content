import argparse
import re
import sys
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JIRA_URL_REGEX = \
    r"(?:\[.+\]\()?(?P<url>https?:\/\/jira-hq\.paloaltonetworks\.local\/browse\/(?P<issue_key>[a-zA-Z][a-zA-Z0-9]+-[0-9]+))"
JIRA_FIXED_ISSUE_REGEX = rf"(?i)fixes:\s*{JIRA_URL_REGEX}"
JIRA_RELATED_ISSUE_REGEX = rf"(?i)relates:\s*{JIRA_URL_REGEX}"
GENERIC_WEBHOOK_NAME = "GenericWebhook_link_pr_to_jira"


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Linking GitHub PR to Jira Issue.')
    parser.add_argument('-l', '--pr_link', help='The PR url.')
    parser.add_argument('-n', '--pr_num', help='The PR number.')
    parser.add_argument('-t', '--pr_title', help='The PR Title.')
    parser.add_argument('-b', '--pr_body', help='The content of the PR description.')
    parser.add_argument('-m', '--is_merged', help='Boolean. Whether the PR was merged or not.',
                        action=argparse.BooleanOptionalAction)
    parser.add_argument('-u', '--username', help='The instance username.')
    parser.add_argument('-s', '--password', help='The instance password.')
    parser.add_argument('-url', '--url', help='The instance url.')

    return parser.parse_args()


def find_fixed_issue_in_body(body_text) -> list[dict[str, str]]:
    """
    Collect issue URLs in PR's body matching a regex.

    Returns:
        list: A list of issues found in a {"link": str, "key": str, "should_close": bool} format.
            "should_close" indicates whether to close the Jira issue once the PR is merged.
    """
    # Issues tagged as "fixes"
    issues = [
        {
            "link": x.group(1),
            "key": x.group(2),
            "should_close": True
        }
        for x in re.finditer(JIRA_FIXED_ISSUE_REGEX, body_text)
    ]

    # Issues tagged as "relates"
    issues.extend([
        {
            "link": x.group(1),
            "key": x.group(2),
            "should_close": False
        }
        for x in re.finditer(JIRA_RELATED_ISSUE_REGEX, body_text)
    ])

    return issues


def trigger_generic_webhook(options):
    pr_link = options.pr_link
    pr_title = options.pr_title
    pr_body = options.pr_body
    is_merged = options.is_merged
    pr_num = options.pr_num
    username = options.username
    password = options.password
    instance_url = options.url

    print(f"Detected Pr: {pr_title=}, {pr_link=}, {pr_body=}")

    # Handle cases where the PR did not intend to add links:
    if all(x.casefold() not in pr_body.casefold() for x in ("fixes:", "relates:", "fixed:", "related:")):
        print("Did not detect Jira linking pattern.")
        return

    issues_in_pr = find_fixed_issue_in_body(pr_body)

    if not issues_in_pr:
        print("ERROR: No linked issues were found in PR. Make sure you correctly linked issues.")

        sys.exit(1)

    print(f"found issues in PR: {issues_in_pr}")

    body = {
        "name": GENERIC_WEBHOOK_NAME,
        "raw_json": {
            "PullRequestNum": pr_num,
            "closeIssue": "true" if is_merged else "false",  # whether to close the fixed issue in Jira
            "PullRequestLink": pr_link,  # will be used to add to jira issue's fields
            "PullRequestTitle": f"{pr_title} ({pr_link})",  # will be used in comment of attaching jira issue.
            "JiraIssues": issues_in_pr
        },
    }
    print(body)
    # post to Content Gold
    res = requests.post(instance_url, json=body, auth=(username, password))

    if res.status_code != 200:
        print(
            f"Trigger playbook for Linking GitHub PR to Jira Issue failed. "
            f"Post request to Content Gold has received a status code of {res.status_code}")
        sys.exit(1)

    res_json = res.json()
    if res_json and isinstance(res_json, list):
        res_json_response_data = res.json()[0]
        if res_json_response_data:
            investigation_id = res_json_response_data.get("id")
            print(f'{investigation_id=}')


def main():
    options = arguments_handler()
    trigger_generic_webhook(options)


if __name__ == "__main__":
    main()
