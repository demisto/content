import argparse
import sys

import requests
import pandas as pd

REPO_OWNER = "demisto"
REPO_NAME = "content"
path_to_csv = 'https://docs.google.com/spreadsheets/d/1vayEoL-rll4fctGq78KgTRPrkFD619ND3l_hUapTbtI'


def is_contrib_pr(pr_number, github_token, verify_ssl):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data")
        sys.exit(1)

    pr_info = response.json()

    for label in pr_info.get('labels', []):
        if label.get('name') == 'Contribution':
            return True

    return False


def check_if_form_is_filled(pr_number, github_token, verify_ssl):
    contrib_pr = is_contrib_pr(pr_number, github_token, verify_ssl)
    if not contrib_pr:
        return True

    df = pd.read_csv(path_to_csv, encoding='utf8')
    pr_numbers = df['Pull Request Number'].value_counts()
    print(pr_numbers)





def main():
    parser = argparse.ArgumentParser(description='Requests contributor pack review.')
    parser.add_argument('-p', '--pr_number', help='Opened PR number')
    parser.add_argument('-g', '--github_token', help='Github token', required=False)
    args = parser.parse_args()

    pr_number = args.pr_number
    github_token = args.github_token
    verify_ssl = True if github_token else False

    if not verify_ssl:
        requests.packages.urllib3.disable_warnings()

    check_if_form_is_filled(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl)


if __name__ == "__main__":
    main()
