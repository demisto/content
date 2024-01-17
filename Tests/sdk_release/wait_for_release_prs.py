import argparse
import sys
import time
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

PRS_LIST_TEMPLATE = 'https://api.github.com/repos/demisto/{}/pulls?head=demisto:{}'
PR_BY_ID_TEMPLATE = 'https://api.github.com/repos/demisto/{}/pulls/{}'
TIMEOUT = 60 * 60 * 6  # 6 hours


def get_pr_from_branch(repository, branch, access_token):
    url = PRS_LIST_TEMPLATE.format(repository, branch)
    res = requests.get(url, headers={'Authorization': f'Bearer {access_token}'}, verify=False)
    if res.status_code != 200:
        sys.exit(1)

    prs_list = res.json()
    if prs_list:
        return prs_list[0]
    return None


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    access_token = options.access_token
    release_branch_name = options.release_branch_name

    sdk_pr = None
    content_pr = None

    # initialize timer
    start = time.time()
    elapsed: float = 0

    # wait to content pr and sdk pr to be open
    while (not sdk_pr or not content_pr) and elapsed < TIMEOUT:
        content_pr = get_pr_from_branch('content', release_branch_name, access_token)
        sdk_pr = get_pr_from_branch('demisto-sdk', release_branch_name, access_token)

        time.sleep(30)
        elapsed = time.time() - start

    content_pr_state = 'open'
    sdk_pr_state = 'open'

    print('sdk and content prs created')

    # wait to content pr and sdk pr to be closed
    while (sdk_pr_state == 'open' or content_pr_state == 'open') and elapsed < TIMEOUT:
        content_pr = get_pr_from_branch('content', release_branch_name, access_token)
        sdk_pr = get_pr_from_branch('demisto-sdk', release_branch_name, access_token)
        content_pr_state = content_pr.get('state')
        sdk_pr_state = sdk_pr.get('state')

        print(f'content pr state is {content_pr_state}')
        print(f'sdk pr state is {sdk_pr_state}')

        time.sleep(300)
        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        sys.exit(1)

    # check that content pr is merged
    if not content_pr.get('merged'):
        sys.exit(1)

    # check that sdk pr is merged
    if not sdk_pr.get('merged'):
        sys.exit(1)


if __name__ == "__main__":
    main()
