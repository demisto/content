import argparse
import json
import sys
import time
import requests


TIMEOUT = 60 * 60 * 6  # 6


def get_pr(pr_id, token, suffix):
    url = f'{suffix}/pulls/{pr_id}'
    res = requests.get(url, headers={'Authorization': f'Bearer {token}'}, verify=False)
    if res.status_code != 200:
        sys.exit(1)

    return res.json()


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-o', '--owner', help='The account owner of the repository', required=True)
    parser.add_argument('-r', '--repo', help='The name of the repository', required=True)
    parser.add_argument('-id', '--pr_id', help='The pull request id', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    access_token = options.access_token
    owner = options.owner
    repo = options.repo
    pr_id = options.pr_id

    suffix = F'https://api.github.com/repos/{owner}/{repo}'
    pr_state = 'open'

    # initialize timer
    start = time.time()
    elapsed: float = 0

    while pr_state == 'open' and elapsed < TIMEOUT:
        pr_info = get_pr(pr_id, access_token, suffix)
        pr_state = pr_info.get('state')
        time.sleep(300)

        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        sys.exit(1)

    if not pr_info.get('merged'):
        sys.exit(1)


if __name__ == "__main__":
    main()
