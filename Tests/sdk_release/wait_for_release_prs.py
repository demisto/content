import argparse
import sys
import time
import requests
import urllib3
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


# Disable insecure warnings
urllib3.disable_warnings()

PRS_LIST_TEMPLATE = 'https://api.github.com/repos/demisto/{}/pulls?head=demisto:{}'

PR_BY_ID_TEMPLATE = 'https://api.github.com/repos/demisto/{}/pulls/{}'

TIMEOUT = 60 * 60 * 6  # 6 hours


def get_pr_from_branch(repository, branch, access_token):
    url = PRS_LIST_TEMPLATE.format(repository, branch)
    res = requests.get(url, headers={'Authorization': f'Bearer {access_token}'}, verify=False)
    if res.status_code != 200:
        logging.error(f'Failed to retrieve pull request from branch {branch}')
        logging.error(res.text)
        sys.exit(1)

    prs_list = res.json()
    if prs_list:
        return prs_list[0]
    return None


def get_pr_by_id(repository, pr_id, access_token):
    url = PR_BY_ID_TEMPLATE.format(repository, pr_id)
    res = requests.get(url, headers={'Authorization': f'Bearer {access_token}'}, verify=False)
    if res.status_code != 200:
        logging.error(f'Failed to retrieve pull request with id {pr_id}')
        logging.error(res.text)
        sys.exit(1)

    return res.json()


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('--artifacts-folder', help='Artifacts folder to create the CHANGELOG_SLACK.txt file', required=True)

    options = parser.parse_args()
    return options


def main():
    install_logging("WaitForReleasePRs.log", logger=logging)

    options = options_handler()
    access_token = options.access_token
    release_branch_name = options.release_branch_name
    artifacts_folder = options.artifacts_folder

    import os
    from Tests.sdk_release.create_release import get_changelog_text
    from Tests.sdk_release.create_content_pr import SLACK_RELEASE_MESSAGE, SLACK_CHANGELOG_FILE
    # write the changelog text to SLACK_CHANGELOG_FILE
    changelog_text = get_changelog_text(release_branch_name, text_format='slack')
    changelog_text = SLACK_RELEASE_MESSAGE.format(release_branch_name, changelog_text)
    changelog_file = os.path.join(artifacts_folder, SLACK_CHANGELOG_FILE)
    with open(changelog_file, "w") as f:
        f.write(str(changelog_text))
    logging.info('SLACK_CHANGELOG_FILE created')

    # get the sdk and content pull requests
    # content_pr = get_pr_from_branch('content', release_branch_name, access_token)
    # sdk_pr = get_pr_from_branch('demisto-sdk', release_branch_name, access_token)
    # logging.info(f'demisto-sdk pull request created: {sdk_pr.get("html_url")}')
    logging.info(f'content pull request created: {content_pr.get("html_url")}')

    # content_pr_id = content_pr.get('number')
    # sdk_pr_id = sdk_pr.get('number')
    content_pr_state = 'open'
    # sdk_pr_state = 'open'

    content_pr_id = '32454'
    # initialize timer
    start = time.time()
    elapsed: float = 0

    # wait to content pr and sdk pr to be closed
    while content_pr_state == 'open' and elapsed < TIMEOUT:
        content_pr = get_pr_by_id('content', content_pr_id, access_token)
        # sdk_pr = get_pr_by_id('demisto-sdk', sdk_pr_id, access_token)

        content_pr_state = content_pr.get('state')
        # sdk_pr_state = sdk_pr.get('state')

        logging.info(f'content pr state is {content_pr_state}')
        # logging.info(f'sdk pr state is {sdk_pr_state}')

        time.sleep(300)  # 5 minutes
        elapsed = time.time() - start

    if elapsed >= TIMEOUT:
        logging.critical('Timeout reached while waiting for SDK and content pull requests to be merged')
        sys.exit(1)

    # check that content pr is merged
    if not content_pr.get('merged'):
        logging.error(f'content pull request not merged yet {content_pr.get("html_url")}')
        sys.exit(1)

    # check that sdk pr is merged
    # if not sdk_pr.get('merged'):
    #     logging.error(f'demisto-sdk pull request not merged yet {sdk_pr.get("html_url")}')
    #     sys.exit(1)

    logging.success('SDK and content pull requests merged successfully!')


if __name__ == "__main__":
    main()
