import argparse
import requests
import os
import sys
import json
from pathlib import Path

REPO_OWNER = "demisto"
REPO_NAME = "content"
PACKS_FOLDER = "Packs"
CONTENT_REPO_FULL_PATH = os.environ.get('GITHUB_WORKSPACE') or os.path.abspath(
    os.path.join(__file__, '../../../..'))
PACKS_FULL_PATH = os.path.join(CONTENT_REPO_FULL_PATH, PACKS_FOLDER)
PACK_METADATA = "pack_metadata.json"
XSOAR_SUPPORT = "xsoar"
PACK_METADATA_GITHUB_USER_FIELD = "githubUser"


def check_if_user_exists(github_user, github_token=None, verify_ssl=True):
    user_endpoint = f"https://api.github.com/users/{github_user}"
    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(user_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling user {github_user} data")
        sys.exit(1)

    github_user_info = response.json()

    if 'id' in github_user_info:
        return True
    else:
        return False


def get_pr_author(pr_number, github_token, verify_ssl):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data")
        sys.exit(1)

    pr_info = response.json()

    return pr_info.get('user', {}).get('login', '').lower()


def get_pr_modified_packs(pr_number, github_token, verify_ssl):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files"

    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data")
        sys.exit(1)

    pr_changed_data = response.json()
    pr_files = [f.get('filename') for f in pr_changed_data]
    modified_packs = {Path(p).parts[1] for p in pr_files if p.startswith(PACKS_FOLDER) and len(Path(p).parts) > 1}

    return modified_packs


def request_review_from_user(reviewers, pr_number, github_token=None, verify_ssl=True):
    review_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/requested_reviewers"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    reviewers_data = {
        "reviewers": list(reviewers)
    }

    response = requests.post(review_endpoint, json=reviewers_data, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed requesting review on PR {pr_number}")
        sys.exit(1)


def check_pack_and_request_review(pr_number, github_token=None, verify_ssl=True):
    modified_packs = get_pr_modified_packs(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl)
    pr_author = get_pr_author(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl)
    reviewers = set()

    for pack in modified_packs:
        pack_metadata_path = os.path.join(PACKS_FULL_PATH, pack, PACK_METADATA)

        if os.path.exists(pack_metadata_path):
            with open(pack_metadata_path, 'r') as pack_metadata_file:
                pack_metadata = json.load(pack_metadata_file)

            if pack_metadata.get('support') != XSOAR_SUPPORT and PACK_METADATA_GITHUB_USER_FIELD in pack_metadata \
                    and pack_metadata[PACK_METADATA_GITHUB_USER_FIELD]:
                github_user = pack_metadata[PACK_METADATA_GITHUB_USER_FIELD].lower()
                user_exists = check_if_user_exists(github_user=github_user, github_token=github_token,
                                                   verify_ssl=verify_ssl)

                if user_exists and github_user != pr_author:
                    reviewers.add(github_user)
                    print(f"Found {github_user} default reviewer of pack {pack}")

            elif pack_metadata.get('support') == XSOAR_SUPPORT:
                print(f"Skipping check of {pack} pack supported by {XSOAR_SUPPORT}")
            else:
                print(f"{pack} pack has no default github reviewer")
        else:
            print(f"Not found {pack} {PACK_METADATA} file.")

    if reviewers:
        request_review_from_user(reviewers=reviewers, pr_number=pr_number, github_token=github_token,
                                 verify_ssl=verify_ssl)
    else:
        print("No reviewers were found.")


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

    check_pack_and_request_review(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl)


if __name__ == "__main__":
    main()
