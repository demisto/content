import argparse
import requests
import os
import sys
import json
from pathlib import Path
from Tests.Marketplace.marketplace_services import PACKS_FOLDER, PACKS_FULL_PATH, Pack, Metadata

REPO_OWNER = "demisto"
REPO_NAME = "content"
PACK_METADATA_GITHUB_USER_FIELD = "githubUser"

requests.packages.urllib3.disable_warnings()


def check_if_user_exists(github_user, github_token=None):
    user_endpoint = f"https://api.github.com/users/{github_user}"
    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(user_endpoint, headers=headers, verify=False)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling user {github_user} data")
        sys.exit()

    github_user_info = response.json()

    if 'id' in github_user_info:
        return True
    else:
        return False


def request_review_from_user(github_user, pr_number, github_token=None):
    review_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/requested_reviewers"
    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    reviewers_data = {
        "reviewers": [
            github_user
        ]
    }

    response = requests.post(review_endpoint, data=reviewers_data, headers=headers, verify=False)

    if response.status_code not in [200, 201]:
        print(f"Failed requesting review of {github_user} user")
        sys.exit()


def request_pack_contributor_review(pr_number, github_token=None):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files"

    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=False)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data")
        sys.exit()

    pr_changed_data = response.json()
    pr_files = [f.get('filename') for f in pr_changed_data]
    modified_packs = {Path(p).parts[1] for p in pr_files if p.startswith(PACKS_FOLDER) and len(Path(p).parts) > 1}

    for pack in modified_packs:
        pack_metadata_path = os.path.join(PACKS_FULL_PATH, pack, Pack.USER_METADATA)

        if os.path.exists(pack_metadata_path):
            with open(pack_metadata_path, 'r') as pack_metadata_file:
                pack_metadata = json.load(pack_metadata_file)

            if pack_metadata.get('support') != Metadata.XSOAR_SUPPORT \
                    and PACK_METADATA_GITHUB_USER_FIELD in pack_metadata \
                    and pack_metadata[PACK_METADATA_GITHUB_USER_FIELD]:
                print(f"Found github user in pack {pack}")

                github_user = pack_metadata[PACK_METADATA_GITHUB_USER_FIELD]
                user_exists = check_if_user_exists(github_user=github_user, github_token=github_token)

                if user_exists:
                    request_review_from_user(github_user=github_user, pr_number=pr_number, github_token=github_token)
                else:
                    print(f"{github_user} user defined in {pack} pack metadata does not exist")
                    sys.exit()

                print(f"Finished requesting review from {github_user} user on PR number {pr_number}")

        else:
            print(f"Not found {pack} {Pack.USER_METADATA} file.")


def main():
    parser = argparse.ArgumentParser(description='Requests contributor pack review.')
    parser.add_argument('-p', '--pr_number', help='Opened PR number')
    parser.add_argument('-g', '--github_token', help='Github token', required=False)
    args = parser.parse_args()

    request_pack_contributor_review(pr_number=args.pr_number, github_token=args.github_token)


if __name__ == "__main__":
    main()
