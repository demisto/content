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
PR_COMMENT_PREFIX = "pack has been modified on files:\n"


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


def get_pr_modified_files_and_packs(pr_number, github_token, verify_ssl):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files"

    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data")
        sys.exit(1)

    pr_changed_data = response.json()
    pr_files = [f.get('filename') for f in pr_changed_data]
    modified_packs = {Path(p).parts[1] for p in pr_files if p.startswith(PACKS_FOLDER) and len(Path(p).parts) > 1}

    blob_url = pr_changed_data[0].get('blob_url').split('/')
    commit = blob_url[blob_url.index('blob')+1]

    return modified_packs, pr_files, commit


def tag_user_on_pr(reviewers: set, pr_number: str, pack: str, pack_files: set, commit: str, github_token: str = None,
                   verify_ssl: bool = True):
    comments_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/comments"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    reviewers_comment = "\n".join({f"- @{r}" for r in reviewers})
    # pack_files_comment = "\n[".join(pack_files) + ']'
    pack_files_comment = ''
    new_line = '/n'
    for file in pack_files:
        pack_files_comment += f'\n[{file}](https://github.com/demisto/content/blob/{commit}/{file})'

    comment_body = {
        "body": f"### Your contributed {pack} {PR_COMMENT_PREFIX}"
                f"{pack_files_comment}\n"
                f" Please review the changes.\n"
                f"{reviewers_comment}"
    }

    response = requests.post(comments_endpoint, headers=headers, verify=verify_ssl, json=comment_body)

    if response.status_code not in [200, 201]:
        print(f"Failed posting comment on PR {pr_number}")
        sys.exit(1)


def get_pr_tagged_reviewers(pr_number, github_token, verify_ssl, pack):
    result_tagged_reviewers = set()

    comments_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/comments"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    response = requests.get(comments_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code != requests.codes.ok:
        print(f"Failed requesting PR {pr_number} comments")
        sys.exit(1)

    comments_info = response.json()
    github_actions_bot_comments = [c.get('body', '') for c in comments_info if c.get('user', {}).get(
        'login') == "github-actions[bot]" and f"### Your contributed {pack} {PR_COMMENT_PREFIX}\n" in c.get('body', '')]

    for comment in github_actions_bot_comments:
        tagged_reviewers = [line.lstrip("- @").rstrip("\n").lower() for line in comment.split('\n') if
                            line.startswith("- @")]
        result_tagged_reviewers.update(tagged_reviewers)

    return result_tagged_reviewers


def check_pack_and_request_review(pr_number, github_token=None, verify_ssl=True):
    modified_packs, modified_files, commit = get_pr_modified_files_and_packs(pr_number=pr_number,
                                                                             github_token=github_token,
                                                                             verify_ssl=verify_ssl)
    pr_author = get_pr_author(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl)

    for pack in modified_packs:
        tagged_packs_reviewers = get_pr_tagged_reviewers(pr_number=pr_number, github_token=github_token,
                                                         verify_ssl=verify_ssl, pack=pack)
        reviewers = set()
        pack_metadata_path = os.path.join(PACKS_FULL_PATH, pack, PACK_METADATA)

        if not os.path.exists(pack_metadata_path):
            print(f"Not found {pack} {PACK_METADATA} file.")
            continue

        with open(pack_metadata_path, 'r') as pack_metadata_file:
            pack_metadata = json.load(pack_metadata_file)

        if pack_metadata.get('support') != XSOAR_SUPPORT and pack_metadata.get(PACK_METADATA_GITHUB_USER_FIELD):
            pack_reviewers = pack_metadata[PACK_METADATA_GITHUB_USER_FIELD]
            pack_reviewers = pack_reviewers if isinstance(pack_reviewers, list) else pack_reviewers.split(",")
            github_users = [u.lower() for u in pack_reviewers]

            for github_user in github_users:
                user_exists = check_if_user_exists(github_user=github_user, github_token=github_token,
                                                   verify_ssl=verify_ssl)

                if user_exists and github_user != pr_author and github_user not in tagged_packs_reviewers:
                    reviewers.add(github_user)
                    print(f"Found {github_user} default reviewer of pack {pack}")

            if reviewers:
                pack_files = {file for file in modified_files if file.startswith(PACKS_FOLDER)
                              and Path(file).parts[1] == pack}
                tag_user_on_pr(reviewers=reviewers, pr_number=pr_number, pack=pack, pack_files=pack_files,
                               commit=commit, github_token=github_token, verify_ssl=verify_ssl)
            else:
                print(f"{pack} pack No reviewers were found.")

        elif pack_metadata.get('support') == XSOAR_SUPPORT:
            print(f"Skipping check of {pack} pack supported by {XSOAR_SUPPORT}")
        else:
            print(f"{pack} pack has no default github reviewer")


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
