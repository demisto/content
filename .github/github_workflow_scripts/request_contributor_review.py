import argparse
import json
import os
from pathlib import Path
from typing import Set

import requests
import sendgrid
import sys

import urllib3
from sendgrid.helpers.mail import Email, Content, Mail

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
PACK_METADATA_SUPPORT_EMAIL_FIELD = "email"
PACK_METADATA_DEV_EMAIL_FIELD = "devEmail"
EMAIL_FROM = "do-not-reply@xsoar-contrib.pan.dev"  # disable-secrets-detection


def check_if_user_exists(github_user, github_token=None, verify_ssl=True):
    user_endpoint = f"https://api.github.com/users/{github_user}"
    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(user_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling user {github_user} data:\n{response.text}")
        sys.exit(1)

    github_user_info = response.json()
    return 'id' in github_user_info


def get_pr_author(pr_number, github_token, verify_ssl):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data:\n{response.text}")
        sys.exit(1)

    pr_info = response.json()

    return pr_info.get('user', {}).get('login', '').lower()


def get_pr_modified_files_and_packs(pr_number, github_token, verify_ssl):
    pr_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files"

    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(pr_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling PR {pr_number} data:\n{response.text}")
        sys.exit(1)

    pr_changed_data = response.json()
    pr_files = [f.get('filename') for f in pr_changed_data]
    modified_packs = {Path(p).parts[1] for p in pr_files if p.startswith(PACKS_FOLDER) and len(Path(p).parts) > 1}

    return modified_packs, pr_files


def tag_user_on_pr(reviewers: set, pr_number: str, pack: str, pack_files: set, github_token: str = None,
                   verify_ssl: bool = True):
    comments_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/comments"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    reviewers_comment = "\n".join({f"- @{r}" for r in reviewers})
    pack_files_comment = "\n".join(pack_files)

    comment_body = {
        "body": f"### Your contributed {pack} {PR_COMMENT_PREFIX}\n"
                f"{pack_files_comment}\n"
                f" [Please review the changes here](https://github.com/demisto/content/pull/{pr_number}/files)\n"
                f"{reviewers_comment}"
    }

    response = requests.post(comments_endpoint, headers=headers, verify=verify_ssl, json=comment_body)

    if response.status_code not in [200, 201]:
        print(f"Failed posting comment on PR {pr_number}:\n{response.text}")
        sys.exit(1)


def get_pr_tagged_reviewers(pr_number, github_token, verify_ssl, pack):
    result_tagged_reviewers = set()

    comments_endpoint = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/comments"
    headers = {"Authorization": "Bearer " + github_token} if github_token else {}

    response = requests.get(comments_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code != 200:
        print(f"Failed requesting PR {pr_number} comments:\n{response.text}")
        sys.exit(1)

    comments_info = response.json()
    github_actions_bot_comments = [c.get('body', '') for c in comments_info if c.get('user', {}).get(
        'login') == "github-actions[bot]" and f"### Your contributed {pack} {PR_COMMENT_PREFIX}\n" in c.get('body', '')]

    for comment in github_actions_bot_comments:
        tagged_reviewers = [line.lstrip("- @").rstrip("\n").lower() for line in comment.split('\n') if
                            line.startswith("- @")]
        result_tagged_reviewers.update(tagged_reviewers)

    return result_tagged_reviewers


def check_pack_and_request_review(pr_number, github_token=None, verify_ssl=True, email_api_token=None):
    modified_packs, modified_files = get_pr_modified_files_and_packs(pr_number=pr_number, github_token=github_token,
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

        # Notify contributors if this is not new pack
        if pack_metadata.get('support') != XSOAR_SUPPORT and pack_metadata.get('currentVersion') != '1.0.0':
            notified_by_email = False
            # Notify contributors by emailing them on dev email:
            if reviewers_emails := pack_metadata.get(PACK_METADATA_DEV_EMAIL_FIELD):
                reviewers_emails = reviewers_emails.split(',') if isinstance(reviewers_emails,
                                                                             str) else reviewers_emails
                notified_by_email = send_email_to_reviewers(
                    reviewers_emails=reviewers_emails,
                    api_token=email_api_token,
                    pack_name=pack,
                    pr_number=pr_number,
                    modified_files=modified_files
                )

            # Notify contributors by tagging them on github:
            if pack_reviewers := pack_metadata.get(PACK_METADATA_GITHUB_USER_FIELD):
                pack_reviewers = pack_reviewers if isinstance(pack_reviewers, list) else pack_reviewers.split(",")
                github_users = [u.lower() for u in pack_reviewers]

                for github_user in github_users:
                    user_exists = check_if_user_exists(github_user=github_user, github_token=github_token,
                                                       verify_ssl=verify_ssl)

                    if user_exists and github_user != pr_author:
                        reviewers.add(github_user)
                        print(f"Found {github_user} default reviewer of pack {pack}")

                notified_by_github = check_reviewers(reviewers=reviewers, pr_author=pr_author,
                                                     version=pack_metadata.get('currentVersion'),
                                                     modified_files=modified_files, pack=pack, pr_number=pr_number,
                                                     github_token=github_token,
                                                     verify_ssl=verify_ssl,
                                                     tagged_packs_reviewers=tagged_packs_reviewers)

                # Notify contributors by emailing them on support email:
                if (reviewers_emails := pack_metadata.get(
                        PACK_METADATA_SUPPORT_EMAIL_FIELD)) and not notified_by_github and not notified_by_email:
                    reviewers_emails = reviewers_emails.split(',') if isinstance(reviewers_emails,
                                                                                 str) else reviewers_emails
                    send_email_to_reviewers(
                        reviewers_emails=reviewers_emails,
                        api_token=email_api_token,
                        pack_name=pack,
                        pr_number=pr_number,
                        modified_files=modified_files
                    )

        elif pack_metadata.get('support') == XSOAR_SUPPORT:
            print(f"Skipping check of {pack} pack supported by {XSOAR_SUPPORT}")
        else:
            print(f"{pack} pack has no default github reviewer")


def check_reviewers(reviewers: set, pr_author: str, version: str, modified_files: list, pack: str,
                    pr_number: str, github_token: str, verify_ssl: bool, tagged_packs_reviewers: Set[str]) -> bool:
    """ Tag user on pr and ask for review if there are reviewers, and this is not new pack.

    Args:
        reviewers(set): reviwers to review the changes.
        pr_author(str): Author of the pr.
        version(str): pack version, from packmetadata.
        modified_files(list): list of modified files
        pack(str): pack name
        pr_number(str): pr number on github
        github_token(str): github token provided by the user
        verify_ssl(bool): verify ssl
        tagged_packs_reviewers (Set[str]): Set of reviewers who were already tagged.

     Returns:
         true if notified contributors by github else false

    """
    untagged_reviewers = reviewers.difference(tagged_packs_reviewers)
    for tagged_reviewer in reviewers.difference(untagged_reviewers):
        print(f'User {tagged_reviewer} was already tagged. Skipping re-tagging.')
    # Meaning at least one of the reviewers was already tagged.
    notified_contributors = untagged_reviewers != reviewers
    if untagged_reviewers:
        if pr_author != 'xsoar-bot' or version != '1.0.0':
            pack_files = {file for file in modified_files if file.startswith(PACKS_FOLDER)
                          and Path(file).parts[1] == pack}
            tag_user_on_pr(
                reviewers=untagged_reviewers,
                pr_number=pr_number,
                pack=pack,
                pack_files=pack_files,
                github_token=github_token,
                verify_ssl=verify_ssl
            )
            return True
        else:
            return notified_contributors
    else:
        if not notified_contributors:
            print(f'{pack} pack no reviewers were found.')
        return notified_contributors


def send_email_to_reviewers(reviewers_emails: list, api_token: str, pack_name: str,
                            pr_number: str, modified_files: list) -> bool:
    """ Compose mail and send it to the reviewers_emails, to review the changes in their pack

    Args:
        modified_files(list): modified files on pr
        reviewers_emails(list(str)): reviewers of the pack to send mail to them
        api_token(str): refresh token to send mails using gmail API
        pack_name(str): pack that was modified
        pr_number(str): github pr number

    Return: true if mail was sent, else prints an error

    """

    pack_files = {file for file in modified_files if file.startswith(PACKS_FOLDER)
                  and Path(file).parts[1] == pack_name}

    modified_files_comment = ''.join([f'<li>{file}</li>' for file in pack_files])
    email_subject = f'Cortex XSOAR: Changes made to {pack_name} content pack'
    email_content = f"Hi,<br><br>Your contributed <b>{pack_name}</b> pack has been modified on files:<br>" \
                    f"<ul>{modified_files_comment}</ul>Please review the changes " \
                    f"<a href=\"https://github.com/demisto/content/pull/{pr_number}/files\">here</a>.<br><br>" \
                    f" Cortex XSOAR Content Team."

    sg = sendgrid.SendGridAPIClient(api_token)
    email_from = Email(EMAIL_FROM)
    to_email = reviewers_emails
    content = Content("text/html", email_content)
    mail = Mail(email_from, to_email, email_subject, content)

    try:
        response = sg.client.mail.send.post(request_body=mail.get())
        if response.status_code in range(200, 209):
            print(f'Email sent to {",".join(reviewers_emails)} contributors of pack {pack_name}')
            return True
        else:
            print('An error occurred during sending emails to contributors:\n{response}')
            return False
    except Exception as e:
        print(f'An error occurred during sending emails to contributors:\n{str(e)}')
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Requests contributor pack review.')
    parser.add_argument('-p', '--pr_number', help='Opened PR number')
    parser.add_argument('-g', '--github_token', help='Github token', required=False)
    parser.add_argument('-e', '--email_api_token', help='Email API Token', required=False)
    args = parser.parse_args()

    pr_number = args.pr_number
    github_token = args.github_token
    verify_ssl = bool(github_token)
    email_api_token = args.email_api_token if args.email_api_token else ''

    if not verify_ssl:
        urllib3.disable_warnings()

    check_pack_and_request_review(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl,
                                  email_api_token=email_api_token)


if __name__ == "__main__":
    main()
