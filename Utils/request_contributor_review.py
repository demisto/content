import argparse
import requests
import os
import sys
from pathlib import Path
from googleapiclient.discovery import build
from apiclient import errors
import httplib2
from httplib2 import Http
from email.mime.text import MIMEText
import base64
from oauth2client.client import AccessTokenCredentials
import urllib.parse
import json
import urllib3
from datetime import datetime

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
PACK_METADATA_DEV_EMAIL_FIELD = "developerEmail"
GMAIL_CLIENT_ID = "391797357217-pa6jda1554dbmlt3hbji2bivphl0j616.apps.googleusercontent.com"
TOKEN_FORM_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    'Accept': 'application/json',
}
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
EMAIL_FROM = 'dkoval@paloaltonetworks.com'


def check_if_user_exists(github_user, github_token=None, verify_ssl=True):
    user_endpoint = f"https://api.github.com/users/{github_user}"
    headers = {'Authorization': 'Bearer ' + github_token} if github_token else {}

    response = requests.get(user_endpoint, headers=headers, verify=verify_ssl)

    if response.status_code not in [200, 201]:
        print(f"Failed in pulling user {github_user} data:\n{response.text}")
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

    if response.status_code != requests.codes.ok:
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


def check_pack_and_request_review(pr_number, github_token=None, verify_ssl=True, email_refresh_token=''):
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

        if pack_metadata.get('support') != XSOAR_SUPPORT:
            # Notify contributors by tagging them on github:
            if pack_metadata.get(PACK_METADATA_GITHUB_USER_FIELD):
                pack_reviewers = pack_metadata[PACK_METADATA_GITHUB_USER_FIELD]
                pack_reviewers = pack_reviewers if isinstance(pack_reviewers, list) else pack_reviewers.split(",")
                github_users = [u.lower() for u in pack_reviewers]

                for github_user in github_users:
                    user_exists = check_if_user_exists(github_user=github_user, github_token=github_token,
                                                       verify_ssl=verify_ssl)

                    if user_exists and github_user != pr_author and github_user not in tagged_packs_reviewers:
                        reviewers.add(github_user)
                        print(f"Found {github_user} default reviewer of pack {pack}")

                check_reviewers(reviewers=reviewers, pr_author=pr_author, version=pack_metadata.get('currentVersion'),
                                modified_files=modified_files, pack=pack, pr_number=pr_number,
                                github_token=github_token,
                                verify_ssl=verify_ssl)

            # Notify contributors by emailing them if this is not new pack:
            if (pack_metadata.get(PACK_METADATA_DEV_EMAIL_FIELD) or pack_metadata.get(
                    PACK_METADATA_SUPPORT_EMAIL_FIELD)) and pack_metadata.get('currentVersion') != '1.0.0':
                dev_emails = pack_metadata.get(PACK_METADATA_DEV_EMAIL_FIELD, '')
                dev_emails = ','.join(dev_emails) if isinstance(dev_emails, list) else dev_emails
                support_emails = pack_metadata.get(PACK_METADATA_SUPPORT_EMAIL_FIELD, '')
                support_emails = ','.join(support_emails) if isinstance(support_emails, list) else support_emails

                # send mail to developers if there are dev-mails, else send mail to pack support
                reviewers_emails = dev_emails if dev_emails else support_emails
                if reviewers_emails:
                    notify_contributors_by_email(
                        reviewers_emails=reviewers_emails,
                        refresh_token=email_refresh_token,
                        pack_name=pack,
                        pr_number=pr_number,
                        modified_files=modified_files
                    )

        elif pack_metadata.get('support') == XSOAR_SUPPORT:
            print(f"Skipping check of {pack} pack supported by {XSOAR_SUPPORT}")
        else:
            print(f"{pack} pack has no default github reviewer")


def check_reviewers(reviewers: set, pr_author: str, version: str, modified_files: list, pack: str,
                    pr_number: str, github_token: str, verify_ssl: bool):
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

    """
    if reviewers:
        if pr_author != 'xsoar-bot' or version != '1.0.0':
            pack_files = {file for file in modified_files if file.startswith(PACKS_FOLDER)
                          and Path(file).parts[1] == pack}
            tag_user_on_pr(
                reviewers=reviewers,
                pr_number=pr_number,
                pack=pack,
                pack_files=pack_files,
                github_token=github_token,
                verify_ssl=verify_ssl
            )

    else:
        print(f'{pack} pack no reviewers were found.')


def notify_contributors_by_email(reviewers_emails: str, refresh_token: str, pack_name: str,
                                 pr_number: str, modified_files: list):
    access_token = get_access_token(refresh_token)
    credentials = AccessTokenCredentials(access_token, 'Demisto Github send mails to contributors')
    service = build('gmail', 'v1', credentials=credentials)

    pack_files = {file for file in modified_files if file.startswith(PACKS_FOLDER)
                  and Path(file).parts[1] == pack_name}
    pack_files_comment = "\n".join(pack_files)

    email_content = f"### Your contributed {pack_name} {PR_COMMENT_PREFIX}\n"
    email_content += f"{pack_files_comment}\n"
    email_content += f" [Please review the changes here](https://github.com/demisto/content/pull/{pr_number}/files)\n"
    email_subject = f'Your contributed pack - {pack_name} has been modified'

    message = MIMEText(email_content, 'plain', 'utf-8')
    message['bcc'] = reviewers_emails  # send mails to all contributors in bcc
    message['from'] = EMAIL_FROM
    message['subject'] = email_subject
    message_to_send = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

    try:
        service.users().messages().send(userId=EMAIL_FROM, body=message_to_send).execute()
        print(f'Email sent to {reviewers_emails} reviewers of pack {pack_name}')
    except errors.HttpError as e:
        print(f'An error occurred during sending emails to contributors: {str(e)}')
        sys.exit(1)


def get_access_token(refresh_token: str):
    access_token = os.getenv('ACCESS_TOKEN')
    valid_until = int(os.getenv('VALID_UNTIL')) if os.getenv('VALID_UNTIL') else None

    # check if access token is valid
    if access_token and valid_until:
        if int(datetime.now().timestamp()) < valid_until:
            return access_token

    if not refresh_token:
        print(f"Error obtaining access token. Failed sending mails.")
        sys.exit(1)

    # else access token should be obtained from refresh token
    http_client = httplib2.Http()
    body = {
        'refresh_token': refresh_token,
        'client_id': GMAIL_CLIENT_ID,
        'grant_type': 'refresh_token',
    }
    resp, content = http_client.request(TOKEN_URL, "POST", urllib.parse.urlencode(body), TOKEN_FORM_HEADERS)

    if resp.status not in [200, 201]:
        print(f"Error obtaining access token. Failed sending mails.")
        sys.exit(1)

    parsed_response = json.loads(content)
    access_token = parsed_response.get('access_token')
    expires_in = parsed_response.get('expires_in', 3595)

    time_now = int(datetime.now().timestamp())
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    # set environment variables
    os.environ['ACCESS_TOKEN'] = access_token
    os.environ['VALID_UNTIL'] = str(time_now + expires_in)

    return access_token


def main():
    parser = argparse.ArgumentParser(description='Requests contributor pack review.')
    parser.add_argument('-p', '--pr_number', help='Opened PR number')
    parser.add_argument('-g', '--github_token', help='Github token', required=False)
    parser.add_argument('-e', '--email_refresh_token', help='Email refresh token', required=False)
    args = parser.parse_args()

    pr_number = args.pr_number
    github_token = args.github_token
    verify_ssl = True if github_token else False
    email_refresh_token = args.email_refresh_token if args.email_refresh_token else ''

    if not verify_ssl:
        urllib3.disable_warnings()

    check_pack_and_request_review(pr_number=pr_number, github_token=github_token, verify_ssl=verify_ssl,
                                  email_refresh_token=email_refresh_token)


if __name__ == "__main__":
    main()
