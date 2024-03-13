import argparse
import logging
import os
import sys
import requests
from distutils.util import strtobool
from slack_sdk import WebClient
from slack_sdk.web import SlackResponse
from Utils.github_workflow_scripts.utils import get_env_var
from Tests.scripts.utils.log_util import install_logging
from pathlib import Path


CONTENT_CHANNEL = 'dmst-build-test'

SLACK_USERNAME = 'Content GitlabCI'

SLACK_WORKSPACE_NAME = os.getenv('SLACK_WORKSPACE_NAME', '')
CI_API_V4_URL = get_env_var('CI_API_V4_URL', 'https://gitlab.xdr.pan.local/api/v4')  # disable-secrets-detection
INFRA_PROJECT_ID = get_env_var('INFRA_PROJECT_ID', '1701')

NAME_MAPPING_URL = f'{CI_API_V4_URL}/projects/{INFRA_PROJECT_ID}/repository/files/.gitlab%2Fci%2Fname_mapping.json/raw'


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-s', '--slack_token', help='The token for slack', required=True)
    parser.add_argument('-t', '--message_text', help='The message text')
    parser.add_argument('-f', '--file', help='File path with the text to send')
    parser.add_argument('-gt', '--gitlab_token', help='Gitlab API token, required when using the --github_username argument')
    parser.add_argument('-gu', '--github_username', help='Github username to tag in the message')
    parser.add_argument(
        '-ch', '--slack_channel', help='The slack channel in which to send the notification', default=CONTENT_CHANNEL
    )
    parser.add_argument('-a', '--allow-failure',
                        help="Allow posting message to fail in case the channel doesn't exist", required=True)
    return parser.parse_args()


def get_slack_user(gitlab_token, github_username):
    headers = {'PRIVATE-TOKEN': gitlab_token}
    response = requests.request('GET', NAME_MAPPING_URL, headers=headers, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error('Failed to retrieve the name_mapping.json file')
        logging.error(response.text)
        sys.exit(1)

    slack_user = response.json().get('names', {}).get(github_username)
    if not slack_user:
        logging.error(f'The user {github_username} not exists in the name_mapping.json file')
        sys.exit(1)
    return slack_user


def build_link_to_message(response: SlackResponse) -> str:
    if SLACK_WORKSPACE_NAME and response.status_code == requests.codes.ok:
        data: dict = response.data  # type: ignore[assignment]
        channel_id: str = data['channel']
        message_ts: str = data['ts'].replace('.', '')
        return f"https://{SLACK_WORKSPACE_NAME}.slack.com/archives/{channel_id}/p{message_ts}"
    return ""


def main():
    install_logging('gitlab_basic_slack_notifier.log')
    options = options_handler()
    slack_channel = options.slack_channel
    slack_token = options.slack_token
    text = options.message_text
    text_file = options.file
    gitlab_token = options.gitlab_token
    github_username = options.github_username

    if github_username and not gitlab_token:
        logging.error('In order to use the --github_username, --gitlab_token must be provided')
        sys.exit(1)

    if not text and not text_file:
        logging.error('One of the arguments --message_text or --file must be provided, none given')
        sys.exit(1)
    elif not text:
        # read the text from the file
        try:
            text = Path(text_file).read_text()
        except Exception as e:
            logging.error(f'Failed to read from file {text_file}, error: {str(e)}')
            sys.exit(1)

    slack_client = WebClient(token=slack_token)

    logging.info(f"Sending Slack message to slack channel:{slack_channel}, "
                 f"allowing failure:{options.allow_failure}")

    if github_username:
        # tag the slack user in the message
        text = f'Hi @{get_slack_user(gitlab_token, github_username)} {text}'

    try:
        response = slack_client.chat_postMessage(
            channel=slack_channel, text=text, username=SLACK_USERNAME, link_names=True
        )
        link = build_link_to_message(response)
        logging.info(f'Successfully sent Slack message to channel {slack_channel} link: {link}')
    except Exception:
        if strtobool(options.allow_failure):
            logging.warning(f'Failed to send Slack message to channel {slack_channel} not failing build')
        else:
            logging.exception(f'Failed to send Slack message to channel {slack_channel}')
            sys.exit(1)


if __name__ == '__main__':
    main()
