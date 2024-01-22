import argparse
import logging
import os
import sys
from distutils.util import strtobool

import requests

from slack_sdk import WebClient
from slack_sdk.web import SlackResponse

from Tests.scripts.utils.log_util import install_logging


CONTENT_CHANNEL = 'dmst-build-test'
SLACK_USERNAME = 'Content GitlabCI'
SLACK_WORKSPACE_NAME = os.getenv('SLACK_WORKSPACE_NAME', '')


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-s', '--slack_token', help='The token for slack', required=True)
    parser.add_argument('-t', '--message_text', help='The message text', required=True)
    parser.add_argument(
        '-ch', '--slack_channel', help='The slack channel in which to send the notification', default=CONTENT_CHANNEL
    )
    parser.add_argument('-a', '--allow-failure',
                        help="Allow posting message to fail in case the channel doesn't exist", required=True)
    return parser.parse_args()


def build_link_to_message(response: SlackResponse) -> str:
    if SLACK_WORKSPACE_NAME and response.status_code == requests.codes.ok:
        data: dict = response.data  # type: ignore[assignment]
        channel_id: str = data['channel']
        message_ts: str = data['ts'].replace('.', '')
        return f"https://{SLACK_WORKSPACE_NAME}.slack.com/archives/{channel_id}/p{message_ts}"
    return ""


def main():
    install_logging('SlackNotifier.log')
    options = options_handler()
    computed_slack_channel = options.slack_channel
    slack_token = options.slack_token
    text = options.message_text

    slack_client = WebClient(token=slack_token)

    logging.info(f"Sending Slack message to slack channel:{computed_slack_channel}, "
                 f"allowing failure:{options.allow_failure}")

    try:
        response = slack_client.chat_postMessage(
            channel=computed_slack_channel, text=text, username=SLACK_USERNAME
        )
        link = build_link_to_message(response)
        logging.info(f'Successfully sent Slack message to channel {computed_slack_channel} link: {link}')
    except Exception:
        if strtobool(options.allow_failure):
            logging.warning(f'Failed to send Slack message to channel {computed_slack_channel} not failing build')
        else:
            logging.exception(f'Failed to send Slack message to channel {computed_slack_channel}')
            sys.exit(1)


if __name__ == '__main__':
    main()
