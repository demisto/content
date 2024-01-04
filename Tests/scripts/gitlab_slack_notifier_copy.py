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
    parser.add_argument(
        '-ch', '--slack_channel', help='The slack channel in which to send the notification', default=CONTENT_CHANNEL
    )
    return parser.parse_args()


def build_link_to_message(response: SlackResponse) -> str:
    if SLACK_WORKSPACE_NAME and response.status_code == requests.codes.ok:
        data: dict = response.data  # type: ignore[assignment]
        channel_id: str = data['channel']
        message_ts: str = data['ts'].replace('.', '')
        return f"https://{SLACK_WORKSPACE_NAME}.slack.com/archives/{channel_id}/p{message_ts}"
    return ""


def main():
    install_logging('Slack_Notifier.log')
    options = options_handler()
    computed_slack_channel = options.slack_channel

    slack_token = options.slack_token
    slack_client = WebClient(token=slack_token)

    # logging.info(f"Sending Slack message for pipeline {pipeline_id} in project {project_id} on server {server_url} "
    #              f"triggering workflow:'{triggering_workflow}' allowing failure:{options.allow_failure} "
    #              f"slack channel:{computed_slack_channel}")


    title = 'test'
    fallback = 'fallback'

    pipeline_url = 'https://gitlab.xdr.pan.local/xdr/cortex-content/content/-/jobs/4175703'
    color = 'warning'
    color = 'danger'
    color = 'good'

    slack_msg_data = [{
        'fallback': fallback,
        'color': color,
        'title': title,
        'title_link': pipeline_url
    }]

    try:
        response = slack_client.chat_postMessage(
            channel=computed_slack_channel, attachments=slack_msg_data, username=SLACK_USERNAME
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
