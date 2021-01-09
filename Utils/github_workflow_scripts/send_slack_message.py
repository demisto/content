#!/usr/bin/env python3

from typing import List

from slack_sdk import WebClient
from blessings import Terminal
from utils import get_env_var
import json
import requests
from github import Github, PaginatedList, File, PullRequest
import urllib3
from pprint import pformat

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN_COLOR = "#6eb788"
SLACK_CHANNEL_TO_SEND_PR_TO = 'contribution-reviews'


def get_metadata_file(file: File) -> dict:
    """Perform a GET request to receive a given file content

    Args:
        file (File): The file object to receive the content for

    Returns:
        (dict): Content of a metadata file
    """
    raw_url = file.raw_url
    try:
        response_json = requests.get(raw_url, verify=False).json()
    except ValueError:
        raise Exception(f'{file.filename} is not a well-formatted metadata.json file')
    return response_json


def create_slack_markdown(text: str) -> dict:
    """Create slack block-kit markdown entry

    Args:
        text (str): String to appear in the entry

    Returns:
        (dict): markdown entry for the slack block-kit
    """
    return {
        "type": "mrkdwn",
        "text": text
    }


def create_slack_fields(text_fields: List) -> dict:
    """Create slack block-kit section entry with fields key

        Args:
            text_fields (List): list of key-value tuples

        Returns:
            (dict): section entry for the slack block-kit
    """
    return {
        "type": "section",
        "fields": [create_slack_markdown(f'*{key}*:\n {value}') for key, value in text_fields]
    }


def create_slack_section(key: str, value: str) -> dict:
    """Create slack block-kit section entry with text key

        Args:
            key (str): pack related key (example pack version)
            value (str): pack related value (example 1.0.0)

        Returns:
            (dict): section entry for the slack block-kit
    """
    return ({
        "type": "section",
        "text": create_slack_markdown(f'```{key}: {value}\n```')
    })


def create_individual_pack_segment(metadata_obj: dict) -> List[dict]:
    """Create the pack information segment of the message

        Args:
            metadata_obj (dict): metadata information dictionary

        Returns:
            (List): List of slack blocks representing the pack information
    """
    pack_name = metadata_obj.get('name')
    version = metadata_obj.get('currentVersion')
    support = metadata_obj.get('support')

    pack_details = [
        create_slack_section('Pack Name', pack_name),
        create_slack_section('Support Type', support),
        create_slack_section('Version', version),
        {
            "type": "divider"
        }
    ]
    return pack_details


def create_packs_segment(metadata_files: PaginatedList) -> List[dict]:
    """Aggregate the pack information segments of the message

        Args:
            metadata_files (PaginatedList): List of File objects representing metadata files

        Returns:
            (List): List of slack blocks representing all packs information
    """
    all_packs = []
    for file in metadata_files:
        metadata_obj = get_metadata_file(file)
        pack_segment = create_individual_pack_segment(metadata_obj)
        all_packs += pack_segment
    return all_packs


def create_pull_request_segment(pr: PullRequest) -> List[dict]:
    """Create the pull request information segment of the message

        Args:
            pr (PullRequest): object that represents the pull request.

        Returns:
            (List): List containing a slack block-kit section entry which represents the PR info
    """
    assignees = ','.join([assignee.login for assignee in pr.assignees])
    contributor = pr.user.login
    number_of_changed_changed_files = pr.changed_files
    labels = ','.join([label.name for label in pr.labels])
    pr_info_segment = create_slack_fields([
        ('Assignees', assignees),
        ('Contributor', contributor),
        ('Changed Files', number_of_changed_changed_files),
        ('Labels', labels),
    ])
    return [pr_info_segment]


def create_pr_title(pr: PullRequest) -> List[dict]:
    """Create the message title

        Args:
            pr (PullRequest): object that represents the pull request.

        Returns:
            (List): List containing a dictionary which represents the message title
    """
    header = [{
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"{pr.title}",
            "emoji": True
        }
    }]
    return header


def slack_post_message(client: WebClient, message_blocks: List, pr: PullRequest):
    """Post a message to a slack channel

        Args:
            client (WebClient): Slack web-client object.
            message_blocks (List): List of blocks representing the message blocks.
            pr (PullRequest): object that represents the pull request.

        Returns:
            (List): List containing a dictionary which represents the message title
    """
    client.chat_postMessage(
        channel=SLACK_CHANNEL_TO_SEND_PR_TO,
        attachments=[
            {
                "color": GREEN_COLOR,
                "blocks": message_blocks
            }],
        text=f"<{pr.html_url}|*New Contribution:* {pr.title}>")


def main():
    t = Terminal()
    payload_str = get_env_var('EVENT_PAYLOAD')
    print(f'{t.cyan}Starting the slack notifier{t.normal}')

    payload = json.loads(payload_str)
    pr_number = payload.get('pull_request', {}).get('number')

    # Get the PR information in order to get information like metadata
    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')
    slack_token = get_env_var('CORTEX_XSOAR_SLACK_TOKEN')
    print(slack_token[-3:])
    pr = content_repo.get_pull(pr_number)
    metadata_files = [file for file in pr.get_files() if file.filename.endswith('_metadata.json')]

    # Build all blocks of the message
    header = create_pr_title(pr)
    pull_request_segment = create_pull_request_segment(pr)
    packs_segment = create_packs_segment(metadata_files)
    blocks = header + pull_request_segment + packs_segment
    print(f'{t.yellow}Finished preparing message: \n{pformat(blocks)}{t.normal}')

    # Send message

    client = WebClient(token=slack_token)
    slack_post_message(client, blocks, pr)
    print(f'{t.cyan}Slack message sent successfully{t.normal}')


if __name__ == "__main__":
    main()
