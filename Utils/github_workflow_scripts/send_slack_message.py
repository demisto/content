from typing import List

from slack_sdk import WebClient
from blessings import Terminal
from utils import get_env_var
import json
import requests
from github import Github, PaginatedList, File, PullRequest
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN_COLOR = "#6eb788"


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


def create_slack_fields(text_fields: list) -> dict:
    """Create slack block-kit section entry with fields key

        Args:
            text_fields (list): String to appear in the entry

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
            (list): List of slack blocks representing the pack information
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
            (list): List of slack blocks representing all packs information
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
            (list): List containing a lack block-kit section entry which represents the PR info
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


def create_pr_title(pr: PullRequest) -> list[dict]:
    header = [{
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"{pr.title}",
            "emoji": True
        }
    }]

def main():
    t = Terminal()
    payload_str = get_env_var('EVENT_PAYLOAD')
    if not payload_str:
        raise ValueError('EVENT_PAYLOAD env variable not set or empty')
    print(f'{t.cyan}Starting the slack notifier{t.normal}')

    payload = json.loads(payload_str)
    pr_number = payload.get('pull_request', {}).get('number')

    # Get the PR information in order to get information like metadata
    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')
    pr = content_repo.get_pull(pr_number)
    metadata_files = [file for file in pr.get_files() if file.filename.endswith('_metadata.json')]


    pull_request_segment = create_pull_request_segment(pr)
    packs_segment = create_packs_segment(metadata_files)

    blocks = header + pull_request_segment + packs_segment
    print(json.dumps(blocks))
    slack_token = get_env_var('CORTEX_XSOAR_SLACK_TOKEN')
    client = WebClient(token=slack_token)
    client.chat_postMessage(
        channel="WHCL130LE",
        url="https://google.coms",
        attachments=[
            {
                "color": GREEN_COLOR,
                "blocks": blocks
            }],
        text=f"<{pr.html_url}|*New Contribution:* {pr.title}>")


if __name__ == "__main__":
    main()
