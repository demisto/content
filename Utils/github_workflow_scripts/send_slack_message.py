from typing import List

from slack_sdk import WebClient
from blessings import Terminal
from utils import get_env_var
import json
import requests
from github import Github, PaginatedList, File, PullRequest
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_metadata_file(file: File) -> dict:
    raw_url = file.raw_url
    return requests.get(raw_url, verify=False).json()


def create_slack_markdown(text: str) -> dict:
    return {
        "type": "mrkdwn",
        "text": text
    }


def create_slack_fields(text_fields: list) -> dict:
    return {
        "type": "section",
        "fields": [create_slack_markdown(f'*{key}*:\n {value}') for key, value in text_fields]
    }


def create_slack_section(key: str, value: str) -> dict:
    return ({
        "type": "section",
        "text": create_slack_markdown(f'```{key}: {value}```')
    })


def create_individual_pack_segment(metadata_obj: dict) -> List[dict]:
    pack_name = metadata_obj.get('name')
    version = metadata_obj.get('currentVersion')
    support = metadata_obj.get('support')

    pack_details = [{
        "type": "divider"
    },
        create_slack_section('Pack Name', pack_name),
        create_slack_section('Support Type', support),
        create_slack_section('Version', version),
    ]
    return pack_details


def create_packs_segment(metadata_files: PaginatedList) -> List[dict]:
    all_packs = []
    for file in metadata_files:
        metadata_obj = get_metadata_file(file)
        pack_segment = create_individual_pack_segment(metadata_obj)
        all_packs += pack_segment
    return all_packs


def create_pull_request_segment(pr: PullRequest) -> dict:
    title = pr.title
    assignees = ','.join([assignee.login for assignee in pr.assignees])
    contributor = pr.user.login
    number_of_changed_changed_files = pr.changed_files
    pr_info_segment = create_slack_fields([
        ('Title', title),
        ('Assignees', assignees),
        ('Contributor', contributor),
        ('Changed Files', number_of_changed_changed_files)
    ])
    return pr_info_segment


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

    pull_request_segment = create_pull_request_segment(pr)

    metadata_files = [file for file in pr.get_files() if file.filename.endswith('_metadata.json')]
    packs_segment = create_packs_segment(metadata_files)

    print(json.dumps([pull_request_segment] + packs_segment))
    slack_token = get_env_var('CORTEX_XSOAR_SLACK_TOKEN')
    client = WebClient(token=slack_token)
    client.chat_postMessage(
        channel="WHCL130LE",
        url="https://google.coms",
        Text={"attachments": [pull_request_segment] + packs_segment})
    # attachments={
    #     "blocks": [pull_request_segment] + packs_segment})

    #     blocks=[
    #         {
    #             "type": "section",
    #             "fields": [
    #                 {
    #                     "type": "mrkdwn",
    #                     "text": "*Title:* ```add aws network firewall integration ```"
    #                 },
    #                 {
    #                     "type": "mrkdwn",
    #                     "text": "*Pack Name:*```\nSubmitted Aut 10```"
    #                 },
    #                 {
    #                     "type": "mrkdwn",
    #                     "text": "*Test Update:*\nMar 10, 2015 (3 years, 5 months)"
    #                 },
    #                 {
    #                     "type": "mrkdwn",
    #                     "text": "*Reason:*\nAll vowel keys aren't working."
    #                 },
    #                 {
    #                     "type": "mrkdwn",
    #                     "text": "*Specs:*\n\"Cheetah Pro 15\" - Fast, really fast\""
    #                 }
    #             ]
    #         }
    #     ]
    # )


if __name__ in ["__main__"]:
    main()
