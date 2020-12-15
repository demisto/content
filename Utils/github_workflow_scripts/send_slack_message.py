from slack import WebClient
from blessings import Terminal
from utils import get_env_var
import json
from github import Github


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
    files = pr.get_files().get_page(0)
    print(files)

    slack_token = get_env_var('CORTEX_XSOAR_SLACK_TOKEN')
    client = WebClient(token=slack_token)
    # client.chat_postMessage(
    #     channel="WHCL130LE",
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


if __name__ == "__main__":
    main()
