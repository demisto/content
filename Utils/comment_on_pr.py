#!/usr/bin/env python3
import argparse
import os
import sys

import requests

from demisto_sdk.commands.common.tools import print_success, print_error


def main():
    parser = argparse.ArgumentParser(description='Add a comment to a pull request in the repo.')
    parser.add_argument('-p', '--pr_number', help='Pull request number')
    parser.add_argument('-c', '--comment', help='The comment to add')
    args = parser.parse_args()

    pr_number = args.pr_number
    comment = args.comment
    token = os.environ['CONTENT_GITHUB_TOKEN']

    pr_url = f'https://api.github.com/repos/demisto/content/pulls/{pr_number}'
    response = requests.get(pr_url)
    response.raise_for_status()
    pr = response.json()
    if not pr:
        print_error('Could not find the pull request to reply on.')
        sys.exit(1)

    comments_url = pr['comments_url']
    response = requests.get(comments_url)
    response.raise_for_status()
    comments = response.json()
    link_comments = [comment for comment in comments if 'Instance is ready.' in comment.get('body', '')]
    if link_comments:
        comments_url = link_comments[0]['url']

    headers = {'Authorization': 'Bearer ' + token}
    response = requests.post(comments_url, json={'body': comment}, headers=headers)
    response.raise_for_status()

    print_success('Successfully added the comment to the PR.')


if __name__ == '__main__':
    main()
