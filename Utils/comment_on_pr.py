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

    comments_url = get_pr_comments_url(pr_number)

    headers = {'Authorization': 'Bearer ' + token}
    response = requests.post(comments_url, json={'body': comment}, headers=headers)
    response.raise_for_status()

    print_success('Successfully added the comment to the PR.')


def get_pr_comments_url(pr_number: str) -> str:
    """
    Get the comments URL for a PR. If the PR contains a comment about an instance test (for contrib PRs),
    it will use that comment.
    Args:
        pr_number: The pull request number

    Returns:
        The comments URL for the PR.
    """
    pr_url = f'https://api.github.com/repos/demisto/content/pulls/{pr_number}'
    response = requests.get(pr_url)
    response.raise_for_status()
    pr = response.json()
    if not pr:
        print_error('Could not find the pull request to reply on.')
        sys.exit(1)
    page = 1
    comments_url = pr['comments_url']
    while True:
        response = requests.get(comments_url, params={'page': str(page)})
        response.raise_for_status()
        comments = response.json()
        if not comments:
            break

        link_comments = [comment for comment in comments if 'Instance is ready.' in comment.get('body', '')]
        if link_comments:
            comments_url = link_comments[0]['url']
            break
        page += 1

    return comments_url


if __name__ == '__main__':
    main()
