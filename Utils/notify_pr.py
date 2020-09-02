#!/usr/bin/env python3
import argparse

from Tests.test_content import add_pr_comment
from demisto_sdk.commands.common.tools import print_success


def main():
    parser = argparse.ArgumentParser(description='Add a comment to a pull request in the repo.')
    parser.add_argument('-p', '--pr_number', help='Pull request number')
    parser.add_argument('-c', '--comment', help='The comment to add')
    args = parser.parse_args()

    pr_number = args.pr_number
    comment = args.comment

    add_pr_comment(comment)

    print_success(f'Successfully added the comment to the PR.')


if __name__ == "__main__":
    main()
