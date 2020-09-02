#!/usr/bin/env python3
import argparse
import os
import sys

from demisto_sdk.commands.common.tools import run_command, print_error, print_success
from github import Github


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-p', '--pr_number', help='Contrib PR number')
    parser.add_argument('-b', '--branch', help='The contrib branch')
    parser.add_argument('-u', '--user', help='The contrib repo')
    args = parser.parse_args()

    pr_number = args.pr_number
    user = args.user
    branch = args.branch

    gh = Github(os.getenv('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = gh.get_repo(f'{organization}/{repo}')
    pr = content_repo.get_pull(pr_number)
    pr_files = pr.get_files()
    # choose a file
    pack_dir_name = ''
    for pr_file in pr_files:
        if pr_file.filename.startswith('Packs/'):
            pack_dir_name = pr_file.filename.split('/')[1]
            break

    if not pack_dir_name:
        print_error('Did not find a pack in the PR')
        sys.exit(1)

    pack_dir = f'Packs/{pack_dir_name}'
    print(f'Copy the changes from the contributor branch {user}/{branch} in the pack {pack_dir_name}')
    os.remove(pack_dir)
    run_command(f'git remote add {user} git@github.com:{user}/content.git')
    run_command(f'git fetch {user} {branch}')
    run_command(f'git checkout {user}/{branch} {pack_dir}')

    print_success(f'Successfully updated the base branch with the contrib pack {pack_dir_name}')


if __name__ == "__main__":
    main()
