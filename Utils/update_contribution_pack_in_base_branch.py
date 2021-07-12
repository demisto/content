#!/usr/bin/env python3
import argparse
import os
from typing import Iterable, List
from urllib.parse import urljoin

import requests
from demisto_sdk.commands.common.tools import print_success


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-p', '--pr_number', help='Contrib PR number')
    parser.add_argument('-b', '--branch', help='The contrib branch')
    parser.add_argument('-c', '--contrib_repo', help='The contrib repo')
    args = parser.parse_args()

    pr_number = args.pr_number
    repo = args.contrib_repo
    branch = args.branch

    packs_dir_names = get_files_from_github(repo, branch, pr_number)
    if packs_dir_names:
        print_success(f'Successfully updated the base branch with the following contrib packs: Packs/'
                    f'{", Packs/".join(packs_dir_names)}')


def get_pr_files(pr_number: str) -> Iterable[str]:
    """
    Get changed files names from a contribution pull request.
    Args:
        pr_number: The contrib PR

    Returns:
        A list of changed file names (under the Packs dir), if found.
    """

    page = 1
    while True:
        response = requests.get(f'https://api.github.com/repos/demisto/content/pulls/{pr_number}/files',
                                params={'page': str(page)})
        response.raise_for_status()
        files = response.json()
        if not files:
            break
        for pr_file in files:
            if pr_file['filename'].startswith('Packs/'):
                yield pr_file['filename']
        page += 1


def get_files_from_github(username: str, branch: str, pr_number: str) -> List[str]:
    """
    Write the changed files content repo
    Args:
        username: The username of the contributor (e.g. demisto / xsoar-bot)
        branch: The contributor branch
        pr_number: The contrib PR
    Returns:
        A list of packs names, if found.
    """
    content_path = os.getcwd()
    files_list = set()
    chunk_size = 1024 * 500     # 500 Kb
    base_url = f'https://raw.githubusercontent.com/{username}/content/{branch}'
    for file_path in get_pr_files(pr_number):
        file_path_parts = file_path.split('/')
        file_dir = os.path.sep.join(file_path_parts[:-1])
        abs_dir = os.path.join(content_path, file_dir)
        if not os.path.isdir(abs_dir):
            os.makedirs(abs_dir)
        with open(os.path.join(content_path, file_path), 'wb') as changed_file:
            with requests.get(urljoin(base_url, file_path), stream=True) as file_content:
                for data in file_content.iter_content(chunk_size=chunk_size):
                    changed_file.write(data)
        
        files_list.add(file_path_parts[1])
    return list(files_list)
    
if __name__ == '__main__':
    main()
