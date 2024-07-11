#!/usr/bin/env python3
import argparse
import os
from collections.abc import Iterable
from urllib.parse import urljoin

import requests

PER_PAGE = 100  # value of `per_page` request parameter


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-p', '--pr_number', help='Contrib PR number')
    parser.add_argument('-b', '--branch', help='The contrib branch')
    parser.add_argument('-c', '--contrib_repo', help='The contrib repo')
    parser.add_argument('-u', '--username', help='The contrib user name')
    parser.add_argument("-gt", "--github_token", help="The Github token")
    args = parser.parse_args()

    pr_number = args.pr_number
    username = args.username
    repo = args.contrib_repo
    branch = args.branch
    github_token = args.github_token

    print(
        f"args received in .circleci/update_contribution_pack_in_base_branch.py script: {pr_number=}, {username=}, {repo=}, {branch=}"
    )

    packs_dir_names = get_files_from_github(
        username, branch, pr_number, repo, github_token
    )
    if packs_dir_names:
        print('Successfully updated the base branch '  # noqa: T201
              'with the following contrib packs: Packs/'
              f'{", Packs/".join(packs_dir_names)}')


def get_pr_files(pr_number: str, github_token: str) -> Iterable[str]:
    """
    Get changed files names from a contribution pull request.
    Args:
        pr_number: The contrib PR

    Returns:
        A list of changed file names (under the Packs dir), if found.
    """
    page = 1
    while True:
        response = requests.get(
            f"https://api.github.com/repos/demisto/content/pulls/{pr_number}/files",
            params={"page": str(page), "per_page": str(PER_PAGE)},
            headers={"Authorization": f"Bearer {github_token}"},
        )
        response.raise_for_status()
        files = response.json()
        if not files:
            break
        for pr_file in files:
            if pr_file['filename'].startswith('Packs/'):
                yield pr_file['filename']
        page += 1


def get_files_from_github(
    username: str, branch: str, pr_number: str, repo: str, github_token: str
) -> list[str]:
    """
    Write the changed files content repo
    Args:
        username: The username of the contributor (e.g. demisto / xsoar-bot)
        branch: The contributor branch
        pr_number: The contrib PR
        repo: The contrib repository
    Returns:
        A list of packs names, if found.
    """
    print("Getting files from Github")
    content_path = os.getcwd()
    print(f"content_path: {content_path}")
    files_list = set()
    chunk_size = 1024 * 500     # 500 Kb
    base_url = f'https://raw.githubusercontent.com/{username}/{repo}/{branch}/'
    print(f"base url: {base_url}")
    for file_path in get_pr_files(pr_number, github_token):
        print(f"file_path: {file_path}")
        abs_file_path = os.path.join(content_path, file_path)
        print(f"abs_file_path: {abs_file_path}")
        abs_dir = os.path.dirname(abs_file_path)
        print(f"abs_dir: {abs_dir}")
        if not os.path.isdir(abs_dir):
            os.makedirs(abs_dir)
        with open(abs_file_path, "wb") as changed_file, requests.get(
            urljoin(base_url, file_path),
            stream=True,
            headers={"Authorization": f"Bearer {github_token}"},
        ) as file_content:
            # mypy didn't like the request being used as context manager
            file_content.raise_for_status()  # type:ignore[attr-defined]
            for data in file_content.iter_content(chunk_size=chunk_size):  # type:ignore[attr-defined]
                changed_file.write(data)

        files_list.add(file_path.split(os.path.sep)[1])
    print(f"list(files_list): {list(files_list)}")
    return list(files_list)


if __name__ == '__main__':
    main()
