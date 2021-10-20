import argparse
import os
from pathlib import Path
from typing import List

from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.common.tools import get_pack_names_from_files
from git import Repo

PACK_PATH_REGEX = r'Packs/([a-zA-Z0-9_]+)/'


def dir_path(path: str):
    """Directory type module for argparse.
    """
    if os.path.isdir(path):
        return Path(path)
    else:
        raise argparse.ArgumentTypeError(f'{path} is not a valid path.')


def option_handler() -> argparse.Namespace:
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description='Collect the packs that has changed.')
    parser.add_argument('-rp', '--repo_path', help='The path to the required repo.', type=dir_path)
    return parser.parse_args()


def get_changed_files(repo_path: Path) -> List[str]:
    """Uses the demisto-sdk's GitUtil to get all the changed files.

    Args:
        repo_path (Path): The path to the repo.

    Returns:
        List[str]. All the files that have changed.
    """
    repo = Repo(repo_path, search_parent_directories=True)
    git_util = GitUtil(repo)

    prev_ver = 'master'
    if str(repo.active_branch) == 'master':
        # Get the latest commit in master, prior the merge.
        commits_list = list(repo.iter_commits())
        prev_ver = str(commits_list[1])

    modified_files = git_util.modified_files(prev_ver=prev_ver)
    added_files = git_util.added_files(prev_ver=prev_ver)
    renamed_tuples = git_util.renamed_files(prev_ver=prev_ver)
    renamed_files = {new_file_path for _, new_file_path in renamed_tuples}

    all_changed_files = modified_files.union(added_files).union(renamed_files)
    return [str(changed_file) for changed_file in all_changed_files]


def main():
    options = option_handler()
    repo_path: Path = options.repo_path

    changed_files = get_changed_files(repo_path)

    packs_changed = get_pack_names_from_files(changed_files)
    changed_packs_string = ",".join(packs_changed)

    print(changed_packs_string)


if __name__ == '__main__':
    main()
