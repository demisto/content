from Tests.scripts.collect_tests.logger import logger
from Tests.scripts.collect_tests.utils import find_pack_folder, FilesToCollect
from pathlib import Path
import os
from git import Repo
from Tests.scripts.collect_tests.exceptions import NotUnderPackException
from Tests.Marketplace.marketplace_services import get_last_commit_from_index


class DiffChecker:
    def __init__(self, repo_path: Repo, branch_name: str, service_account: str | None, marketplace: str):
        self.repo = repo_path
        self.branch_name = branch_name
        self.service_account = service_account
        self.marketplace = marketplace

    def get_diff_master_bucket(self):
        # return ['Zoom', 'AHA']  # TODO
        return []

    def get_git_diff(self) -> FilesToCollect: #TODO ADD rshunim upload_delta_from_last_upload
        """
        The method extracts the files based on the diff between the two commits.

        """
        changed_files: list[str] = []
        packs_files_were_removed_from: set[str] = set()

        previous_commit = 'origin/master'
        current_commit = self.branch_name

        logger.debug(f'Getting changed files for {self.branch_name=}')

        if os.getenv('NIGHTLY'):
            logger.info('NIGHTLY: getting failed packs from the previous upload')
            # TODO
            logger.info('NIGHTLY: getting last commit from index')
            previous_commit = get_last_commit_from_index(self.service_account, self.marketplace)
            if self.branch_name == 'master':
                current_commit = os.getenv("CI_COMMIT_SHA", "")

        elif self.branch_name == 'master':
            current_commit, previous_commit = tuple(self.repo.iter_commits(max_count=2))

        diff = self.repo.git.diff(f'{previous_commit}...{current_commit}', '--name-status')
        logger.debug(f'raw changed files string:\n{diff}')

        # diff is formatted as `M  foo.json\n A  bar.py\n ...`, turning it into ('foo.json', 'bar.py', ...).
        for line in diff.splitlines():
            match len(parts := line.split('\t')):
                case 2:
                    git_status, file_path = parts
                case 3:
                    git_status, old_file_path, file_path = parts  # R <old location> <new location>

                    if git_status.startswith('R'):
                        logger.debug(f'{git_status=} for {file_path=}, considering it as <M>odified')
                        git_status = 'M'

                    if pack_file_moved_from := self.find_pack_file_removed_from(Path(old_file_path), Path(file_path)):
                        packs_files_were_removed_from.add(pack_file_moved_from)

                case _:
                    raise ValueError(f'unexpected line format '
                                     f'(expected `<modifier>\t<file>` or `<modifier>\t<old_location>\t<new_location>`'
                                     f', got {line}')

            if git_status not in {'A', 'M', 'D', }:
                logger.warning(f'unexpected {git_status=}, considering it as <M>odified')

            if git_status == 'D':  # git-deleted file
                if pack_file_removed_from := self.find_pack_file_removed_from(Path(file_path), None):
                    packs_files_were_removed_from.add(pack_file_removed_from)
                continue  # not adding to changed files list

            changed_files.append(file_path)  # non-deleted files (added, modified)
        return FilesToCollect(changed_files=tuple(changed_files),
                              pack_ids_files_were_removed_from=tuple(packs_files_were_removed_from))

    def find_pack_file_removed_from(self, old_path: Path, new_path: Path | None = None):
        """
        If a file is moved between packs, we should collect the older one, to make sure it is installed properly.
        """
        # two try statements as we need to tell which of the two is a pack, separately.
        try:
            old_pack = find_pack_folder(old_path).name
        except NotUnderPackException:
            logger.debug(f'Skipping pack collection for removed file: {old_path}, as it does not belong to any pack')
            return None  # not moved from a pack, no special treatment we can do here.

        if new_path:
            try:
                new_pack = find_pack_folder(new_path).name
            except NotUnderPackException:
                new_pack = None
                logger.warning(f'Could not find the new pack of the file that was moved from {old_path}')

            if old_pack != new_pack:  # file moved between packs
                logger.info(f'file {old_path.name} was moved '
                            f'from pack {old_pack}, adding it, to make sure it still installs properly')
        else:
            # Since new_path is None we understand the item was deleted
            logger.info(f'file {old_path.name} was deleted '  # changing log
                        f'from pack {old_pack}, adding it, to make sure it still installs properly')

        return old_pack
