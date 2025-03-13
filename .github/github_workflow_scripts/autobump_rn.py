from pathlib import Path
from itertools import pairwise
from typing import List
import urllib3
import argparse
from blessings import Terminal
from demisto_sdk.commands.common.constants import ExecutionMode
from demisto_sdk.commands.validate.config_reader import ConfigReader
from demisto_sdk.commands.validate.initializer import Initializer
from demisto_sdk.commands.validate.validate_manager import ValidateManager
from demisto_sdk.commands.validate.validation_results import ResultWriter
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository
import sys
from skip_conditions import MetadataCondition, \
    LastModifiedCondition, LabelCondition, AddedRNFilesCondition, HasConflictOnAllowedFilesCondition, \
    PackSupportCondition, MajorChangeCondition, MaxVersionCondition, OnlyVersionChangedCondition, \
    OnlyOneRNPerPackCondition, SameRNMetadataVersionCondition, AllowedBumpCondition, UpdateType
from utils import timestamped_print, Checkout
from git import Repo
from demisto_sdk.commands.update_release_notes.update_rn import UpdateRN
import os

urllib3.disable_warnings()

print = timestamped_print
t = Terminal()

ORGANIZATION_NAME = "demisto"
REPO_MANE = "content"
BASE = "iamthemaster" #todo change obviously
PR_COMMENT_TITLE = "### This PR was automatically updated by a " \
                   "[GitHub Action](https://github.com/demisto/content/actions/runs/{})\n"
PR_COMMENT = "- **{}** pack version was bumped to **{}**.\n"
COMMIT_MESSAGE = "Bump pack from version {} to {}."
MERGE_FROM_MASTER_COMMIT_MESSAGE = f"Merged {BASE} into current branch."
PACKS_DIR = "Packs"
NOT_UPDATE_RN_LABEL = "ignore-auto-bumasdasdp-version"
PR_COMMENT_STOP_AUTOMATION = f"\nTo stop automatic version bumps, add the `{NOT_UPDATE_RN_LABEL}` " \
                             f"label to the github PR.\n"


class PackAutoBumper:
    def __init__(
        self,
        pack_id: str,
        rn_file_path: Path,
        update_type: UpdateType,
    ):
        """
        Autobump pack version.
        Args:
            pack_id: Pack id to its release notes.
            rn_file_path: last release notes path.
            update_type: the update type that was in the pr.
        """
        self.pack_id = pack_id
        self._last_rn_file_path = rn_file_path
        self._update_type = update_type
        self._update_rn_obj = UpdateRN(
            pack_path=f"{PACKS_DIR}/{pack_id}",
            update_type=update_type.value,
            modified_files_in_pack=set(),
            added_files=set(),
            pack=pack_id,
            is_force=True,
        )
        # Setting to default. Will be updated once we are checked out to the branch in set_pr_changed_rn_related_data.
        self._bc_file = self._last_rn_file_path.with_suffix(".json")
        self._has_bc = False
        self._rn_text = ""
        self._bc_text = ""

    def set_pr_changed_rn_related_data(self):
        """Opens release notes and bc changes files and saves its text."""
        self._rn_text = self._last_rn_file_path.read_text()
        self._has_bc = self._bc_file.exists()
        if self._has_bc:
            self._bc_text = self._bc_file.read_text()

    def autobump(self) -> str:
        """AutoBumps packs version:
        1. Bumps numeric version of the pack
        2. Writes new version to metadata
        3. Creates new release notes file
        4. Writes previous release notes content to new path
        5. If there breaking changes file, updating it to the new version
        Returns: (str) new pack version.
        """

        print(f"Starting to bump packs {self.pack_id} version.")
        print(f"Update type: {self._update_type}, Previous RN path: {self._last_rn_file_path}, Is BC: {self._has_bc}.")
        new_version, metadata_dict = self._update_rn_obj.bump_version_number()
        self._update_rn_obj.write_metadata_to_file(metadata_dict=metadata_dict)
        new_release_notes_str = self._update_rn_obj.get_release_notes_path(new_version)
        new_release_notes_path = Path(new_release_notes_str)

        if new_release_notes_path.stem != self._last_rn_file_path.stem:
            new_release_notes_path.write_text(self._rn_text)
            if self._last_rn_file_path.read_text() == self._rn_text:
                self._last_rn_file_path.unlink()

            if self._has_bc:
                new_release_notes_path.with_suffix(".json").write_text(self._bc_text)
                if self._bc_file.read_text() == self._bc_text:
                    # delete previous bc file, if it was not changed after merge from master
                    self._bc_file.unlink()
        return new_version


class BranchAutoBumper:
    def __init__(
        self,
        pr: PullRequest,
        git_repo: Repo,
        packs_to_autobump: List[PackAutoBumper],
        run_id: str,
    ):
        """
        Args:
            pr: Pull Request related to the branch.
            git_repo: Git API object
            packs_to_autobump: Pack that was changed in this PR and need to autobump its versions.
            run_id: GitHub action run id.
        """
        assert (
            packs_to_autobump
        ), f"packs_to_autobump in the pr: {pr.number}, cant be empty."
        self.pr = pr
        self.branch = pr.head.ref
        self.git_repo = git_repo
        self.packs_to_autobump = packs_to_autobump
        self.github_run_id = run_id

    def autobump(self):
        """AutoBumps version for all relevant packs in the pr:
        1. Checkouts the branch and saves pr changed related data.
        2. Merges from BASE and accept `theirs` changes.
        3. AutoBumps version for each relevant packs.
        4. Commit changes for each pack.
        5. Comment on the PR.
        6. Pushes the changes.
        """
        body = PR_COMMENT_TITLE.format(self.github_run_id)
        with Checkout(self.git_repo, self.branch):
            for pack_auto_bumper in self.packs_to_autobump:
                pack_auto_bumper.set_pr_changed_rn_related_data()
            self.git_repo.git.merge(
                f"origin/{BASE}", "-Xtheirs", "-m", MERGE_FROM_MASTER_COMMIT_MESSAGE
            )
            for pack_auto_bumper in self.packs_to_autobump:
                new_version = pack_auto_bumper.autobump()
                print(f"Pack {pack_auto_bumper.pack_id} new version: {new_version}.")
                self.git_repo.git.add(f"{PACKS_DIR}/{pack_auto_bumper.pack_id}")

                config_reader = ConfigReader(explicitly_selected=["RN111"])
                initializer = Initializer(
                    prev_ver=BASE, execution_mode=ExecutionMode.USE_GIT
                )
                validation_results = ResultWriter()
                validate_manager = ValidateManager(
                    validation_results=validation_results,
                    config_reader=config_reader,
                    initializer=initializer,
                    allow_autofix=True
                )
                results = validate_manager.run_validations()

                print(f'Finished running validate fix on {pack_auto_bumper.pack_id}')

                self.git_repo.git.add(f"{PACKS_DIR}/{pack_auto_bumper.pack_id}")

                self.git_repo.git.commit(
                    "-m",
                    COMMIT_MESSAGE.format(
                        pack_auto_bumper.pack_id,
                        new_version,
                    ),
                )
                body += PR_COMMENT.format(
                    pack_auto_bumper.pack_id,
                    new_version,
                )
            print(f"[{self.pr.number}] Committed the changes. Commenting on the pr: \n{body}.\n")
            body += PR_COMMENT_STOP_AUTOMATION
            # self.git_repo.git.push()
            # self.pr.create_issue_comment(body)
        return body


class AutoBumperManager:
    def __init__(
        self,
        github_repo_obj: Repository,
        git_repo_obj: Repo,
        run_id: str,
    ):
        """
        Args:
            github_repo_obj: GitHub API repo object.
            git_repo_obj: Git API repo object.
            run_id: GitHub action run id.
        """
        self.github_repo_obj = github_repo_obj
        self.git_repo_obj = git_repo_obj
        self.run_id = run_id

    def manage(self):
        """
        Iterates over all PR's in the repo, checks if all conditions to update pack version met.
        If no - skips checks for the pack/branch.
        If the pack meets all conditions to autobump pack version, it bumps the version.
        """
        for pr in self.github_repo_obj.get_pulls(
            state="open", sort="created", base=BASE, direction='desc'
        ):
            if pr.draft:
                # The bot does not go through a PR that is in draft
                continue

            print(
                f"{t.yellow}Looking on pr number [{pr.number}]: last updated: "
                f"{str(pr.updated_at)}, branch={pr.head.ref}"
            )

            conditions = [
                LastModifiedCondition(pr=pr, git_repo=self.git_repo_obj),
                LabelCondition(pr=pr, git_repo=self.git_repo_obj),
                AddedRNFilesCondition(pr=pr, git_repo=self.git_repo_obj),
                HasConflictOnAllowedFilesCondition(pr=pr, git_repo=self.git_repo_obj),
            ]
            for c1, c2 in pairwise(conditions):
                c1.set_next_condition(c2)

            base_cond_result = conditions[0].check()
            if base_cond_result.should_skip:
                continue

            packs_to_autobump = []
            conflicting_packs = base_cond_result.conflicting_packs or set()
            for pack in conflicting_packs:
                origin_md, branch_md, pr_base_md = MetadataCondition.get_metadata_files(
                    pack_id=pack,
                    pr=pr,
                    git_repo=self.git_repo_obj,
                )
                metadata_condition_kwargs = {
                    'pack': pack,
                    'pr': pr,
                    'git_repo': self.git_repo_obj,
                    'branch_metadata': branch_md,
                    'pr_base_metadata': pr_base_md,
                    'origin_base_metadata': origin_md,
                }
                conditions = [
                    PackSupportCondition(**metadata_condition_kwargs),
                    MajorChangeCondition(**metadata_condition_kwargs),
                    MaxVersionCondition(**metadata_condition_kwargs),
                    OnlyVersionChangedCondition(**metadata_condition_kwargs),
                    OnlyOneRNPerPackCondition(**metadata_condition_kwargs),
                    SameRNMetadataVersionCondition(**metadata_condition_kwargs),
                    AllowedBumpCondition(**metadata_condition_kwargs),
                ]
                for c1, c2 in pairwise(conditions):
                    c1.set_next_condition(c2)

                metadata_cond_result = conditions[0].check()
                if metadata_cond_result.should_skip:
                    continue

                print(f"{t.yellow} [{pr.number}] Adding pack {pack} to autobump its release notes.")
                packs_to_autobump.append(
                    PackAutoBumper(
                        pack_id=pack,
                        rn_file_path=metadata_cond_result.pack_new_rn_file,     # type: ignore[arg-type]
                        update_type=metadata_cond_result.update_type,       # type: ignore[arg-type]
                    )
                )

            if packs_to_autobump:
                BranchAutoBumper(
                    packs_to_autobump=packs_to_autobump,
                    git_repo=self.git_repo_obj,
                    run_id=self.run_id,
                    pr=pr,
                ).autobump()

        return "AutoBumping Done."


def arguments_handler():  # pragma: no cover
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(
        description="Autobump release notes version for packs where ."
    )
    parser.add_argument(
        "-g",
        "--github_token",
        help="The GitHub token to authenticate the GitHub client.",
    )
    parser.add_argument("-r", "--run_id", help="The GitHub action run id.")
    return parser.parse_args()


def main():  # pragma: no cover
    options = arguments_handler()
    github_token = options.github_token
    run_id = options.run_id

    git_repo_obj = Repo(os.getcwd())
    git_repo_obj.remote().fetch()

    github_client: Github = Github(github_token, verify=False)
    github_repo_obj: Repository = github_client.get_repo(
        f"{ORGANIZATION_NAME}/{REPO_MANE}"
    )

    autobump_manager = AutoBumperManager(
        git_repo_obj=git_repo_obj,
        github_repo_obj=github_repo_obj,
        run_id=run_id,
    )

    res = autobump_manager.manage()
    print(f"{t.green}{res}")

    sys.exit(0)


if __name__ == "__main__":
    main()
