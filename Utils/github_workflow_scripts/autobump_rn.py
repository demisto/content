from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from itertools import pairwise
from packaging.version import Version
from typing import Tuple, Optional, Set, Dict, List
import urllib3
import argparse
from blessings import Terminal
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository
import sys
from Tests.Marketplace.marketplace_constants import Metadata
from Tests.Marketplace.marketplace_services import Pack
from Utils.github_workflow_scripts.utils import timestamped_print, load_json
from datetime import datetime, timedelta
from git import Repo, GitCommandError
from demisto_sdk.commands.common.tools import get_pack_names_from_files
from demisto_sdk.commands.update_release_notes.update_rn import UpdateRN
import os

urllib3.disable_warnings()

print = timestamped_print
t = Terminal()

ORGANIZATION_NAME = 'demisto'
REPO_MANE = 'content'
BASE = 'master'
PR_COMMENT_TITLE = '### This PR Automatically updated by github action: {}\n'
PR_COMMENT = 'Pack {} version was automatically bumped to {}. \n'
COMMIT_MESSAGE = 'Bump version to: {}, for {} pack.'
MERGE_FROM_MASTER_COMMIT_MESSAGE = f'Merged {BASE} into current branch.'
SKIPPING_MESSAGE = 'Skipping Auto-Bumping release notes.'
PACKS_DIR = 'Packs'
PACK_METADATA_FILE = Pack.USER_METADATA
RELEASE_NOTES_DIR = Pack.RELEASE_NOTES


class UpdateType(str, Enum):
    """Pack version update type"""
    REVISION = 'revision'
    MINOR = 'minor'
    MAJOR = 'major'


class SkipReason(str, Enum):
    """ Reasons to skip update release notes"""
    LAST_MODIFIED_TIME = 'The PR was not updated in last {} days. PR last update time: {}'
    NOT_UPDATE_RN_LABEL_EXIST = 'Label "{}" exist in this PR. PR labels: {}.'
    NO_NEW_RELEASE_NOTES = 'No new files were detected on {} directory.'
    CONFLICTING_FILES = 'The PR has conflicts not only at {} and {}. The conflicting files are: {}.'
    NO_CONFLICTING_FILES = 'No conflicts were detected.'
    NOT_ALLOW_SUPPORTED_TYPE_PACK = 'The pack is not {} supported. Pack {} support type is: {}.'
    DIFFERENT_MAJOR_VERSION = 'Pack: {} major version different in origin {} and at the branch {}.'
    EXCEED_MAX_ALLOWED_VERSION = 'Pack: {} has not allowed version part {}. Versions: origin {}, branch {}.'
    MORE_THAN_ONE_RN = 'Pack: {} has more than one added rn {}.'
    DIFFERENT_RN_METADATA_VERSIONS = 'Pack: {} has different rn version {}, and metadata version {}.'
    ALLOWED_BUMP_CONDITION = 'Pack {} version was updated from {} to {} version. Allowed bump only by + 1.'
    ONLY_VERSION_CHANGED = 'Pack {} metadata file has different keys in master and branch: {}.'


class ConditionResult:
    """ Result artifacts of the condition that was checked"""

    def __init__(
            self,
            should_skip: bool,
            reason: Optional[SkipReason] = '',
            conflicting_packs: Optional[Set] = None,
            pack_new_rn_file: Path = None,
            pr_rn_version: Version = None,
            update_type: UpdateType = None,
    ):
        """
        Args:
            should_skip(bool): Whether to stop the checks.
            reason(SkipReason): Why to skip this condition.
            conflicting_packs(set): Result artifact: Packs that has conflicts with base branch.
            pack_new_rn_file(Path): Result artifact: Path to pack's new release notes.
            pr_rn_version(Version): Result artifact: New version of the pack.
            update_type(UpdateType): Result artifact: What update type was at the pr.
        """
        assert reason if should_skip else True, 'Condition that should be skipped, should have a reason.'
        self.should_skip = should_skip
        self.reason = reason
        self.conflicting_packs = conflicting_packs
        self.pack_new_rn_file = pack_new_rn_file
        self.pr_rn_version = pr_rn_version
        self.update_type = update_type

    def __add__(self, other: 'ConditionResult'):
        """ Sum of conditional results. Contains data of other conditional result if not empty, else self result.
        Args:
            other: conditional result to sum with.
        Returns:
            New conditional result, sum of both.
        """
        should_skip = self.should_skip or other.should_skip
        reason = self.reason or other.reason
        conflicting_packs = other.conflicting_packs or self.conflicting_packs
        pack_new_rn_file = other.pack_new_rn_file or self.pack_new_rn_file
        pr_rn_version = other.pr_rn_version or self.pr_rn_version
        update_type = other.update_type or self.update_type
        return ConditionResult(
            should_skip=should_skip,
            reason=reason,
            conflicting_packs=conflicting_packs,
            pack_new_rn_file=pack_new_rn_file,
            pr_rn_version=pr_rn_version,
            update_type=update_type,
        )


class BaseCondition(ABC):
    """ Base abstract class for conditions"""

    def __init__(self, pr: PullRequest, git_repo: Repo, **kwargs):
        self.pr = pr
        self.git_repo = git_repo
        self.next_cond = None

    def set_next_condition(self, condition: 'BaseCondition') -> 'BaseCondition':
        """
        Args:
            condition: next condition to check after current condition.
        Returns:
            next condition to check after current condition.
        """
        self.next_cond = condition
        return self.next_cond

    @abstractmethod
    def generate_skip_reason(self, **kwargs) -> SkipReason:
        """ Abstract method. Will be over-written by classes that implements Condition."""
        raise NotImplementedError

    @abstractmethod
    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Abstract method. Will be over-written by classes that implements Condition."""
        raise NotImplementedError

    def check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Checks conditions one after another.
        Checks condition and if it is pass, checks next_condition.
        If condition fails (should_skip set to True), exit and return last condition result.
        Args:
            previous_result: result of the previous condition that was handled.
        Returns:
            last checked condition's result.
        """
        curr_result = self._check(previous_result=previous_result)
        if curr_result.should_skip:
            print(f'{t.red} PR: [{self.pr.number}]. {curr_result.reason} {SKIPPING_MESSAGE}')
            return curr_result
        elif self.next_cond:
            return self.next_cond.check(curr_result)
        else:
            return curr_result


class MetadataCondition(BaseCondition, ABC):
    """ Conditions that needs metadata files in order to check them."""
    DEFAULT_VERSION = '1.0.0'

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Optional[Dict] = None,
                 origin_base_metadata: Optional[Dict] = None, pr_base_metadata: Optional[Dict] = None):
        """
        Args:
            pack(str): pack name.
            pr(PullRequest): pull request where the metadata pack was changed.
            git_repo(Repo): git repo object for git API.
            branch_metadata(dict): Pack's metadata as it appears in the branch.
            origin_base_metadata(dict): Pack's metadata as it appears in the base (origin/master).
            pr_base_metadata(dict): Pack's metadata as it appears in the base of the branch.
        """
        super().__init__(pr, git_repo)
        self.pack = pack
        self.branch_metadata = branch_metadata
        self.origin_base_metadata = origin_base_metadata
        self.pr_base_metadata = pr_base_metadata

    @abstractmethod
    def generate_skip_reason(self, **kwargs) -> SkipReason:
        """ Generates the reason why the condition failed and why to skip the check"""
        raise NotImplementedError

    @abstractmethod
    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Check the condition."""
        raise NotImplementedError

    @staticmethod
    def get_metadata_files(pack_id: str, pr: PullRequest, git_repo: Repo):
        """ Open packs metadata files (branch, origin/master, base/master) and read its content.
        Args:
            pack_id(str): The pack id.
            pr(PullRequest): Pull request where metadata file was changed.
            git_repo(Repo): Git repo object, for git API.

        Returns:
            branch_metadata(dict): Pack's metadata as it appears in the branch.
            origin_base_metadata(dict): Pack's metadata as it appears in the base (origin/master).
            pr_base_metadata(dict): Pack's metadata as it appears in the base of the branch
            (master where the branches diverged).
        """
        metadata_path = f'{PACKS_DIR}/{pack_id}/{PACK_METADATA_FILE}'
        origin_base_pack_metadata = load_json(metadata_path)
        with checkout(git_repo, pr.head.ref):
            branch_pack_metadata = load_json(metadata_path)
            log = git_repo.git.log()
        base_sha = MetadataCondition.get_base_commit(branch_git_log=log, pr=pr)
        with checkout(git_repo, base_sha):
            pr_base_metadata = load_json(metadata_path)
        return origin_base_pack_metadata, branch_pack_metadata, pr_base_metadata

    @staticmethod
    def get_base_commit(branch_git_log: str, pr: PullRequest):
        """ Returns the pr's base commit. (The master where the branches diverged)
        We are using github's pr.base.sha commit if the branch was rebased.
        If pr was rebased, base sha will not appear in git log.
        If pr was never rebased, github's pr.base.sha commit is masters commit in the repo when pr was opened
        (bad behavior - fake base). Then the parent of the first branch commit is the base commit we should use.

        Args:
            branch_git_log: outputs of git log command
            pr: pull request which we are looking on

        Returns:
            Branch base commit (The commit where base and branch are diverse, considering merge from master)
        """
        base_sha = pr.base.sha
        if base_sha not in branch_git_log:
            try:
                commits = pr.get_commits()
                base_sha = commits[0].parents[0].sha
            except Exception:
                base_sha = pr.base.sha
        return base_sha


class LastModifiedCondition(BaseCondition):
    LAST_SUITABLE_UPDATE_TIME_DAYS = 14

    def generate_skip_reason(self, last_updated: str, **kwargs) -> SkipReason:
        """
        Args:
            last_updated: when the pr was last updated.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.LAST_MODIFIED_TIME.format(self.LAST_SUITABLE_UPDATE_TIME_DAYS, last_updated)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Checks if the PR was updated in last LAST_SUITABLE_UPDATE_TIME_DAYS days.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        if self.pr.updated_at < datetime.now() - timedelta(days=self.LAST_SUITABLE_UPDATE_TIME_DAYS):
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(
                last_updated=str(self.pr.updated_at)))
        else:
            return ConditionResult(should_skip=False)


class LabelCondition(BaseCondition):
    NOT_UPDATE_RN_LABEL = 'ignore-auto-bump-version'

    def generate_skip_reason(self, labels: str, **kwargs) -> SkipReason:
        """
        Args:
            labels: pr labels.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.NOT_UPDATE_RN_LABEL_EXIST.format(self.NOT_UPDATE_RN_LABEL, labels)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Checks if the PR has NOT_UPDATE_RN_LABEL.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pr_labels = [label.name for label in self.pr.labels]
        if self.NOT_UPDATE_RN_LABEL in pr_labels:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(labels=", ".join(pr_labels)))
        else:
            return ConditionResult(should_skip=False)


class AddedRNFilesCondition(BaseCondition):

    def generate_skip_reason(self, **kwargs) -> SkipReason:
        """
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.NO_NEW_RELEASE_NOTES.format(RELEASE_NOTES_DIR)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Checks if there are new Release Notes files in the PR.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pr_files = list(self.pr.get_files())
        pr_rn_files = [f for f in pr_files if f.status == 'added' and RELEASE_NOTES_DIR in Path(f.filename).parts]
        if not pr_rn_files:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason())
        else:
            return ConditionResult(should_skip=False)


class HasConflictOnAllowedFilesCondition(BaseCondition):

    def generate_skip_reason(self, conflicting_files, **kwargs) -> SkipReason:
        """
        Args:
            conflicting_files: files on the pr that conflicts with base.
        Returns: Reason why the condition failed, and pr skipped.
        """
        if not conflicting_files:
            return SkipReason.NO_CONFLICTING_FILES
        else:
            return SkipReason.CONFLICTING_FILES.format(RELEASE_NOTES_DIR, PACK_METADATA_FILE, conflicting_files)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        """ Checks if the PR conflicting with origin/master on pack_metadata and release notes only.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pr_files = list(self.pr.get_files())
        added_rn_files = [f.filename for f in pr_files if f.status == 'added'
                          and RELEASE_NOTES_DIR in Path(f.filename).parts]
        changed_metadata_files = [f.filename for f in pr_files if PACK_METADATA_FILE in Path(f.filename).parts]
        conflict_only_rn_and_metadata, conflict_files = self._has_conflict_on_given_files(
            added_rn_files + changed_metadata_files)
        if not conflict_only_rn_and_metadata:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(conflicting_files=conflict_files))
        else:
            conflicting_packs = get_pack_names_from_files(conflict_files)
            return ConditionResult(should_skip=False, conflicting_packs=conflicting_packs)

    def _has_conflict_on_given_files(self, files_check_to_conflict_with: list) -> Tuple[bool, list]:
        """Checks if a pull request contains merge conflicts with a local branch.
        Arguments:
            files_check_to_conflict_with: files to check if the pr has conflict on given files only.
        Returns:
            True if the pull request contains merge conflicts with specified files only.
        """
        pr_branch = self.pr.head.ref
        conflicting_files = []
        conflict_only_with_given_files = False
        try:
            self.git_repo.git.merge(f'origin/{pr_branch}', '--no-ff', '--no-commit')
        except GitCommandError as e:
            error = e.stdout
            if error:
                error = error.replace("stdout: '", '').strip()
            conflicting_files = [line.replace('Auto-merging ', '').strip()
                                 for line in error.splitlines() if 'Auto-merging ' in line]
            conflict_only_with_given_files = True
            for file_name in conflicting_files:
                if file_name not in files_check_to_conflict_with:
                    conflict_only_with_given_files = False
        finally:
            self.git_repo.git.merge('--abort')
        return (conflict_only_with_given_files and conflicting_files), conflicting_files


class PackSupportCondition(MetadataCondition):
    ALLOWED_SUPPORT_TYPE = Metadata.XSOAR_SUPPORT

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata)

    def generate_skip_reason(self, support_type: str, **kwargs) -> SkipReason:
        """
        Args:
            support_type: pack support type.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.NOT_ALLOW_SUPPORTED_TYPE_PACK.format(self.ALLOWED_SUPPORT_TYPE, self.pack, support_type)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks if the pack is XSOAR supported.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        support_type = self.branch_metadata.get(Metadata.SUPPORT)
        if support_type != self.ALLOWED_SUPPORT_TYPE:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(support_type=support_type))
        else:
            return ConditionResult(should_skip=False)


class MajorChangeCondition(MetadataCondition):

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict, origin_base_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata,
                         origin_base_metadata=origin_base_metadata)

    def generate_skip_reason(self, origin_version: Version, branch_version: Version, **kwargs) -> SkipReason:
        """
        Args:
            origin_version: pack version in the base branch (origin/master).
            branch_version: pack versio in the branch.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.DIFFERENT_MAJOR_VERSION.format(self.pack, str(origin_version), str(branch_version))

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks if packs major changed.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        origin_pack_metadata_version = Version(self.origin_base_metadata.get(Metadata.CURRENT_VERSION,
                                                                             self.DEFAULT_VERSION))
        branch_pack_metadata_version = Version(self.branch_metadata.get(Metadata.CURRENT_VERSION,
                                                                        self.DEFAULT_VERSION))
        if origin_pack_metadata_version.major != branch_pack_metadata_version.major:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(
                origin_version=origin_pack_metadata_version, branch_version=branch_pack_metadata_version))
        else:
            return ConditionResult(should_skip=False)


class MaxVersionCondition(MetadataCondition):
    MAX_ALLOWED_VERSION = '99'

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict, origin_base_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata,
                         origin_base_metadata=origin_base_metadata)

    def generate_skip_reason(self, origin_version: str, branch_version: str, **kwargs) -> SkipReason:
        """
        Args:
            origin_version: pack version in the base branch (origin/master).
            branch_version: pack versio in the branch.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.EXCEED_MAX_ALLOWED_VERSION.format(self.pack, self.MAX_ALLOWED_VERSION,
                                                            origin_version, branch_version)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks if packs version is 99. (99 is the last supported version number).
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        origin_pack_metadata_version = self.origin_base_metadata.get(Metadata.CURRENT_VERSION,
                                                                     self.DEFAULT_VERSION)
        branch_pack_metadata_version = self.branch_metadata.get(Metadata.CURRENT_VERSION,
                                                                self.DEFAULT_VERSION)
        if self.MAX_ALLOWED_VERSION in origin_pack_metadata_version or \
                self.MAX_ALLOWED_VERSION in branch_pack_metadata_version:
            return ConditionResult(
                should_skip=True, reason=self.generate_skip_reason(
                    origin_version=origin_pack_metadata_version,
                    branch_version=branch_pack_metadata_version,
                )
            )
        else:
            return ConditionResult(should_skip=False)


class OnlyVersionChangedCondition(MetadataCondition):
    ALLOWED_CHANGED_KEYS = [Metadata.CURRENT_VERSION]

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict, origin_base_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata,
                         origin_base_metadata=origin_base_metadata)

    def generate_skip_reason(self, not_allowed_changed_keys, **kwargs) -> SkipReason:
        """
        Args:
            not_allowed_changed_keys: pack_metadata keys that was changed.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.ONLY_VERSION_CHANGED.format(self.pack, not_allowed_changed_keys)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks if other pack metadata fields changed except ALLOWED CHANGED PACKS.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        not_allowed_changed_keys = [k for k, v in self.branch_metadata.items() if k not in self.ALLOWED_CHANGED_KEYS
                                    and self.origin_base_metadata.get(k) != v]
        if not_allowed_changed_keys:
            return ConditionResult(
                should_skip=True, reason=self.generate_skip_reason(
                    not_allowed_changed_keys=not_allowed_changed_keys,
                )
            )
        else:
            return ConditionResult(should_skip=False)


class OnlyOneRNPerPackCondition(MetadataCondition):
    def generate_skip_reason(self, rn_files: list, **kwargs) -> SkipReason:
        """
        Args:
            rn_files: release notes files for the pack in current pr.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.MORE_THAN_ONE_RN.format(self.pack, [str(f) for f in rn_files])

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks that only one release notes files per pack was added.
            Args:
                previous_result: previous check artifacts.

            Returns(ConditionResult): whether the condition check pass,
                or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
            """
        pack_new_rn_files = [Path(f.filename) for f in self.pr.get_files() if f.status == 'added' and RELEASE_NOTES_DIR
                             in Path(f.filename).parts and self.pack in Path(f.filename).parts and
                             'md' in Path(f.filename).suffix]
        if len(pack_new_rn_files) != 1:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(pack_new_rn_files))
        else:
            return ConditionResult(should_skip=False, pack_new_rn_file=pack_new_rn_files[0])


class SameRNMetadataVersionCondition(MetadataCondition):

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata)

    def generate_skip_reason(self, rn_version: Version, metadata_version: Version, **kwargs) -> SkipReason:
        """
        Args:
            rn_version: version of the release notes.
            metadata_version: version of the pack in the metadata file.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.DIFFERENT_RN_METADATA_VERSIONS.format(self.pack, rn_version, metadata_version)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks if the new Release Notes has the same version as pack metadata version.
            Args:
                previous_result: previous check artifacts.

            Returns(ConditionResult): whether the condition check pass,
                or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
            """
        branch_pack_metadata_version = Version(self.branch_metadata.get(Metadata.CURRENT_VERSION,
                                                                        self.DEFAULT_VERSION))
        assert previous_result, 'No previous result was supplied to the SameRNMetadataVersionCondition object.'
        rn_version_file_name = previous_result.pack_new_rn_file.stem
        rn_version = Version(rn_version_file_name.replace('_', '.'))
        if branch_pack_metadata_version != rn_version:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(rn_version,
                                                                                      branch_pack_metadata_version))
        else:
            return previous_result + ConditionResult(should_skip=False, pr_rn_version=rn_version)


class AllowedBumpCondition(MetadataCondition):

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict, pr_base_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata,
                         pr_base_metadata=pr_base_metadata)

    def generate_skip_reason(self, previous_version: Version, new_version: Version, **kwargs) -> SkipReason:
        """
        Args:
            previous_version: previous version of the pack.
            new_version: new pack version.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.ALLOWED_BUMP_CONDITION.format(self.pack, previous_version, new_version)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        """ Checks if the pack version was updated by +1. (The only bump we allow).
            Args:
                previous_result: previous check artifacts.

            Returns(ConditionResult): whether the condition check pass,
                or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
            """
        branch_pack_metadata_version = Version(self.branch_metadata.get(Metadata.CURRENT_VERSION,
                                                                        self.DEFAULT_VERSION))
        base_pack_metadata_version = Version(self.pr_base_metadata.get(Metadata.CURRENT_VERSION,
                                                                       self.DEFAULT_VERSION))
        update_type = self.check_update_type(base_pack_metadata_version, branch_pack_metadata_version)
        if not update_type:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(base_pack_metadata_version,
                                                                                      branch_pack_metadata_version))
        else:
            assert previous_result, 'No previous result was supplied to the AllowedBumpCondition object.'
            return previous_result + ConditionResult(should_skip=False, update_type=update_type)

    @staticmethod
    def check_update_type(prev_version: Version, new_version: Version) -> Optional[UpdateType]:
        """ Checks what was the update type when the release notes were generated.
        Args:
            prev_version: the pack version before updating release notes.
            new_version: the pack version after updating release notes.
        Returns:
            The pack update type if the update type was legal.
        """
        same_major = (prev_version.major == prev_version.major)
        same_minor = (prev_version.minor == prev_version.minor)
        if prev_version.micro + 1 == new_version.micro and same_minor and same_major:
            return UpdateType.REVISION
        elif prev_version.minor + 1 == new_version.minor and same_major and not new_version.micro:
            return UpdateType.MINOR
        elif prev_version.major + 1 == new_version.major and not new_version.minor and not new_version.micro:
            return UpdateType.MAJOR
        else:
            return None


class PackAutoBumper:

    def __init__(
            self, pack_id: str,
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
            pack_path=f'{PACKS_DIR}/{pack_id}',
            update_type=update_type.value,
            modified_files_in_pack=set(),
            added_files=set(),
            pack=pack_id,
            is_force=True,
        )
        # Setting to default. Will be updated once we are checked out to the branch in set_pr_changed_rn_related_data.
        self._bc_file = Path(str(self._last_rn_file_path).replace('md', 'json'))
        self._has_bc = False
        self._rn_text = ''
        self._bc_text = ''

    def set_pr_changed_rn_related_data(self):
        """Opens release notes and bc changes files and saves its text."""
        with open(self._last_rn_file_path) as f:
            self._rn_text = f.read()

        self._has_bc = self._bc_file.is_file()
        if self._has_bc:
            with open(self._bc_file) as f:
                self._bc_text = f.read()

    def autobump(self) -> str:
        """ AutoBumps packs version:
        1. Bumps numeric version of the pack
        2. Writes new version to metadata
        3. Creates new release notes file
        4. Writes previous release notes content to new path
        5. If there breaking changes file, updating it to the new version
        Returns: (str) new pack version.
        """
        new_version, metadata_dict = self._update_rn_obj.bump_version_number()
        self._update_rn_obj.write_metadata_to_file(metadata_dict=metadata_dict)
        new_release_notes_path = self._update_rn_obj.get_release_notes_path(new_version)
        with open(new_release_notes_path, "w") as fp:
            fp.write(self._rn_text)
        if self._has_bc:
            with open(new_release_notes_path.replace('md', 'json'), "w") as fp:
                fp.write(self._bc_text)
            with open(self._bc_file) as f:
                previous_bc_txt = f.read()
            if previous_bc_txt == self._bc_file:
                # delete previous bc file, if it was not changed after merge from master
                os.remove(self._bc_file)
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
        assert packs_to_autobump, f'packs_to_autobump in the pr: {pr.number}, cant be empty.'
        self.pr = pr
        self.branch = pr.head.ref
        self.git_repo = git_repo
        self.packs_to_autobump = packs_to_autobump
        self.github_run_id = run_id

    def autobump(self):
        """ AutoBumps version for all relevant packs in the pr:
        1. Checkouts the branch and saves pr changed related data.
        2. Merges from BASE and accept `theirs` changes.
        3. AutoBumps version for each relevant packs.
        4. Commit changes for each pack.
        5. Comment on the PR.
        6. Pushes the changes.
        """
        body = PR_COMMENT_TITLE.format(self.github_run_id)
        if self.branch not in ["conflict_in_cs", "conflicts_in_base"]:
            # todo: delete it
            return 'Pack MyPack version was automatically bumped to 1.0.2.'
        with checkout(self.git_repo, self.branch):
            for pack_auto_bumper in self.packs_to_autobump:
                pack_auto_bumper.set_pr_changed_rn_related_data()
            self.git_repo.git.merge(f'origin/{BASE}', '-Xtheirs', '-m', MERGE_FROM_MASTER_COMMIT_MESSAGE)
            for pack_auto_bumper in self.packs_to_autobump:
                new_version = pack_auto_bumper.autobump()
                self.git_repo.git.add(f'{PACKS_DIR}/{pack_auto_bumper.pack_id}')
                self.git_repo.git.commit('-m', COMMIT_MESSAGE.format(
                    new_version,
                    pack_auto_bumper.pack_id,
                ))
                body += PR_COMMENT.format(pack_auto_bumper.pack_id, new_version, )
            # todo: uncomment - dont work with my creds, only bots should work.
            # self.pr.create_issue_comment(body)
            self.git_repo.git.push()
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
        for pr in self.github_repo_obj.get_pulls(state='open', sort='created', base=BASE):
            print(f'{t.yellow}Looking on pr {pr.number=}: {str(pr.updated_at)=}, {pr.head.ref=}')

            conditions = [
                LastModifiedCondition(pr=pr, git_repo=self.git_repo_obj),
                LabelCondition(pr=pr, git_repo=self.git_repo_obj),
                AddedRNFilesCondition(pr=pr, git_repo=self.git_repo_obj),
                HasConflictOnAllowedFilesCondition(pr=pr, git_repo=self.git_repo_obj)
            ]
            for c1, c2 in pairwise(conditions):
                c1.set_next_condition(c2)

            base_cond_result = conditions[0].check()
            if base_cond_result.should_skip:
                continue

            packs_to_autobump = []
            conflicting_packs = base_cond_result.conflicting_packs
            for pack in conflicting_packs:
                origin_md, branch_md, pr_base_md = MetadataCondition.get_metadata_files(
                    pack_id=pack,
                    pr=pr,
                    git_repo=self.git_repo_obj,
                )
                conditions = [
                    PackSupportCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj, branch_metadata=branch_md),
                    MajorChangeCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj, branch_metadata=branch_md,
                                         origin_base_metadata=origin_md),
                    MaxVersionCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj, branch_metadata=branch_md,
                                        origin_base_metadata=origin_md),
                    OnlyVersionChangedCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj, branch_metadata=branch_md,
                                                origin_base_metadata=origin_md),
                    OnlyOneRNPerPackCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj),
                    SameRNMetadataVersionCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj,
                                                   branch_metadata=branch_md),
                    AllowedBumpCondition(pack=pack, pr=pr, git_repo=self.git_repo_obj, branch_metadata=branch_md,
                                         pr_base_metadata=pr_base_md),
                ]
                for c1, c2 in pairwise(conditions):
                    c1.set_next_condition(c2)

                metadata_cond_result = conditions[0].check()
                if metadata_cond_result.should_skip:
                    continue

                print(f'{t.yellow}Adding pack {pack} to autobump its release notes.')
                packs_to_autobump.append(
                    PackAutoBumper(
                        pack_id=pack,
                        rn_file_path=metadata_cond_result.pack_new_rn_file,
                        update_type=metadata_cond_result.update_type,
                    )
                )

            if packs_to_autobump:
                BranchAutoBumper(
                    packs_to_autobump=packs_to_autobump,
                    git_repo=self.git_repo_obj,
                    run_id=self.run_id,
                    pr=pr,
                ).autobump()


class checkout:
    """Checks out a given branch.
    When the context manager exits, the context manager checks out the
    previously current branch.
    """

    def __init__(self, repo: Repo, branch_to_checkout: str):
        """Initializes instance attributes.
        Arguments:
            repo: git repo object
            branch_to_checkout: The branch or commit hash to check out.
        """
        self.repo = repo
        self.repo.remote().fetch(branch_to_checkout)
        self._original_branch = self.repo.active_branch.name
        self._branch_to_checkout = branch_to_checkout

    def __enter__(self):
        """Checks out the given branch"""
        self.repo.git.checkout(self._branch_to_checkout)
        return self

    def __exit__(self, *args):
        """Checks out the previous branch"""
        self.repo.git.checkout(self._original_branch)


def arguments_handler():  # pragma: no cover
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Autobump release notes version for packs where .')
    parser.add_argument('-g', '--github_token', help='The GitHub token to authenticate the GitHub client.')
    parser.add_argument('-r', '--run_id', help='The GitHub action run id.')
    return parser.parse_args()


def main():     # pragma: no cover
    options = arguments_handler()
    github_token = options.github_token
    run_id = options.run_id

    git_repo_obj = Repo(os.getcwd())
    git_repo_obj.remote().fetch()

    github_client: Github = Github(github_token, verify=False)
    github_repo_obj: Repository = github_client.get_repo(f'{ORGANIZATION_NAME}/{REPO_MANE}')

    autobump_manager = AutoBumperManager(
        git_repo_obj=git_repo_obj,
        github_repo_obj=github_repo_obj,
        run_id=run_id,
    )

    autobump_manager.manage()

    sys.exit(0)


if __name__ == "__main__":
    main()
