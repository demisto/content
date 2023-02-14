from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from itertools import pairwise
from packaging.version import Version
from typing import List, Tuple, Optional, Set, Dict
import urllib3
import argparse
from blessings import Terminal
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository
import sys
from Tests.Marketplace.marketplace_constants import Metadata
from Tests.Marketplace.marketplace_services import Pack
from utils import timestamped_print, load_json
from datetime import datetime, timedelta
from git import Repo, GitCommandError
from demisto_sdk.commands.common.tools import get_pack_names_from_files
import os

# bump_version_number

urllib3.disable_warnings()

print = timestamped_print
t = Terminal()

ORGANIZATION_NAME = 'demisto'
REPO_MANE = 'content'
BASE = 'master'

SKIPPING_MESSAGE = 'Skipping Auto-Bumping release notes.'
PACKS_DIR = 'Packs'
PACK_METADATA_FILE = Pack.USER_METADATA
RELEASE_NOTES_DIR = Pack.RELEASE_NOTES


class UpdateType(str, Enum):
    REVISION = 'revision'
    MINOR = 'minor'
    MAJOR = 'major'


class SkipReason(str, Enum):
    LAST_MODIFIED_TIME = 'The PR was not updated in last {} days. PR last update time: {}'
    NOT_UPDATE_RN_LABEL_EXIST = 'Label {} exist in this PR. PR labels: {}'
    NO_RELEASE_NOTES_CHANGED = 'No changes were detected on {} directory.'
    CONFLICTING_FILES = 'The PR has conflicts not only at {} and {}. The conflicting files are: {}.'
    NO_CONFLICTING_FILES = 'No conflicts were detected.'
    NOT_ALLOW_SUPPORTED_TYPE_PACK = 'The pack is not {} supported. Pack {} support type is: {}.'
    DIFFERENT_MAJOR_VERSION = 'Pack: {} major version different in origin {} and at the branch {}.'
    EXCEED_MAX_ALLOWED_VERSION = 'Pack: {} has not allowed version part {}. Versions: origin {}, branch {}.'
    MORE_THAN_ONE_RN = 'Pack: {} has more than one added rn {}.'
    DIFFERENT_RN_METADATA_VERSIONS = 'Pack: {} has different rn version {}, and metadata version {}.'
    ALLOWED_BUMP_CONDITION = 'Pack {} version was updated from {} to {} version. Allowed bump only by + 1.'


# todo:dataclass
class ConditionResult:
    def __init__(
            self,
            should_skip: bool,
            reason: Optional[SkipReason] = None,
            conflicting_packs: Optional[Set] = None,
            pack_new_rn_file: Path = None,
            pr_rn_version: Version = None,
            update_type: UpdateType = None,
    ):
        assert reason if should_skip else True, 'Condition that should be skipped, should have a reason.'
        self.should_skip = should_skip
        self.reason = reason
        self.conflicting_packs = conflicting_packs
        self.pack_new_rn_file = pack_new_rn_file
        self.pr_rn_version = pr_rn_version
        self.update_type = update_type

    def __add__(self, other: 'ConditionResult'):
        should_skip = self.should_skip or other.should_skip
        reason = self.reason or other.reason
        conflicting_packs = other.conflicting_packs if other.conflicting_packs else self.conflicting_packs
        pack_new_rn_file = other.pack_new_rn_file if other.pack_new_rn_file else self.pack_new_rn_file
        pr_rn_version = other.pr_rn_version if other.pr_rn_version else self.pr_rn_version
        update_type = other.update_type if other.update_type else self.update_type
        return ConditionResult(
            should_skip=should_skip,
            reason=reason,
            conflicting_packs=conflicting_packs,
            pack_new_rn_file=pack_new_rn_file,
            pr_rn_version=pr_rn_version,
            update_type=update_type,
        )


class BaseCondition(ABC):

    def __init__(self, pr: PullRequest, git_repo: Repo):
        self.pr = pr
        self.git_repo = git_repo
        self.next_cond = None

    def set_next_condition(self, condition: 'BaseCondition'):
        self.next_cond = condition
        return self.next_cond

    @abstractmethod
    def generate_skip_reason(self, **kwargs) -> SkipReason:
        raise NotImplementedError

    @abstractmethod
    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        raise NotImplementedError

    def check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        curr_result = self._check(previous_result=previous_result)
        if curr_result.should_skip:
            print(f'{t.red} PR: [{self.pr.number}]. {curr_result.reason} {SKIPPING_MESSAGE}')
            return curr_result
        elif self.next_cond:
            return self.next_cond.check(curr_result)
        else:
            return curr_result


class MetadataCondition(BaseCondition, ABC):
    DEFAULT_VERSION = '1.0.0'

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Optional[Dict] = None,
                 origin_base_metadata: Optional[Dict] = None, pr_base_metadata: Optional[Dict] = None):
        super().__init__(pr, git_repo)
        self.pack = pack
        self.branch_metadata = branch_metadata
        self.origin_base_metadata = origin_base_metadata
        self.pr_base_metadata = pr_base_metadata

    @abstractmethod
    def generate_skip_reason(self, **kwargs) -> SkipReason:
        raise NotImplementedError

    @abstractmethod
    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        raise NotImplementedError

    @staticmethod
    def get_metadata_files(pack_id: str, pr: PullRequest, git_repo: Repo):
        """ TODO docstring """
        metadata_path = f'{PACKS_DIR}/{pack_id}/{PACK_METADATA_FILE}'
        origin_base_pack_metadata = load_json(metadata_path)
        with checkout(git_repo, pr.head.ref):
            branch_pack_metadata = load_json(metadata_path)
        # todo: check if works
        with checkout(git_repo, pr.base.sha):
            pr_base_metadata = load_json(metadata_path)
        return origin_base_pack_metadata, branch_pack_metadata, pr_base_metadata


class LastModifiedCondition(BaseCondition):
    LAST_SUITABLE_UPDATE_TIME_DAYS = 14

    def generate_skip_reason(self, last_updated: str, **kwargs) -> SkipReason:
        return SkipReason.LAST_MODIFIED_TIME.format(self.LAST_SUITABLE_UPDATE_TIME_DAYS, last_updated)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        if self.pr.updated_at < datetime.now() - timedelta(days=self.LAST_SUITABLE_UPDATE_TIME_DAYS):
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(
                last_updated=str(self.pr.updated_at)))
        else:
            return ConditionResult(should_skip=False)


class LabelCondition(BaseCondition):
    NOT_UPDATE_RN_LABEL = 'ignore-auto-bump-version'

    def generate_skip_reason(self, labels: str, **kwargs) -> SkipReason:
        return SkipReason.NOT_UPDATE_RN_LABEL_EXIST.format(self.NOT_UPDATE_RN_LABEL, labels)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        pr_labels = [label.name for label in self.pr.labels]
        if self.NOT_UPDATE_RN_LABEL in pr_labels:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(labels=", ".join(pr_labels)))
        else:
            return ConditionResult(should_skip=False)


class AddedRNFilesCondition(BaseCondition):

    def generate_skip_reason(self, **kwargs) -> SkipReason:
        return SkipReason.NO_RELEASE_NOTES_CHANGED.format(RELEASE_NOTES_DIR)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
        pr_files = list(self.pr.get_files())
        pr_rn_files = [f for f in pr_files if f.status == 'added' and RELEASE_NOTES_DIR in Path(f.filename).parts]
        if not pr_rn_files:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason())
        else:
            return ConditionResult(should_skip=False)


class HasConflictOnAllowedFilesCondition(BaseCondition):

    def generate_skip_reason(self, conflicting_files, **kwargs) -> SkipReason:
        if not conflicting_files:
            return SkipReason.NO_CONFLICTING_FILES
        else:
            return SkipReason.CONFLICTING_FILES.format(RELEASE_NOTES_DIR, PACK_METADATA_FILE, conflicting_files)

    def _check(self, previous_result: Optional[ConditionResult] = None) -> ConditionResult:
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
            conflicting_files = [line.replace('Auto-merging ', '').strip()
                                 for line in error.splitlines() if 'Auto-merging ' in line]
            conflict_only_with_given_files = True
            for file_name in conflicting_files:
                if file_name not in files_check_to_conflict_with:
                    conflict_only_with_given_files = False
        self.git_repo.git.merge('--abort')
        return (conflict_only_with_given_files and conflicting_files), conflicting_files


class PackSupportCondition(MetadataCondition):
    ALLOWED_SUPPORT_TYPE = Metadata.XSOAR_SUPPORT

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata)

    def generate_skip_reason(self, support_type: str, **kwargs) -> SkipReason:
        return SkipReason.NOT_ALLOW_SUPPORTED_TYPE_PACK.format(self.ALLOWED_SUPPORT_TYPE, self.pack, support_type)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
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
        return SkipReason.DIFFERENT_MAJOR_VERSION.format(self.pack, str(origin_version), str(branch_version))

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
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
        return SkipReason.EXCEED_MAX_ALLOWED_VERSION.format(self.pack, self.MAX_ALLOWED_VERSION,
                                                            origin_version, branch_version)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        origin_pack_metadata_version = self.origin_base_metadata.get(Metadata.CURRENT_VERSION,
                                                                     self.DEFAULT_VERSION)
        branch_pack_metadata_version = self.branch_metadata.get(Metadata.CURRENT_VERSION,
                                                                self.DEFAULT_VERSION)
        if self.MAX_ALLOWED_VERSION in origin_pack_metadata_version or \
                self.MAX_ALLOWED_VERSION in branch_pack_metadata_version:
            return ConditionResult(
                should_skip=True, reason=self.generate_skip_reason(
                    origin_version=origin_pack_metadata_version,
                    branch_version=branch_pack_metadata_version)
            )
        else:
            return ConditionResult(should_skip=False)


class OnlyOneRNPerPackCondition(MetadataCondition):
    def generate_skip_reason(self, rn_files, **kwargs) -> SkipReason:
        return SkipReason.MORE_THAN_ONE_RN.format(self.pack, ', '.join(rn_files))

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        pack_new_rn_files = [Path(f.filename) for f in self.pr.get_files() if f.status == 'added' and RELEASE_NOTES_DIR
                             in Path(f.filename).parts and self.pack in Path(f.filename).parts]
        if len(pack_new_rn_files) != 1:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(pack_new_rn_files))
        else:
            return ConditionResult(should_skip=False, pack_new_rn_file=pack_new_rn_files[0])


class SameRNMetadataVersionCondition(MetadataCondition):

    def __init__(self, pack: str, pr: PullRequest, git_repo: Repo, branch_metadata: Dict):
        super().__init__(pack=pack, pr=pr, git_repo=git_repo, branch_metadata=branch_metadata)

    def generate_skip_reason(self, rn_version, metadata_version, **kwargs) -> SkipReason:
        return SkipReason.DIFFERENT_RN_METADATA_VERSIONS.format(self.pack, rn_version, metadata_version)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
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

    def generate_skip_reason(self, previous_version, new_version, **kwargs) -> SkipReason:
        return SkipReason.ALLOWED_BUMP_CONDITION.format(self.pack, previous_version, new_version)

    def _check(self, previous_result: Optional[ConditionResult] = None, **kwargs) -> ConditionResult:
        branch_pack_metadata_version = Version(self.branch_metadata.get(Metadata.CURRENT_VERSION,
                                                                        self.DEFAULT_VERSION))
        base_pack_metadata_version = Version(self.pr_base_metadata.get(Metadata.CURRENT_VERSION,
                                                                       self.DEFAULT_VERSION))
        update_type = self.check_update_type(base_pack_metadata_version, branch_pack_metadata_version)
        if not update_type:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason(base_pack_metadata_version,
                                                                                      branch_pack_metadata_version))
        else:
            return previous_result + ConditionResult(should_skip=False, update_type=update_type)

    @staticmethod
    def check_update_type(prev_version: Version, new_version: Version):
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


class checkout:
    """Checks out a given branch.
    When the context manager exits, the context manager checks out the
    previously current branch.
    """

    def __init__(self, repo: Repo, branch_to_checkout: str):
        """Initializes instance attributes.
        Arguments:
            repo: git repo object
            branch_to_checkout: The branch to check out.
        """
        self.repo = repo
        # todo: fetch only branch
        self.repo.remote().fetch()
        self._original_branch = self.repo.active_branch.name
        self._branch_to_checkout = branch_to_checkout

    def __enter__(self):
        """Checks out the given branch"""
        self.repo.git.checkout(self._branch_to_checkout)
        return self

    def __exit__(self, *args):
        """Checks out the previous branch"""
        self.repo.git.checkout(self._original_branch)


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Autobump release notes version for packs where .')
    parser.add_argument('-g', '--github_token', help='The GitHub token to authenticate the GitHub client.')
    return parser.parse_args()


def autobump_release_notes(pack_id, update_type):
    # todo: 1.
    #  checkout branch
    #  2. save previous rn text
    # 3. merge from master accept master changes
    # 4. bump metadata file rn
    # 5. create rn file
    # 6. commit changes - commit has build nubmer

    pass


def main():
    options = arguments_handler()
    github_token = options.github_token

    git_repo_obj = Repo(os.getcwd())
    git_repo_obj.remote().fetch()

    github_client: Github = Github(github_token, verify=False)
    github_repo_obj: Repository = github_client.get_repo(f'{ORGANIZATION_NAME}/{REPO_MANE}')

    for pr in github_repo_obj.get_pulls(state='open', sort='created', base=BASE):
        print(f'{t.yellow}Looking on pr {pr.number=}: {pr.updated_at=}, {pr.head.ref=}')

        conditions = [
            LastModifiedCondition(pr=pr, git_repo=git_repo_obj),
            LabelCondition(pr=pr, git_repo=git_repo_obj),
            AddedRNFilesCondition(pr=pr, git_repo=git_repo_obj),
            HasConflictOnAllowedFilesCondition(pr=pr, git_repo=git_repo_obj)
        ]
        for c1, c2 in pairwise(conditions):
            c1.set_next_condition(c2)

        base_cond_result = conditions[0].check()
        if base_cond_result.should_skip:
            continue

        conflicting_packs = base_cond_result.conflicting_packs
        for pack in conflicting_packs:
            origin_md, branch_md, pr_base_md = MetadataCondition.get_metadata_files(
                pack_id=pack,
                pr=pr,
                git_repo=git_repo_obj,
            )
            conditions = [
                PackSupportCondition(pack=pack, pr=pr, git_repo=git_repo_obj, branch_metadata=branch_md),
                MajorChangeCondition(pack=pack, pr=pr, git_repo=git_repo_obj, branch_metadata=branch_md,
                                     origin_base_metadata=origin_md),
                MaxVersionCondition(pack=pack, pr=pr, git_repo=git_repo_obj, branch_metadata=branch_md,
                                    origin_base_metadata=origin_md),
                OnlyOneRNPerPackCondition(pack=pack, pr=pr, git_repo=git_repo_obj),
                SameRNMetadataVersionCondition(pack=pack, pr=pr, git_repo=git_repo_obj, branch_metadata=branch_md),
                AllowedBumpCondition(pack=pack, pr=pr, git_repo=git_repo_obj, branch_metadata=branch_md,
                                     pr_base_metadata=pr_base_md),
            ]
            for c1, c2 in pairwise(conditions):
                c1.set_next_condition(c2)

            metadata_cond_result = conditions[0].check()
            if metadata_cond_result.should_skip:
                continue

            rn_file: Path = metadata_cond_result.pack_new_rn_file
            ut: UpdateType = metadata_cond_result.update_type

        print('got here')
        # with checkout(git_repo_obj, pr_branch):
        #     autobump_release_notes(packs_rn_to_update_in_this_pr)

    # todo git push
    # todo: slack notify success or print success logs
    sys.exit(0)


if __name__ == "__main__":
    main()
