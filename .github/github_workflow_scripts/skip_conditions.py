from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from demisto_sdk.commands.common.tools import get_pack_names_from_files
from git import Repo, GitCommandError
from github.PullRequest import PullRequest
from packaging.version import Version
from blessings import Terminal
from utils import load_json, Checkout, timestamped_print


print = timestamped_print
SKIPPING_MESSAGE = "Skipping Auto-Bumping release notes."
PACKS_DIR = "Packs"
PACK_METADATA_FILE = "pack_metadata.json"
RELEASE_NOTES_DIR = "ReleaseNotes"
LAST_SUITABLE_PR_UPDATE_TIME_DAYS = 14
t = Terminal()
FAILED_TO_MERGE = 'Failed to merge'

XSOAR_SUPPORT = "xsoar"
PARTNER_SUPPORT = "partner"
COMMUNITY_SUPPORT = "community"
CURRENT_VERSION = 'currentVersion'
SUPPORT = 'support'


class UpdateType(str, Enum):
    """Pack version update type"""

    REVISION = "revision"
    MINOR = "minor"
    MAJOR = "major"


class SkipReason:
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
    UNALLOWED_KEYS_CHANGED = 'Pack {} metadata file has different keys in master and branch: {}.'
    FAILED_TO_MERGE = 'Cannot git merge this PR. It can happened when no mutual history between branch and master, ' \
                      'for example in PR from forked repo.'


class ConditionResult:
    """Result artifacts of the condition that was checked"""

    def __init__(
        self,
        should_skip: bool,
        reason: str | None = "",
        conflicting_packs: set | None = None,
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
        assert (
            reason if should_skip else True
        ), "Condition that should be skipped, should have a reason."
        self.should_skip = should_skip
        self.reason = reason
        self.conflicting_packs = conflicting_packs
        self.pack_new_rn_file = pack_new_rn_file
        self.pr_rn_version = pr_rn_version
        self.update_type = update_type

    def __add__(self, other: "ConditionResult"):
        """Sum of conditional results. Contains data of other conditional result if not empty, else self result.
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
    """Base abstract class for conditions"""

    def __init__(self, pr: PullRequest, git_repo: Repo, **kwargs):
        self.pr: PullRequest = pr
        self.git_repo = git_repo
        self.next_cond = None

    def set_next_condition(self, condition: "BaseCondition") -> "BaseCondition":
        """
        Args:
            condition: next condition to check after current condition.
        Returns:
            next condition to check after current condition.
        """
        self.next_cond = condition  # type: ignore[assignment]
        return self.next_cond   # type: ignore[return-value]

    @abstractmethod
    def generate_skip_reason(self, **kwargs) -> str:
        """Abstract method. Will be over-written by classes that implements Condition."""
        raise NotImplementedError

    @abstractmethod
    def _check(
        self, previous_result: ConditionResult | None = None
    ) -> ConditionResult:
        """Abstract method. Will be over-written by classes that implements Condition."""
        raise NotImplementedError

    def check(
        self, previous_result: ConditionResult | None = None
    ) -> ConditionResult:
        """Checks conditions one after another.
        Checks condition and if it is pass, checks next_condition.
        If condition fails (should_skip set to True), exit and return last condition result.
        Args:
            previous_result: result of the previous condition that was handled.
        Returns:
            last checked condition's result.
        """
        curr_result = self._check(previous_result=previous_result)
        if curr_result.should_skip:
            print(
                f"{t.red} PR: [{self.pr.number}]. {curr_result.reason} {SKIPPING_MESSAGE}\n\n"
            )
            return curr_result
        elif self.next_cond:
            return self.next_cond.check(curr_result)
        else:
            return curr_result


class MetadataCondition(BaseCondition):
    """Conditions that needs metadata files in order to check them."""

    DEFAULT_VERSION = "1.0.0"

    def __init__(
        self,
        pack: str,
        pr: PullRequest,
        git_repo: Repo,
        branch_metadata: dict | None = None,
        origin_base_metadata: dict | None = None,
        pr_base_metadata: dict | None = None,
    ):
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
        self.branch_metadata = branch_metadata or {}
        self.origin_base_metadata = origin_base_metadata or {}
        self.pr_base_metadata = pr_base_metadata or {}

    @staticmethod
    def get_metadata_files(pack_id: str, pr: PullRequest, git_repo: Repo):
        """Open packs metadata files (branch, origin/master, base/master) and read its content.
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
        metadata_path = f"{PACKS_DIR}/{pack_id}/{PACK_METADATA_FILE}"
        origin_base_pack_metadata = load_json(metadata_path)
        with Checkout(git_repo, pr.head.ref):
            branch_pack_metadata = load_json(metadata_path)
            log = git_repo.git.log()
        base_sha = MetadataCondition.get_base_commit(branch_git_log=log, pr=pr)
        with Checkout(git_repo, base_sha):
            pr_base_metadata = load_json(metadata_path)
        return origin_base_pack_metadata, branch_pack_metadata, pr_base_metadata

    @staticmethod
    def get_base_commit(branch_git_log: str, pr: PullRequest):
        """Returns the pr's base commit. (The master where the branches diverged)
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
    LAST_SUITABLE_UPDATE_TIME_DAYS = LAST_SUITABLE_PR_UPDATE_TIME_DAYS

    def generate_skip_reason(self, last_updated: str, **kwargs) -> str:     # type: ignore[override]
        """
        Args:
            last_updated: when the pr was last updated.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.LAST_MODIFIED_TIME.format(
            self.LAST_SUITABLE_UPDATE_TIME_DAYS,
            last_updated
        )

    def _check(
        self, previous_result: ConditionResult | None = None
    ) -> ConditionResult:
        """Checks if the PR was updated in last LAST_SUITABLE_UPDATE_TIME_DAYS days.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        if self.pr.updated_at and self.pr.updated_at < datetime.now(timezone.utc) - timedelta(
            days=self.LAST_SUITABLE_UPDATE_TIME_DAYS
        ):
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(last_updated=str(self.pr.updated_at)),
            )
        else:
            return ConditionResult(should_skip=False)


class LabelCondition(BaseCondition):
    NOT_UPDATE_RN_LABEL = "igasd"
    def generate_skip_reason(self, labels: str, **kwargs) -> str:   # type: ignore[override]
        """
        Args:
            labels: pr labels.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.NOT_UPDATE_RN_LABEL_EXIST.format(
            self.NOT_UPDATE_RN_LABEL, labels
        )

    def _check(
        self, previous_result: ConditionResult | None = None
    ) -> ConditionResult:
        """Checks if the PR has NOT_UPDATE_RN_LABEL.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pr_labels = [label.name for label in self.pr.labels]
        if self.NOT_UPDATE_RN_LABEL in pr_labels:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(labels=", ".join(pr_labels)),
            )
        else:
            return ConditionResult(should_skip=False)


class AddedRNFilesCondition(BaseCondition):
    def generate_skip_reason(self, **kwargs) -> str:
        """
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.NO_NEW_RELEASE_NOTES.format(RELEASE_NOTES_DIR)

    def _check(
        self, previous_result: ConditionResult | None = None
    ) -> ConditionResult:
        """Checks if there are new Release Notes files in the PR.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pr_files = list(self.pr.get_files())
        pr_rn_files = [
            f
            for f in pr_files
            if f.status == "added" and RELEASE_NOTES_DIR in Path(f.filename).parts
        ]
        if not pr_rn_files:
            return ConditionResult(should_skip=True, reason=self.generate_skip_reason())
        else:
            return ConditionResult(should_skip=False)


class HasConflictOnAllowedFilesCondition(BaseCondition):
    def generate_skip_reason(self, conflicting_files, **kwargs) -> str:  # type: ignore[override]
        """
        Args:
            conflicting_files: files on the pr that conflicts with base.
        Returns: Reason why the condition failed, and pr skipped.
        """
        if not conflicting_files:
            return SkipReason.NO_CONFLICTING_FILES
        elif FAILED_TO_MERGE in conflicting_files:
            return SkipReason.FAILED_TO_MERGE
        else:
            return SkipReason.CONFLICTING_FILES.format(
                RELEASE_NOTES_DIR, PACK_METADATA_FILE, conflicting_files
            )

    def _check(
        self, previous_result: ConditionResult | None = None
    ) -> ConditionResult:
        """Checks if the PR conflicting with origin/master on pack_metadata and release notes only.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pr_files = list(self.pr.get_files())
        added_rn_files = [
            f.filename
            for f in pr_files
            if f.status == "added" and RELEASE_NOTES_DIR in Path(f.filename).parts
        ]
        changed_metadata_files = [
            f.filename for f in pr_files if Path(f.filename).name == PACK_METADATA_FILE
        ]
        (
            conflict_only_rn_and_metadata,
            conflict_files,
        ) = self._has_conflict_on_given_files(added_rn_files + changed_metadata_files)
        if not conflict_only_rn_and_metadata:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(conflicting_files=conflict_files),
            )
        else:
            conflicting_packs = get_pack_names_from_files(conflict_files)
            return ConditionResult(
                should_skip=False, conflicting_packs=conflicting_packs
            )

    def _has_conflict_on_given_files(
        self, files_check_to_conflict_with: list
    ) -> tuple[bool, list]:
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
            self.git_repo.git.merge(f"origin/{pr_branch}", "--no-ff", "--no-commit")
        except GitCommandError as e:
            print(f'Got git error: {e=}')
            if 'not something we can merge' in e.stderr:
                return False, [FAILED_TO_MERGE]
            error = e.stdout
            if error:
                error = error.replace("stdout: '", "").strip()
            conflicting_files = [
                line.replace("Auto-merging ", "").strip()
                for line in error.splitlines()
                if "Auto-merging " in line
            ]
            conflict_only_with_given_files = all(
                file_name in files_check_to_conflict_with
                for file_name in conflicting_files
            )
        self.git_repo.git.merge("--abort")
        self.git_repo.git.clean("-f")
        return bool(conflict_only_with_given_files and conflicting_files), conflicting_files


class PackSupportCondition(MetadataCondition):
    ALLOWED_SUPPORT_TYPES = (XSOAR_SUPPORT, PARTNER_SUPPORT, COMMUNITY_SUPPORT)

    def generate_skip_reason(self, support_type: str | None, **kwargs) -> str:  # type: ignore[override]
        """
        Args:
            support_type: pack support type.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.NOT_ALLOW_SUPPORTED_TYPE_PACK.format(
            self.ALLOWED_SUPPORT_TYPES, self.pack, support_type
        )

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks if the pack is XSOAR supported.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        support_type = self.branch_metadata.get(SUPPORT)
        if support_type not in self.ALLOWED_SUPPORT_TYPES:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(support_type=support_type),
            )
        else:
            return ConditionResult(should_skip=False)


class MajorChangeCondition(MetadataCondition):

    def generate_skip_reason(       # type: ignore[override]
        self, origin_version: Version, branch_version: Version, **kwargs
    ) -> str:
        """
        Args:
            origin_version: pack version in the base branch (origin/master).
            branch_version: pack versio in the branch.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.DIFFERENT_MAJOR_VERSION.format(
            self.pack, str(origin_version), str(branch_version)
        )

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks if packs major changed.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        origin_pack_metadata_version = Version(
            self.origin_base_metadata.get(
                CURRENT_VERSION, self.DEFAULT_VERSION
            )
        )
        branch_pack_metadata_version = Version(
            self.branch_metadata.get(CURRENT_VERSION, self.DEFAULT_VERSION)
        )
        if origin_pack_metadata_version.major != branch_pack_metadata_version.major:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(
                    origin_version=origin_pack_metadata_version,
                    branch_version=branch_pack_metadata_version,
                ),
            )
        else:
            return ConditionResult(should_skip=False)


class MaxVersionCondition(MetadataCondition):
    MAX_ALLOWED_VERSION = "99"

    def generate_skip_reason(       # type: ignore[override]
        self, origin_version: str, branch_version: str, **kwargs
    ) -> str:
        """
        Args:
            origin_version: pack version in the base branch (origin/master).
            branch_version: pack versio in the branch.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.EXCEED_MAX_ALLOWED_VERSION.format(
            self.pack, self.MAX_ALLOWED_VERSION, origin_version, branch_version
        )

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks if packs version is 99. (99 is the last supported version number).
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        origin_pack_metadata_version = self.origin_base_metadata.get(
            CURRENT_VERSION, self.DEFAULT_VERSION
        )
        branch_pack_metadata_version = self.branch_metadata.get(
            CURRENT_VERSION, self.DEFAULT_VERSION
        )
        if (
            self.MAX_ALLOWED_VERSION in origin_pack_metadata_version
            or self.MAX_ALLOWED_VERSION in branch_pack_metadata_version
        ):
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(
                    origin_version=origin_pack_metadata_version,
                    branch_version=branch_pack_metadata_version,
                ),
            )
        else:
            return ConditionResult(should_skip=False)


class OnlyVersionChangedCondition(MetadataCondition):
    ALLOWED_CHANGED_KEYS = [CURRENT_VERSION]

    def generate_skip_reason(self, not_allowed_changed_keys, **kwargs) -> str:      # type: ignore[override]
        """
        Args:
            not_allowed_changed_keys: pack_metadata keys that was changed.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.UNALLOWED_KEYS_CHANGED.format(
            self.pack, not_allowed_changed_keys
        )

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks if other pack metadata fields changed except ALLOWED CHANGED PACKS.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        not_allowed_changed_keys = [
            k
            for k, v in self.branch_metadata.items()
            if k not in self.ALLOWED_CHANGED_KEYS
            and self.origin_base_metadata.get(k) != v
        ]
        if not_allowed_changed_keys:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(
                    not_allowed_changed_keys=not_allowed_changed_keys,
                ),
            )
        else:
            return ConditionResult(should_skip=False)


class OnlyOneRNPerPackCondition(MetadataCondition):
    def generate_skip_reason(self, rn_files: list, **kwargs) -> str:    # type: ignore[override]
        """
        Args:
            rn_files: release notes files for the pack in current pr.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.MORE_THAN_ONE_RN.format(self.pack, [str(f) for f in rn_files])

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks that only one release notes files per pack was added.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        pack_new_rn_files = [
            Path(f.filename)
            for f in self.pr.get_files()
            if f.status == "added"
            and RELEASE_NOTES_DIR in Path(f.filename).parts
            and self.pack in Path(f.filename).parts
            and "md" in Path(f.filename).suffix
        ]
        if len(pack_new_rn_files) != 1:
            return ConditionResult(
                should_skip=True, reason=self.generate_skip_reason(pack_new_rn_files)
            )
        else:
            return ConditionResult(
                should_skip=False, pack_new_rn_file=pack_new_rn_files[0]
            )


class SameRNMetadataVersionCondition(MetadataCondition):

    def generate_skip_reason(       # type: ignore[override]
        self, rn_version: Version, metadata_version: Version, **kwargs
    ) -> str:
        """
        Args:
            rn_version: version of the release notes.
            metadata_version: version of the pack in the metadata file.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.DIFFERENT_RN_METADATA_VERSIONS.format(
            self.pack, rn_version, metadata_version
        )

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks if the new Release Notes has the same version as pack metadata version.
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        branch_pack_metadata_version = Version(
            self.branch_metadata.get(CURRENT_VERSION, self.DEFAULT_VERSION)
        )
        assert previous_result, "No previous result was supplied to the SameRNMetadataVersionCondition object."
        assert previous_result.pack_new_rn_file, "No previous result was supplied to the SameRNMetadataVersionCondition object."
        rn_version_file_name = previous_result.pack_new_rn_file.stem
        rn_version = Version(rn_version_file_name.replace("_", "."))
        if branch_pack_metadata_version != rn_version:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(
                    rn_version, branch_pack_metadata_version
                ),
            )
        else:
            return previous_result + ConditionResult(
                should_skip=False, pr_rn_version=rn_version
            )


class AllowedBumpCondition(MetadataCondition):

    def generate_skip_reason(       # type: ignore[override]
        self, previous_version: Version, new_version: Version, **kwargs
    ) -> str:
        """
        Args:
            previous_version: previous version of the pack.
            new_version: new pack version.
        Returns: Reason why the condition failed, and pr skipped.
        """
        return SkipReason.ALLOWED_BUMP_CONDITION.format(
            self.pack, previous_version, new_version
        )

    def _check(
        self, previous_result: ConditionResult | None = None, **kwargs
    ) -> ConditionResult:
        """Checks if the pack version was updated by +1. (The only bump we allow).
        Args:
            previous_result: previous check artifacts.

        Returns(ConditionResult): whether the condition check pass,
            or we should skip this pr from auto-bumping its release notes, with the reason why to skip.
        """
        branch_pack_metadata_version = Version(
            self.branch_metadata.get(CURRENT_VERSION, self.DEFAULT_VERSION)
        )
        base_pack_metadata_version = Version(
            self.pr_base_metadata.get(CURRENT_VERSION, self.DEFAULT_VERSION)
        )
        update_type = self.check_update_type(
            base_pack_metadata_version, branch_pack_metadata_version
        )
        if not update_type:
            return ConditionResult(
                should_skip=True,
                reason=self.generate_skip_reason(
                    base_pack_metadata_version, branch_pack_metadata_version
                ),
            )
        else:
            assert (
                previous_result
            ), "No previous result was supplied to the AllowedBumpCondition object."
            return previous_result + ConditionResult(
                should_skip=False, update_type=update_type
            )

    @staticmethod
    def check_update_type(
        prev_version: Version, new_version: Version
    ) -> UpdateType | None:
        """Checks what was the update type when the release notes were generated.
        Args:
            prev_version: the pack version before updating release notes.
            new_version: the pack version after updating release notes.
        Returns:
            The pack update type if the update type was legal.
        """
        same_major = prev_version.major == prev_version.major
        same_minor = prev_version.minor == prev_version.minor
        if prev_version.micro + 1 == new_version.micro and same_minor and same_major:
            return UpdateType.REVISION
        elif (
            prev_version.minor + 1 == new_version.minor
            and same_major
            and new_version.micro == 0
        ):
            return UpdateType.MINOR
        elif (
            prev_version.major + 1 == new_version.major
            and new_version.minor == 0
            and new_version.micro == 0
        ):
            return UpdateType.MAJOR
        else:
            return None
