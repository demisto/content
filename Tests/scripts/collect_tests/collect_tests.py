import json
import os
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions
from demisto_sdk.commands.common.tools import find_type, str2bool

from Tests.Marketplace.marketplace_services import get_last_commit_from_index
from Tests.scripts.collect_tests.constants import (
    ALWAYS_INSTALLED_PACKS, DEFAULT_MARKETPLACE_WHEN_MISSING,
    DEFAULT_REPUTATION_TESTS, IGNORED_FILE_TYPES, ONLY_INSTALL_PACK_FILE_TYPES,
    SANITY_TEST_TO_PACK, SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK,
    XSOAR_SANITY_TEST_NAMES)
from Tests.scripts.collect_tests.exceptions import (
    DeprecatedPackException, InvalidTestException, NonDictException,
    NonXSIAMContentException, NonXsoarSupportedPackException,
    NoTestsConfiguredException, NothingToCollectException,
    NotUnderPackException, PrivateTestException, SkippedPackException,
    SkippedTestException, TestMissingFromIdSetException)
from Tests.scripts.collect_tests.id_set import IdSet
from Tests.scripts.collect_tests.logger import logger
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.test_conf import TestConf
from Tests.scripts.collect_tests.utils import (ContentItem, Machine,
                                               PackManager, VersionRange,
                                               find_pack_folder,
                                               find_yml_content_type)

PATHS = PathManager(Path(__file__).absolute().parents[3])
PACK_MANAGER = PackManager(PATHS)


class CollectionReason(str, Enum):
    ID_SET_MARKETPLACE_VERSION = 'id_set marketplace version'
    PACK_MARKETPLACE_VERSION_VALUE = 'marketplace version of pack'
    CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE = 'marketplace version of contained item'
    SANITY_TESTS = 'sanity tests'
    NON_CODE_FILE_CHANGED = 'non-code pack file changed'
    INTEGRATION_CHANGED = 'integration changed, collecting all conf.json tests using it'
    SCRIPT_PLAYBOOK_CHANGED = 'file changed, taking tests from `tests` section in script yml'
    SCRIPT_PLAYBOOK_CHANGED_NO_TESTS = 'file changed, but has `No Tests` configured, taking tests from id_set'
    TEST_PLAYBOOK_CHANGED = 'test playbook changed'
    MAPPER_CHANGED = 'mapper file changed, configured as incoming_mapper_id in test conf'
    CLASSIFIER_CHANGED = 'classifier file changed, configured as classifier_id in test conf'
    DEFAULT_REPUTATION_TESTS = 'default reputation tests'
    ALWAYS_INSTALLED_PACKS = 'packs that are always installed'
    PACK_TEST_DEPENDS_ON = 'packs under which integrations are stored, on which a test depends'

    DUMMY_OBJECT_FOR_COMBINING = 'creating an empty object, to combine two CollectionResult objects'


REASONS_ALLOWING_NO_ID_SET_OR_CONF = {
    # these may be used without an id_set or conf.json object, see _validate_args.
    CollectionReason.DUMMY_OBJECT_FOR_COMBINING,
    CollectionReason.ALWAYS_INSTALLED_PACKS
}


class CollectionResult:
    def __init__(
            self,
            test: Optional[str],
            pack: Optional[str],
            reason: CollectionReason,
            version_range: Optional[VersionRange],
            reason_description: str,
            conf: Optional[TestConf],
            id_set: Optional[IdSet],
            is_sanity: bool = False,
    ):
        """
        Collected test playbook, and/or pack to install.

        NOTE:   the constructor only accepts a single Optional[str] for test and pack, but they're kept as set[str].
                This is done to require a reason for every collection, which is logged.
                Use the + operator or CollectedTests.union() to join two or more objects and hold multiple tests.

        :param test: test playbook id
        :param pack: pack name to install
        :param reason: CollectionReason explaining the collection
        :param version_range: XSOAR versions on which the content should be tested, matching the from/toversion fields.
        :param reason_description: free text elaborating on the collection, e.g. path of the changed file.
        :param conf: a ConfJson object. It may be None only when reason in VALIDATION_BYPASSING_REASONS.
        :param id_set: an IdSet object. It may be None only when reason in VALIDATION_BYPASSING_REASONS.
        :param is_sanity: whether the test is a sanity test. Sanity tests do not have to be in the id_set.
        """
        self.tests: set[str] = set()
        self.packs: set[str] = set()
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: Optional[tuple[Machine, ...]] = None

        try:
            self._validate_args(pack, test, reason, conf, id_set, is_sanity)  # raises if invalid

        except NonXsoarSupportedPackException:
            if test:
                logger.info(f'{pack} support level != XSOAR, not collecting {test}, pack will be installed')
                test = None

        except InvalidTestException as e:
            suffix = ' (pack will be installed)' if pack else ''
            logger.info(f'{str(e)}, not collecting {test}{suffix}')
            test = None

        except (SkippedPackException, DeprecatedPackException,) as e:
            logger.warning(str(e))
            return

        if test:
            self.tests = {test}
            logger.info(f'collected {test=}, {reason} ({reason_description}, {version_range=})')

        if pack:
            self.packs = {pack}
            logger.info(f'collected {pack=}, {reason} ({reason_description}, {version_range=})')

    @staticmethod
    def _validate_args(pack: Optional[str], test: Optional[str], reason: CollectionReason, conf: Optional[TestConf],
                       id_set: Optional[IdSet], is_sanity: bool):
        """
        Validates the arguments of the constructor.
        """
        if reason not in REASONS_ALLOWING_NO_ID_SET_OR_CONF:
            for (arg, arg_name) in ((conf, 'conf.json'), (id_set, 'id_set')):
                if not arg:
                    # may be None only when reason not in REASONS_ALLOWING_NO_ID_SET_OR_CONF
                    raise ValueError(f'no {arg_name} was provided')

        if not any((pack, test)) and reason != CollectionReason.DUMMY_OBJECT_FOR_COMBINING:
            # at least one is required, unless the reason is DUMMY_OBJECT_FOR_COMBINING
            raise ValueError('neither pack nor test were provided')

        if test:
            if not is_sanity:  # sanity tests do not show in the id_set
                if test not in id_set.id_to_test_playbook:  # type:ignore[union-attr]
                    raise TestMissingFromIdSetException(test)

                test_playbook = id_set.id_to_test_playbook[test]  # type:ignore[union-attr]
                if not (pack_id := test_playbook.pack_id):
                    raise ValueError(f'{test} has no pack_id')
                if not (playbook_path := test_playbook.path):
                    raise ValueError(f'{test} has no path')
                if PACK_MANAGER.is_test_skipped_in_pack_ignore(playbook_path.name, pack_id):
                    raise SkippedTestException(test, skip_place='.pack_ignore')

            if skip_reason := conf.skipped_tests.get(test):  # type:ignore[union-attr]
                raise SkippedTestException(test, skip_place='conf.json', skip_reason=skip_reason)

            if test in conf.private_tests:  # type:ignore[union-attr]
                raise PrivateTestException(test)

        if pack:
            try:
                PACK_MANAGER.validate_pack(pack)

            except NonXsoarSupportedPackException:
                if is_sanity and pack == 'HelloWorld':  # Sanity tests are saved under HelloWorld, so we allow it.
                    return
                raise

    @staticmethod
    def __empty_result() -> 'CollectionResult':
        # used for combining two CollectionResult objects
        return CollectionResult(
            test=None, pack=None, reason=CollectionReason.DUMMY_OBJECT_FOR_COMBINING, version_range=None,
            reason_description='', conf=None, id_set=None
        )

    def __add__(self, other: Optional['CollectionResult']) -> 'CollectionResult':
        # initial object just to add others to
        if not other:
            return self
        result = self.__empty_result()
        result.tests = self.tests | other.tests  # type: ignore[operator]
        result.packs = self.packs | other.packs  # type: ignore[operator]
        result.version_range = self.version_range | other.version_range if self.version_range else other.version_range
        return result

    @staticmethod
    def union(collected_tests: Optional[tuple[Optional['CollectionResult'], ...]]) -> Optional['CollectionResult']:
        non_none = filter(None, collected_tests or (None,))
        return sum(non_none, start=CollectionResult.__empty_result())

    def __repr__(self):
        return f'{len(self.packs)} packs, {len(self.tests)} tests, {self.version_range=}'

    def __bool__(self):
        return bool(self.tests or self.packs)


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions):
        self.marketplace = marketplace
        self.id_set = IdSet(marketplace, PATHS.id_set_path)
        self.conf = TestConf(PATHS.conf_path)
        self.trigger_sanity_tests = False

    @property
    def sanity_tests(self) -> Optional[CollectionResult]:
        return CollectionResult.union(tuple(
            CollectionResult(
                test=test,
                pack=SANITY_TEST_TO_PACK.get(test),  # None in most cases
                reason=CollectionReason.SANITY_TESTS,
                version_range=None,
                reason_description=f'by marketplace version {self.marketplace}',
                conf=self.conf,
                id_set=self.id_set,
                is_sanity=True
            )
            for test in self._sanity_test_names
        ))

    @property
    def _always_installed_packs(self) -> Optional[CollectionResult]:
        return CollectionResult.union(tuple(
            CollectionResult(test=None, pack=pack, reason=CollectionReason.ALWAYS_INSTALLED_PACKS,
                             version_range=None, reason_description=pack, conf=None, id_set=None, is_sanity=True)
            for pack in ALWAYS_INSTALLED_PACKS)
        )

    @property
    def _sanity_test_names(self) -> tuple[str, ...]:
        match self.marketplace:
            case MarketplaceVersions.MarketplaceV2:
                return tuple(self.conf['test_marketplacev2'])
            case MarketplaceVersions.XSOAR:
                return XSOAR_SANITY_TEST_NAMES
            case _:
                raise RuntimeError(f'unexpected marketplace value {self.marketplace.value}')

    @abstractmethod
    def _collect(self) -> Optional[CollectionResult]:
        """
        Collects all relevant tests and packs.
        Every subclass implements its own methodology here.
        :return: A CollectedTests object with only the pack_name_to_pack_metadata to install and tests to run,
                with machines=None.
        """
        pass

    def collect(self) -> Optional[CollectionResult]:
        result: Optional[CollectionResult] = self._collect()

        if not result:
            if self.trigger_sanity_tests:
                result = self.sanity_tests
                logger.warning('Nothing was collected, but sanity-test-triggering files were changed, '
                               'returning sanity tests')
            else:
                logger.warning('Nothing was collected, and no sanity-test-triggering files were changed')
                return None

        self._validate_tests_in_id_set(result.tests)  # type:ignore[union-attr]
        result += self._always_installed_packs  # type:ignore[operator]
        result += self._collect_test_dependencies(result.tests if result else ())  # type:ignore[union-attr]
        result.machines = Machine.get_suitable_machines(result.version_range)  # type:ignore[union-attr]

        return result

    def _collect_test_dependencies(self, test_ids: Iterable[str]) -> Optional[CollectionResult]:
        result = []

        for test_id in test_ids:
            test_object = self.conf.get_test(test_id)

            for integration in test_object.integrations:
                result.append(
                    self._collect_test_dependency(
                        dependency=integration,
                        test_id=test_id,
                        pack_id=self.id_set.id_to_integration[integration].pack_id
                    )
                )

            for script in test_object.scripts:
                result.append(
                    self._collect_test_dependency(
                        dependency=script,
                        test_id=test_id,
                        pack_id=self.id_set.id_to_script[script].pack_id
                    )
                )

        return CollectionResult.union(tuple(result))

    def _collect_test_dependency(self, dependency: str, test_id: str, pack_id: str) -> CollectionResult:
        return (
            CollectionResult(
                test=None, pack=pack_id, reason=CollectionReason.PACK_TEST_DEPENDS_ON,
                version_range=None, reason_description=f'{test_id} depends on {dependency} from {pack_id}',
                conf=self.conf, id_set=self.id_set,
            )
        )

    def _validate_tests_in_id_set(self, tests: Iterable[str]):
        if not_found := set(tests).difference(self.id_set.id_to_test_playbook.keys()):
            not_found_string = ', '.join(sorted(not_found))
            logger.warning(f'{len(not_found)} tests were not found in id-set: \n{not_found_string}')

    def _collect_pack(self, pack_id: str, reason: CollectionReason, reason_description: str,
                      content_item_range: Optional[VersionRange] = None) -> CollectionResult:
        pack = PACK_MANAGER[pack_id]

        version_range = content_item_range \
            if pack.version_range.is_default \
            else (pack.version_range | content_item_range)

        return CollectionResult(
            test=None,
            pack=pack_id,
            reason=reason,
            version_range=version_range,
            reason_description=reason_description,
            conf=self.conf,
            id_set=self.id_set,
        )


class BranchTestCollector(TestCollector):
    def __init__(
            self,
            branch_name: str,
            marketplace: MarketplaceVersions,
            service_account: Optional[str],
            private_pack_path: Optional[Path] = None,
    ):
        """

        :param branch_name: branch name
        :param marketplace: marketplace value
        :param service_account: used for comparing with the latest upload bucket
        :param private_pack_path: path to a pack, only used for content-private.
        """
        super().__init__(marketplace)
        logger.debug(f'Created BranchTestCollector for {branch_name}')
        self.branch_name = branch_name
        self.service_account = service_account
        self.private_pack_path: Optional[Path] = private_pack_path

    def _get_private_pack_files(self) -> tuple[Path, ...]:
        if not self.private_pack_path:
            raise RuntimeError('private_pack_path cannot be empty')
        return tuple(path for path in self.private_pack_path.rglob('*') if path.is_file())

    def _collect(self) -> Optional[CollectionResult]:
        result = []
        paths = self._get_private_pack_files() if self.private_pack_path else self._get_changed_files()
        for path in paths:
            try:
                logger.debug(f'Collecting tests for {path}')
                result.append(self._collect_single(PATHS.content_path / path))
            except NothingToCollectException as e:
                logger.warning(e.message)
            except Exception as e:
                logger.exception(f'Error while collecting tests for {path}', exc_info=True, stack_info=True)
                raise e

        return CollectionResult.union(tuple(result))

    def _collect_yml(self, content_item_path: Path) -> Optional[CollectionResult]:
        """
        collecting a yaml-based content item (including py-based, whose names match a yaml based one)
        """
        yml_path = content_item_path.with_suffix('.yml') if content_item_path.suffix != '.yml' else content_item_path
        try:
            yml = ContentItem(yml_path)
            if not yml.id_:
                raise ValueError(f'id field of {yml_path} cannot be empty')
        except FileNotFoundError:
            raise FileNotFoundError(f'could not find yml matching {PACK_MANAGER.relative_to_packs(content_item_path)}')
        self._validate_xsiam_compatibility(yml)
        self._validate_skipped_integration(yml)
        relative_yml_path = PACK_MANAGER.relative_to_packs(yml_path)
        tests: tuple[str, ...]

        match actual_content_type := find_yml_content_type(yml_path):
            case None:
                path_description = f'{yml_path} (original item {content_item_path}' \
                    if content_item_path != yml_path \
                    else yml_path
                raise ValueError(f'could not detect type for {path_description}')

            case FileType.TEST_PLAYBOOK:
                if yml.id_ in self.conf.test_id_to_test:
                    tests = yml.id_,
                    reason = CollectionReason.TEST_PLAYBOOK_CHANGED
                else:
                    raise ValueError(f'test playbook with id {yml.id_} is missing from conf.test_ids')

            case FileType.INTEGRATION:

                if yml.explicitly_no_tests():
                    suffix = ''

                    if tests_from_conf := self.conf.integrations_to_tests.get(yml.id_, ()):
                        tests_str = ', '.join(sorted(tests_from_conf))
                        suffix = f'. NOTE: NOT COLLECTING tests from conf.json={tests_str}'

                    logger.warning(f'{yml.id_} explicitly states `no tests`: only collecting pack {suffix}')
                    tests = ()

                elif yml.id_ not in self.conf.integrations_to_tests:
                    if PACK_MANAGER.get_support_level(yml.pack_id) == 'xsoar':
                        raise ValueError(
                            f'integration {str(PACK_MANAGER.relative_to_packs(yml.path))} is '
                            f'(1) missing from conf.json, AND'
                            ' (2) does not explicitly state `tests: no tests` AND'
                            ' (3) has support level == xsoar. '
                            'Please change at least one of these to allow test collection.'
                        )
                    else:
                        logger.info(f'{yml.id_} has tests configured, but support level != xsoar. '
                                    f'The {yml.pack_id} pack will be installed, but no tests will be collected.')
                        tests = ()
                else:
                    # integration to test mapping available, and support level == xsoar (so - we run the tests)
                    tests = tuple(self.conf.integrations_to_tests[yml.id_])
                reason = CollectionReason.INTEGRATION_CHANGED

            case FileType.SCRIPT | FileType.PLAYBOOK:
                try:
                    tests = tuple(yml.tests)  # raises NoTestsConfiguredException if 'no tests' in the tests field
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED

                except NoTestsConfiguredException:
                    # collecting all tests that implement this script/playbook
                    id_to_tests = {
                        FileType.SCRIPT: self.id_set.implemented_scripts_to_tests,
                        FileType.PLAYBOOK: self.id_set.implemented_playbooks_to_tests
                    }[actual_content_type]
                    tests = tuple(test.name for test in id_to_tests.get(yml.id_, ()))
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED_NO_TESTS

                    if not tests:  # no tests were found in yml nor in id_set
                        logger.warning(f'{actual_content_type.value} {relative_yml_path} '
                                       f'has `No Tests` configured, and no tests in id_set')
            case _:
                raise RuntimeError(f'Unexpected content type {actual_content_type.value} for {content_item_path}'
                                   f'(expected `Integrations`, `Scripts` or `Playbooks`)')
        if tests:
            return CollectionResult.union(tuple(
                CollectionResult(
                    test=test,
                    pack=yml.pack_id,
                    reason=reason,
                    version_range=yml.version_range,
                    reason_description=f'{yml.id_=} ({relative_yml_path})',
                    conf=self.conf,
                    id_set=self.id_set
                ) for test in tests))
        else:
            return self._collect_pack(yml.pack_id, reason, 'collecting pack only', yml.version_range)

    def _validate_skipped_integration(self, yml: ContentItem):
        if yml.id_ in self.conf.skipped_integrations:
            raise NothingToCollectException(yml.path, 'integration is skipped')

    def _validate_xsiam_compatibility(self, content_item: ContentItem):
        if self.marketplace == MarketplaceVersions.MarketplaceV2:
            # tests should be collected only for items whose only marketplace is marketplacev2
            if content_item.marketplaces != (self.marketplace,):
                raise NonXSIAMContentException(content_item.path)

    def _validate_triggering_sanity_test(self, path):
        if path in PATHS.files_triggering_sanity_tests:
            self.trigger_sanity_tests = True
            raise NothingToCollectException(path, 'not under a pack (triggering sanity tests)')

    @staticmethod
    def _validate_not_ignored(path: Path):
        if path in PATHS.files_to_ignore:
            raise NothingToCollectException(path, 'not under a pack (ignored, not triggering sanity tests')

    def _collect_single(self, path: Path) -> Optional[CollectionResult]:
        if not path.exists():
            raise FileNotFoundError(path)

        self._validate_not_ignored(path)
        self._validate_triggering_sanity_test(path)

        reason_description = relative_path = PACK_MANAGER.relative_to_packs(path)
        file_type = find_type(str(path))

        try:
            content_item = ContentItem(path)
            self._validate_xsiam_compatibility(content_item)

        except NonDictException:
            # for `.py`, `.md`, etc: anything not dictionary-based. Suitable logic follows, see collect_yml.
            content_item = None

        if file_type in ONLY_INSTALL_PACK_FILE_TYPES:
            # install pack without collecting tests.
            pack_id = find_pack_folder(path).name

            if not content_item:
                self._validate_xsiam_compatibility(PACK_MANAGER[pack_id])  # checks marketplaces under pack_metadata

            return self._collect_pack(
                pack_id=pack_id,
                reason=CollectionReason.NON_CODE_FILE_CHANGED,
                reason_description=reason_description,
                content_item_range=content_item.version_range if content_item else None
            )

        elif file_type in IGNORED_FILE_TYPES:
            raise NothingToCollectException(path, f'ignored type {file_type}')

        elif file_type in {FileType.PYTHON_FILE, FileType.POWERSHELL_FILE, FileType.JAVASCRIPT_FILE}:
            if path.name.lower().endswith(('_test.py', 'tests.ps1')):
                raise NothingToCollectException(path, 'changing unit tests does not trigger collection')
            return self._collect_yml(path)

        elif file_type == FileType.REPUTATION:
            tests = DEFAULT_REPUTATION_TESTS
            reason = CollectionReason.DEFAULT_REPUTATION_TESTS

        elif file_type in {FileType.MAPPER, FileType.CLASSIFIER}:
            source, reason = {
                FileType.MAPPER: (self.conf.incoming_mapper_to_test, CollectionReason.MAPPER_CHANGED),
                FileType.CLASSIFIER: (self.conf.classifier_to_test, CollectionReason.CLASSIFIER_CHANGED),
            }[file_type]
            if not (tests := source.get(content_item, ())):  # type: ignore[call-overload]
                reason = CollectionReason.NON_CODE_FILE_CHANGED
                reason_description = f'no specific tests for {relative_path} were found'

        elif path.suffix == '.yml':  # file_type is often None in these cases
            return self._collect_yml(path)  # checks for containing folder (content item type)

        elif file_type is None:
            raise NothingToCollectException(path, 'unknown file type')

        else:
            raise ValueError(path, f'unexpected content type {file_type} - please update collect_tests.py')

        if not content_item:
            raise RuntimeError(f'failed collecting {path} for an unknown reason')

        return CollectionResult.union(tuple(
            CollectionResult(
                test=test,
                pack=content_item.pack_id,
                reason=reason,
                version_range=content_item.version_range,
                reason_description=reason_description,
                conf=self.conf,
                id_set=self.id_set,
            )
            for test in tests)
        )

    def _get_changed_files(self) -> tuple[str, ...]:
        repo = PATHS.content_repo
        changed_files: list[str] = []

        previous_commit = 'origin/master'
        current_commit = self.branch_name

        logger.debug(f'Getting changed files for {self.branch_name=}')

        if os.getenv('IFRA_ENV_TYPE') == 'Bucket-Upload':
            logger.info('bucket upload: getting last commit from index')
            previous_commit = get_last_commit_from_index(self.service_account)
            if self.branch_name == 'master':
                current_commit = 'origin/master'

        elif self.branch_name == 'master':
            current_commit, previous_commit = tuple(repo.iter_commits(max_count=2))

        elif os.getenv('CONTRIB_BRANCH'):
            # gets files of unknown status
            contrib_diff: tuple[str, ...] = tuple(filter(lambda f: f.startswith('Packs/'), repo.untracked_files))
            logger.info('contribution branch found, contrib-diff:\n' + '\n'.join(contrib_diff))
            changed_files.extend(contrib_diff)

        diff = repo.git.diff(f'{previous_commit}...{current_commit}', '--name-status')
        logger.debug(f'raw changed files string:\n{diff}')

        # diff is formatted as `M  foo.json\n A  bar.py\n ...`, turning it into ('foo.json', 'bar.py', ...).
        for line in diff.splitlines():
            match len(parts := line.split('\t')):
                case 2:
                    git_status, file_path = parts
                case 3:
                    git_status, _, file_path = parts  # R <old location> <new location>

                    if git_status.startswith('R'):
                        logger.debug(f'{git_status=} for {file_path=}, considering it as <M>odified')
                        git_status = 'M'
                case _:
                    raise ValueError(f'unexpected line format '
                                     f'(expected `<modifier>\t<file>` or `<modifier>\t<old_location>\t<new_location>`'
                                     f', got {line}')

            if git_status not in {'A', 'M', 'D', }:
                logger.warning(f'unexpected {git_status=}, considering it as <M>odified')

            if git_status == 'D':  # git-deleted file
                logger.warning(f'Found a file deleted from git {file_path}, '
                               f'skipping it as TestCollector cannot properly find the appropriate tests (by design)')
                continue
            changed_files.append(file_path)  # non-deleted files (added, modified)
        return tuple(changed_files)


class UploadCollector(BranchTestCollector):
    def _collect(self) -> Optional[CollectionResult]:
        # same as BranchTestCollector, but without tests.
        if result := super()._collect():
            logger.info('UploadCollector drops collected tests, as they are not required')
            result.tests = set()
        return result


class NightlyTestCollector(TestCollector, ABC):
    def _id_set_tests_matching_marketplace_value(self, only_value: bool) -> Optional[CollectionResult]:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all tests whose marketplace field includes the collector's marketplace value
                    (or is equal to it, if `only_value` is used).
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(f'collecting test playbooks by their marketplace field, searching for {self.marketplace.value}'
                    f'{postfix}')

        result = []

        for playbook in self.id_set.test_playbooks:
            playbook_marketplaces = playbook.marketplaces or default

            if only_value and len(playbook_marketplaces) != 1:
                continue

            if self.marketplace in playbook_marketplaces:
                result.append(CollectionResult(
                    test=playbook.id_, pack=playbook.pack_id,
                    reason=CollectionReason.ID_SET_MARKETPLACE_VERSION,
                    reason_description=self.marketplace.value,
                    version_range=playbook.version_range,
                    conf=self.conf, id_set=self.id_set)
                )

        if not result:
            logger.warning(f'no tests matching marketplace {self.marketplace.value} ({only_value=}) were found')
            return None

        return CollectionResult.union(tuple(result))

    def _packs_matching_marketplace_value(self, only_value: bool) -> Optional[CollectionResult]:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all packs whose marketplaces field contains self.marketplaces (or is equal to, if only_value is True).
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(f'collecting packs by their marketplace field, searching for {self.marketplace.value}{postfix}')
        packs = []

        for pack in PACK_MANAGER:
            pack_marketplaces = pack.marketplaces or default
            if only_value and len(pack_marketplaces) != 1:
                continue
            if self.marketplace in pack_marketplaces:
                packs.append(pack.pack_id)

        if not packs:
            logger.warning(f'no packs matching marketplace {self.marketplace.value} ({only_value=}) were found')
            return None

        return CollectionResult.union(
            tuple(CollectionResult(test=None, pack=pack, reason=CollectionReason.PACK_MARKETPLACE_VERSION_VALUE,
                                   version_range=None, reason_description=self.marketplace.value,
                                   conf=self.conf, id_set=self.id_set)
                  for pack in packs)
        )

    def _packs_of_content_matching_marketplace_value(self, only_value: bool) -> Optional[CollectionResult]:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all packs whose under which a content item marketplace field contains self.marketplaces
                (or is equal to, if only_value is True).
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(
            f'collecting content items by their marketplace field, searching for {self.marketplace.value} {postfix}')

        result = []

        for item in self.id_set.artifact_iterator:
            item_marketplaces = item.marketplaces or default

            if only_value and len(item_marketplaces) != 1:
                continue

            if self.marketplace in item_marketplaces:
                path = PATHS.content_path / item.file_path_str
                try:
                    pack = PACK_MANAGER[find_pack_folder(path).name]
                    if not item.path:
                        raise RuntimeError(f'missing path for {item.id_=} {item.name=}')
                    relative_path = PACK_MANAGER.relative_to_packs(item.path)
                    result.append(
                        CollectionResult(
                            test=None,
                            pack=pack.pack_id,
                            reason=CollectionReason.CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE,
                            version_range=item.version_range or pack.version_range,
                            reason_description=f'{str(relative_path)}, ({self.marketplace.value})',
                            conf=self.conf,
                            id_set=self.id_set,
                        )
                    )

                except NotUnderPackException:
                    if path.name in SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK:
                        logger.info(f'skipping unsupported content item: {str(path)}, not under a pack')
                        continue
        return CollectionResult.union(tuple(result))


class XSIAMNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.MarketplaceV2)
        self.trigger_sanity_tests = True

    @property
    def sanity_tests(self) -> Optional[CollectionResult]:
        return CollectionResult(
            test='Sanity Test - Playbook with Unmockable Whois Integration',
            pack='Whois',
            reason=CollectionReason.SANITY_TESTS,
            reason_description='XSIAM Nightly sanity',
            version_range=None,
            conf=self.conf,
            id_set=self.id_set,
            is_sanity=True,
        )

    def _collect(self) -> Optional[CollectionResult]:
        return CollectionResult.union((
            self._id_set_tests_matching_marketplace_value(only_value=True),
            self._packs_matching_marketplace_value(only_value=True),
            self._packs_of_content_matching_marketplace_value(only_value=True)
        ))


class XSOARNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.XSOAR)

    def _collect(self) -> Optional[CollectionResult]:
        return CollectionResult.union((
            self._id_set_tests_matching_marketplace_value(only_value=False),
            self._packs_matching_marketplace_value(only_value=False),
        ))


def output(result: Optional[CollectionResult]):
    """
    writes to both log and files
    """
    tests = sorted(result.tests, key=lambda x: x.lower()) if result else ()
    packs = sorted(result.packs, key=lambda x: x.lower()) if result else ()
    machines = result.machines if result and result.machines else ()

    test_str = '\n'.join(tests)
    pack_str = '\n'.join(packs)
    machine_str = ', '.join(sorted(map(str, machines)))

    logger.info(f'collected {len(tests)} test playbooks:\n{test_str}')
    logger.info(f'collected {len(packs)} packs:\n{pack_str}')
    logger.info(f'collected {len(machines)} machines: {machine_str}')

    PATHS.output_tests_file.write_text(test_str)
    PATHS.output_packs_file.write_text(pack_str)
    PATHS.output_machines_file.write_text(json.dumps({str(machine): (machine in machines) for machine in Machine}))


if __name__ == '__main__':
    logger.info('TestCollector v20220831')
    sys.path.append(str(PATHS.content_path))
    parser = ArgumentParser()
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly')
    parser.add_argument('-p', '--changed_pack_path', type=str,
                        help='Path to a changed pack. Used for private content')
    parser.add_argument('-mp', '--marketplace', type=MarketplaceVersions, help='marketplace version',
                        default='xsoar')
    parser.add_argument('--service_account', help="Path to gcloud service account")
    args = parser.parse_args()
    args_string = '\n'.join(f'{k}={v}' for k, v in vars(args).items())
    logger.debug(f'parsed args:\n{args_string}')
    logger.debug('CONTRIB_BRANCH=' + os.getenv('CONTRIB_BRANCH', '<undefined>'))
    branch_name = PATHS.content_repo.active_branch.name

    marketplace = MarketplaceVersions(args.marketplace)
    nightly = args.nightly
    service_account = args.service_account

    collector: TestCollector

    if args.changed_pack_path:
        collector = BranchTestCollector('master', marketplace, service_account, args.changed_pack_path)

    elif os.environ.get("IFRA_ENV_TYPE") == 'Bucket-Upload':
        collector = UploadCollector(branch_name, marketplace, service_account)

    else:
        match (nightly, marketplace):
            case False, _:  # not nightly
                collector = BranchTestCollector(branch_name, marketplace, service_account)
            case True, MarketplaceVersions.XSOAR:
                collector = XSOARNightlyTestCollector()
            case True, MarketplaceVersions.MarketplaceV2:
                collector = XSIAMNightlyTestCollector()
            case _:
                raise ValueError(f"unexpected values of {marketplace=} and/or {nightly=}")

    collected = collector.collect()
    output(collected)  # logs and writes to output files
