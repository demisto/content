import json
import os
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from constants import (DEFAULT_MARKETPLACE_WHEN_MISSING,
                       DEFAULT_REPUTATION_TESTS, ONLY_INSTALL_PACK,
                       SKIPPED_CONTENT_ITEMS, XSOAR_SANITY_TEST_NAMES)
from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions
from demisto_sdk.commands.common.tools import (find_type_by_path, run_command,
                                               str2bool)
from exceptions import (DeprecatedPackException, EmptyMachineListException,
                        NonDictException, NoTestsConfiguredException,
                        NothingToCollectException, NotUnderPackException,
                        SkippedPackException, UnsupportedPackException, SkippedTestException, PrivateTestException,
                        InvalidTestException, TestMissingFromIdSetException)
from id_set import IdSet
from logger import logger
from test_conf import TestConf

from Tests.Marketplace.marketplace_services import get_last_commit_from_index
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import find_yml_content_type
from utils import (ContentItem, Machine, PackManager, VersionRange,
                   find_pack_folder)

PATHS = PathManager(Path(__file__).absolute().parents[3])
PACK_MANAGER = PackManager(PATHS)


class CollectionReason(str, Enum):
    ID_SET_MARKETPLACE_VERSION = 'id_set marketplace version'
    PACK_MARKETPLACE_VERSION_VALUE = 'marketplace version of pack'
    CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE = 'marketplace version of contained item'
    SANITY_TESTS = 'sanity tests by marketplace value'
    NON_CODE_FILE_CHANGED = 'non-code pack file changed'
    INTEGRATION_CHANGED = 'integration changed, collecting all conf.json tests using it'
    SCRIPT_PLAYBOOK_CHANGED = 'file changed, taking tests from `tests` section in script yml'
    SCRIPT_PLAYBOOK_CHANGED_NO_TESTS = 'file changed, but has `No Tests` configured, taking tests from id_set'
    TEST_PLAYBOOK_CHANGED = 'test playbook changed'
    MAPPER_CHANGED = 'mapper file changed, configured as incoming_mapper_id in test conf'
    CLASSIFIER_CHANGED = 'classifier file changed, configured as classifier_id in test conf'
    DEFAULT_REPUTATION_TESTS = 'default reputation tests'
    DUMMY_OBJECT_FOR_COMBINING = 'creating an empty object, to combine two CollectionResult objects'


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
        :param conf: a ConfJson object. It may be None only when reason==DUMMY_OBJECT_FOR_COMBINING.
        :param id_set: an IdSet object. It may be None only when reason==DUMMY_OBJECT_FOR_COMBINING.
        :param is_sanity: whether the test is a sanity test. Sanity tests do not have to be in the id_set.
        """
        self.tests: set[str] = set()
        self.packs: set[str] = set()
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: Optional[Iterable[Machine]] = None

        try:
            self._validate_args(pack, test, reason, conf, id_set, is_sanity)  # raises if invalid

        except (InvalidTestException, SkippedPackException, DeprecatedPackException, UnsupportedPackException) as e:
            logger.warning(str(e))
            return

        if test:
            self.tests = {test}
            logger.info(f'collected {test=}, {reason} ({reason_description})')

        if pack:
            self.packs = {pack}
            logger.info(f'collected {pack=}, {reason} ({reason_description})')

    @staticmethod
    def _validate_args(pack: Optional[str], test: Optional[str], reason: CollectionReason, conf: Optional[TestConf],
                       id_set: Optional[IdSet], is_sanity: bool):
        """
        Validates the arguments of the constructor.
        """
        if reason != CollectionReason.DUMMY_OBJECT_FOR_COMBINING:
            for (arg, arg_name) in ((conf, 'conf.json'), (id_set, 'id_set')):
                if not arg:
                    # may be None only when reason==DUMMY_OBJECT_FOR_COMBINING
                    raise ValueError(f'no {arg_name} was provided')

            if not any((pack, test)):
                # should not be none unless reason==DUMMY_OBJECT_FOR_COMBINING
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
                    raise SkippedTestException(test, 'skipped in .pack_ignore')

            if skip_reason := conf.skipped_tests.get(test):  # type:ignore[union-attr]
                raise SkippedTestException(test, skip_reason)

            if test in conf.private_tests:  # type:ignore[union-attr]
                raise PrivateTestException(test)

        if pack:
            PACK_MANAGER.validate_pack(pack)

    @staticmethod
    def __empty_result() -> 'CollectionResult':
        # used for combining two CollectionResult objects
        return CollectionResult(
            test=None, pack=None, reason=CollectionReason.DUMMY_OBJECT_FOR_COMBINING, version_range=None,
            reason_description='', conf=None, id_set=None
        )

    def __add__(self, other: 'CollectionResult') -> 'CollectionResult':
        # initial object just to add others to
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
            CollectionResult(test=test, pack=None, reason=CollectionReason.SANITY_TESTS,
                             version_range=None, reason_description=str(self.marketplace.value),
                             conf=self.conf, id_set=self.id_set, is_sanity=True)
            for test in self._sanity_test_names)
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

    def collect(self, run_nightly: bool) -> Optional[CollectionResult]:
        result: Optional[CollectionResult] = self._collect()

        if not result:
            if self.trigger_sanity_tests:
                result = self.sanity_tests
                logger.warning('Nothing was collected, but sanity-test-triggering files were changed, '
                               'returning sanity tests')
            else:
                logger.warning('Nothing was collected, and no sanity-test-triggering files were changed')
                return None

        self._validate_tests_in_id_set(result.tests)

        if (suitable_machines := Machine.get_suitable_machines(result.version_range, run_nightly)) is None:
            raise EmptyMachineListException()
        result.machines = suitable_machines

        return result

    def _validate_tests_in_id_set(self, tests: Iterable[str]):
        if not_found := (
                (set(tests) - set(self._sanity_test_names)).difference(self.id_set.id_to_test_playbook.keys())
        ):
            not_found_string = ', '.join(sorted(not_found))
            logger.warning(f'{len(not_found)} tests were not found in id-set: \n{not_found_string}')

    def _collect_pack(self, pack_name: str, reason: CollectionReason, reason_description: str) -> CollectionResult:
        return CollectionResult(
            test=None,
            pack=pack_name,
            reason=reason,
            version_range=PACK_MANAGER[pack_name].version_range,
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
                result.append(self._collect_single(PATHS.content_path / path))
            except NothingToCollectException as e:
                logger.warning(e.message)

        return CollectionResult.union(tuple(result))

    def _collect_yml(self, content_item_path: Path) -> CollectionResult:
        """
        collecting a yaml-based content item (including py-based, whose names match a yaml based one)
        """
        result: Optional[CollectionResult] = None
        yml_path = content_item_path.with_suffix('.yml') if content_item_path.suffix != '.yml' else content_item_path
        try:
            yml = ContentItem(yml_path)
            if not yml.id_:
                raise ValueError(f'id field of {yml_path} cannot be empty')
        except FileNotFoundError:
            raise FileNotFoundError(
                f'could not find yml matching {PackManager.relative_to_packs(content_item_path)}'
            )
        if yml.id_ in self.conf.skipped_integrations:
            raise NothingToCollectException(yml.path, 'integration is skipped')
        relative_yml_path = PackManager.relative_to_packs(yml_path)
        tests: tuple[str, ...]

        match actual_content_type := find_yml_content_type(yml_path):
            case None:
                path_description = f'{yml_path} (original item {content_item_path}' \
                    if content_item_path != yml_path else yml_path
                raise ValueError(f'could not detect type for {path_description}')

            case FileType.TEST_PLAYBOOK:
                if yml.id_ in self.conf.test_ids:
                    tests = yml.id_,
                    reason = CollectionReason.TEST_PLAYBOOK_CHANGED
                else:
                    raise ValueError(f'test playbook with id {yml.id_} is missing from conf.test_ids')

            case FileType.INTEGRATION:
                tests = tuple(self.conf.integrations_to_tests[yml.id_])
                reason = CollectionReason.INTEGRATION_CHANGED

            case FileType.SCRIPT | FileType.PLAYBOOK:
                try:
                    tests = tuple(yml.tests)  # raises NoTestsConfiguredException if 'no tests' in the tests field
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED

                except NoTestsConfiguredException:
                    # collecting all tests that implement this script/playbook
                    source = {
                        FileType.SCRIPT: self.id_set.implemented_scripts_to_tests,
                        FileType.PLAYBOOK: self.id_set.implemented_playbooks_to_tests
                    }[actual_content_type]
                    tests = tuple(test.name for test in source.get(yml.id_, ()))
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED_NO_TESTS

                    if not tests:  # no tests were found in yml nor in id_set
                        logger.warning(f'{actual_content_type.value} {relative_yml_path} '
                                       f'has `No Tests` configured, and no tests in id_set')
            case _:
                raise RuntimeError(f'Unexpected content type {actual_content_type.value} for {content_item_path}'
                                   f'(expected `Integrations`, `Scripts` or `Playbooks`)')
        # creating an object for each, as CollectedTests require #packs==#tests
        if tests:
            result = CollectionResult.union(tuple(
                CollectionResult(
                    test=test,
                    pack=yml.pack_id,
                    reason=reason,
                    version_range=yml.version_range,
                    reason_description=f'{yml.id_=} ({relative_yml_path})',
                    conf=self.conf,
                    id_set=self.id_set
                ) for test in tests))
        if result:
            return result
        else:
            raise NothingToCollectException(yml.path, 'no tests were found')

    def _collect_single(self, path: Path) -> Optional[CollectionResult]:
        if not path.exists():
            raise FileNotFoundError(path)

        file_type = find_type_by_path(path)
        try:
            reason_description = relative_path = PackManager.relative_to_packs(path)
        except NotUnderPackException:
            # infrastructure files are not collected

            if path in PATHS.files_to_ignore:
                raise NothingToCollectException(path, 'not under a pack (ignored, not triggering sanity tests')

            if path in PATHS.files_triggering_sanity_tests:
                self.trigger_sanity_tests = True
                raise NothingToCollectException(path, 'not under a pack (triggering sanity tests)')
            raise

        try:
            content_item = ContentItem(path)
        except NonDictException:
            # for `.py`, `.md`, etc., that are not dictionary-based
            # Suitable logic follows, see collect_yml
            content_item = None

        if file_type in {FileType.PACK_IGNORE, FileType.SECRET_IGNORE, FileType.DOC_FILE, FileType.README}:
            raise NothingToCollectException(path, f'ignored type {file_type}')

        elif file_type in ONLY_INSTALL_PACK:
            # install pack without collecting tests.
            return self._collect_pack(
                pack_name=find_pack_folder(path).name,
                reason=CollectionReason.NON_CODE_FILE_CHANGED,
                reason_description=reason_description,
            )

        elif file_type in {FileType.PYTHON_FILE, FileType.POWERSHELL_FILE, FileType.JAVASCRIPT_FILE}:
            if path.name.lower().endswith(('_test.py', 'tests.ps1')):
                raise NothingToCollectException(path, 'unit tests changed')
            return self._collect_yml(path)

        elif file_type == FileType.REPUTATION:
            tests = DEFAULT_REPUTATION_TESTS
            reason = CollectionReason.DEFAULT_REPUTATION_TESTS

        elif file_type in {FileType.MAPPER, FileType.CLASSIFIER}:
            source, reason = {
                FileType.MAPPER: (self.conf.incoming_mapper_to_test, CollectionReason.MAPPER_CHANGED),
                FileType.CLASSIFIER: (self.conf.classifier_to_test, CollectionReason.CLASSIFIER_CHANGED),
            }[file_type]
            if not (tests := source.get(content_item)):  # type: ignore[call-overload]
                reason = CollectionReason.NON_CODE_FILE_CHANGED
                reason_description = f'no specific tests for {relative_path} were found'
        elif path.suffix == '.yml':
            return self._collect_yml(path)  # checks for containing folder (content item type)

        else:
            raise ValueError(f'Unexpected {file_type=} for {relative_path}')

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
        contrib_diff = None  # overridden on contribution branches, added to the git diff.

        current_commit = self.branch_name
        previous_commit = 'origin/master'

        logger.info(f'Getting changed files for {self.branch_name=}')

        if os.getenv('IFRA_ENV_TYPE') == 'Bucket-Upload':
            logger.info('bucket upload: getting last commit from index')
            previous_commit = get_last_commit_from_index(self.service_account)
            current_commit = 'origin/master' if self.branch_name == 'master' else self.branch_name

        elif self.branch_name == 'master':
            previous_commit, current_commit = run_command("git log -n 2 --pretty='%H'").replace("'", "").split()

        elif os.getenv('CONTRIB_BRANCH'):
            contrib_diff = run_command('git status -uall --porcelain -- Packs').replace('??', 'A')
            logger.info(f'contribution branch, {contrib_diff=}')

        diff: str = run_command(f'git diff --name-status {current_commit}...{previous_commit}')
        logger.debug(f'Changed files: {diff}')

        if contrib_diff:
            logger.debug('adding contrib_diff to diff')
            diff = f'{diff}\n{contrib_diff}'

        # diff is formatted as `M  foo.json\n A  bar.py\n ...`, turning it into ('foo.json', 'bar.py', ...).
        return tuple((value.split()[1] for value in filter(None, diff.split('\n'))))


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
                    reason_description=f'({self.marketplace.value})',
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
        logger.info(
            f'collecting pack_name_to_pack_metadata by their marketplace field, searching for {self.marketplace.value}'
            f'{postfix}')
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
                                   version_range=None, reason_description=f'({self.marketplace.value})',
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
                    if path.name in SKIPPED_CONTENT_ITEMS:
                        logger.info(f'skipping unsupported content item: {str(path)}, not under a pack')
                        continue
        return CollectionResult.union(tuple(result))


class XSIAMNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.MarketplaceV2)

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
    if not result:
        raise RuntimeError('Nothing was collected, not even sanity tests')

    machines = tuple(result.machines) if result.machines else ()

    test_str = '\n'.join(sorted(result.tests, key=lambda x: x.lower()))
    pack_str = '\n'.join(sorted(result.packs, key=lambda x: x.lower()))
    machine_str = ','.join(str(m) for m in machines)

    logger.info(f'collected {len(result.tests)} tests:\n{test_str}')
    logger.info(f'collected {len(result.packs)} packs:\n{pack_str}')
    logger.info(f'collected {len(machines)} machines: {machine_str}')

    PATHS.output_tests_file.write_text(test_str)
    PATHS.output_packs_file.write_text(pack_str)
    PATHS.output_machines_file.write_text(json.dumps({str(machine): (machine in machines) for machine in Machine}))


if __name__ == '__main__':
    sys.path.append(str(PATHS.content_path))
    parser = ArgumentParser()
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly')
    parser.add_argument('-p', '--changed_pack_path', type=str,
                        help='Path to a changed pack. Used for private content')
    parser.add_argument('-mp', '--marketplace', type=MarketplaceVersions, help='marketplace version',
                        default='xsoar')
    parser.add_argument('--service_account', help="Path to gcloud service account")
    options = parser.parse_args()
    marketplace = MarketplaceVersions(options.marketplace)

    collector: TestCollector

    if options.changed_pack_path:
        collector = BranchTestCollector('master', marketplace, options.service_account, options.changed_pack_path)
    else:
        match (options.nightly, marketplace):
            case False, _:  # not nightly
                collector = BranchTestCollector('master', marketplace, options.service_account)
            case True, MarketplaceVersions.XSOAR:
                collector = XSOARNightlyTestCollector()
            case True, MarketplaceVersions.MarketplaceV2:
                collector = XSIAMNightlyTestCollector()
            case _:
                raise ValueError(f"unexpected values of (either) {marketplace=}, {options.nightly=}")

    collected = collector.collect(run_nightly=options.nightly)
    output(collected)  # logs and writes to output files
