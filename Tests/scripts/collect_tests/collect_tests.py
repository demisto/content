import os
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from enum import Enum
from functools import reduce
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
                        SkippedPackException, UnsupportedPackException)
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


class CollectionReason(Enum):
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
    COMBINING_COLLECTED_TESTS = 'combining CollectedTest object'  # NOTE: using this reason changes CollectedTests init!


class CollectedTests:
    def __init__(
            self,
            tests: Optional[tuple[Optional[str], ...]],
            packs: tuple[Optional[str], ...],
            reason: CollectionReason,
            version_range: Optional[VersionRange],
            reason_description: str,
    ):

        self.tests: set[str] = set()  # only updated on init
        self.packs: set[str] = set()  # only updated on init
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: Optional[Iterable[Machine]] = None

        if reason == CollectionReason.COMBINING_COLLECTED_TESTS:
            # when combining two existing CollectedTests objects, there is no need for logs or logic.
            self.tests = set(tests)
            self.packs = set(packs)
            return

        if tests and packs:
            if len(tests) != len(packs):
                raise ValueError(f'when both are not empty, {len(tests)=} must be equal to {len(packs)=}')

            tests = tuple(tests)
            packs = tuple(packs)

        elif tests and not packs:
            packs = (None,) * len(tests)  # so accessors get a None
        elif packs and not tests:
            tests = (None,) * len(packs)  # so accessors get a None

        if tests:
            for i in range(len(tests)):
                self._add_single(tests[i], packs[i], reason, reason_description)

    def __add__(self, other: 'CollectedTests') -> 'CollectedTests':
        return CollectedTests(
            tests=tuple(set(self.tests).union(other.tests)),
            packs=tuple(set(self.packs).union(other.packs)),
            version_range=self.version_range | other.version_range if self.version_range else other.version_range,
            reason=CollectionReason.COMBINING_COLLECTED_TESTS,
            reason_description='',
        )

    @staticmethod
    def union(collected_tests: Optional[tuple[Optional['CollectedTests'], ...]]) -> Optional['CollectedTests']:
        collected_tests = tuple(filter(None, collected_tests or (None,)))

        if not collected_tests:
            logger.warning('no tests to union')
            return None

        return reduce(lambda a, b: a + b, collected_tests)

    def _add_single(
            self,
            test: Optional[str],
            pack: Optional[str],
            reason: CollectionReason,
            description: str,
    ):
        """ Should only be called from add_multiple """
        if not any((test, pack)):
            raise RuntimeError('both test and pack provided are empty')

        if test:
            self.tests.add(test)
            if reason != CollectionReason.COMBINING_COLLECTED_TESTS:  # to avoid excessive logs
                logger.info(f'collected {test:}, {reason.value} {description}')

        if pack:
            try:
                PACK_MANAGER.validate_pack(pack)
            except (SkippedPackException, DeprecatedPackException, UnsupportedPackException) as e:
                logger.info(e.message)

            self.packs.add(pack)
            if reason != CollectionReason.COMBINING_COLLECTED_TESTS:  # to avoid excessive logs
                logger.info(f'collected {pack=}, {reason.value} {description}')

    def __repr__(self):
        return f'{len(self.packs)} packs, {len(self.tests)} tests, {self.version_range=}'

    def __bool__(self):
        return bool(self.tests or self.packs)


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions):
        self.marketplace = marketplace
        self.id_set = IdSet(marketplace, PATHS.id_set_path)
        self.conf = TestConf(PATHS.conf_path)

    @property
    def sanity_tests(self) -> CollectedTests:
        match self.marketplace:
            case MarketplaceVersions.MarketplaceV2:
                test_names = self.conf['test_marketplacev2']
            case MarketplaceVersions.XSOAR:
                test_names = XSOAR_SANITY_TEST_NAMES
            case _:
                raise RuntimeError(f'unexpected marketplace value {self.marketplace.value}')

        return CollectedTests(
            tests=test_names,
            packs=(),
            reason=CollectionReason.SANITY_TESTS,
            version_range=None,
            reason_description=str(self.marketplace.value),
        )

    @abstractmethod
    def _collect(self) -> Optional[CollectedTests]:
        """
        Collects all relevant tests into self.collected.
        Every inheriting class implements its own methodology here.
        :return: A CollectedTests object with only the pack_name_to_pack_metadata to install and tests to run,
                with machines=None.
        """
        pass

    def collect(self, run_nightly: bool) -> Optional[CollectedTests]:
        collected: Optional[CollectedTests] = self._collect()

        if not collected:
            logger.warning('No tests were collected, returning sanity tests only')
            collected = self.sanity_tests

        collected.machines = Machine.get_suitable_machines(collected.version_range, run_nightly)

        if collected and collected.machines is None:
            raise EmptyMachineListException()

        #  todo check TPBs that use optional dependencies, e.g EDL performance test
        self._validate_tests_in_id_set(collected.tests)
        return collected

    def _validate_tests_in_id_set(self, tests: Iterable[str]):
        if not_found := ((set(tests) - self.sanity_tests.tests).difference(self.id_set.id_to_test_playbook.keys())):
            not_found_string = ', '.join(sorted(not_found))
            logger.warning(f'{len(not_found)} tests were not found in id-set: \n{not_found_string}')

    @staticmethod
    def _collect_pack(pack_name: str, reason: CollectionReason, reason_description: str) -> CollectedTests:
        return CollectedTests(
            tests=None,
            packs=(pack_name,),
            reason=reason,
            version_range=PACK_MANAGER[pack_name].version_range,
            reason_description=reason_description,
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

    def _collect(self) -> Optional[CollectedTests]:
        collected = []
        paths = self._get_private_pack_files() if self.private_pack_path else self._get_changed_files()
        for path in paths:
            try:
                collected.append(self._collect_single(PATHS.content_path / path))
            except NothingToCollectException as e:
                logger.warning(e.message)

        return CollectedTests.union(tuple(collected))

    def _collect_yml(self, content_item_path: Path) -> CollectedTests:
        """
        collecting a yaml-based content item (including py-based, whose names match a yaml based one)
        """
        yml_path = content_item_path.with_suffix('.yml') if content_item_path.suffix != '.yml' else content_item_path
        try:
            yml = ContentItem(yml_path)
        except FileNotFoundError:
            raise FileNotFoundError(
                f'could not find yml matching {PackManager.relative_to_packs(content_item_path)}'
            )
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
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED_NO_TESTS

                    match actual_content_type:
                        case FileType.SCRIPT:
                            tests = tuple(
                                test.name for test in self.id_set.implemented_scripts_to_tests.get(yml.id_)
                            )

                        case FileType.PLAYBOOK:
                            tests = tuple(
                                test.name for test in self.id_set.implemented_playbooks_to_tests.get(yml.id_)
                            )
                        case _:
                            raise RuntimeError(f'unexpected content type folder {actual_content_type}')

                    if not tests:  # no tests were found in yml nor in id_set
                        logger.warning(f'{actual_content_type.value} {relative_yml_path} '
                                       f'has `No Tests` configured, and no tests in id_set')
            case _:
                raise RuntimeError(f'Unexpected content type {actual_content_type.value} for {content_item_path}'
                                   f'(expected `Integrations`, `Scripts` or `Playbooks`)')
        # creating an object for each, as CollectedTests require #packs==#tests
        if tests:
            collected = CollectedTests.union(
                tuple(
                    CollectedTests(
                        tests=(test,),
                        packs=yml.pack_id_tuple,
                        reason=reason,
                        version_range=yml.version_range,
                        reason_description=f'{yml.id_=} ({relative_yml_path})'
                    )
                    for test in tests
                ))
            if collected:
                return collected
        else:
            raise NothingToCollectException(yml.path, 'no tests were found')

    def _collect_single(self, path: Path) -> CollectedTests:
        if not path.exists():
            raise FileNotFoundError(path)

        file_type = find_type_by_path(path)
        try:
            reason_description = relative_path = PackManager.relative_to_packs(path)
            content_item = ContentItem(path)
        except NonDictException:  # for `.py`, `.md`, etc., that are not dictionary-based. Suitable logic follows.
            content_item = None
            relative_path = reason_description = str(path)
        except NotUnderPackException:
            if path in PATHS.excluded_files:
                raise NothingToCollectException(path, 'not under a pack')  # infrastructure files that are ignored
            raise

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
            if path.name.lower().endswith(('_test.py', 'tests.ps1')):  # todo make sure we should skip them
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

            if not (tests := source.get(content_item.id_) if content_item else ''):
                reason = CollectionReason.NON_CODE_FILE_CHANGED
                reason_description = f'no specific tests for {relative_path} were found'
        elif path.suffix == '.yml':
            return self._collect_yml(path)  # checks for containing folder (content item type)

        else:
            raise ValueError(f'Unexpected {file_type=} for {relative_path}')

        if not content_item:
            raise RuntimeError(f'failed collecting {path} for an unknown reason')

        return CollectedTests(
            tests=tests,
            packs=content_item.pack_id_tuple,
            reason=reason,
            version_range=content_item.version_range,
            reason_description=reason_description,
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

        # diff is formatted as `M  foo.json\n A  bar.py`, turning it into ('foo.json', 'bar.py').
        return tuple((value.split()[1] for value in filter(None, diff.split('\n'))))


class NightlyTestCollector(TestCollector, ABC):
    def _id_set_tests_matching_marketplace_value(self, only_value: bool) -> Optional[CollectedTests]:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all tests whose marketplace field includes the collector's marketplace value
                    (or is equal to it, if `only_value` is used).
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(f'collecting test playbooks by their marketplace field, searching for {self.marketplace.value}'
                    f'{postfix}')

        collected = []

        for playbook in self.id_set.test_playbooks:
            playbook_marketplaces = playbook.marketplaces or default

            if only_value and len(playbook_marketplaces) != 1:
                continue

            if self.marketplace in playbook_marketplaces:
                collected.append(CollectedTests(tests=(playbook.name,), packs=playbook.pack_name_tuple,
                                                reason=CollectionReason.ID_SET_MARKETPLACE_VERSION,
                                                reason_description=f'({self.marketplace.value})',
                                                version_range=VersionRange(playbook.from_version, playbook.to_version)))

        if not collected:
            logger.warning(f'no tests matching marketplace {self.marketplace.value} ({only_value=}) were found')
            return None

        return CollectedTests.union(tuple(collected))

    def _packs_matching_marketplace_value(self, only_value: bool) -> Optional[CollectedTests]:
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

        return CollectedTests(tests=None, packs=tuple(packs), reason=CollectionReason.PACK_MARKETPLACE_VERSION_VALUE,
                              version_range=None, reason_description=f'({self.marketplace.value})')

    def _packs_of_content_matching_marketplace_value(self, only_value: bool) -> Optional[CollectedTests]:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all packs whose under which a content item marketplace field contains self.marketplaces
                (or is equal to, if only_value is True).
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(
            f'collecting content items by their marketplace field, searching for {self.marketplace.value} {postfix}')

        collected = []

        for item in self.id_set.artifact_iterator:
            item_marketplaces = item.marketplaces or default

            if only_value and len(item_marketplaces) != 1:
                continue

            if self.marketplace in item_marketplaces:
                path = PATHS.content_path / item.file_path
                try:
                    pack = PACK_MANAGER[find_pack_folder(path).name]
                    relative_path = PACK_MANAGER.relative_to_packs(item.file_path)
                    collected.append(
                        CollectedTests(
                            tests=None,
                            packs=pack.pack_id_tuple,
                            reason=CollectionReason.CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE,
                            version_range=item.version_range or pack.version_range,
                            reason_description=f'{str(relative_path)}, ({self.marketplace.value})'
                        )
                    )

                except NotUnderPackException:
                    if path.name in SKIPPED_CONTENT_ITEMS:
                        logger.info(f'skipping unsupported content item: {str(path)}, not under a pack')
                        continue
        return CollectedTests.union(tuple(collected))


class XSIAMNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.MarketplaceV2)

    def _collect(self) -> Optional[CollectedTests]:
        return CollectedTests.union((
            self._id_set_tests_matching_marketplace_value(only_value=True),  # todo both ?
            self._packs_matching_marketplace_value(only_value=True),
            self._packs_of_content_matching_marketplace_value(only_value=True)
        ))


class XSOARNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.XSOAR)

    def _collect(self) -> Optional[CollectedTests]:
        return CollectedTests.union((
            self._id_set_tests_matching_marketplace_value(only_value=False),
            self._packs_matching_marketplace_value(only_value=False),
        ))


class UploadCollector(BranchTestCollector):
    def _collect(self) -> Optional[CollectedTests]:
        # same as BranchTestCollector, but without tests.
        if collected := super()._collect():
            logger.info('UploadCollector drops collected tests, as they are not required')
            collected.tests = set()
        return collected


if __name__ == '__main__':
    sys.path.append(str(PATHS.content_path))
    parser = ArgumentParser()
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly')
    parser.add_argument('-p', '--changed_pack_path', type=str, help='Path to a changed pack. Used for private content')
    parser.add_argument('-mp', '--marketplace', type=MarketplaceVersions, help='marketplace version', default='xsoar')
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
    if not collected:
        logger.error('done collecting, no tests or packs were collected.')

    else:
        logger.info(f'done collecting, got {len(collected.tests)} tests and {len(collected.packs)} packs')

        logger.info(f'writing output to {str(PATHS.output_tests_file)}, {str(PATHS.output_packs_file)}')
        PATHS.output_tests_file.write_text('\n'.join(collected.tests))
        PATHS.output_packs_file.write_text('\n'.join(collected.packs))
        PATHS.output_machines_file.write_text('\n'.join(map(str, collected.machines)))
