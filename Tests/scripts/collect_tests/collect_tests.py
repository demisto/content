import functools
import sys
from abc import ABC, abstractmethod
from enum import Enum
from logging import DEBUG, getLogger
from pathlib import Path
from typing import Iterable, Optional

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions
from demisto_sdk.commands.common.tools import find_type_by_path
from git import Repo

from Tests.scripts.collect_tests.constants import (
    CONTENT_PATH, DEFAULT_MARKETPLACE_WHEN_MISSING, DEFAULT_REPUTATION_TESTS,
    XSOAR_SANITY_TEST_NAMES)
from Tests.scripts.collect_tests.exceptions import (DeprecatedPackException,
                                                    EmptyMachineListException,
                                                    NonDictException,
                                                    NoTestsConfiguredException,
                                                    NothingToCollectException,
                                                    NotUnderPackException,
                                                    SkippedPackException)
from Tests.scripts.collect_tests.id_set import IdSet
from Tests.scripts.collect_tests.test_conf import TestConf
from Tests.scripts.collect_tests.utils import (ContentItem, Machine,
                                               PackManager, VersionRange,
                                               find_pack)

logger = getLogger('test_collection')
logger.level = DEBUG

IGNORED_INFRASTRUCTURE_FILES = {  # todo check the list
    '.gitignore',
    '.lgtm.yml',
    '.nvmrc',
    '.pylintrc',
    '__init__.py',
    'CODE_OF_CONDUCT.md',
    'content-descriptor.json',
    'CONTRIBUTING.md',
    'dev-requirements-py2.txt',
    'dev-requirements-py3.txt',
    'LICENSE',
    'package.json',
    'package-lock.json',
    'Pipfile',
    'Pipfile.lock',
    'tox.ini',
    'xsoar_content_logo.png',
}
IS_GITLAB = False  # todo replace
PACK_MANAGER = PackManager()
COMMIT = 'ds-test-collection'  # todo use arg


class CollectionReason(Enum):
    # todo remove unused
    MARKETPLACE_VERSION_BY_VALUE = 'value of the test `marketplace` field'
    SANITY_TESTS = 'sanity tests by marketplace value'
    PACK_MATCHES_INTEGRATION = 'pack added as the integration is used in a playbook'
    PACK_MATCHES_TEST = 'pack added as the test playbook was collected earlier'
    NIGHTLY_ALL_TESTS__ID_SET = 'collecting all id_set test playbooks for nightly'
    NIGHTLY_ALL_TESTS__TEST_CONF = 'collecting all test_conf tests for nightly'
    ALL_ID_SET_PACKS = 'collecting all id_set pack_name_to_pack_metadata'
    NON_CODE_FILE_CHANGED = 'non-code pack file changed'
    INTEGRATION_CHANGED = 'integration changed, collecting all conf.json tests using it'
    SCRIPT_PLAYBOOK_CHANGED = 'file changed, taking tests from `tests` section in script yml'
    SCRIPT_PLAYBOOK_CHANGED_NO_TESTS = 'file changed, but has `No Tests` configured, taking tests from id_set'
    TEST_PLAYBOOK_CHANGED = 'test playbook changed'
    MAPPER_CHANGED = 'mapper file changed, configured as incoming_mapper_id in test conf'
    CLASSIFIER_CHANGED = 'classifier file changed, configured as classifier_id in test conf'
    EMPTY_UNION = 'no tests to union'
    DEFAULT_REPUTATION_TESTS = 'default reputation tests'


class CollectedTests:
    def __init__(
            self,
            tests: Optional[tuple[str] | list[str]],
            packs: Optional[tuple[str] | list[str]],
            reason: CollectionReason,
            version_range: Optional[VersionRange],
            reason_description: Optional[str] = None,
    ):

        self.tests = set()  # only updated on init
        self.packs = set()  # only updated on init
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: Optional[Iterable[Machine]] = None

        if tests and packs and len(tests) != len(packs):
            raise ValueError(f'when both are not empty, {len(tests)=} must be equal to {len(packs)=}')
        elif tests:
            packs = (None,) * len(packs)  # so accessors get a None
        elif packs:
            tests = (None,) * len(packs)  # so accessors get a None

        for i in range(len(tests)):
            self._add_single(tests[i], packs[i], reason, reason_description)

    @property
    def not_empty(self):
        return any((self.tests, self.packs))

    def __or__(self, other: 'CollectedTests') -> 'CollectedTests':
        self.tests.update(other.tests)
        self.packs.update(other.packs)
        self.version_range = self.version_range | other.version_range if self.version_range else other.version_range
        return self

    @classmethod
    def union(cls, collected_tests: Iterable['CollectedTests']) -> Optional['CollectedTests']:
        if not collected_tests:
            logger.warning('no tests to union')
            return None
        return functools.reduce(lambda a, b: a | b, collected_tests)

    def _add_single(
            self,
            test: Optional[str],
            pack: Optional[str],
            reason: CollectionReason,
            description: str,
    ):
        """ Should only be called from add_multiple """  # todo really?
        if not any((test, pack)):
            raise RuntimeError('both test and pack provided are empty')

        if test:
            self.tests.add(test)
            logger.info(f'collected {test=}, {reason.value} {description}')

        if pack:
            try:
                PACK_MANAGER.validate_pack(pack)
                self.packs.add(pack)
                logger.info(f'collected {pack=}, {reason.value} {description}')
            except (SkippedPackException, DeprecatedPackException) as e:
                logger.info(str(e))

    def __repr__(self):
        return f'{len(self.packs)} packs, {len(self.tests)} tests, {self.version_range=}'


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions):
        self.marketplace = marketplace
        self.id_set = IdSet(marketplace)
        self.conf = TestConf()
        # todo FAILED_

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
            packs=None,
            reason=CollectionReason.SANITY_TESTS,
            version_range=None,
            reason_description=self.marketplace.value,
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

    def collect(self, run_nightly: bool, run_master: bool) -> Optional[CollectedTests]:
        collected: CollectedTests = self._collect()
        if not collected:
            return

        collected.machines = Machine.get_suitable_machines(collected.version_range, run_nightly, run_master)

        if collected.machines is None and not collected.not_empty:  # todo reconsider
            raise EmptyMachineListException()

        # collected |= self._add_packs_used(collected.tests)  # todo should we use it?
        return collected

    def _add_packs_used(self, tests: set[str]) -> list[CollectedTests]:  # todo is used?
        return self._add_packs_from_tested_integrations(tests) + self._add_packs_from_test_playbooks(tests)

    def _add_packs_from_tested_integrations(self, tests: set[str]) -> list[CollectedTests]:
        # only called in _add_packs_used
        # todo is it used in the new version?
        logger.info(f'searching for integrations used in test playbooks, '
                    f'to make sure the integration pack_name_to_pack_metadata are installed')
        collected = []

        for test in tests:
            for integration in self.conf.tests_to_integrations.get(test, ()):
                if pack := self.id_set.integration_to_pack.get(integration):  # todo what if not?
                    collected.append(self._collect_pack(pack, CollectionReason.PACK_MATCHES_INTEGRATION,
                                                        reason_description=f'{integration=}'))
        return collected

    @staticmethod
    def _collect_pack(name: str, reason: CollectionReason, reason_description: str) -> CollectedTests:
        # todo decide whether we also want to collect all tests related to the pack (Dean)
        return CollectedTests(
            tests=None,
            packs=(name,),
            reason=reason,
            version_range=PACK_MANAGER[name].version_range,
            reason_description=reason_description,
        )

    def _add_packs_from_test_playbooks(self, tests: set[str]) -> list[CollectedTests]:  # only called in _add_packs_used
        logger.info(f'searching for pack_name_to_pack_metadata under which test playbooks are saved,'
                    f' to make sure they are installed')
        collected = []

        for test in tests:
            if pack := self.id_set.test_playbooks_to_pack[test]:  # todo is okay to fail when tpb is not in id-set?
                collected.append(
                    self._collect_pack(pack, reason=CollectionReason.PACK_MATCHES_TEST, reason_description='')
                )
        return collected


class BranchTestCollector(TestCollector):
    def __init__(self, branch_name: str, marketplace: MarketplaceVersions):
        super().__init__(marketplace)
        self.branch_name = branch_name
        self.repo = Repo(CONTENT_PATH)
        self.repo.git.checkout(self.branch_name)

    def _collect(self) -> Optional[CollectedTests]:
        collected = []
        for path in self._get_changed_files():
            try:
                collected.append(self._collect_single(CONTENT_PATH / Path(path)))
            except NothingToCollectException as e:
                logger.warning(e.message)

        if not collected:
            logger.warning('No tests were collected, returning sanity tests only')
            return self.sanity_tests

        return CollectedTests.union(collected)

    def _collect_yml(self, content_item: Path) -> CollectedTests:
        yml = ContentItem(content_item.with_suffix('.yml'))
        # todo handle yml-free python files
        if not yml.path.exists():
            raise FileNotFoundError(f'could not find yml matching {PackManager.relative_to_packs(content_item)}')

        match containing_folder := yml.path.parents[1].name:
            case 'Integrations':
                tests = self.conf.integrations_to_tests[yml.id_]
                reason = CollectionReason.INTEGRATION_CHANGED

            case 'Scripts' | 'Playbooks':
                try:
                    tests = yml.tests  # raises if 'no tests' in the tests field
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED

                except NoTestsConfiguredException:
                    # collecting all tests that implement this script/playbook
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED_NO_TESTS

                    match containing_folder:
                        case 'Scripts':
                            tests = self.id_set.implemented_scripts_to_tests.get(yml.id_)
                        case 'Playbooks':
                            tests = self.id_set.implemented_playbooks_to_tests.get(yml.id_)
                        case _:
                            raise RuntimeError(f'unexpected content type folder {containing_folder}')

                    if not tests:
                        original_type: str = find_type_by_path(content_item).value
                        relative_path = str(PackManager.relative_to_packs(yml.path))
                        logger.warning(f'{original_type} {relative_path} '
                                       f'has `No Tests` configured, and no tests in id_set')
            case _:
                raise RuntimeError(f'Unexpected content type original_file_path {containing_folder} '
                                   f'(expected `Integrations`, `Scripts`, etc)')
        relative_path = PackManager.relative_to_packs(content_item)
        # creating an object for each, as CollectedTests require #packs==#tests
        return CollectedTests.union([CollectedTests(tests=(test,), packs=yml.pack_tuple, reason=reason,
                                                    version_range=yml.version_range,
                                                    reason_description=f'{yml.id_=} ({relative_path})')
                                     for test in tests])

    def _collect_single(self, path) -> CollectedTests:
        file_type = find_type_by_path(path)
        relative_path = PackManager.relative_to_packs(path)
        description_suffix = f'({file_type.value})' if file_type else ''
        reason_description = f'{relative_path} {description_suffix}'

        try:
            content_item = ContentItem(path)
        except NonDictException:  # for `.py`, `.md`, etc., that are not dictionary-based. Suitable logic follows.
            content_item = None
        except NotUnderPackException:
            if path.parent == CONTENT_PATH and path.name in IGNORED_INFRASTRUCTURE_FILES:
                raise NothingToCollectException(path, 'not under a pack')  # infrastructure files that are ignored
            raise  # files that are either supposed to be under a pack OR should not be ignored. # todo wat

        match file_type:
            case FileType.PACK_IGNORE | FileType.SECRET_IGNORE | FileType.DOC_FILE | FileType.README:
                raise NothingToCollectException(path, f'ignored type ({file_type}')

            case FileType.RELEASE_NOTES_CONFIG | FileType.RELEASE_NOTES | FileType.IMAGE | \
                 FileType.DESCRIPTION | FileType.METADATA | \
                 FileType.RELEASE_NOTES_CONFIG | FileType.IMAGE | FileType.DESCRIPTION | FileType.INCIDENT_TYPE | \
                 FileType.INCIDENT_FIELD | FileType.INDICATOR_FIELD | FileType.LAYOUT | FileType.WIDGET | \
                 FileType.DASHBOARD | FileType.REPORT | FileType.PARSING_RULE | FileType.MODELING_RULE | \
                 FileType.CORRELATION_RULE | FileType.XSIAM_DASHBOARD | FileType.XSIAM_REPORT | FileType.REPORT | \
                 FileType.GENERIC_TYPE | FileType.GENERIC_FIELD | FileType.GENERIC_MODULE | \
                 FileType.GENERIC_DEFINITION | FileType.PRE_PROCESS_RULES | FileType.JOB | FileType.CONNECTION | \
                 FileType.RELEASE_NOTES_CONFIG | FileType.XSOAR_CONFIG:
                # pack should be installed, but no tests are collected.
                return self._collect_pack(
                    name=find_pack(path).name,
                    reason=CollectionReason.NON_CODE_FILE_CHANGED,
                    reason_description=reason_description,
                )

            case FileType.PYTHON_FILE | FileType.POWERSHELL_FILE | FileType.JAVASCRIPT_FILE:
                if path.name.endswith('Tests.ps1'):
                    path = path.with_name(path.name.replace('.Tests.ps1', '.ps1'))
                return self._collect_yml(path)

            case FileType.TEST_PLAYBOOK:
                if (test_id := content_item.id_) in self.conf.test_ids:
                    tests = test_id,
                    reason = CollectionReason.TEST_PLAYBOOK_CHANGED
                else:
                    raise

            case FileType.REPUTATION:  # todo reputationjson
                tests = DEFAULT_REPUTATION_TESTS
                reason = CollectionReason.DEFAULT_REPUTATION_TESTS
                # todo anything else?

            case FileType.MAPPER | FileType.CLASSIFIER:
                source, reason = {
                    FileType.MAPPER: (self.conf.incoming_mapper_to_test, CollectionReason.MAPPER_CHANGED),
                    FileType.CLASSIFIER: (self.conf.classifier_to_test, CollectionReason.CLASSIFIER_CHANGED),
                }[file_type]

                if not (tests := source.get(content_item.id_)):
                    tests = None  # replacing with None, so the pack is installed
                    reason = CollectionReason.NON_CODE_FILE_CHANGED
                    reason_description = f'no specific tests for {relative_path} were found'

            case _:
                if path.suffix == '.yml':
                    return self._collect_yml(path)  # checks for containing folder (content item type)
                raise RuntimeError(f'Unexpected filetype {file_type}, {relative_path}')

        return CollectedTests(
            tests=tests,
            packs=content_item.pack_tuple,
            reason=reason,
            version_range=content_item.version_range,
            reason_description=reason_description,
        )

    def _get_changed_files(self) -> tuple[str]:
        repo = Repo(CONTENT_PATH)
        full_branch_name = f'origin/{self.branch_name}'  # todo remove, debugging only
        latest, previous = tuple(repo.iter_commits(
            rev=f'{full_branch_name}~1...{full_branch_name}~3' if IS_GITLAB
            else f'{full_branch_name}...{full_branch_name}~2'
        ))
        return tuple(str(file.b_path) for file in latest.diff(previous))


class NightlyTestCollector(TestCollector, ABC):
    def _id_set_tests_matching_marketplace_value(self, only_value: bool) -> CollectedTests:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all tests whose marketplace field includes the collector's marketplace value.
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(f'collecting test playbooks by their marketplace field, searching for {self.marketplace.value}'
                    f'{postfix}')
        tests = []

        for playbook in self.id_set.test_playbooks:
            playbook_marketplaces = playbook.marketplaces or default

            if only_value and len(playbook_marketplaces) != 1:
                continue

            if self.marketplace.value in playbook_marketplaces and playbook.tests:
                tests.extend(playbook.tests)

        return CollectedTests(tests=tests, packs=None, reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              version_range=None, reason_description=f'({self.marketplace.value})')

    def _packs_matching_marketplace_value(self, only_value: bool) -> CollectedTests:
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
            if only_value and len(pack_marketplaces) >= 2:
                continue
            if self.marketplace in pack_marketplaces:
                packs.append(pack.name)

        return CollectedTests(tests=None, packs=packs, reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              version_range=None, reason_description=f'({self.marketplace.value})')

    def _packs_of_content_matching_marketplace_value(self, only_value: bool) -> CollectedTests:
        """
        :param only_value: whether the value is the only one under the marketplaces field.
        :return: all packs whose under which a content item marketplace field contains self.marketplaces
                (or is equal to, if only_value is True).
        """
        default = (DEFAULT_MARKETPLACE_WHEN_MISSING,)  # MUST BE OF LENGTH==1
        postfix = ' (only where this is the only marketplace value)' if only_value else ''
        logger.info(
            f'collecting content items by their marketplace field, searching for {self.marketplace.value}'
            f'{postfix}')

        packs = []
        for item in self.id_set.artifact_iterator:
            item_marketplaces = item.marketplaces or default

            if only_value and len(item_marketplaces) >= 2:  # 0 is ok because of the default, and 1 for obvious reasons
                continue

            if self.marketplace in item_marketplaces:
                if not item.pack:
                    raise ValueError('can not collect pack for items without one')  # todo replace with `continue`?
                packs.append(item.pack)

        return CollectedTests(tests=None, packs=tuple(packs), reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              version_range=None, reason_description=f'({self.marketplace.value})')


class XSIAMNightlyTestCollector(NightlyTestCollector):
    def _collect(self) -> Optional[CollectedTests]:
        return CollectedTests.union((
            self._id_set_tests_matching_marketplace_value(only_value=True),
            self._packs_matching_marketplace_value(only_value=True),
            self._packs_of_content_matching_marketplace_value(only_value=True)
        ))


class XSOARNightlyTestCollector(NightlyTestCollector):
    def _collect(self) -> Optional[CollectedTests]:
        return CollectedTests.union((
            self._id_set_tests_matching_marketplace_value(only_value=False),
            self._packs_matching_marketplace_value(only_value=False),
            self._packs_of_content_matching_marketplace_value(only_value=False)
        ))


class UploadCollector(TestCollector):
    # todo today we collect pack_name_to_pack_metadata, not tests
    def _collect(self) -> Optional[CollectedTests]:
        pass


if __name__ == '__main__':
    try:
        sys.path.append(str(CONTENT_PATH))
        collector = XSOARNightlyTestCollector(marketplace=MarketplaceVersions.XSOAR)
        # collector = BranchTestCollector(marketplace=MarketplaceVersions.XSOAR, branch_name='master')
        print(collector.collect(True, True))

    except:  # todo remove
        Repo(CONTENT_PATH).git.checkout('ds-test-collection')  # todo remove
        raise
