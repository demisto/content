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
from git import Repo
from id_set import IdSet
from logger import logger
from test_conf import TestConf

from Tests.scripts.collect_tests.path_manager import PathManager
from utils import (ContentItem, Machine, PackManager, VersionRange,
                   find_pack_folder)


# from Tests.Marketplace.marketplace_services import get_last_commit_from_index # todo uncomment
def get_last_commit_from_index(*args, **kwargs):  # todo remove
    pass


PATHS = PathManager(Path(__file__).absolute().parents[3])
PACK_MANAGER = PackManager(PATHS)


class CollectionReason(Enum):
    # todo remove unused
    ID_SET_MARKETPLACE_VERSION = 'id_set marketplace version'
    PACK_MARKETPLACE_VERSION_VALUE = 'marketplace version of pack'
    CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE = 'marketplace version of contained item'
    SANITY_TESTS = 'sanity tests by marketplace value'
    PACK_MATCHES_INTEGRATION = 'pack added as the integration is used in a playbook'  # todo is used?
    PACK_MATCHES_TEST = 'pack added as the test playbook was collected earlier'
    NIGHTLY_ALL_TESTS__ID_SET = 'collecting all id_set test playbooks for nightly'  # todo is used?
    NIGHTLY_ALL_TESTS__TEST_CONF = 'collecting all test_conf tests for nightly'  # todo is used?
    ALL_ID_SET_PACKS = 'collecting all id_set pack_name_to_pack_metadata'  # todo is used?
    NON_CODE_FILE_CHANGED = 'non-code pack file changed'
    INTEGRATION_CHANGED = 'integration changed, collecting all conf.json tests using it'
    SCRIPT_PLAYBOOK_CHANGED = 'file changed, taking tests from `tests` section in script yml'
    SCRIPT_PLAYBOOK_CHANGED_NO_TESTS = 'file changed, but has `No Tests` configured, taking tests from id_set'
    TEST_PLAYBOOK_CHANGED = 'test playbook changed'
    MAPPER_CHANGED = 'mapper file changed, configured as incoming_mapper_id in test conf'
    CLASSIFIER_CHANGED = 'classifier file changed, configured as classifier_id in test conf'
    DEFAULT_REPUTATION_TESTS = 'default reputation tests'


class CollectedTests:
    def __init__(
            self,
            tests: Optional[tuple[Optional[str]] | list[Optional[str]]],
            packs: Optional[tuple[Optional[str]] | list[Optional[str]]],
            reason: CollectionReason,
            version_range: Optional[VersionRange],
            reason_description: Optional[str] = None,
    ):

        self.tests: set[str] = set()  # only updated on init
        self.packs: set[str] = set()  # only updated on init
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: Optional[Iterable[Machine]] = None

        if tests and packs and len(tests) != len(packs):
            raise ValueError(f'when both are not empty, {len(tests)=} must be equal to {len(packs)=}')
        elif tests and not packs:
            packs = (None,) * len(tests)  # so accessors get a None
        elif packs and not tests:
            tests = (None,) * len(packs)  # so accessors get a None

        for i in range(len(tests)):
            self._add_single(tests[i], packs[i], reason, reason_description)

    def __or__(self, other: 'CollectedTests') -> 'CollectedTests':
        self.tests.update(other.tests)
        self.packs.update(other.packs)
        self.version_range = self.version_range | other.version_range if self.version_range else other.version_range
        return self

    @classmethod
    def union(cls, collected_tests: Iterable['CollectedTests']) -> Optional['CollectedTests']:
        collected_tests = tuple(filter(None, collected_tests))

        if not collected_tests:
            logger.warning('no tests to union')
            return None

        return reduce(lambda a, b: a | b, collected_tests)

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
            logger.info(f'collected {test:}, {reason.value} {description}')

        if pack:
            try:
                PACK_MANAGER.validate_pack(pack)
            except (SkippedPackException, DeprecatedPackException, UnsupportedPackException) as e:
                logger.info(e.message)
            # except NonexistentPackException as e:
            #     logger.critical(e.message)

            self.packs.add(pack)
            logger.info(f'collected {pack=}, {reason.value} {description}')

    def __repr__(self):
        return f'{len(self.packs)} packs, {len(self.tests)} tests, {self.version_range=}'

    def __bool__(self):
        return bool(self.tests or self.packs)


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions):
        self.marketplace = marketplace
        self.id_set = IdSet(marketplace, PATHS.debug_id_set_path)  # todo change
        self.conf = TestConf(PATHS.debug_conf_path)  # todo change
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

    def collect(self, run_nightly: bool, run_master: bool) -> Optional[CollectedTests]:
        collected: Optional[CollectedTests] = self._collect()

        if not collected:
            logger.warning('No tests were collected, returning sanity tests only')
            collected = self.sanity_tests

        collected.machines = Machine.get_suitable_machines(collected.version_range, run_nightly, run_master)

        if collected and collected.machines is None:  # todo reconsider
            raise EmptyMachineListException()

        # collected |= self._add_packs_used(collected.tests)  # todo should we use it?
        self._validate_tests_in_id_set(collected.tests)
        return collected

    def _validate_tests_in_id_set(self, tests: Iterable[str]):
        if not_found := ((set(tests) - self.sanity_tests.tests).difference(self.id_set.id_to_test_playbook.keys())):
            not_found_string = '\n\t'.join(not_found)
            logger.warning(f'{len(not_found)} tests were not found in id-set: \n{not_found_string}')

    # def _add_packs_used(self, tests: set[str]) -> list[CollectedTests]:  # todo is used?
    #     return self._add_packs_from_tested_integrations(tests) + self._add_packs_from_test_playbooks(tests)
    #
    # def _add_packs_from_tested_integrations(self, tests: set[str]) -> list[CollectedTests]:
    #     # only called in _add_packs_used
    #     # todo is it used in the new version?
    #     logger.info(f'searching for integrations used in test playbooks, '
    #                 f'to make sure the integration pack_name_to_pack_metadata are installed')
    #     collected = []
    #
    #     for test in tests:
    #         for integration in self.conf.tests_to_integrations.get(test, ()):
    #             if pack := self.id_set.integration_to_pack.get(integration):  # todo what if not?
    #                 collected.append(self._collect_pack(pack, CollectionReason.PACK_MATCHES_INTEGRATION,
    #                                                     reason_description=f'{integration=}'))
    #     return collected

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
        logger.info('searching for pack_name_to_pack_metadata under which test playbooks are saved,'
                    ' to make sure they are installed')
        collected = []

        for test in tests:
            if test not in self.id_set.test_playbooks_to_pack_id:
                raise ValueError(f'test {test} is missing from id-set, stopping collection.')
            if pack := self.id_set.test_playbooks_to_pack_id[test]:
                collected.append(
                    self._collect_pack(pack, reason=CollectionReason.PACK_MATCHES_TEST, reason_description='')
                )
        return collected


class BranchTestCollector(TestCollector):
    def __init__(self, branch_name: str,
                 marketplace: MarketplaceVersions,
                 service_account: Optional[str]):
        super().__init__(marketplace)
        self.branch_name = branch_name
        self.repo = Repo(PATHS.content_path)
        self.service_account = service_account

    def _collect(self) -> Optional[CollectedTests]:
        collected = []
        for path in self._get_changed_files():
            try:
                collected.append(self._collect_single(PATHS.content_path / path))
            except NothingToCollectException as e:
                logger.warning(e.message)

        return CollectedTests.union(collected)

    @classmethod
    def _find_yml_content_type(cls, yml_path: Path):
        if yml_path.parent.name == 'TestPlaybooks':
            return FileType.TEST_PLAYBOOK

        if result := ({
            'Integrations': FileType.INTEGRATION,
            'Scripts': FileType.SCRIPT
        }.get(yml_path.parents[1].name)):
            return result

    def _collect_yml(self, content_item_path: Path) -> Optional[CollectedTests]:
        yml_path = content_item_path.with_suffix('.yml')
        try:
            yml = ContentItem(yml_path)
        except FileNotFoundError:
            raise FileNotFoundError(f'could not find yml matching {PackManager.relative_to_packs(yml_path)}')

        relative_path = PackManager.relative_to_packs(yml_path)

        match actual_content_type := self._find_yml_content_type(yml_path):
            case None:
                raise ValueError(f'could not detect type for {yml_path}')

            case FileType.TEST_PLAYBOOK:
                if (test_id := yml.id_) in self.conf.test_ids:
                    tests = test_id,
                    reason = CollectionReason.TEST_PLAYBOOK_CHANGED
                else:
                    raise ValueError(f'{test_id} missing from conf.test_ids')

            case FileType.INTEGRATION:
                tests = self.conf.integrations_to_tests[yml.id_]
                reason = CollectionReason.INTEGRATION_CHANGED

            case FileType.SCRIPT | FileType.PLAYBOOK:
                try:
                    tests = yml.tests  # raises NoTestsConfiguredException if 'no tests' in the tests field
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED
                except NoTestsConfiguredException:
                    # collecting all tests that implement this script/playbook
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED_NO_TESTS

                    match actual_content_type:
                        case FileType.SCRIPT:
                            tests = self.id_set.implemented_scripts_to_tests.get(yml.id_)
                        case FileType.PLAYBOOK:
                            tests = self.id_set.implemented_playbooks_to_tests.get(yml.id_)
                        case _:
                            raise RuntimeError(f'unexpected content type folder {actual_content_type}')

                    if not tests:
                        original_type: str = actual_content_type.value
                        relative_path = str(PackManager.relative_to_packs(yml.path))
                        logger.warning(f'{original_type} {relative_path} '
                                       f'has `No Tests` configured, and no tests in id_set')
            case _:
                raise RuntimeError(f'Unexpected content type {actual_content_type} for {content_item_path}'
                                   f'(expected `Integrations`, `Scripts` or `Playbooks`)')
        # creating an object for each, as CollectedTests require #packs==#tests
        if tests:
            return CollectedTests.union(
                (CollectedTests(tests=(test,), packs=yml.pack_folder_name_tuple, reason=reason,
                                version_range=yml.version_range, reason_description=f'{yml.id_=} ({relative_path})')
                 for test in tests))

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
            raise  # todo is this the expected behavior?

        if file_type in {FileType.PACK_IGNORE, FileType.SECRET_IGNORE, FileType.DOC_FILE, FileType.README}:
            raise NothingToCollectException(path, f'ignored type {file_type}')

        elif file_type in ONLY_INSTALL_PACK:
            # install pack without collecting tests.
            return self._collect_pack(
                name=find_pack_folder(path).name,
                reason=CollectionReason.NON_CODE_FILE_CHANGED,
                reason_description=reason_description,
            )

        elif file_type in {FileType.PYTHON_FILE, FileType.POWERSHELL_FILE, FileType.JAVASCRIPT_FILE}:
            if path.name.endswith('Tests.ps1'):
                path = path.with_name(path.name.replace('.Tests.ps1', '.ps1'))
            return self._collect_yml(path)

        elif file_type == FileType.REPUTATION:
            tests = DEFAULT_REPUTATION_TESTS
            reason = CollectionReason.DEFAULT_REPUTATION_TESTS

        elif file_type in {FileType.MAPPER, FileType.CLASSIFIER}:
            source, reason = {
                FileType.MAPPER: (self.conf.incoming_mapper_to_test, CollectionReason.MAPPER_CHANGED),
                FileType.CLASSIFIER: (self.conf.classifier_to_test, CollectionReason.CLASSIFIER_CHANGED),
            }[file_type]

            if not (tests := source.get(content_item.id_)):
                reason = CollectionReason.NON_CODE_FILE_CHANGED
                reason_description = f'no specific tests for {relative_path} were found'
        elif path.suffix == '.yml':
            return self._collect_yml(path)  # checks for containing folder (content item type)

        else:
            raise ValueError(f'Unexpected filetype {file_type}, {relative_path}')

        return CollectedTests(
            tests=tests,
            packs=content_item.pack_folder_name_tuple,
            reason=reason,
            version_range=content_item.version_range,
            reason_description=reason_description,
        )

    def _get_changed_files(self) -> tuple[str]:
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

        diff = run_command(f'git diff --name-status {current_commit}...{previous_commit}')
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
                collected.append(CollectedTests(tests=(playbook.name,), packs=(playbook.pack_id,),
                                                reason=CollectionReason.ID_SET_MARKETPLACE_VERSION,
                                                reason_description=f'({self.marketplace.value})',
                                                version_range=VersionRange(playbook.from_version, playbook.to_version)))

        if not collected:
            logger.warning(f'no tests matching marketplace {self.marketplace.value} ({only_value=}) were found')
            return None

        return CollectedTests.union(collected)

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

        return CollectedTests(tests=None, packs=packs, reason=CollectionReason.PACK_MARKETPLACE_VERSION_VALUE,
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
                    pack_folder = find_pack_folder(path)
                    pack = PACK_MANAGER.get_pack_by_path(pack_folder)
                    relative_path = PACK_MANAGER.relative_to_packs(item.file_path)
                    collected.append(
                        CollectedTests(tests=None,
                                       packs=(pack_folder.name,),  # pack folder name is used as id for packs
                                       reason=CollectionReason.CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE,
                                       version_range=item.version_range or pack.version_range,
                                       reason_description=f'{str(relative_path)}, ({self.marketplace.value})')
                    )

                except NotUnderPackException:
                    if path.name in SKIPPED_CONTENT_ITEMS:
                        logger.info(f'skipping unsupported content item: {str(path)}')
                        continue

                # todo check if the following can be replaced by the previous 2 lines
                # if not item.pack:
                #     logger.error('can not collect pack for items without a pack value')  # todo fix in id_set
                #     continue  # todo remove, fix in id_set
                # packs.append(item.pack)
        return CollectedTests.union(collected)


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
    # todo is necessary? Or can we just use a BranchTestCollector instead?
    def _collect(self) -> Optional[CollectedTests]:
        # same as BranchTestCollector, but without tests.
        collected = super()._collect()
        collected.tests = set()
        return collected


# todo install_logging, see destroy_instances

def ui():  # todo put as real main
    parser = ArgumentParser(description='Utility CircleCI usage')  # todo (?)
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly')
    parser.add_argument('-p', '--changed_pack_path', type=str, help='A string representing the changed files')  # todo
    parser.add_argument('-mp', '--marketplace', help='marketplace version', default='xsoar')
    parser.add_argument('--service_account', help="Path to gcloud service account")
    options = parser.parse_args()

    match (options.nightly, marketplace := MarketplaceVersions(options.marketplace)):
        case False, _:  # not nightly
            collector = BranchTestCollector(
                marketplace=marketplace,
                branch_name='master',  # todo branch name?
                service_account=options.service_account
            )
        case True, MarketplaceVersions.XSOAR:
            collector = XSOARNightlyTestCollector()
        case True, MarketplaceVersions.MarketplaceV2:
            collector = XSIAMNightlyTestCollector()
        case _:
            raise ValueError(f"unexpected values of (either) {marketplace=}, {options.nightly=}")

    collected = collector.collect(run_nightly=options.nightly, run_master=True)  # todo what to put in master?
    logger.info(f'done collecting, got ({len(collected.tests)} tests and {len(collected.packs)} packs')

    logger.info(f'writing output to {str(PATHS.output_tests_file)}, {str(PATHS.output_packs_file)}')
    PATHS.output_tests_file.write_text('\n'.join(collected.tests))
    PATHS.output_packs_file.write_text('\n'.join(collected.packs))


# def debug():  # todo remove
#     collector = XSOARNightlyTestCollector()
#     print(collector.collect(True, True))


if __name__ == '__main__':
    sys.path.append(str(PATHS.content_path))
    raise NotImplementedError()
