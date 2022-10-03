import json
import os
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional, Sequence

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions, CONTENT_ENTITIES_DIRS
from demisto_sdk.commands.common.tools import find_type, str2bool

from Tests.Marketplace.marketplace_services import get_last_commit_from_index
from Tests.scripts.collect_tests.constants import (
    ALWAYS_INSTALLED_PACKS, DEFAULT_MARKETPLACE_WHEN_MISSING,
    DEFAULT_REPUTATION_TESTS, IGNORED_FILE_TYPES, NON_CONTENT_FOLDERS,
    ONLY_INSTALL_PACK_FILE_TYPES, SANITY_TEST_TO_PACK,
    SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK, XSOAR_SANITY_TEST_NAMES)
from Tests.scripts.collect_tests.exceptions import (
    DeprecatedPackException, IncompatibleMarketplaceException,
    InvalidTestException, NonDictException, NonXsoarSupportedPackException,
    NoTestsConfiguredException, NothingToCollectException,
    NotUnderPackException, PrivateTestException, SkippedPackException,
    SkippedTestException, TestMissingFromIdSetException,
    NonNightlyPackInNightlyBuildException)
from Tests.scripts.collect_tests.id_set import IdSet, IdSetItem
from Tests.scripts.collect_tests.logger import logger
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.test_conf import TestConf
from Tests.scripts.collect_tests.utils import (ContentItem, Machine,
                                               PackManager, find_pack_folder,
                                               find_yml_content_type, to_tuple, hotfix_detect_old_script_yml)
from Tests.scripts.collect_tests.version_range import VersionRange

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
    PACK_TEST_DEPENDS_ON = 'a test depends on this pack'
    NON_XSOAR_SUPPORTED = 'support level is not xsoar: collecting the pack, not collecting tests'

    DUMMY_OBJECT_FOR_COMBINING = 'creating an empty object, to combine two CollectionResult objects'


REASONS_ALLOWING_NO_ID_SET_OR_CONF = {
    # these may be used without an id_set or conf.json object, see _validate_collection.
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
            is_nightly: bool = False,
            override_pack_compatibility_check: bool = False,
    ):
        """
        Collected test playbook, and/or a pack to install.

        NOTE:   The constructor only accepts a single Optional[str] for test and pack, but they're kept as set[str].
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
        :param is_nightly: whether the run is a nightly run. When running on nightly, only specific packs need to run.
        :param override_pack_compatibility_check:
                whether to install a pack, even if it is not directly compatible.
                This is used when collecting a pack containing a content item, when their marketplace values differ.
        """
        self.tests: set[str] = set()
        self.packs: set[str] = set()
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: Optional[tuple[Machine, ...]] = None

        try:
            # raises if invalid
            self._validate_collection(
                pack=pack,
                test=test,
                reason=reason,
                conf=conf,
                id_set=id_set,
                is_sanity=is_sanity,
                is_nightly=is_nightly,
                skip_pack_compatibility=override_pack_compatibility_check,
            )

        except NonXsoarSupportedPackException:
            if test:
                logger.info(f'{pack} support level != XSOAR, not collecting {test}, pack will be installed')
                test = None

        except InvalidTestException as e:
            suffix = ' (pack will be installed)' if pack else ''
            logger.info(f'{str(e)}, not collecting {test}{suffix}')
            test = None

        except NonNightlyPackInNightlyBuildException as e:
            test_suffix = f', not collecting {test}' if test else ''
            logger.info(f'{str(e)}{test_suffix} (pack will be installed)')
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
    def _validate_collection(
            pack: Optional[str],
            test: Optional[str],
            reason: CollectionReason,
            conf: Optional[TestConf],
            id_set: Optional[IdSet],
            is_sanity: bool,
            is_nightly: bool,
            skip_pack_compatibility: bool,
    ):
        """
        Validates the arguments of the constructor.
        NOTE: Here, we only validate information regarding the test and pack directly.
                For validations regarding contentItem or IdSetItem objects, see __validate_compatibility.
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
                for integration in test_playbook.implementing_integrations:
                    if reason := conf.skipped_integrations.get(integration):  # type:ignore[union-attr]
                        raise SkippedTestException(
                            test_name=test,
                            skip_place='conf.json (integrations)',
                            skip_reason=f'{test=} uses {integration=}, which is skipped ({reason=})'
                        )

            if skip_reason := conf.skipped_tests.get(test):  # type:ignore[union-attr]
                raise SkippedTestException(test, skip_place='conf.json (skipped_tests)', skip_reason=skip_reason)

            if test in conf.private_tests:  # type:ignore[union-attr]
                raise PrivateTestException(test)

        if pack:
            try:
                PACK_MANAGER.validate_pack(pack)

            except NonXsoarSupportedPackException:
                if skip_pack_compatibility:
                    logger.info(f'overriding pack compatibility check for {pack} - not compliant, but IS collected')
                elif is_sanity and pack == 'HelloWorld':  # Sanity tests are saved under HelloWorld, so we allow it.
                    pass
                else:
                    raise

        if is_nightly:
            if test and test in conf.non_api_tests:  # type:ignore[union-attr]
                return

            if pack and pack not in conf.nightly_packs:  # type:ignore[union-attr]
                raise NonNightlyPackInNightlyBuildException(pack)

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
    def union(collected_tests: Optional[Sequence[Optional['CollectionResult']]]) -> Optional['CollectionResult']:
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
            if not (test_object := self.conf.get_test(test_id)):
                # todo prevent this case, see CIAC-4006
                continue

            # collect the pack containing the test playbook
            pack_id = self.id_set.id_to_test_playbook[test_id].pack_id
            result.append(self._collect_pack(
                pack_id=pack_id,
                reason=CollectionReason.PACK_TEST_DEPENDS_ON,
                reason_description=f'test {test_id} is saved under pack {pack_id}',
                content_item_range=test_object.version_range,
                allow_incompatible_marketplace=True,  # allow xsoar&xsiam packs
            ))

            # collect integrations used in the test
            for integration in test_object.integrations:
                if integration_object := self.id_set.id_to_integration.get(integration):
                    result.append(self._collect_test_dependency(
                        dependency_name=integration,
                        test_id=test_id,
                        pack_id=integration_object.pack_id,
                        dependency_type='integration',
                    ))
                else:
                    logger.warning(f'could not find integration {integration} in id_set'
                                   f' when searching for integrations the {test_id} test depends on')

            # collect scripts used in the test
            for script in test_object.scripts:
                if script_object := self.id_set.id_to_script.get(script):
                    result.append(self._collect_test_dependency(
                        dependency_name=script,
                        test_id=test_id,
                        pack_id=script_object.pack_id,
                        dependency_type='script',
                    ))
                else:
                    logger.warning(f'Could not find script {script} in id_set'
                                   f' when searching for integrations the {test_id} test depends on')

        return CollectionResult.union(tuple(result))

    def _collect_test_dependency(
            self, dependency_name: str, test_id: str, pack_id: str, dependency_type: str
    ) -> CollectionResult:
        return CollectionResult(
            test=None,
            pack=pack_id,
            reason=CollectionReason.PACK_TEST_DEPENDS_ON,
            version_range=None,
            reason_description=f'test {test_id} depends on {dependency_type} {dependency_name} from {pack_id}',
            conf=self.conf,
            id_set=self.id_set,
        )

    def __validate_compatibility(
            self,
            id_: str,
            pack_id: str,
            marketplaces: Optional[tuple[MarketplaceVersions, ...]],
            path: Path,
            version_range: Optional[VersionRange],
            is_integration: bool,
    ):
        # exception order matters: important tests come first.
        """
        NOTE:
            Here, we validate information that indirectly affects the collection
            (information regarding IdSet or ContentItem objects, based on which we collect tests or packs)
            e.g. skipped integrations, marketplace compatibility, support level.

            For validating the pack/test directly, see _validate_collection.
        """

        self._validate_path(path)
        if is_integration:
            self.__validate_skipped_integration(id_, path)
        self.__validate_marketplace_compatibility(marketplaces or (), path)
        self.__validate_support_level_is_xsoar(pack_id, version_range)

    def _validate_path(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(path)

        self.__validate_triggering_sanity_test(path)
        self.__validate_not_ignored_file(path)

    def _validate_content_item_compatibility(self, content_item: ContentItem, is_integration: bool) -> None:
        self.__validate_compatibility(
            id_=content_item.id_,
            pack_id=content_item.pack_id,
            marketplaces=content_item.marketplaces,
            path=content_item.path,
            version_range=content_item.version_range,
            is_integration=is_integration,
        )

    def _validate_id_set_item_compatibility(self, id_set_item: IdSetItem, is_integration: bool) -> None:
        if not (pack_id := id_set_item.pack_id or find_pack_folder(id_set_item.path).name):
            raise RuntimeError(f'could not find pack of {id_set_item.name}')

        self.__validate_compatibility(
            id_=id_set_item.id_,
            pack_id=pack_id,
            marketplaces=id_set_item.marketplaces,
            path=id_set_item.path,
            version_range=id_set_item.version_range,
            is_integration=is_integration,
        )

    def _collect_pack(
            self,
            pack_id: str,
            reason: CollectionReason,
            reason_description: str,
            content_item_range: Optional[VersionRange] = None,
            allow_incompatible_marketplace: bool = False,
            is_nightly: bool = False,
    ) -> Optional[CollectionResult]:
        pack_metadata = PACK_MANAGER.get_pack_metadata(pack_id)

        try:
            self._validate_content_item_compatibility(pack_metadata, is_integration=False)
        except NonXsoarSupportedPackException as e:
            # we do want to install packs in this case (tests are not collected in this case anyway)
            logger.info(f'pack {pack_id} has support level {e.support_level} (not xsoar), '
                        f'collecting to make sure it is installed properly.')
        except IncompatibleMarketplaceException:
            # sometimes, we want to install packs that are not compatible (e.g. both marketplaces)
            # because they have content that IS compatible.
            if not allow_incompatible_marketplace:
                raise

        version_range = content_item_range \
            if pack_metadata.version_range.is_default \
            else (pack_metadata.version_range | content_item_range)

        return CollectionResult(
            test=None,
            pack=pack_id,
            reason=reason,
            version_range=version_range,
            reason_description=reason_description,
            conf=self.conf,
            id_set=self.id_set,
            is_nightly=is_nightly
        )

    def __validate_skipped_integration(self, id_: str, path: Path):
        if id_ in self.conf.skipped_integrations:
            raise NothingToCollectException(path, 'integration is skipped')

    def __validate_triggering_sanity_test(self, path: Path):
        if path in PATHS.files_triggering_sanity_tests:
            self.trigger_sanity_tests = True
            raise NothingToCollectException(path, 'not under a pack (triggering sanity tests)')

    @staticmethod
    def __validate_not_ignored_file(path: Path):
        if path in PATHS.files_to_ignore:
            raise NothingToCollectException(path, 'not under a pack (ignored, not triggering sanity tests)')

        if set(PACK_MANAGER.relative_to_packs(path).parts).intersection(NON_CONTENT_FOLDERS):
            raise NothingToCollectException(path, 'file under test_data, samples or documentation folder,'
                                                  ' (not triggering sanity tests)')

    @staticmethod
    def __validate_support_level_is_xsoar(pack_id: str, content_item_range: Optional[VersionRange]) -> None:
        # intended to only be called from __validate_compatibility
        if (support_level := PACK_MANAGER.get_support_level(pack_id)) != 'xsoar':
            raise NonXsoarSupportedPackException(pack_id, support_level, content_item_range)

    def __validate_marketplace_compatibility(self,
                                             content_item_marketplaces: tuple[MarketplaceVersions, ...],
                                             content_item_path: Path) -> None:
        # intended to only be called from __validate_compatibility
        if not content_item_marketplaces:
            logger.debug(f'{content_item_path} has no marketplaces set, '
                         f'using default={DEFAULT_MARKETPLACE_WHEN_MISSING}')
            content_item_marketplaces = to_tuple(DEFAULT_MARKETPLACE_WHEN_MISSING)

        match self.marketplace:
            case MarketplaceVersions.MarketplaceV2:
                if content_item_marketplaces != (self.marketplace,):
                    # marketplacev2 must be the only value in order to be collected
                    raise IncompatibleMarketplaceException(content_item_path, self.marketplace)

            case MarketplaceVersions.XSOAR:
                if self.marketplace not in content_item_marketplaces:
                    raise IncompatibleMarketplaceException(content_item_path, self.marketplace)

            case _:
                raise RuntimeError(f'Unexpected self.marketplace value {self.marketplace}')

    def _validate_tests_in_id_set(self, tests: Iterable[str]):
        if not_found := set(tests).difference(self.id_set.id_to_test_playbook.keys()):
            not_found_string = ', '.join(sorted(not_found))
            logger.warning(f'{len(not_found)} tests were not found in id-set: \n{not_found_string}')


class BranchTestCollector(TestCollector):
    def __init__(
            self,
            branch_name: str,
            marketplace: MarketplaceVersions,
            service_account: Optional[str],
            private_pack_path: Optional[str] = None,
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
        self.private_pack_path: Optional[Path] = Path(private_pack_path) if private_pack_path else None

    def _get_private_pack_files(self) -> tuple[str, ...]:
        if not self.private_pack_path:
            raise RuntimeError('private_pack_path cannot be empty')
        return tuple(str(path) for path in self.private_pack_path.rglob('*') if path.is_file())

    def _collect(self) -> Optional[CollectionResult]:
        result = []
        paths: tuple[str, ...] = self._get_private_pack_files() \
            if self.private_pack_path \
            else self._get_changed_files()

        for raw_path in paths:
            path = PATHS.content_path / raw_path
            logger.debug(f'Collecting tests for {raw_path}')
            try:
                result.append(self._collect_single(path))
            except NonXsoarSupportedPackException as e:
                result.append(self._collect_pack(
                    pack_id=find_pack_folder(path).name,
                    reason=CollectionReason.NON_XSOAR_SUPPORTED,
                    reason_description=raw_path,
                    content_item_range=e.content_version_range,
                ))
            except NothingToCollectException as e:
                logger.info(e.message)
            except Exception as e:
                logger.exception(f'Error while collecting tests for {raw_path}', exc_info=True, stack_info=True)
                raise e

        return CollectionResult.union(result)

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

        actual_content_type = find_yml_content_type(yml_path) or hotfix_detect_old_script_yml(yml_path)
        self._validate_content_item_compatibility(yml, is_integration=actual_content_type == FileType.INTEGRATION)

        relative_yml_path = PACK_MANAGER.relative_to_packs(yml_path)
        tests: tuple[str, ...]
        override_pack_compatibility_check = False

        match actual_content_type:
            case None:
                path_description = f'{yml_path} (original item {content_item_path}' \
                    if content_item_path != yml_path \
                    else yml_path
                raise ValueError(f'could not detect type for {path_description}')

            case FileType.TEST_PLAYBOOK:
                if yml.id_ in self.conf.test_id_to_test:
                    tests = yml.id_,
                else:
                    # todo fix in CIAC-4006
                    logger.warning(f'test playbook with id {yml.id_} is missing from conf.json tests section')
                    tests = ()
                reason = CollectionReason.TEST_PLAYBOOK_CHANGED

            case FileType.INTEGRATION:
                if yml.explicitly_no_tests():
                    suffix = ''

                    if tests_from_conf := self.conf.integrations_to_tests.get(yml.id_, ()):
                        tests_str = ', '.join(sorted(tests_from_conf))
                        suffix = f'. NOTE: NOT COLLECTING tests from conf.json={tests_str}'

                    logger.warning(f'{yml.id_} explicitly states `no tests`: only collecting pack {suffix}')
                    override_pack_compatibility_check = True
                    tests = ()

                elif yml.id_ not in self.conf.integrations_to_tests:
                    # note, this whole method is always called after validating support level is xsoar
                    raise ValueError(
                        f'integration {str(PACK_MANAGER.relative_to_packs(yml.path))} is '
                        f'(1) missing from conf.json, AND'
                        ' (2) does not explicitly state `tests: no tests` AND'
                        ' (3) has support level == xsoar. '
                        'Please change at least one of these to allow test collection.'
                    )
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
                        override_pack_compatibility_check = True
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
                    id_set=self.id_set,
                    is_nightly=False,
                    override_pack_compatibility_check=override_pack_compatibility_check,
                ) for test in tests))
        else:
            return self._collect_pack(
                pack_id=yml.pack_id,
                reason=reason,
                reason_description='collecting pack only',
                content_item_range=yml.version_range,
                allow_incompatible_marketplace=override_pack_compatibility_check,
            )

    def _collect_single(self, path: Path) -> Optional[CollectionResult]:
        self._validate_path(path)

        file_type = find_type(str(path))

        if file_type in IGNORED_FILE_TYPES:
            raise NothingToCollectException(path, f'ignored type {file_type}')

        if file_type is None and path.parent.name not in CONTENT_ENTITIES_DIRS:
            raise NothingToCollectException(
                path,
                f'file of unknown type, and not directly under a content directory ({path.parent.name})')

        try:
            content_item = ContentItem(path)
        except NonDictException:
            content_item = None  # py, md, etc. Anything not dictionary-based. Suitable logic follows, see collect_yml

        pack_id = find_pack_folder(path).name
        reason_description = relative_path = PACK_MANAGER.relative_to_packs(path)

        if file_type in ONLY_INSTALL_PACK_FILE_TYPES:
            return self._collect_pack(
                pack_id=pack_id,
                reason=CollectionReason.NON_CODE_FILE_CHANGED,
                reason_description=reason_description,
                content_item_range=content_item.version_range if content_item else None
            )
        if content_item:
            try:
                '''
                Upon reaching this part, we know the file is a content item (and not release note config, scheme, etc.)
                so _validate_content_item can be called (which we can't do to non-content files, often lacking an id).

                when content_item *is* None, the same validations are called either in _collect_yml or _collect_pack.

                '''
                self._validate_content_item_compatibility(
                    content_item,
                    is_integration=file_type == FileType.INTEGRATION,
                )
            except NonXsoarSupportedPackException as e:
                return self._collect_pack(
                    pack_id=find_pack_folder(path).name,
                    reason=CollectionReason.NON_XSOAR_SUPPORTED,
                    reason_description=e.support_level,
                )

        if file_type in {FileType.PYTHON_FILE, FileType.POWERSHELL_FILE, FileType.JAVASCRIPT_FILE}:
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
                is_nightly=False,
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
    def _id_set_tests_matching_marketplace_value(self) -> Optional[CollectionResult]:
        """
        :return: all tests whose marketplace field includes the collector's marketplace value
                    (or is equal to it, if `only_value` is used).
        """
        result = []
        for playbook in self.id_set.test_playbooks:
            try:
                self._validate_id_set_item_compatibility(playbook, is_integration=False)
                result.append(CollectionResult(
                    test=playbook.id_,
                    pack=playbook.pack_id,
                    reason=CollectionReason.ID_SET_MARKETPLACE_VERSION,
                    reason_description=self.marketplace.value,
                    version_range=playbook.version_range,
                    conf=self.conf,
                    id_set=self.id_set,
                    is_nightly=True,
                ))
            except (NothingToCollectException, NonXsoarSupportedPackException) as e:
                logger.debug(str(e))

        return CollectionResult.union(result)

    def _collect_all_marketplace_compatible_packs(self) -> Optional[CollectionResult]:
        result = []
        for pack_metadata in PACK_MANAGER.iter_pack_metadata():
            try:
                result.append(self._collect_pack(
                    pack_id=pack_metadata.pack_id,
                    reason=CollectionReason.PACK_MARKETPLACE_VERSION_VALUE,
                    reason_description=self.marketplace.value,
                    allow_incompatible_marketplace=False,
                    is_nightly=True,
                ))
            except (NothingToCollectException, NonXsoarSupportedPackException) as e:
                logger.debug(str(e))
        return CollectionResult.union(result)


class XSIAMNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.MarketplaceV2)

    def _collect_packs_of_content_matching_marketplace_value(self) -> Optional[CollectionResult]:
        """
        :return: all packs whose under which a content item marketplace field contains self.marketplaces
                (or is equal to, if only_value is True).
        """
        result = []

        for item in self.id_set.artifact_iterator:
            if not item.path or not item.file_path_str:
                raise RuntimeError(f'missing path for {item.id_=} {item.name=}')
            path = PATHS.content_path / item.file_path_str

            try:
                pack_id = find_pack_folder(path).name
                pack_metadata = PACK_MANAGER.get_pack_metadata(pack_id)
                try:
                    self._validate_id_set_item_compatibility(item, is_integration='Integrations' in path.parts)
                except NonXsoarSupportedPackException as e:
                    logger.info(f'{str(e)} - collecting pack anyway')
                except NothingToCollectException as e:
                    logger.info(e)
                    continue

                marketplaces_string = ', '.join(map(str, item.marketplaces))
                result.append(self._collect_pack(
                    pack_id=pack_metadata.pack_id,
                    reason=CollectionReason.CONTAINED_ITEM_MARKETPLACE_VERSION_VALUE,
                    reason_description=f'{item.file_path_str} ({marketplaces_string})',
                    content_item_range=item.version_range,
                    allow_incompatible_marketplace=True,
                    is_nightly=True,
                ))

            except NotUnderPackException:
                if path.name in SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK:
                    logger.info(f'skipping unsupported content item: {str(path)}, not under a pack')
                    continue
        return CollectionResult.union(result)

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
            self._id_set_tests_matching_marketplace_value(),
            self._collect_all_marketplace_compatible_packs(),
            self._collect_packs_of_content_matching_marketplace_value(),
            self.sanity_tests,  # XSIAM nightly always collects its sanity test(s)
        ))


class XSOARNightlyTestCollector(NightlyTestCollector):
    def __init__(self):
        super().__init__(MarketplaceVersions.XSOAR)

    def _collect(self) -> Optional[CollectionResult]:
        return CollectionResult.union((
            self._id_set_tests_matching_marketplace_value(),
            self._collect_all_marketplace_compatible_packs(),
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
    logger.info('TestCollector v20220913')
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
