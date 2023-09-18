import json
import os
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from enum import Enum
from pathlib import Path
from typing import Optional
from collections.abc import Iterable, Sequence

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions, CONTENT_ENTITIES_DIRS
from demisto_sdk.commands.common.tools import find_type, str2bool, get_yaml

from Tests.Marketplace.marketplace_services import get_last_commit_from_index
from Tests.scripts.collect_tests.constants import (
    DEFAULT_MARKETPLACE_WHEN_MISSING, IGNORED_FILE_TYPES, NON_CONTENT_FOLDERS,
    ONLY_INSTALL_PACK_FILE_TYPES, SANITY_TEST_TO_PACK, ONLY_UPLOAD_PACK_FILE_TYPES,
    SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK, XSOAR_SANITY_TEST_NAMES,
    ALWAYS_INSTALLED_PACKS_MAPPING, MODELING_RULE_COMPONENT_FILES, XSIAM_COMPONENT_FILES)
from Tests.scripts.collect_tests.exceptions import (
    DeprecatedPackException, IncompatibleMarketplaceException,
    InvalidTestException, NonDictException, NonXsoarSupportedPackException,
    NoTestsConfiguredException, NothingToCollectException,
    NotUnderPackException, PrivateTestException, SkippedPackException,
    SkippedTestException, TestMissingFromIdSetException,
    NonNightlyPackInNightlyBuildException)
from Tests.scripts.collect_tests.id_set import Graph, IdSet, IdSetItem
from Tests.scripts.collect_tests.logger import logger
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.test_conf import TestConf
from Tests.scripts.collect_tests.utils import (ContentItem, Machine,
                                               PackManager, find_pack_folder,
                                               find_yml_content_type, to_tuple, hotfix_detect_old_script_yml,
                                               FilesToCollect)
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
    DEFAULT_REPUTATION_TESTS = 'Indicator type file changed, running reputation tests from conf.json[\'reputation_tests\']'
    ALWAYS_INSTALLED_PACKS = 'packs that are always installed'
    PACK_TEST_DEPENDS_ON = 'a test depends on this pack'
    NON_XSOAR_SUPPORTED = 'support level is not xsoar: collecting the pack, not collecting tests'
    FILES_REMOVED_FROM_PACK = 'files were removed from this pack, installing to make sure it is not broken'
    MODELING_RULE_CHANGED = 'modeling rule changed'
    MODELING_RULE_XIF_CHANGED = 'modeling rule\'s associated xif file was changed'
    MODELING_RULE_SCHEMA_CHANGED = 'modeling rule\'s associated schema file was changed'
    MODELING_RULE_TEST_DATA_CHANGED = 'modeling rule\'s associated testdata file was changed'
    MODELING_RULE_NIGHTLY = 'nightly testing of modeling rules'
    DUMMY_OBJECT_FOR_COMBINING = 'creating an empty object, to combine two CollectionResult objects'
    XSIAM_COMPONENT_CHANGED = 'xsiam component was changed'
    README_FILE_CHANGED = 'readme file was changed'
    PACK_CHOSEN_TO_UPLOAD = 'pack chosen to upload'


REASONS_ALLOWING_NO_ID_SET_OR_CONF = {
    # these may be used without an id_set or conf.json object, see _validate_collection.
    CollectionReason.DUMMY_OBJECT_FOR_COMBINING,
    CollectionReason.ALWAYS_INSTALLED_PACKS
}


class CollectionResult:
    def __init__(
            self,
            test: str | None,
            modeling_rule_to_test: str | Path | None,  # path to dir of modeling rule to test
            pack: str | None,
            reason: CollectionReason,
            version_range: VersionRange | None,
            reason_description: str,
            conf: TestConf | None,
            id_set: IdSet | Graph | None,
            is_sanity: bool = False,
            is_nightly: bool = False,
            skip_support_level_compatibility: bool = False,
            only_to_install: bool = False,
            only_to_upload: bool = False,
    ):
        """
        Collected test playbook, and/or a pack to install.

        NOTE:   The constructor only accepts a single Optional[str] for test and pack, but they're kept as set[str].
                This is done to require a reason for every collection, which is logged.
                Use the + operator or CollectedTests.union() to join two or more objects and hold multiple tests.

        :param test: test playbook id
        :param modeling_rule_to_test: path to containing directory of a modeling rule that should be marked for
            testing, e.g. PackName/ModelingRules/MyModelingRule
        :param pack: pack name to install
        :param reason: CollectionReason explaining the collection
        :param version_range: XSOAR versions on which the content should be tested, matching the from/toversion fields.
        :param reason_description: free text elaborating on the collection, e.g. path of the changed file.
        :param conf: a ConfJson object. It may be None only when reason in VALIDATION_BYPASSING_REASONS.
        :param id_set: an IdSet object. It may be None only when reason in VALIDATION_BYPASSING_REASONS.
        :param is_sanity: whether the test is a sanity test. Sanity tests do not have to be in the id_set.
        :param is_nightly: whether the run is a nightly run. When running on nightly, only specific packs need to run.
        :param skip_support_level_compatibility:
                whether to install a pack, even if it is not directly compatible.
                This is used when collecting a pack containing a content item, when their marketplace values differ.
        :param only_to_install: whether to collect the pack only to install it without upload to the bucket.
        :param only_to_upload: whether to collect the pack only to upload it to the bucket without install.
        """
        self.tests: set[str] = set()
        self.modeling_rules_to_test: set[str | Path] = set()
        self.packs_to_install: set[str] = set()
        self.packs_to_upload: set[str] = set()
        self.version_range = None if version_range and version_range.is_default else version_range
        self.machines: tuple[Machine, ...] | None = None

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
                skip_support_level_compatibility=skip_support_level_compatibility,
            )

        except NonXsoarSupportedPackException:
            if test:
                logger.info(f'{pack} support level != XSOAR, not collecting {test}, pack will be installed')
                test = None

        except InvalidTestException as e:
            suffix = ' (pack will be installed)' if pack else ''
            logger.error(f'{str(e)}, not collecting {test}{suffix}')
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
            if only_to_upload == only_to_install:

                if only_to_upload and only_to_install:
                    raise ValueError(f"Packs can be collected for both to install and to upload. {pack=}, {reason}")

                self.packs_to_install = {pack}
                self.packs_to_upload = {pack}
                logger.info(f'collected {pack=}, {reason} ({reason_description}, {version_range=})')

            elif only_to_install:
                self.packs_to_install = {pack}
                logger.info(f'collected {pack=} only to install, {reason} ({reason_description}, {version_range=})')

            elif only_to_upload:
                self.packs_to_upload = {pack}
                logger.info(f'collected {pack=} only to upload, {reason} ({reason_description}, {version_range=})')

        if modeling_rule_to_test:
            self.modeling_rules_to_test = {modeling_rule_to_test}
            logger.info(f'collected {modeling_rule_to_test=}, {reason} ({reason_description}, {version_range=})')

    @staticmethod
    def _validate_collection(
            pack: str | None,
            test: str | None,
            reason: CollectionReason,
            conf: TestConf | None,
            id_set: IdSet | Graph | None,
            is_sanity: bool,
            is_nightly: bool,
            skip_support_level_compatibility: bool,
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

        if pack:
            try:
                PACK_MANAGER.validate_pack(pack)

            except NonXsoarSupportedPackException:
                if skip_support_level_compatibility:
                    logger.info(f'overriding pack support level compatibility check for {pack} - it IS collected')
                elif is_sanity and pack == 'HelloWorld':  # Sanity tests are saved under HelloWorld, so we allow it.
                    pass
                else:
                    raise

        if test:
            if not is_sanity:  # sanity tests do not show in the id_set
                if test not in id_set.id_to_test_playbook:  # type: ignore[union-attr]
                    raise TestMissingFromIdSetException(test)

                test_playbook = id_set.id_to_test_playbook[test]  # type: ignore[union-attr]
                if not (pack_id := test_playbook.pack_id):
                    raise ValueError(f'{test} has no pack_id')
                if not (playbook_path := test_playbook.path):
                    raise ValueError(f'{test} has no path')
                if PACK_MANAGER.is_test_skipped_in_pack_ignore(playbook_path.name, pack_id):
                    raise SkippedTestException(test, skip_place='.pack_ignore')
                for integration in test_playbook.implementing_integrations:
                    if reason := conf.skipped_integrations.get(integration):  # type: ignore[union-attr, assignment]
                        raise SkippedTestException(
                            test_name=test,
                            skip_place='conf.json (integrations)',
                            skip_reason=f'{test=} uses {integration=}, which is skipped ({reason=})'
                        )

            if skip_reason := conf.skipped_tests.get(test):  # type: ignore[union-attr]
                raise SkippedTestException(test, skip_place='conf.json (skipped_tests)', skip_reason=skip_reason)

            if test in conf.private_tests:  # type: ignore[union-attr]
                raise PrivateTestException(test)

        if is_nightly:
            if test and test in conf.non_api_tests:  # type: ignore[union-attr]
                return

            if pack and pack not in conf.nightly_packs:  # type: ignore[union-attr]
                raise NonNightlyPackInNightlyBuildException(pack)

    @staticmethod
    def __empty_result() -> 'CollectionResult':
        # used for combining two CollectionResult objects
        return CollectionResult(
            test=None, modeling_rule_to_test=None, pack=None, reason=CollectionReason.DUMMY_OBJECT_FOR_COMBINING,
            version_range=None, reason_description='', conf=None, id_set=None
        )

    def __add__(self, other: Optional['CollectionResult']) -> 'CollectionResult':
        # initial object just to add others to
        if not other:
            return self
        result = self.__empty_result()
        result.tests = self.tests | other.tests  # type: ignore[operator]
        result.modeling_rules_to_test = self.modeling_rules_to_test | other.modeling_rules_to_test
        result.packs_to_install = self.packs_to_install | other.packs_to_install  # type: ignore[operator]
        result.packs_to_upload = self.packs_to_upload | other.packs_to_upload
        result.version_range = self.version_range | other.version_range if self.version_range else other.version_range
        return result

    @staticmethod
    def union(collected_tests: Sequence[Optional['CollectionResult']] | None) -> Optional['CollectionResult']:
        non_none = filter(None, collected_tests or (None,))
        return sum(non_none, start=CollectionResult.__empty_result())

    def __repr__(self):
        return f'{len(self.packs_to_install)} packs, {len(self.packs_to_upload)} packs to upload, {len(self.tests)} tests, ' \
               f'{self.version_range=}'

    def __bool__(self):
        return bool(self.tests or self.packs_to_install or self.packs_to_upload)


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions, graph: bool = False):
        self.marketplace = marketplace
        self.id_set: IdSet | Graph
        if graph:
            self.id_set = Graph(marketplace)
        else:
            self.id_set = IdSet(marketplace, PATHS.id_set_path)
        self.conf = TestConf(PATHS.conf_path)
        self.trigger_sanity_tests = False

    @property
    def sanity_tests(self) -> CollectionResult:
        return CollectionResult.union(tuple(  # type: ignore[return-value]
            CollectionResult(
                test=test,
                modeling_rule_to_test=None,
                pack=SANITY_TEST_TO_PACK.get(test),  # None in most cases
                reason=CollectionReason.SANITY_TESTS,
                version_range=None,
                reason_description=f'by marketplace version {self.marketplace}',
                conf=self.conf,
                id_set=self.id_set,
                is_sanity=True,
                only_to_install=True,
            )
            for test in self._sanity_test_names
        ))

    @property
    def _always_installed_packs(self) -> CollectionResult | None:
        always_installed_packs_list = ALWAYS_INSTALLED_PACKS_MAPPING[self.marketplace]
        return CollectionResult.union(tuple(
            CollectionResult(test=None, modeling_rule_to_test=None, pack=pack,
                             reason=CollectionReason.ALWAYS_INSTALLED_PACKS,
                             version_range=None, reason_description=pack, conf=None, id_set=None, is_sanity=True,
                             only_to_install=True)
            for pack in always_installed_packs_list)
        )

    @property
    def _sanity_test_names(self) -> tuple[str, ...]:
        match self.marketplace:
            case MarketplaceVersions.MarketplaceV2:
                return tuple(self.conf['test_marketplacev2'])
            case MarketplaceVersions.XSOAR:
                return XSOAR_SANITY_TEST_NAMES
            case MarketplaceVersions.XPANSE:
                return ()  # none at the moment
            case _:
                raise RuntimeError(f'unexpected marketplace value {self.marketplace.value}')

    @abstractmethod
    def _collect(self) -> CollectionResult | None:
        """
        Collects all relevant tests and packs.
        Every subclass implements its own methodology here.
        :return: A CollectedTests object with only the pack_name_to_pack_metadata to install and tests to run,
                with machines=None.
        """

    def collect(self) -> CollectionResult | None:
        result: CollectionResult | None = self._collect()

        if not result:
            if self.trigger_sanity_tests:
                result = self.sanity_tests
                logger.warning('Nothing was collected, but sanity-test-triggering files were changed, '
                               'returning sanity tests')
            else:
                logger.warning('Nothing was collected, and no sanity-test-triggering files were changed')
                return None

        self._validate_tests_in_id_set(result.tests)  # type: ignore[union-attr]
        if result.packs_to_install:
            result += self._always_installed_packs  # type: ignore[operator]
        result += self._collect_test_dependencies(result.tests if result else ())  # type: ignore[union-attr]
        result.machines = Machine.get_suitable_machines(result.version_range)  # type: ignore[union-attr]

        return result

    def _collect_test_dependencies(self, test_ids: Iterable[str]) -> CollectionResult | None:
        result = []

        for test_id in test_ids:
            if not (test_object := self.conf.get_test(test_id)):
                # todo prevent this case, see CIAC-4006
                continue

            # collect the pack containing the test playbook
            pack_id = self.id_set.id_to_test_playbook[test_id].pack_id
            result.append(self._collect_pack(
                pack_id=pack_id,  # type: ignore[arg-type]
                reason=CollectionReason.PACK_TEST_DEPENDS_ON,
                reason_description=f'test {test_id} is saved under pack {pack_id}',
                content_item_range=test_object.version_range,
                allow_incompatible_marketplace=True,  # allow xsoar&xsiam packs
                only_to_install=True
            ))

            # collect integrations used in the test
            for integration in test_object.integrations:
                if integration_object := self.id_set.id_to_integration.get(integration):
                    pack_id = integration_object.pack_id
                    result.append(self._collect_test_dependency(
                        dependency_name=integration,
                        test_id=test_id,
                        pack_id=pack_id,  # type: ignore[arg-type]
                        dependency_type='integration',
                    ))
                else:
                    logger.warning(f'could not find integration {integration} in id_set'
                                   f' when searching for integrations the {test_id} test depends on')

            # collect scripts used in the test
            for script in test_object.scripts:
                if script_object := self.id_set.id_to_script.get(script):
                    pack_id = script_object.pack_id
                    result.append(self._collect_test_dependency(
                        dependency_name=script,
                        test_id=test_id,
                        pack_id=pack_id,  # type: ignore[arg-type]
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
            modeling_rule_to_test=None,
            pack=pack_id,
            reason=CollectionReason.PACK_TEST_DEPENDS_ON,
            version_range=None,
            reason_description=f'test {test_id} depends on {dependency_type} {dependency_name} from {pack_id}',
            conf=self.conf,
            id_set=self.id_set,
            only_to_install=True,
        )

    def _collect_all_marketplace_compatible_packs(self, is_nightly) -> CollectionResult | None:
        result = []
        for pack_metadata in PACK_MANAGER.iter_pack_metadata():
            try:
                result.append(self._collect_pack(
                    pack_id=pack_metadata.pack_id,
                    reason=CollectionReason.PACK_MARKETPLACE_VERSION_VALUE,
                    reason_description=self.marketplace.value,
                    allow_incompatible_marketplace=False,
                    is_nightly=is_nightly,
                ))
            except (NothingToCollectException, NonXsoarSupportedPackException, IncompatibleMarketplaceException) as e:
                logger.debug(str(e))
        return CollectionResult.union(result)

    def _collect_specific_marketplace_compatible_packs(self, packs_to_upload) -> CollectionResult | None:
        result = []
        for pack_id in packs_to_upload:
            try:
                result.append(self._collect_pack(
                    pack_id=pack_id,
                    reason=CollectionReason.PACK_CHOSEN_TO_UPLOAD,
                    reason_description="",
                    allow_incompatible_marketplace=False,
                ))
            except (NothingToCollectException, NonXsoarSupportedPackException, IncompatibleMarketplaceException) as e:
                logger.debug(str(e))
        return CollectionResult.union(result)

    def __validate_compatibility(
            self,
            id_: str,
            pack_id: str,
            marketplaces: tuple[MarketplaceVersions, ...] | None,
            path: Path,
            version_range: VersionRange | None,
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
            self.__validate_deprecated_integration(path)
        pack_marketplaces = PACK_MANAGER.get_pack_metadata(pack_id).marketplaces
        self.__validate_marketplace_compatibility(marketplaces or pack_marketplaces or (), path)
        self.__validate_support_level_is_xsoar(pack_id, version_range)

    def _validate_path(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(path)

        self.__validate_triggering_sanity_test(path)
        self.__validate_not_ignored_file(path)

    def _validate_content_item_compatibility(self, content_item: ContentItem, is_integration: bool) -> None:
        object_id = content_item.id_
        self.__validate_compatibility(
            id_=object_id,  # type: ignore[arg-type]
            pack_id=content_item.pack_id,
            marketplaces=content_item.marketplaces,
            path=content_item.path,
            version_range=content_item.version_range,
            is_integration=is_integration,
        )

    def _validate_id_set_item_compatibility(self, id_set_item: IdSetItem, is_integration: bool) -> None:
        if not (pack_id := id_set_item.pack_id or find_pack_folder(id_set_item.path).name):  # type: ignore[arg-type]
            raise RuntimeError(f'could not find pack of {id_set_item.name}')
        object_id = id_set_item.id_
        path = id_set_item.path
        self.__validate_compatibility(
            id_=object_id,  # type: ignore[arg-type]
            pack_id=pack_id,  # type: ignore[arg-type]
            marketplaces=id_set_item.marketplaces,
            path=path,  # type: ignore[arg-type]
            version_range=id_set_item.version_range,
            is_integration=is_integration,
        )

    def _collect_pack(
            self,
            pack_id: str,
            reason: CollectionReason,
            reason_description: str,
            content_item_range: VersionRange | None = None,
            allow_incompatible_marketplace: bool = False,
            is_nightly: bool = False,
            only_to_install: bool = False,
    ) -> CollectionResult | None:
        pack_metadata = PACK_MANAGER.get_pack_metadata(pack_id)
        collect_only_to_upload: bool = False

        try:
            self._validate_content_item_compatibility(pack_metadata, is_integration=False)
        except NonXsoarSupportedPackException as e:
            # we do want to install packs in this case (tests are not collected in this case anyway)
            logger.info(f'pack {pack_id} has support level {e.support_level} (not xsoar), '
                        f'collecting to make sure it is installed properly.')
        except IncompatibleMarketplaceException:
            is_xsoar_and_xsiam_pack = MarketplaceVersions.XSOAR in (pack_metadata.marketplaces or ()) and \
                MarketplaceVersions.MarketplaceV2 in (pack_metadata.marketplaces or ())

            # collect only to upload if:
            # 1. collecting for marketplacev2 and pack is XSOAR & XSIAM - we want it to be uploaded but not installed
            # 2. allow_incompatible_marketplace=False, if True, then should be also to install
            if self.marketplace == MarketplaceVersions.MarketplaceV2 and is_xsoar_and_xsiam_pack and \
                    not allow_incompatible_marketplace:
                collect_only_to_upload = True

            # sometimes, we want to install or upload packs that are not compatible (e.g. pack belongs to both marketplaces)
            # because they have content that IS compatible.
            # But still need to avoid collecting packs that belongs to one marketplace when collecting to the other marketplace.
            if (not allow_incompatible_marketplace or (allow_incompatible_marketplace and not is_xsoar_and_xsiam_pack)) \
                    and not collect_only_to_upload:
                raise

        # If changes are done to README files. Upload only.
        if reason == CollectionReason.README_FILE_CHANGED:
            collect_only_to_upload = True

        version_range = content_item_range \
            if pack_metadata.version_range.is_default \
            else (pack_metadata.version_range | content_item_range)

        return CollectionResult(
            test=None,
            modeling_rule_to_test=None,
            pack=pack_id,
            reason=reason,
            version_range=version_range,
            reason_description=reason_description,
            conf=self.conf,
            id_set=self.id_set,
            is_nightly=is_nightly,
            only_to_upload=collect_only_to_upload,
            only_to_install=only_to_install
        )

    def _collect_pack_for_modeling_rule(
        self, pack_id: str, reason_description: str, changed_file_path: Path,
        content_item_range: VersionRange | None = None, is_nightly: bool = False,
        reason: CollectionReason | None = None
    ) -> CollectionResult:
        """Create a CollectionResult for a pack because of a modeling rule

        Marks the pack being collected and the modeling rule that needs to be tested

        Args:
            pack_id (str): the id of the pack being collected
            reason (Optional[CollectionReason]): the reason the pack is being collected. Defaults to None.
            reason_description (str): the reason the pack is being collected
            changed_file_path (Path): the path to the file that was modified
            content_item_range (Optional[VersionRange], optional): version range. Defaults to None.
            is_nightly (Optional[bool]): whether this is a nightly flow. Defaults to False.

        Returns:
            CollectionResult: the object detailing the pack to collect and the modeling rule that should be tested
        """
        if self.marketplace != MarketplaceVersions.MarketplaceV2:
            logger.info(f'Not collecting pack {pack_id} for Modeling Rule {changed_file_path} because '
                        f'it is not a collection for an XSIAM (MarketplaceV2) marketplace - '
                        f'marketplace is {self.marketplace}')
            raise NothingToCollectException(changed_file_path, 'packs for Modeling Rules are only collected for XSIAM')

        pack = PACK_MANAGER.get_pack_metadata(pack_id)

        version_range = content_item_range \
            if pack.version_range.is_default \
            else (pack.version_range | content_item_range)

        if not reason:
            file_type = find_type(changed_file_path.as_posix())
            if file_type == FileType.MODELING_RULE:
                reason = CollectionReason.MODELING_RULE_CHANGED
            elif file_type == FileType.MODELING_RULE_SCHEMA:
                reason = CollectionReason.MODELING_RULE_SCHEMA_CHANGED
            elif file_type == FileType.MODELING_RULE_TEST_DATA:
                reason = CollectionReason.MODELING_RULE_TEST_DATA_CHANGED
            elif file_type == FileType.MODELING_RULE_XIF:
                reason = CollectionReason.MODELING_RULE_XIF_CHANGED
            else:  # pragma: no cover
                raise RuntimeError(f'Unexpected file type {file_type} for changed file {changed_file_path}')
        # the modeling rule to test will be the containing directory of the modeling rule's component files
        relative_path_of_mr = PACK_MANAGER.relative_to_packs(changed_file_path)
        modeling_rule_to_test = relative_path_of_mr.parent
        return CollectionResult(
            test=None,
            modeling_rule_to_test=modeling_rule_to_test,
            pack=pack_id,
            reason=reason,
            version_range=version_range,
            reason_description=reason_description,
            conf=self.conf,
            id_set=self.id_set,
            is_nightly=is_nightly
        )

    def _collect_pack_for_xsiam_component(
        self, pack_id: str, reason_description: str, changed_file_path: Path,
        content_item_range: VersionRange | None = None, is_nightly: bool = False,
        reason: CollectionReason | None = None
    ) -> CollectionResult:
        """Create a CollectionResult for a pack because of an xsiam component.

        Marks the pack being collected and the modeling rule that needs to be tested

        Args:
            pack_id (str): the id of the pack being collected
            reason (Optional[CollectionReason]): the reason the pack is being collected. Defaults to None.
            reason_description (str): the reason the pack is being collected
            changed_file_path (Path): the path to the file that was modified
            content_item_range (Optional[VersionRange], optional): version range. Defaults to None.
            is_nightly (Optional[bool]): whether this is a nightly flow. Defaults to False.

        Returns:
            CollectionResult: the object detailing the pack to collect and the modeling rule that should be tested
        """
        # Not validating compatibility with function so xsoar & marketplacev2 supported packs will be installed if needed.
        if self.marketplace != MarketplaceVersions.MarketplaceV2:
            logger.info(f'Not collecting pack {pack_id} for XSIAM component {changed_file_path} because '
                        f'it is not a collection for an XSIAM (MarketplaceV2) marketplace - '
                        f'marketplace is {self.marketplace}')
            raise NothingToCollectException(changed_file_path, 'packs for XSIAM components are only collected for XSIAM')

        pack = PACK_MANAGER.get_pack_metadata(pack_id)

        version_range = content_item_range \
            if pack.version_range.is_default \
            else (pack.version_range | content_item_range)

        if not reason:
            file_type = find_type(changed_file_path.as_posix())
            reason = CollectionReason.XSIAM_COMPONENT_CHANGED
            reason_description = file_type.value

        return CollectionResult(
            test=None,
            modeling_rule_to_test=None,
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

    @staticmethod
    def __validate_deprecated_integration(path: Path):
        if path.suffix == '.yml' and get_yaml(path).get('deprecated'):
            raise NothingToCollectException(path, 'integration is deprecated')

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
    def __validate_support_level_is_xsoar(pack_id: str, content_item_range: VersionRange | None) -> None:
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
                # For XSIAM machines we collect tests that have not xsoar marketplace.
                # Tests for the packs that has only mpv2, or mpv2 and xpanse marketplaces,
                # will run on xsiam machines only.
                # However only xsiam component files will be collected anyway in
                # _collect_xsiam_and_modeling_pack function.
                if (MarketplaceVersions.MarketplaceV2 not in content_item_marketplaces) or \
                        (MarketplaceVersions.XSOAR in content_item_marketplaces):
                    raise IncompatibleMarketplaceException(content_item_path, self.marketplace)
            case MarketplaceVersions.XSOAR | MarketplaceVersions.XPANSE:
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
            service_account: str | None,
            private_pack_path: str | None = None,
            graph: bool = False,
    ):
        """

        :param branch_name: branch name
        :param marketplace: marketplace value
        :param service_account: used for comparing with the latest upload bucket
        :param private_pack_path: path to a pack, only used for content-private.
        """
        super().__init__(marketplace, graph)
        logger.debug(f'Created BranchTestCollector for {branch_name}')
        self.branch_name = branch_name
        self.service_account = service_account
        self.private_pack_path: Path | None = Path(private_pack_path) if private_pack_path else None

    def _get_private_pack_files(self) -> tuple[str, ...]:
        if not self.private_pack_path:
            raise RuntimeError('private_pack_path cannot be empty')
        return tuple(str(path) for path in self.private_pack_path.rglob('*') if path.is_file())

    def _collect(self) -> CollectionResult | None:
        collect_from = FilesToCollect(changed_files=self._get_private_pack_files(),
                                      pack_ids_files_were_removed_from=()) \
            if self.private_pack_path \
            else self._get_git_diff()

        return CollectionResult.union([
            self.__collect_from_changed_files(collect_from.changed_files),
            self.__collect_packs_from_which_files_were_removed(collect_from.pack_ids_files_were_removed_from)
        ])

    def __collect_from_changed_files(self, changed_files: tuple[str, ...]) -> CollectionResult | None:
        """NOTE: this should only be used from _collect"""
        collected = []
        for raw_path in changed_files:
            path = PATHS.content_path / raw_path
            logger.debug(f'Collecting tests for {raw_path}')
            try:
                collected.append(self._collect_single(path))
            except NonXsoarSupportedPackException as e:
                collected.append(self._collect_pack(
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
        return CollectionResult.union(collected)

    def __collect_packs_from_which_files_were_removed(self, pack_ids: tuple[str, ...]) -> CollectionResult | None:
        """NOTE: this should only be used from _collect"""
        collected: list[CollectionResult] = []
        for pack_id in pack_ids:
            logger.info(f'one or more files were removed from the {pack_id} pack, attempting to collect the pack.')
            try:
                if pack_to_collect := self._collect_pack(pack_id=pack_id,
                                                         reason=CollectionReason.FILES_REMOVED_FROM_PACK,
                                                         reason_description='',
                                                         ):
                    collected.append(pack_to_collect)
            except NothingToCollectException as e:
                logger.info(e.message)
            except Exception as e:
                logger.exception(f'Error while collecting tests for {pack_id=}', exc_info=True, stack_info=True)
                raise e
        return CollectionResult.union(collected)

    def _collect_yml(self, content_item_path: Path) -> CollectionResult | None:
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
        override_support_level_compatibility = False

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
                    override_support_level_compatibility = True
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
                        override_support_level_compatibility = True
            case _:
                raise RuntimeError(f'Unexpected content type {actual_content_type.value} for {content_item_path}'
                                   f'(expected `Integrations`, `Scripts` or `Playbooks`)')
        if tests:
            return CollectionResult.union(tuple(
                CollectionResult(
                    test=test,
                    modeling_rule_to_test=None,
                    pack=yml.pack_id,
                    reason=reason,
                    version_range=yml.version_range,
                    reason_description=f'{yml.id_=} ({relative_yml_path})',
                    conf=self.conf,
                    id_set=self.id_set,
                    is_nightly=False,
                    skip_support_level_compatibility=override_support_level_compatibility,
                ) for test in tests))
        else:
            return self._collect_pack(
                pack_id=yml.pack_id,
                reason=reason,
                reason_description='collecting pack only',
                content_item_range=yml.version_range,
                allow_incompatible_marketplace=override_support_level_compatibility,
            )

    def _collect_xsiam_and_modeling_pack(self,
                                         file_type: FileType | None,
                                         pack_id: str, reason_description: str,
                                         path: Path,
                                         content_item_range: VersionRange | None) -> CollectionResult | None:
        if file_type in MODELING_RULE_COMPONENT_FILES:
            # mark pack for installation and mark the modeling rule for dynamic testing
            return self._collect_pack_for_modeling_rule(
                pack_id=pack_id, reason_description=reason_description,
                changed_file_path=path, content_item_range=content_item_range
            )

        # if the file is an xsiam component and is not a modeling rule
        return self._collect_pack_for_xsiam_component(
            pack_id=pack_id, reason_description=reason_description,
            changed_file_path=path, content_item_range=content_item_range
        )

    def _collect_single(self, path: Path) -> CollectionResult | None:
        self._validate_path(path)

        file_type = find_type(str(path))

        if file_type in IGNORED_FILE_TYPES:
            raise NothingToCollectException(path, f'ignored type {file_type}')

        if file_type is None and path.parent.name not in CONTENT_ENTITIES_DIRS:
            raise NothingToCollectException(
                path,
                f'file of unknown type, and not directly under a content directory ({path.parent.name})')

        content_item = None
        try:
            content_item = ContentItem(path)
            self._validate_content_item_compatibility(content_item, is_integration='Integrations' in path.parts)
        except IncompatibleMarketplaceException:
            if file_type not in (MODELING_RULE_COMPONENT_FILES | XSIAM_COMPONENT_FILES):
                raise
        except NonDictException:
            content_item = None  # py, md, etc. Anything not dictionary-based. Suitable logic follows, see collect_yml

        pack_id = find_pack_folder(path).name
        reason_description = relative_path = PACK_MANAGER.relative_to_packs(path)

        if file_type in ONLY_INSTALL_PACK_FILE_TYPES:
            content_item_range = content_item.version_range if content_item else None

            if file_type in (MODELING_RULE_COMPONENT_FILES | XSIAM_COMPONENT_FILES):
                return self._collect_xsiam_and_modeling_pack(
                    file_type=file_type, pack_id=pack_id, reason_description=reason_description,
                    path=path, content_item_range=content_item_range
                )

            else:
                # install pack without collecting tests.
                return self._collect_pack(
                    pack_id=pack_id,
                    reason=CollectionReason.NON_CODE_FILE_CHANGED,
                    reason_description=reason_description,
                    content_item_range=content_item.version_range if content_item else None
                )

        if file_type in ONLY_UPLOAD_PACK_FILE_TYPES:
            return self._collect_pack(
                pack_id=pack_id,
                reason=CollectionReason.README_FILE_CHANGED,
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
                    reason_description=e.support_level or "xsoar",
                )

        if file_type in {FileType.PYTHON_FILE, FileType.POWERSHELL_FILE, FileType.JAVASCRIPT_FILE}:
            if path.name.lower().endswith(('_test.py', 'tests.ps1')):
                raise NothingToCollectException(path, 'changing unit tests does not trigger collection')
            return self._collect_yml(path)

        elif file_type == FileType.REPUTATION:
            tests = self.conf['reputation_tests']
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
                modeling_rule_to_test=None,
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

    def _get_git_diff(self) -> FilesToCollect:
        repo = PATHS.content_repo
        changed_files: list[str] = []
        packs_files_were_removed_from: set[str] = set()

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

        elif os.getenv('EXTRACT_PRIVATE_TESTDATA'):
            logger.info('considering extracted private test data')
            private_test_data = tuple(filter(lambda f: f.startswith('Packs/'), repo.untracked_files))
            changed_files.extend(private_test_data)

        diff = repo.git.diff(f'{previous_commit}...{current_commit}', '--name-status')
        logger.debug(f'raw changed files string:\n{diff}')

        # diff is formatted as `M  foo.json\n A  bar.py\n ...`, turning it into ('foo.json', 'bar.py', ...).
        for line in diff.splitlines():
            match len(parts := line.split('\t')):
                case 2:
                    git_status, file_path = parts
                case 3:
                    git_status, old_file_path, file_path = parts  # R <old location> <new location>

                    if git_status.startswith('R'):
                        logger.debug(f'{git_status=} for {file_path=}, considering it as <M>odified')
                        git_status = 'M'

                    if pack_file_removed_from := find_pack_file_removed_from(Path(old_file_path), Path(file_path)):
                        packs_files_were_removed_from.add(pack_file_removed_from)

                case _:
                    raise ValueError(f'unexpected line format '
                                     f'(expected `<modifier>\t<file>` or `<modifier>\t<old_location>\t<new_location>`'
                                     f', got {line}')

            if git_status not in {'A', 'M', 'D', }:
                logger.warning(f'unexpected {git_status=}, considering it as <M>odified')

            if git_status == 'D':  # git-deleted file
                if pack_file_removed_from := find_pack_file_removed_from(Path(file_path), None):
                    packs_files_were_removed_from.add(pack_file_removed_from)
                continue  # not adding to changed files list

            changed_files.append(file_path)  # non-deleted files (added, modified)
        return FilesToCollect(changed_files=tuple(changed_files),
                              pack_ids_files_were_removed_from=tuple(packs_files_were_removed_from))


def find_pack_file_removed_from(old_path: Path, new_path: Path | None = None):
    """
    If a file is moved between packs, we should collect the older one, to make sure it is installed properly.
    """
    # two try statements as we need to tell which of the two is a pack, separately.
    try:
        old_pack = find_pack_folder(old_path).name
    except NotUnderPackException:
        logger.debug(f'Skipping pack collection for removed file: {old_path}, as it does not belong to any pack')
        return None  # not moved from a pack, no special treatment we can do here.

    if new_path:
        try:
            new_pack = find_pack_folder(new_path).name
        except NotUnderPackException:
            new_pack = None
            logger.warning(f'Could not find the new pack of the file that was moved from {old_path}')

        if old_pack != new_pack:  # file moved between packs
            logger.info(f'file {old_path.name} was moved '
                        f'from pack {old_pack}, adding it, to make sure it still installs properly')
    else:
        # Since new_path is None we understand the item was deleted
        logger.info(f'file {old_path.name} was deleted '  # changing log
                    f'from pack {old_pack}, adding it, to make sure it still installs properly')

    return old_pack


class UploadBranchCollector(BranchTestCollector):
    def _collect(self) -> CollectionResult | None:
        # same as BranchTestCollector, but without tests.
        if result := super()._collect():
            logger.info('UploadCollector drops collected tests, as they are not required')
            result.tests = set()
        return result


class SpecificPacksTestCollector(TestCollector):
    def __init__(
            self,
            packs_to_upload: str,
            marketplace: MarketplaceVersions,
            graph: bool = False,
    ):
        super().__init__(marketplace, graph=graph)
        self.packs_to_upload = packs_to_upload

    def _collect(self) -> CollectionResult | None:
        result: CollectionResult | None = super()._collect_specific_marketplace_compatible_packs(self.packs_to_upload)
        return result


class NightlyTestCollector(TestCollector, ABC):
    def collect(self) -> CollectionResult | None:
        result: CollectionResult | None = super().collect()

        logger.info('NightlyCollector drops packs to upload, as they don\'t need to be uploaded')
        if result:
            result.packs_to_upload = set()
        return result

    def _id_set_tests_matching_marketplace_value(self) -> CollectionResult | None:
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
                    modeling_rule_to_test=None,
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


class UploadAllCollector(TestCollector):
    def _collect(self) -> CollectionResult | None:
        return self._collect_all_marketplace_compatible_packs(is_nightly=False)


class XSIAMNightlyTestCollector(NightlyTestCollector):
    def __init__(self, graph: bool = False):
        super().__init__(MarketplaceVersions.MarketplaceV2, graph=graph)

    def _collect_packs_of_content_matching_marketplace_value(self) -> CollectionResult | None:
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

                marketplaces_string = ', '.join(map(str, item.marketplaces or ()))
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

    def _collect_modeling_rule_packs(self) -> CollectionResult | None:
        """Collect packs that are XSIAM compatible and have a modeling rule with a testdata file.

        Returns:
            Optional[CollectionResult]: pack collection result.
        """
        result = []
        for modeling_rule in self.id_set.modeling_rules:
            try:
                logger.debug(f'collecting modeling rule with id: {modeling_rule.id_}, with name: {modeling_rule.name}')
                path = PATHS.content_path / modeling_rule.file_path_str
                pack_id = modeling_rule.pack_id
                result.append(self._collect_pack_for_modeling_rule(
                    pack_id=pack_id,  # type: ignore[arg-type]
                    changed_file_path=path,
                    reason=CollectionReason.MODELING_RULE_NIGHTLY,
                    reason_description=f'{modeling_rule.file_path_str} ({modeling_rule.id_})',
                    content_item_range=modeling_rule.version_range,
                    is_nightly=True,
                ))
            except (NothingToCollectException, NonXsoarSupportedPackException) as e:
                logger.debug(str(e))

        return CollectionResult.union(result)

    @property
    def sanity_tests(self) -> CollectionResult:
        return CollectionResult.union(tuple(
            CollectionResult(
                test=test,
                pack=SANITY_TEST_TO_PACK.get(test),  # None in most cases
                modeling_rule_to_test=None,
                reason=CollectionReason.SANITY_TESTS,
                version_range=None,
                reason_description='XSIAM Nightly sanity',
                conf=self.conf,
                id_set=self.id_set,
                is_sanity=True,
                only_to_install=True
            )
            for test in self.conf['test_marketplacev2']
        ))  # type: ignore[return-value]

    def _collect(self) -> CollectionResult | None:
        return CollectionResult.union((
            self._id_set_tests_matching_marketplace_value(),
            self._collect_all_marketplace_compatible_packs(is_nightly=True),
            self._collect_packs_of_content_matching_marketplace_value(),
            self._collect_modeling_rule_packs(),
            self.sanity_tests,  # XSIAM nightly always collects its sanity test(s)
        ))


class XSOARNightlyTestCollector(NightlyTestCollector):
    def __init__(self, graph: bool = False):
        super().__init__(MarketplaceVersions.XSOAR, graph=graph)

    def _collect(self) -> CollectionResult | None:
        return CollectionResult.union((
            self._id_set_tests_matching_marketplace_value(),
            self._collect_all_marketplace_compatible_packs(is_nightly=True),
        ))


def output(result: CollectionResult | None):
    """
    writes to both log and files
    """
    tests = sorted(result.tests, key=lambda x: x.lower()) if result else ()
    packs_to_install = sorted(result.packs_to_install, key=lambda x: x.lower()) if result else ()
    packs_to_upload = sorted(result.packs_to_upload, key=lambda x: x.lower()) if result else ()
    modeling_rules_to_test = sorted(
        result.modeling_rules_to_test, key=lambda x: x.casefold() if isinstance(x, str) else x.as_posix().casefold()
    ) if result else ()
    modeling_rules_to_test = (x.as_posix() if isinstance(x, Path) else str(x) for x in modeling_rules_to_test)
    machines = result.machines if result and result.machines else ()

    test_str = '\n'.join(tests)
    packs_to_install_str = '\n'.join(packs_to_install)
    packs_to_upload_str = '\n'.join(packs_to_upload)
    modeling_rules_to_test_str = '\n'.join(modeling_rules_to_test)
    machine_str = ', '.join(sorted(map(str, machines)))

    logger.info(f'collected {len(tests)} test playbooks:\n{test_str}')
    logger.info(f'collected {len(packs_to_install)} packs to install:\n{packs_to_install_str}')
    logger.info(f'collected {len(packs_to_upload)} packs to upload:\n{packs_to_upload_str}')
    num_of_modeling_rules = len(modeling_rules_to_test_str.split("\n"))
    logger.info(f'collected {num_of_modeling_rules} modeling rules to test:\n{modeling_rules_to_test_str}')
    logger.info(f'collected {len(machines)} machines: {machine_str}')

    PATHS.output_tests_file.write_text(test_str)
    PATHS.output_packs_file.write_text(packs_to_install_str)
    PATHS.output_packs_to_upload_file.write_text(packs_to_upload_str)
    PATHS.output_modeling_rules_to_test_file.write_text(modeling_rules_to_test_str)
    PATHS.output_machines_file.write_text(json.dumps({str(machine): (machine in machines) for machine in Machine}))


class XPANSENightlyTestCollector(NightlyTestCollector):
    def __init__(self, graph: bool = False):
        super().__init__(MarketplaceVersions.XPANSE, graph=graph)

    def _collect(self) -> CollectionResult | None:
        logger.info('tests are not currently supported for XPANSE, returning nothing.')
        return None


if __name__ == '__main__':
    logger.info('TestCollector v20230123')
    sys.path.append(str(PATHS.content_path))
    parser = ArgumentParser()
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly')
    parser.add_argument('-p', '--changed_pack_path', type=str,
                        help='Path to a changed pack. Used for private content')
    parser.add_argument('-mp', '--marketplace', type=MarketplaceVersions, help='marketplace version',
                        default='xsoar')
    parser.add_argument('--service_account', help="Path to gcloud service account")
    parser.add_argument('--graph', '-g', type=str2bool, help='Should use graph', default=False, required=False)
    parser.add_argument('--override_all_packs', '-a', type=str2bool, help='Collect all packs if override upload', default=False,
                        required=False)
    parser.add_argument('-up', '--pack_names', help="Packs to upload, will only collect what is related to them", default='',
                        required=False)

    args = parser.parse_args()
    args_string = '\n'.join(f'{k}={v}' for k, v in vars(args).items())

    logger.debug(f'parsed args:\n{args_string}')
    logger.debug('CONTRIB_BRANCH=' + os.getenv('CONTRIB_BRANCH', '<undefined>'))
    branch_name = PATHS.content_repo.active_branch.name

    marketplace = MarketplaceVersions(args.marketplace)
    if marketplace == MarketplaceVersions.XSOAR_SAAS:
        # When collecting test xsoar is equivalent to xsoar saas
        marketplace = MarketplaceVersions.XSOAR

    nightly = args.nightly
    service_account = args.service_account
    graph = args.graph
    pack_to_upload = args.pack_names
    collector: TestCollector

    if args.changed_pack_path:
        collector = BranchTestCollector('master', marketplace, service_account, args.changed_pack_path, graph=graph)

    elif os.environ.get("IFRA_ENV_TYPE") == 'Bucket-Upload':
        if args.override_all_packs:
            collector = UploadAllCollector(marketplace, graph)
        elif pack_to_upload:
            collector = SpecificPacksTestCollector(pack_to_upload.split(','), marketplace, graph)
        else:
            collector = UploadBranchCollector(branch_name, marketplace, service_account, graph=graph)

    else:
        match (nightly, marketplace):
            case False, _:  # not nightly
                collector = BranchTestCollector(branch_name, marketplace, service_account, graph=graph)
            case True, MarketplaceVersions.XSOAR:
                collector = XSOARNightlyTestCollector(graph=graph)
            case True, MarketplaceVersions.MarketplaceV2:
                collector = XSIAMNightlyTestCollector(graph=graph)
            case True, MarketplaceVersions.XPANSE:
                collector = XPANSENightlyTestCollector(graph=graph)
            case _:
                raise ValueError(f"unexpected values of {marketplace=} and/or {nightly=}")

    collected = collector.collect()
    output(collected)  # logs and writes to output files
