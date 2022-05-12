import json

import functools

import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from itertools import islice, chain
from pathlib import Path
from typing import Any, Iterable, Optional

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions
from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.common.tools import find_type_by_path, get_file, get_remote_file, yaml, json
from git import Repo
from packaging import version
from packaging.version import Version

from Tests.scripts.collect_tests.constants import (CONTENT_PATH,
                                                   DEBUG_CONF_PATH,
                                                   DEBUG_ID_SET_PATH,
                                                   IGNORED_FILES, MASTER,
                                                   PACKS_PATH, SKIPPED_PACKS, CODE_FILE_TYPES)
from Tests.scripts.collect_tests.exceptions import (IgnoredPackException,
                                                    InvalidPackNameException,
                                                    SkippedPackException, InexistentPackException)
from logging import getLogger, DEBUG, WARNING, ERROR

logger = getLogger()
logger.level = DEBUG

PACK_NAMES = {p.name for p in PACKS_PATH.glob('*') if p.is_dir()}
COMMIT = 'ds-test-collection'


class CollectionReason(Enum):
    # todo remove unused
    MARKETPLACE_VERSION_BY_VALUE = 'value of the test `marketplace` field'
    MARKETPLACE_VERSION_SECTION = 'listed under conf.json marketplace-specific section'
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


class DictBased:
    def __init__(self, dict_: dict):
        self.content = dict_
        self.from_version = self._calculate_from_version()
        self.to_version = self._calculate_to_version()
        self.version_range = VersionRange(self.from_version, self.to_version)

    def get(self, key: str, default: Any = None, warn_if_missing: bool = True):
        if key not in self.content and warn_if_missing:
            logger.warning(f'attempted to access key {key}, which does not exist')
        return self.content.get(key, default)

    def __getitem__(self, key):
        return self.content[key]

    def _calculate_from_version(self) -> Version:
        if value := (
                self.get('fromversion', warn_if_missing=False)
                or self.get('fromVersion', warn_if_missing=False)
                or self.get('fromServerVersion', warn_if_missing=False)
        ):
            return Version(value)
        return version.NegativeInfinity

    def _calculate_to_version(self) -> Version:
        if value := (
                self.get('toversion', warn_if_missing=False)
                or self.get('toVersion', warn_if_missing=False)
                or self.get('toServerVersion', warn_if_missing=False)
        ):
            return Version(value)
        return version.Infinity


@dataclass
class VersionRange:
    min_version: Version
    max_version: Version

    def __contains__(self, item):
        return self.min_version <= item <= self.max_version

    def __repr__(self):
        return f'{self.min_version} -> {self.max_version}'

    def __or__(self, other: 'VersionRange') -> 'VersionRange':
        if other is None or other.is_default or self.is_default:
            return self

        self.min_version = min(self.min_version, other.min_version)
        self.max_version = max(self.max_version, other.max_version)

        return self

    @property
    def is_default(self):
        return self.min_version == version.NegativeInfinity and self.max_version == version.Infinity


class NonDictException(Exception):
    def __init__(self, path: Path):
        self.message = path
        super().__init__(self.message)


class DictFileBased(DictBased):
    def __init__(self, path: Path):
        if path.suffix not in ('.json', '.yml'):
            raise NonDictException(path)

        self.path = path
        with path.open() as file:
            match path.suffix:
                case '.json':
                    body = json.load(file)
                case '.yml':
                    body = yaml.load(file)
        super().__init__(body)


class ContentItem(DictFileBased):
    def __init__(self, path: Path):
        super().__init__(path)
        self.file_type: FileType = find_type_by_path(self.path)
        self.pack = find_pack(self.path)  # todo if not used elsewhere, create inside pack_tuple

    @property
    def pack_tuple(self) -> tuple[str]:
        return self.pack.name,

    @property
    def id_(self):
        if 'commonfields' in self.content:
            return self['commonfields']['id']
        return self['id']

    @property
    def name(self) -> str:
        if self.content:
            return self.get('name', default='')  # todo default?

    @property
    def tests(self):
        tests = self.get('tests', [], warn_if_missing=False)
        if len(tests) == 1 and 'no tests' in tests[0].lower():
            raise NoTestsConfiguredException(self.id_)
        return tests


class Machine(Enum):
    V6_2 = Version('6.2')
    V6_5 = Version('6.5')
    V6_6 = Version('6.6')
    MASTER = 'master'
    NIGHTLY = 'nightly'

    @staticmethod
    def get_suitable_machines(version_range: VersionRange, run_nightly: bool, run_master: bool) -> tuple['Machine']:
        result = [
            machine for machine in Machine
            if isinstance(machine.value, Version) and machine.value in version_range
        ]
        if run_nightly:
            result.append(Machine.NIGHTLY)
        if run_master:
            result.append(Machine.MASTER)

        return tuple(result)

    def __repr__(self):
        return self.value


class TestConf(DictFileBased):
    __test__ = False  # prevents pytest from running it

    def __init__(self):
        super().__init__(DEBUG_CONF_PATH)  # todo not use debug
        self.tests = tuple(TestConfItem(value) for value in self['tests'])
        self.test_ids = {test.playbook_id for test in self.tests}

        self.tests_to_integrations = {test.playbook_id: test.integrations for test in self.tests if test.integrations}
        self.integrations_to_tests = self._calculate_integration_to_tests()

        # Attributes
        self.skipped_tests_dict: dict = self['skipped_tests']  # todo is used?
        self.skipped_integrations_dict: dict[str, str] = self['skipped_integrations']  # todo is used?
        self.unmockable_integrations_dict: dict[str, str] = self['unmockable_integrations']  # todo is used?
        self.nightly_integrations: list[str] = self['nightly_integrations']  # todo is used?
        self.parallel_integrations: list[str] = self['parallel_integrations']  # todo is used?
        self.private_tests: list[str] = self['private_tests']  # todo is used?

        self.classifier_to_test = {test.classifier: test.playbook_id
                                   for test in self.tests if test.classifier}
        self.incoming_mapper_to_test = {test.incoming_mapper: test.playbook_id
                                        for test in self.tests if test.incoming_mapper}

    def _calculate_integration_to_tests(self) -> dict[str, list[str]]:
        result = defaultdict(list)
        for test, integrations in self.tests_to_integrations.items():
            for integration in integrations:
                result[integration].append(test)
        return result

    def get_skipped_tests(self):
        return tuple(self.get('skipped_tests', {}).keys())

    def get_private_tests(self) -> tuple:
        return tuple(self.get('private_tests', ()))

    def get_tests(self) -> dict:
        return self.get('tests', {})

    def get_xsiam_tests(self):
        return self.get('test_marketplacev2')  # todo what's the type here? Add default.


class IdSetItem(DictBased):
    def __init__(self, id_: str, dict_: dict):
        super().__init__(dict_)
        self.id_: str = id_
        self.name: str = self['name']
        self.file_path: str = self['file_path']
        self.deprecated: Optional[bool] = self.get('deprecated', warn_if_missing=False) \
                                          or self.get('hidden', warn_if_missing=False)
        # hidden for pack_name_to_pack_metadata, deprecated for content items
        self.pack: Optional[str] = self.get('pack', warn_if_missing=False)
        if 'pack' not in self.content:
            logger.warning(f'content item with id={id_} and name={self.name} has no pack value')  # todo debug? info?

        self.marketplaces: Optional[tuple[MarketplaceVersions]] = \
            tuple(MarketplaceVersions(v) for v in self.get('marketplaces', (), warn_if_missing=False)) or None

    @property
    def integrations(self):
        return to_tuple(self.get('integrations', (), warn_if_missing=False))

    @property
    def tests(self):
        return self.get('tests', ())

    @property
    def implementing_scripts(self):
        return self.get('implementing_scripts', (), warn_if_missing=False)

    @property
    def implementing_playbooks(self):
        return self.get('implementing_playbooks', (), warn_if_missing=False)


class IdSet(DictFileBased):
    def __init__(self, marketplace: MarketplaceVersions):
        super().__init__(DEBUG_ID_SET_PATH)  # todo use real original_file_path
        self.marketplace = marketplace

        # Content items mentioned in the file
        self.id_to_script = self._parse_items(self['scripts'])
        self.id_to_integration = self._parse_items(self['integrations'])
        self.id_to_test_playbook = self._parse_items(self['TestPlaybooks'])
        # self.id_to_packs = self._parse_items(self['Packs']) # todo remove

        self.implemented_scripts_to_tests = defaultdict(list)
        self.implemented_playbooks_to_tests = defaultdict(list)

        for test in self.test_playbooks:
            for script in test.implementing_scripts:
                self.implemented_scripts_to_tests[script].append(test)
            for playbook in test.implementing_playbooks:
                self.implemented_playbooks_to_tests[playbook].append(test)

        # todo are all the following necessary?
        # self.id_to_classifier = self._parse_items(self['Classifiers'])
        # self.id_to_incident_field = self._parse_items(self['IncidentFields'])
        # self.id_to_incident_type = self._parse_items(self['IncidentType'])
        # self.id_to_indicator_field = self._parse_items(self['IndicatorFields'])
        # self.id_to_indicator_type = self._parse_items(self['IndicatorTypes'])
        # self.id_to_layout =  self._parse_items(self['Layouts'])
        # self.id_to_list = self._parse_items(self['Lists'])
        # self.id_to_job = self._parse_items(self['Jobs'])
        # self.id_to_mapper = self._parse_items(self['Mappers'])
        # self.id_to_generic_type = self._parse_items(self['GenericTypes'])
        # self.id_to_generic_field = self._parse_items(self['GenericFields'])
        # self.id_to_generic_module = self._parse_items(self['GenericModules'])
        # self.id_to_generic_definitions = self._parse_items(self['GenericDefinitions'])
        # self.id_to_report = self._parse_items(self['Reports'])
        # self.id_to_widget = self._parse_items(self['Widgets'])
        # self.id_to_dashboard = self._parse_items(self['Dashboards'])

        self.integration_to_pack = {integration.name: integration.pack for integration in self.integrations}
        self.scripts_to_pack = {script.name: script.pack for script in self.scripts}
        self.test_playbooks_to_pack = {test.name: test.pack for test in self.test_playbooks}

    @property
    def artifact_iterator(self):
        """ returns an iterator for all content items"""
        return (value for value in self.content if isinstance(value, list))

    @property
    def integrations(self) -> Iterable[IdSetItem]:
        return self.id_to_integration.values()

    @property
    def test_playbooks(self) -> Iterable[IdSetItem]:
        return self.id_to_test_playbook.values()

    @property
    def scripts(self) -> Iterable[IdSetItem]:
        return self.id_to_script.values()

    # @property # todo
    # def pack_name_to_pack_metadata(self) -> Iterable[IdSetItem]:
    #     return self.id_to_packs.values()

    def get_marketplace_v2_tests(self) -> 'CollectedTests':
        return CollectedTests(
            tests=self['test_marketplacev2'],
            packs=None,
            reason=CollectionReason.MARKETPLACE_VERSION_SECTION,
            id_set=self,
            version_range=None,
            reason_description=f'({self.marketplace.value})'
        )

    @staticmethod
    def _parse_items(dictionaries: list[dict[str, dict]]) -> dict[str, IdSetItem]:
        result = {}
        for dict_ in dictionaries:
            for id_, values in dict_.items():
                if isinstance(values, dict):
                    values = (values,)

                for value in values:  # multiple values possible, for different server versions
                    item = IdSetItem(id_, value)

                    if item.pack in SKIPPED_PACKS:  # todo does this make sense here? raise exception instead?
                        logger.info(f'skipping {id_=} as the {item.pack} pack is skipped')
                        continue

                    if existing := result.get(id_):
                        # Some content items have multiple copies, each supporting different versions. We use the newer.
                        if item.to_version <= existing.to_version and item.from_version <= existing.from_version:
                            logger.info(f'skipping duplicate of {item.name} as its version range {item.version_range} '
                                        f'is older than of the existing one, {existing.version_range}')
                            continue  # todo makes sense?

                    result[id_] = item
        return result


class CollectedTests:
    def __init__(
            self,
            tests: Optional[tuple[str] | list[str]],
            packs: Optional[tuple[str] | list[str]],
            reason: CollectionReason,
            id_set: IdSet,
            version_range: Optional[VersionRange],  # None when the range should not be changed
            reason_description: Optional[str] = None
    ):
        self._id_set = id_set  # used for validations

        self.tests = set()  # only updated on init
        self.packs = set()  # only updated on init
        self.version_range = None if version_range and version_range.is_default else version_range

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
    def union(cls, collected_tests: list['CollectedTests']) -> 'CollectedTests':
        if not collected_tests:
            logger.warning('no tests to union')
            return None  # todo

        return functools.reduce(lambda a, b: a | b, collected_tests)

    def _add_single(
            self,
            test: Optional[str],
            pack: Optional[str],
            reason: CollectionReason,
            reason_description: str = '',
    ):
        """ Should only be called from add_multiple """  # todo really?
        if not any((test, pack)):
            raise RuntimeError('both test and pack provided are empty')

        if test:
            logger.info(f'collecting {test=}, {reason.value=} {reason_description}')
            self.tests.add(test)

        if pack:
            try:
                self._validate_pack(pack)
                logger.info(f'collecting {pack=}, {reason.value=} {reason_description}')
                self.packs.add(pack)
            except (IgnoredPackException, SkippedPackException) as e:
                logger.info(str(e))

    def add_id_set_item(self, item: IdSetItem, reason: CollectionReason, reason_description: str = '',
                        add_pack: bool = True, add_test: bool = True):
        self._add_single(item.name, item.pack, reason, reason_description)

    @staticmethod
    def _validate_pack(pack: str) -> None:
        """ raises InvalidPackException if the pack name is not valid."""
        if not pack:
            raise InvalidPackNameException(pack)
        if pack not in PACK_NAMES:
            logger.error(f'inexistent pack {pack}')
            raise InexistentPackException(pack)
        if pack in IGNORED_FILES:  # todo is necessary?
            raise IgnoredPackException(pack)
        if pack in SKIPPED_PACKS:  # todo is necessary?
            raise SkippedPackException(pack)
        # if self._id_set.id_to_packs[pack].deprecated:  # todo safer access?
        # todo find if pack is deprecated some other way
        #     raise DeprecatedPackException(pack)

    def __repr__(self):
        return f'{len(self.packs)} pack_name_to_pack_metadata, {len(self.tests)} tests, {self.version_range=}'


def to_tuple(value: Optional[str | list]) -> Optional[tuple]:
    if value is None:
        return value
    if not value:
        return ()
    if isinstance(value, str):
        return value,
    return tuple(value)


class EmptyMachineListException(Exception):
    pass


class InvalidVersionException(Exception):
    pass


class TestConfItem(DictBased):
    def __init__(self, dict_: dict):
        super().__init__(dict_)
        self.playbook_id = self['playbookID']

    @property
    def integrations(self) -> tuple[str]:
        return to_tuple(self.get('integrations', (), warn_if_missing=False))  # todo warn?

    @property
    def is_mockable(self):
        return self.get('is_mockable')

    @property
    def classifier(self):
        return self.get('instance_configuration', {}, warn_if_missing=False).get('classifier_id')

    @property
    def incoming_mapper(self):
        return self.content.get('instance_configuration', {}).get('incoming_mapper_id')


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions):
        self.marketplace = marketplace  # todo is this used anywhere but in passing to id_set?
        self.id_set = IdSet(marketplace)
        self.conf = TestConf()
        self.pack_name_to_pack_metadata = {pack_name: ContentItem(PACKS_PATH / pack_name / 'pack_metadata.json')
                                           for pack_name in PACK_NAMES}
        # todo FAILED_

    @property
    def packs(self) -> Iterable[ContentItem]:
        return self.pack_name_to_pack_metadata.values()

    @abstractmethod
    def _collect(self) -> CollectedTests:
        """
        Collects all relevant tests into self.collected.
        Every inheriting class implements its own methodology here.
        :return: A CollectedTests object with only the pack_name_to_pack_metadata to install and tests to run, with machines=None.
        """
        pass

    def collect(self, run_nightly: bool, run_master: bool):
        collected: CollectedTests = self._collect()
        collected.machines = Machine.get_suitable_machines(self.version_range, run_nightly, run_master)

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
                    collected.append(
                        self._collect_pack(pack, CollectionReason.PACK_MATCHES_INTEGRATION, reason_description=''))
        return collected

    def _collect_pack(self, name: str, reason: CollectionReason, reason_description: str) -> CollectedTests:
        pack = ContentItem(PACKS_PATH / name / 'pack_metadata.json')
        return CollectedTests(
            tests=None,
            packs=(name,),
            reason=reason,
            reason_description=reason_description,
            id_set=self.id_set,
            version_range=pack.version_range
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


IS_GITLAB = False  # todo remove


class NoPackException(Exception):
    def __init__(self, path: Path):
        self.message = f'Could not find a pack for {str(path)}'
        super().__init__(self.message)


def find_pack(path: Path) -> Path:
    """
    >>> find_pack(Path('root/Packs/MyPack/Integrations/MyIntegration/MyIntegration.yml'))
    PosixPath('root/Packs/MyPack')
    >>> find_pack(Path('Packs/MyPack1/Scripts/MyScript/MyScript.py')).name
    'MyPack1'
    >>> find_pack(Path('Packs/MyPack2/Scripts/MyScript')).name
    'MyPack2'
    >>> find_pack(Path('Packs/MyPack3/Scripts')).name
    'MyPack3'
    """
    if 'Packs' not in path.parts:
        raise NoPackException(path)
    return path.parents[len(path.parts) - (path.parts.index('Packs')) - 3]


class NoTestsToCollect(Exception):
    def __init__(self, path: Path, reason: str):
        self.message = f'No tests to collect for {str(path)}: {reason}'
        super().__init__(self.message)


class BranchTestCollector(TestCollector):
    def __init__(self, branch_name: str, marketplace: MarketplaceVersions):
        super().__init__(marketplace)
        self.branch_name = branch_name
        self.repo = Repo(CONTENT_PATH)
        self.repo.git.checkout(self.branch_name)

    def _collect(self) -> CollectedTests:
        # None filter is for empty tests, returned by
        collected = []
        for path in self._get_changed_files():
            try:
                collected.append(self._collect_single(CONTENT_PATH / Path(path)))
            except NoTestsToCollect as e:
                logger.warning(e.message)
        collected = CollectedTests.union(collected)
        if not collected:
            # todo return sanity tests
            raise NotImplementedError()
        return collected

    def _collect_yml(
            self,
            yml_content_item: ContentItem,
            original_file_type: FileType,
            original_file_path: Path,
    ) -> CollectedTests:
        match content_item_folder := yml_content_item.path.parents[1].name:

            case 'Integrations':
                tests = self.conf.integrations_to_tests[yml_content_item.id_]
                reason = CollectionReason.INTEGRATION_CHANGED

            case 'Scripts' | 'Playbooks':
                try:
                    tests = yml_content_item.tests  # raises if 'no tests' in the tests field
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED

                except NoTestsConfiguredException:  # collecting all implementing
                    reason = CollectionReason.SCRIPT_PLAYBOOK_CHANGED_NO_TESTS

                    match content_item_folder:
                        case 'Scripts':
                            tests = self.id_set.implemented_scripts_to_tests.get(yml_content_item.id_)
                        case 'Playbooks':
                            tests = self.id_set.implemented_playbooks_to_tests.get(yml_content_item.id_)
                        case _:
                            raise RuntimeError(f'unexpected content type folder {content_item_folder}')

                    if not tests:
                        logger.warning(f'{original_file_type.value} {str(yml_content_item.path)} '
                                       f'has `No Tests` configured, and no tests in id_set')  # todo necessary?
            case _:
                raise RuntimeError(f'Unexpected content type original_file_path {content_item_folder} '
                                   f'(expected `Integrations`, `Scripts`, etc)')

        return CollectedTests(
            tests=tests,
            packs=yml_content_item.pack_tuple,
            reason=reason,
            id_set=self.id_set,
            version_range=yml_content_item.version_range,
            reason_description=f'{yml_content_item.id_=} ({original_file_path})'
        )

    def _collect_single(self, path) -> CollectedTests:
        file_type = find_type_by_path(path)
        try:
            content_item = ContentItem(path)
        except NonDictException:
            if file_type in CODE_FILE_TYPES:
                yml = ContentItem(path.with_suffix('.yml'))
                # todo handle foo.Tests.ps1
                # todo should this yml be created inside _collect_yml?
                # todo what if not exists?
                return self._collect_yml(yml, yml.file_type, path)
            raise
        except NoPackException as e:
            # files that are supposed to not be in a pack, and are ignored.
            if path in {}:  # todo handle non-content items, exclude list
                raise NoTestsToCollect(path, e.message)
            raise  # files that are either supposed to be in a pack, or should not be ignored.

        reason_description = f'{FileType=}'
        match file_type:
            case FileType.PYTHON_FILE | FileType.POWERSHELL_FILE | FileType.JAVASCRIPT_FILE:
                raise RuntimeError('impossible, these files are handled before the switch case')

            case FileType.PACK_IGNORE | FileType.SECRET_IGNORE | FileType.DOC_FILE | FileType.README:
                raise NoTestsToCollect(path, f'ignored type ({file_type}')

            case FileType.IMAGE | FileType.DESCRIPTION:  # todo readme shows twice
                tests = None
                reason = CollectionReason.NON_CODE_FILE_CHANGED

            case FileType.TEST_PLAYBOOK:
                if (test_id := content_item.id_) in self.conf.test_ids:
                    tests = test_id,
                    reason = CollectionReason.TEST_PLAYBOOK_CHANGED
                else:
                    raise

            case FileType.REPUTATION:  # todo reputationjson
                raise NotImplementedError()  # todo

            case FileType.MAPPER:
                if tests := (self.conf.incoming_mapper_to_test.get(content_item.id_)):
                    reason = CollectionReason.MAPPER_CHANGED
                else:
                    reason = CollectionReason.NON_CODE_FILE_CHANGED
                    reason_description = f'no specific tests for {content_item.name} were found'

            case FileType.CLASSIFIER:
                if tests := (self.conf.classifier_to_test.get(content_item.id_)):
                    reason = CollectionReason.CLASSIFIER_CHANGED
                else:
                    reason = CollectionReason.NON_CODE_FILE_CHANGED
                    reason_description = f'no specific tests for {content_item.name} were found'

            case FileType.README | FileType.METADATA | FileType.RELEASE_NOTES | FileType.RELEASE_NOTES_CONFIG | \
                 FileType.IMAGE | FileType.DESCRIPTION | FileType.INCIDENT_TYPE | FileType.INCIDENT_FIELD | \
                 FileType.INDICATOR_FIELD | FileType.LAYOUT | FileType.WIDGET | FileType.DASHBOARD | FileType.REPORT | \
                 FileType.PARSING_RULE | FileType.MODELING_RULE | FileType.CORRELATION_RULE | \
                 FileType.XSIAM_DASHBOARD | FileType.XSIAM_REPORT | FileType.REPORT | FileType.GENERIC_TYPE | \
                 FileType.GENERIC_FIELD | FileType.GENERIC_MODULE | FileType.GENERIC_DEFINITION | \
                 FileType.PRE_PROCESS_RULES | FileType.JOB | FileType.CONNECTION | FileType.RELEASE_NOTES_CONFIG | \
                 FileType.XSOAR_CONFIG:

                tests = None
                reason = CollectionReason.NON_CODE_FILE_CHANGED
                reason_description = str(path)
                # todo layout container, XSIAM config?

            case _:
                if path.suffix == '.yml':
                    return self._collect_yml(content_item, file_type, path)
                raise RuntimeError(f'Unexpected filetype {file_type}')

        # todo usage before assignment?
        return CollectedTests(
            tests=tests,
            packs=content_item.pack_tuple,
            reason=reason,
            id_set=self.id_set,
            version_range=content_item.version_range,
            reason_description=reason_description
        )

    def _get_changed_files(self) -> tuple[str]:
        repo = Repo(CONTENT_PATH)
        full_branch_name = f'origin/{self.branch_name}'  # todo remove, debugging only
        latest, previous = tuple(repo.iter_commits(
            rev=f'{full_branch_name}~1...{full_branch_name}~3' if IS_GITLAB
            else f'{full_branch_name}...{full_branch_name}~2'
        ))
        return tuple(str(file.b_path) for file in latest.diff(previous))


class NightlyTestCollector(TestCollector):
    def _collect(self) -> CollectedTests:
        collected = [
            self._tests_matching_marketplace_value(),
            self._packs_matching_marketplace_value(),
        ]

        if self.marketplace == MarketplaceVersions.MarketplaceV2:
            collected.append(self.id_set.get_marketplace_v2_tests())
        # todo is there a similar list for the marketplacev1?

        return CollectedTests.union(collected)

    def _tests_matching_marketplace_value(self) -> CollectedTests:
        marketplace_string = self.marketplace.value  # todo is necessary?
        logger.info(f'collecting test playbooks by their marketplace field, searching for {marketplace_string}')
        tests = []

        for playbook in self.id_set.test_playbooks:
            if marketplace_string in (playbook.marketplaces or ()) and playbook.tests:
                tests.extend(playbook.tests)

        return CollectedTests(
            tests=tests,
            packs=None,
            reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
            id_set=self.id_set,
            version_range=None,
            reason_description=f'({marketplace_string})'
        )

    def _packs_matching_marketplace_value(self) -> CollectedTests:
        # todo make sure we have a validation, that pack_metadata.marketplaces includes
        marketplace_string = self.marketplace.value
        logger.info(
            f'collecting pack_name_to_pack_metadata by their marketplace field, searching for {marketplace_string}')
        packs = tuple(pack.name for pack in self.packs if marketplace_string in pack.get('marketplaces', ()))
        # todo what's the default behavior for a missing marketplace value?

        return CollectedTests(
            tests=None,
            packs=packs,
            reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
            id_set=self.id_set,
            version_range=None,
            reason_description=f'({marketplace_string})'
        )


class UploadCollector(TestCollector):
    # todo today we collect pack_name_to_pack_metadata, not tests
    def _collect(self) -> CollectedTests:
        pass


class NoTestsConfiguredException(Exception):
    """ used when an integration has no tests configured """

    # todo log test collection reasons
    def __init__(self, content_id: str):
        self.id_ = content_id  # todo use or remove


if __name__ == '__main__':
    try:
        sys.path.append(str(CONTENT_PATH))
        # collector = NightlyTestCollector(marketplace=MarketplaceVersions.XSOAR)
        collector = BranchTestCollector(marketplace=MarketplaceVersions.XSOAR, branch_name='master')
        print(collector.collect(True, True))

    except:
        Repo(CONTENT_PATH).git.checkout('ds-test-collection')  # todo remove
        raise
