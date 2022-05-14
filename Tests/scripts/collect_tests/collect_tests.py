from csv import DictWriter

import functools
import json
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional, NamedTuple

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions

from logging import DEBUG, getLogger

from demisto_sdk.commands.common.tools import (find_type_by_path, json, yaml)
from git import Repo
from packaging import version
from packaging.version import Version

from Tests.scripts.collect_tests.constants import (CONTENT_PATH,
                                                   DEBUG_CONF_PATH,
                                                   DEBUG_ID_SET_PATH,
                                                   PACKS_PATH, SKIPPED_PACKS, XSOAR_SANITY_TESTS)
from Tests.scripts.collect_tests.exceptions import (IgnoredPackException,
                                                    InexistentPackException,
                                                    InvalidPackNameException,
                                                    SkippedPackException, NonDictException, EmptyMachineListException,
                                                    NoTestsConfiguredException)

IGNORED_INFRASTRUCTURE_FILES = {
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

logger = getLogger()
logger.level = DEBUG
IS_GITLAB = False  # todo replace

PACK_NAMES = {p.name for p in PACKS_PATH.glob('*') if p.is_dir()}
COMMIT = 'ds-test-collection'  # todo use arg


class CollectionReason(Enum):
    # todo remove unused
    MARKETPLACE_VERSION_BY_VALUE = 'value of the test `marketplace` field'
    CONF_MARKETPLACE_V2 = 'conf.json marketplace v2 sanity tests'
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


CollectionLog = NamedTuple(
    'CollectionLog', (
        ('test', Optional[str]),
        ('pack', Optional[str]),
        ('reason', CollectionReason),
        ('description', str),
    )
)
collection_log: list[CollectionLog] = []


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
        self.id_ = self['commonfields']['id'] if 'commonfields' in self.content else self['id']

    @property
    def pack_tuple(self) -> tuple[str]:
        return self.pack.name,

    # @property # todo choose between property and attribute
    # def id_(self) -> str:
    #     if 'commonfields' in self.content:
    #         return self['commonfields']['id']
    #     return self['id']

    @property
    def name(self) -> str:
        return self.get('name', default='')  # todo default? todo warn?

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


class IdSetItem(DictBased):
    def __init__(self, id_: str, dict_: dict):
        super().__init__(dict_)
        self.id_: str = id_
        self.name: str = self['name']
        self.file_path: str = self['file_path']

        # hidden for pack_name_to_pack_metadata, deprecated for content items
        self.deprecated: Optional[bool] = \
            self.get('deprecated', warn_if_missing=False) or self.get('hidden', warn_if_missing=False)

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
        self.id_to_script = self._parse_items('scripts')
        self.id_to_integration = self._parse_items('integrations')
        self.id_to_test_playbook = self._parse_items('TestPlaybooks')

        self.implemented_scripts_to_tests = defaultdict(list)
        self.implemented_playbooks_to_tests = defaultdict(list)

        for test in self.test_playbooks:
            for script in test.implementing_scripts:
                self.implemented_scripts_to_tests[script].append(test)
            for playbook in test.implementing_playbooks:
                self.implemented_playbooks_to_tests[playbook].append(test)

        self.integration_to_pack = {integration.name: integration.pack for integration in self.integrations}
        self.scripts_to_pack = {script.name: script.pack for script in self.scripts}
        self.test_playbooks_to_pack = {test.name: test.pack for test in self.test_playbooks}

    @property
    def artifact_iterator(self):  # todo is used?
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

    # @property # todo is used?
    # def pack_name_to_pack_metadata(self) -> Iterable[IdSetItem]:
    #     return self.id_to_packs.values()

    def _parse_items(self, key: str) -> dict[str, IdSetItem]:
        result = {}
        for dict_ in self[key]:
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
        self._id_set = id_set  # used for validations # todo is it?

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
            description: str = '',
    ):
        """ Should only be called from add_multiple """  # todo really?
        if not any((test, pack)):
            raise RuntimeError('both test and pack provided are empty')

        if test:
            logger.info(f'collecting {test=}, {reason.value} {description}')
            self.tests.add(test)

        if pack:
            try:
                self._validate_pack(pack)
                logger.info(f'collecting {pack=}, {reason.value} {description}')
                self.packs.add(pack)
            except (IgnoredPackException, SkippedPackException) as e:
                logger.info(str(e))
        collection_log.append(CollectionLog(test, pack, reason, description))

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
        if pack in SKIPPED_PACKS:  # todo is necessary?
            raise SkippedPackException(pack)
        # if self._id_set.id_to_packs[pack].deprecated:  # todo safer access?
        # todo find if pack is deprecated some other way
        #     raise DeprecatedPackException(pack)

    def __repr__(self):
        return f'{len(self.packs)} packs, {len(self.tests)} tests, {self.version_range=}'


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

    def get_skipped_tests(self):  # todo is used?
        return tuple(self.get('skipped_tests', {}).keys())

    def get_tests(self) -> dict:
        return self['tests']

    def get_marketplace_v2_sanity_tests(self, id_set: IdSet) -> 'CollectedTests':
        return CollectedTests(
            tests=self['test_marketplacev2'],
            packs=None,
            reason=CollectionReason.CONF_MARKETPLACE_V2,
            id_set=id_set,
            version_range=None,
            reason_description=None
        )


def to_tuple(value: Optional[str | list]) -> Optional[tuple]:
    if value is None:
        return value
    if not value:
        return ()
    if isinstance(value, str):
        return value,
    return tuple(value)


class TestConfItem(DictBased):
    def __init__(self, dict_: dict):
        super().__init__(dict_)
        self.playbook_id: str = self['playbookID']

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

    def collect(self, run_nightly: bool, run_master: bool) -> CollectedTests:
        collected: CollectedTests = self._collect()
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
                    collected.append(
                        self._collect_pack(pack, CollectionReason.PACK_MATCHES_INTEGRATION, reason_description=''))
        return collected

    def _collect_pack(self, name: str, reason: CollectionReason, reason_description: str) -> CollectedTests:
        return CollectedTests(
            tests=None,
            packs=(name,),
            reason=reason,
            reason_description=reason_description,
            id_set=self.id_set,
            version_range=ContentItem(PACKS_PATH / name / 'pack_metadata.json').version_range
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
                        logger.warning(
                            f'{original_file_type.value} {str(yml_content_item.path.relative_to(PACKS_PATH))} '
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
            reason_description=f'{yml_content_item.id_=} ({original_file_path.relative_to(PACKS_PATH)})'
        )

    def _collect_single(self, path) -> CollectedTests:
        file_type = find_type_by_path(path)
        relative_path = path.relative_to(CONTENT_PATH)
        description_suffix = f'({file_type.value})' if file_type else ''
        reason_description = f'{relative_path} {description_suffix}'

        try:
            content_item = ContentItem(path)
        except NonDictException:
            match file_type:
                case FileType.PYTHON_FILE | FileType.POWERSHELL_FILE | FileType.JAVASCRIPT_FILE:
                    if path.name.endswith('Tests.ps1'):
                        path = path.with_name(path.name.replace('Tests.ps1', '.ps1'))  # todo ok?
                    # todo should this yml be created inside _collect_yml?
                    # todo what if yml not exists?
                    yml = ContentItem(path.with_suffix('.yml'))
                    return self._collect_yml(yml, yml.file_type, path)

                case FileType.README | FileType.RELEASE_NOTES_CONFIG | FileType.RELEASE_NOTES:
                    return self._collect_pack(
                        name=find_pack(path).name,
                        reason=CollectionReason.NON_CODE_FILE_CHANGED,
                        reason_description=reason_description
                    )
                case _:
                    raise

        except NoPackException as e:
            # files that are NOT supposed to be in a pack, and are ignored.
            if path.parent == CONTENT_PATH and path.name in IGNORED_INFRASTRUCTURE_FILES:
                # todo is the list ok?
                raise NoTestsToCollect(path, e.message)
            raise  # files that are either supposed to be in a pack, or should not be ignored.

        match file_type:
            case FileType.PACK_IGNORE | FileType.SECRET_IGNORE | FileType.DOC_FILE | FileType.README:
                raise NoTestsToCollect(path, f'ignored type ({file_type}')

            case FileType.IMAGE | FileType.DESCRIPTION:  # todo readme shows twice
                tests = None  # pack should be installed, but no tests are collected.
                reason = CollectionReason.NON_CODE_FILE_CHANGED

            case FileType.TEST_PLAYBOOK:
                if (test_id := content_item.id_) in self.conf.test_ids:
                    tests = test_id,
                    reason = CollectionReason.TEST_PLAYBOOK_CHANGED
                else:
                    raise

            case FileType.REPUTATION:  # todo reputationjson
                raise NotImplementedError()  # todo

            case FileType.MAPPER | FileType.CLASSIFIER:
                source: dict[str, str] = {
                    FileType.MAPPER: self.conf.incoming_mapper_to_test,
                    FileType.CLASSIFIER: self.conf.classifier_to_test
                }[file_type]

                reason: CollectionReason = {
                    FileType.MAPPER: CollectionReason.MAPPER_CHANGED,
                    FileType.CLASSIFIER: CollectionReason.CLASSIFIER_CHANGED
                }[file_type]

                if not (tests := source.get(content_item.id_)):
                    tests = None  # passing None so the pack is installed
                    reason = CollectionReason.NON_CODE_FILE_CHANGED
                    reason_description = f'no specific tests for {relative_path} were found, using tests from id_set'

            case FileType.METADATA | \
                 FileType.RELEASE_NOTES_CONFIG | FileType.IMAGE | FileType.DESCRIPTION | FileType.INCIDENT_TYPE | \
                 FileType.INCIDENT_FIELD | FileType.INDICATOR_FIELD | FileType.LAYOUT | FileType.WIDGET | \
                 FileType.DASHBOARD | FileType.REPORT | FileType.PARSING_RULE | FileType.MODELING_RULE | \
                 FileType.CORRELATION_RULE | FileType.XSIAM_DASHBOARD | FileType.XSIAM_REPORT | FileType.REPORT | \
                 FileType.GENERIC_TYPE | FileType.GENERIC_FIELD | FileType.GENERIC_MODULE | \
                 FileType.GENERIC_DEFINITION | FileType.PRE_PROCESS_RULES | FileType.JOB | FileType.CONNECTION | \
                 FileType.RELEASE_NOTES_CONFIG | FileType.XSOAR_CONFIG:

                tests = None
                reason = CollectionReason.NON_CODE_FILE_CHANGED
                # todo layout container, XSIAM config?

            case _:
                if path.suffix == '.yml':
                    return self._collect_yml(content_item, file_type, path)
                raise RuntimeError(f'Unexpected filetype {file_type}, {relative_path}')

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

        match self.marketplace:
            case MarketplaceVersions.MarketplaceV2:
                collected.append(self.conf.get_marketplace_v2_sanity_tests(self.id_set))
            case MarketplaceVersions.XSOAR:
                collected.append(XSOAR_SANITY_TESTS)
            case _:
                raise RuntimeError(f'unexpected marketplace value {self.marketplace.value=}')

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
        # todo make sure we have a validation, that pack_metadata.marketplaces includes a marketplace
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


def write_log(log: list[CollectionLog]):
    keys = ('test', 'pack', 'reason', 'description')
    with Path('collected_tests.tsv').open('w') as file:
        writer = DictWriter(file, keys, delimiter='\t')
        writer.writeheader()
        for row in log:
            writer.writerow(row._asdict())


if __name__ == '__main__':
    try:
        sys.path.append(str(CONTENT_PATH))
        # collector = NightlyTestCollector(marketplace=MarketplaceVersions.XSOAR)
        collector = BranchTestCollector(marketplace=MarketplaceVersions.XSOAR, branch_name='master')
        print(collector.collect(True, True))
        write_log(collection_log)

    except:  # todo remove
        Repo(CONTENT_PATH).git.checkout('ds-test-collection')  # todo remove
        raise
