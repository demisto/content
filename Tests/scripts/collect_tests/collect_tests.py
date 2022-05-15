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
                                                   PACKS_PATH,
                                                   XSOAR_SANITY_TEST_NAMES)
from Tests.scripts.collect_tests.exceptions import (InexistentPackException,
                                                    InvalidPackNameException,
                                                    SkippedPackException, NonDictException, EmptyMachineListException,
                                                    NoTestsConfiguredException, DeprecatedPackException,
                                                    NotUnderPackException, NothingToCollectException)

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

logger = getLogger()
logger.level = DEBUG
IS_GITLAB = False  # todo replace

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
        self.pack = find_pack(self.path)  # todo if not used elsewhere, create inside pack_tuple
        self.deprecated = self.get('deprecated', warn_if_missing=False)

    @property
    def id_(self):  # property as pack_metadata (for example) doesn't have this field
        return self['commonfields']['id'] if 'commonfields' in self.content else self['id']

    @property
    def pack_tuple(self) -> tuple[str]:
        return self.pack.name,

    @property
    def name(self) -> str:
        return self.get('name', default='', warn_if_missing=True)

    @property
    def tests(self):
        tests = self.get('tests', [], warn_if_missing=False)
        if len(tests) == 1 and 'no tests' in tests[0].lower():
            raise NoTestsConfiguredException(self.id_)
        return tests


class PackManager:
    skipped_packs = {'DeprecatedContent', 'NonSupported', 'ApiModules'}
    pack_names = {p.name for p in PACKS_PATH.glob('*') if p.is_dir()}

    def __init__(self):
        self.pack_name_to_pack_metadata: dict[str, ContentItem] = {}
        self.deprecated_packs: set[str] = set()

        for name in PackManager.pack_names:
            metadata = ContentItem(PACKS_PATH / name / 'pack_metadata.json')
            self.pack_name_to_pack_metadata[name] = metadata

            if metadata.deprecated:
                self.deprecated_packs.add(name)

    def __getitem__(self, pack_name: str) -> ContentItem:
        return self.pack_name_to_pack_metadata[pack_name]

    def __iter__(self):
        yield from self.pack_name_to_pack_metadata.values()

    @staticmethod
    def relative_to_packs(path: Path):
        return path.relative_to(PACKS_PATH)

    def validate_pack(self, pack: str) -> None:
        """ raises InvalidPackException if the pack name is not valid."""
        if not pack:
            raise InvalidPackNameException(pack)
        if pack not in PackManager.pack_names:
            logger.error(f'inexistent pack {pack}')
            raise InexistentPackException(pack)
        if pack in PackManager.skipped_packs:
            raise SkippedPackException(pack)
        if pack in self.deprecated_packs:
            raise DeprecatedPackException(pack)


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
        raise NotUnderPackException(path)
    return path.parents[len(path.parts) - (path.parts.index('Packs')) - 3]


PACK_MANAGER = PackManager()


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
            # todo fix in id_set
            logger.error(f'content item with id={id_} and name={self.name} has no pack value in id_set')

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
        super().__init__(DEBUG_ID_SET_PATH)  # todo use real content_item
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
        yield from self.id_to_integration.values()

    @property
    def test_playbooks(self) -> Iterable[IdSetItem]:
        yield from self.id_to_test_playbook.values()

    @property
    def scripts(self) -> Iterable[IdSetItem]:
        yield from self.id_to_script.values()

    def _parse_items(self, key: str) -> dict[str, IdSetItem]:
        result = {}
        for dict_ in self[key]:
            for id_, values in dict_.items():
                if isinstance(values, dict):
                    values = (values,)

                for value in values:  # multiple values possible, for different server versions
                    item = IdSetItem(id_, value)

                    if item.pack in PackManager.skipped_packs:  # todo does this make sense here? raise exception?
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

        collection_log.append(CollectionLog(test, pack, reason, description))

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

        self.classifier_to_test = {
            test.classifier: test.playbook_id
            for test in self.tests if test.classifier
        }
        self.incoming_mapper_to_test = {
            test.incoming_mapper: test.playbook_id
            for test in self.tests if test.incoming_mapper
        }

    def _calculate_integration_to_tests(self) -> dict[str, list[str]]:
        result = defaultdict(list)
        for test, integrations in self.tests_to_integrations.items():
            for integration in integrations:
                result[integration].append(test)
        return result

    # def get_skipped_tests(self):  # todo is used?
    #     return tuple(self.get('skipped_tests', {}).keys())


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

    def _collect(self) -> CollectedTests:
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
                raise NotImplementedError()  # todo

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


class NightlyTestCollector(TestCollector):
    def _collect(self) -> CollectedTests:
        collected = [
            self._tests_matching_marketplace_value(),
            self._packs_matching_marketplace_value(),
        ]

        return CollectedTests.union(collected)

    def _tests_matching_marketplace_value(self) -> CollectedTests:
        logger.info(f'collecting test playbooks by their marketplace field, searching for {self.marketplace.value}')
        tests = []

        for playbook in self.id_set.test_playbooks:
            if self.marketplace.value in (playbook.marketplaces or ()) and playbook.tests:
                tests.extend(playbook.tests)

        return CollectedTests(tests=tests, packs=None, reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              version_range=None, reason_description=f'({self.marketplace.value})')

    def _packs_matching_marketplace_value(self) -> CollectedTests:
        logger.info(
            f'collecting pack_name_to_pack_metadata by their marketplace field, searching for {self.marketplace.value}')
        packs = tuple(
            pack.name for pack in PACK_MANAGER if self.marketplace.value in
            pack.get('marketplaces', (MarketplaceVersions.XSOAR.value,))
        )

        return CollectedTests(tests=None, packs=packs, reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              version_range=None, reason_description=f'({self.marketplace.value})')


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
