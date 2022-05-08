import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from itertools import islice, chain
from pathlib import Path
from typing import Any, Optional, Iterable

from demisto_sdk.commands.common.constants import MarketplaceVersions, FileType
from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.common.tools import get_file, find_type_by_path
from git import Repo
from packaging.version import Version
from packaging import version

from Tests.scripts.collect_tests.constants import MASTER, CONTENT_PATH, DEBUG_ID_SET_PATH, DEBUG_CONF_PATH, \
    IGNORED_FILES, SKIPPED_PACKS
from Tests.scripts.collect_tests.exceptions import InvalidPackNameException, IgnoredPackException, SkippedPackException, \
    DeprecatedPackException
from Tests.scripts.utils import logging_wrapper as logging
from collections import defaultdict

INTEGRATION_SCRIPT_COLLECTED_FILE_TYPES = {'.py', '.yml', 'js', 'ps1'}

git_util = GitUtil()


class CollectionReason(Enum):
    # todo remove unused
    MARKETPLACE_VERSION_BY_VALUE = 'value of the test `marketplace` field'
    MARKETPLACE_VERSION_SECTION = 'listed under conf.json marketplace-specific section'
    PACK_MATCHES_INTEGRATION = 'pack added as the integration is used in a playbook'
    PACK_MATCHES_TEST = 'pack added as the test playbook was collected earlier'
    NIGHTLY_ALL_TESTS__ID_SET = 'collecting all id_set test playbooks for nightly'
    NIGHTLY_ALL_TESTS__TEST_CONF = 'collecting all test_conf tests for nightly'
    ALL_ID_SET_PACKS = 'collecting all id_set packs'
    NON_CODE_FILE_CHANGED = 'non-code pack file changed'
    INTEGRATION_CHANGED = 'integration changed, collecting all conf.json tests using it'
    SCRIPT_CHANGED_NO_TESTS = 'script changed, but has `No Tests` configured, taking tests from id_set'
    SCRIPT_CHANGED = 'script changed, taking tests from `tests` section in script yml'
    TEST_PLAYBOOK_CHANGED = 'test playbook changed'
    MAPPER_CHANGED = 'mapper file changed, configured as incoming_mapper_id in test conf'
    CLASSIFIER_CHANGED = 'classifier file changed, configured as classifier_id in test conf'


class DictBased:
    def __init__(self, dict_: dict):
        self.content = dict_

    def get(self, key: str, default: Any = None, warn_if_missing: bool = True):
        if key not in self.content and warn_if_missing:
            logging.warning(f'attempted to access key {key}, which does not exist in conf.json')
        return self.content.get(key, default)

    def __getitem__(self, key):
        return self.content[key]


@dataclass
class VersionRange:
    min_version: Version
    max_version: Version

    def __contains__(self, item):
        return self.min_version <= item <= self.max_version

    def __repr__(self):
        return f'{self.min_version} -> {self.max_version}'


class DictFileBased(DictBased):
    def __init__(self, path: Path):
        self.path = path
        super().__init__(get_file(path, path.suffix[1:]))


class ContentItem(DictFileBased):
    def __init__(self, path: Path):
        super().__init__(path)
        self.file_type: FileType = find_type_by_path(path)
        self.pack = find_pack(path)  # todo if not used elsewhere, create inside pack_tuple
        self.from_version = self._calculate_from_version()
        self.to_version = self._calculate_to_version()
        self.version_range = VersionRange(self.from_version, self.to_version)

    @property
    def pack_tuple(self) -> tuple[str]:
        return self.pack.name,

    @property
    def id_(self):
        return self['id']

    @property
    def name(self):
        if self.content:
            return self.content.get('name', '-')  # todo why '-'?
        # else, returns None. todo was there justification for this (copied) behavior?

    @property
    def tests(self):
        tests = self.get('tests', [], warn_if_missing=False)
        if len(tests) == 1 and tests[0].lower() == 'no tests':
            raise NoTestsConfiguredException(self.id_)
        return tests

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


def pack_path(pack_name: str) -> Path:  # todo move to utils?
    return CONTENT_PATH / 'Packs' / pack_name


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
        assert (id_field := self['id']) == id_, f'{id_field} does not match key {id_=}'  # todo
        self.id_: str = id_
        self.name: str = self['name']
        self.file_path = self['file_path']
        self.deprecated = self.get('deprecated', warn_if_missing=False) or self.get('hidden', warn_if_missing=False)
        # hidden for packs, deprecated for content items
        self.pack: Optional[str] = self.get('pack', warn_if_missing=False)
        if 'pack' not in self.content:
            logging.debug(f'content item with id={id_} and name={self.name} has no pack value')  # todo debug? info?

        self.from_version = Version(value) \
            if (value := self.get('fromversion', warn_if_missing=False)) \
            else None  # todo None or NegativeInfinity # todo fromVersion?
        self.to_version = Version(value) \
            if (value := self.get('toversion', warn_if_missing=False)) \
            else None  # todo None or Infinity
        self.marketplaces = tuple(MarketplaceVersions(v) for v in values) \
            if (values := self.get('marketplaces', warn_if_missing=False)) \
            else None

    @property
    def integrations(self):
        return to_tuple(self.content.get('integrations'))

    @property
    def tests(self):
        return self.get('tests', ())

    @property
    def implementing_scripts(self):
        return self.get('implementing_scripts', (), warn_if_missing=False)


class IdSet(DictFileBased):
    def __init__(self, version_range: VersionRange, marketplace: MarketplaceVersions):
        super().__init__(DEBUG_ID_SET_PATH)  # todo use real path
        self.version_range = version_range
        self.marketplace = marketplace

        # Content items mentioned in the file
        self.id_to_script = self._parse_items(self['scripts'])
        self.id_to_integration = self._parse_items(self['integrations'])
        self.id_to_test_playbook = self._parse_items(self['TestPlaybooks'])
        self.id_to_packs = self._parse_items(self['Packs'])

        self.scripts_to_tests = self._calculate_script_to_tests()

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

    @property
    def packs(self) -> Iterable[IdSetItem]:
        return self.id_to_packs.values()

    def get_marketplace_v2_tests(self) -> 'CollectedTests':
        return CollectedTests(tests=self['test_marketplacev2'], packs=None,
                              reason=CollectionReason.MARKETPLACE_VERSION_SECTION, id_set=self, version_range=,
                              reason_description=f'({self.marketplace.value})')

    def _parse_items(self, dictionaries: list[dict[str, dict]]) -> dict[str, IdSetItem]:
        result = {}
        for dict_ in dictionaries:
            for id_, values in dict_.items():
                if isinstance(values, dict):
                    values = (values,)
                for value in values:  # multiple values possible, for different server versions
                    item = IdSetItem(id_, value)

                    if item.from_version and item.from_version > self.version_range.max_version:
                        logging.debug(f'skipping {id_=} as {item.from_version} not in {self.version_range=}')
                        continue
                    if item.to_version and item.to_version < self.version_range.min_version:
                        logging.debug(f'skipping {id_=} as {item.to_version=} not in {self.version_range=}')
                        continue

                    """
                    the next checks are applied here, after the `continue` checks (and not before) 
                    as the preceding checks prevent false positives.
                     """
                    if id_ in result:
                        raise ValueError(f'{id_=} already parsed')
                    result[id_] = item
        return result

    def _calculate_script_to_tests(self):
        result = defaultdict(list)
        for test in self.test_playbooks:
            for script in test.implementing_scripts:
                result[script].append(test)
        return result


class CollectedTests:
    def __init__(
            self,
            tests: Optional[tuple[str] | list[str]],
            packs: Optional[tuple[str] | list[str]],
            reason: CollectionReason,
            id_set: IdSet,
            version_range: VersionRange,
            reason_description: Optional[str] = None
    ):
        self._id_set = id_set  # used for validations

        self.tests = set()  # only updated on init
        self.packs = set()  # only updated on init
        self.version_range = version_range

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
        # if self.machines or other.machines: # todo
        #     self.machines = set().union((self.machines or (), other.machines or ())) or None
        return self  # todo test

    @classmethod
    def union(cls, collected_tests: tuple['CollectedTests']):
        if not collected_tests:
            raise ValueError('Can not union an empty tuple of CollectedTests')

        result = collected_tests[0]
        for other in collected_tests[1:]:
            result |= other
        return result

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
            logging.info(f'collecting {test=}, {reason.value=} {reason_description}')
            self.tests.add(test)

        if pack:
            self._validate_pack(pack)
            logging.info(f'collecting {pack=}, {reason.value=} {reason_description}')
            self.packs.add(pack)

    def add_id_set_item(self, item: IdSetItem, reason: CollectionReason, reason_description: str = '',
                        add_pack: bool = True, add_test: bool = True):
        self._add_single(item.name, item.pack, reason, reason_description)

    def _validate_pack(self, pack: str) -> None:
        """ raises InvalidPackException if the pack name is not valid."""
        if not pack:
            raise InvalidPackNameException(pack)
        if pack in IGNORED_FILES:  # todo is necessary?
            raise IgnoredPackException(pack)
        if pack in SKIPPED_PACKS:  # todo is necessary?
            raise SkippedPackException(pack)
        if self._id_set.id_to_packs[pack].deprecated:  # todo safer access?
            raise DeprecatedPackException(pack)
        if not (CONTENT_PATH / 'Packs' / pack).exists():  # todo consider using listdir at beginning and checking there
            raise InvalidPackNameException(pack)

    def __repr__(self):
        return f'{len(self.packs)} packs, {len(self.tests)} tests, version range: {self.version_range}'


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
        return to_tuple(self.get('integrations'))  # todo may warn a lot, consider default value

    @property
    def from_version(self) -> Optional[Version]:
        if value := self.get('fromversion', warn_if_missing=False):
            return Version(value)

    @property
    def to_version(self) -> Optional[Version]:
        if value := self.get('toversion', warn_if_missing=False):
            return Version(value)

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
    def __init__(self, version_range: VersionRange, marketplace: MarketplaceVersions):
        self.marketplace = marketplace  # todo is this used anywhere but in passing to id_set?
        self.version_range = version_range

        self.id_set = IdSet(self.version_range, marketplace)
        self.conf = TestConf()

        # todo FAILED_

    @abstractmethod
    def _collect(self) -> CollectedTests:
        """
        Collects all relevant tests into self.collected.
        Every inheriting class implements its own methodology here.
        :return: A CollectedTests object with only the packs to install and tests to run, with machines=None.
        """
        pass

    def collect(self, run_nightly: bool, run_master: bool):
        collected = self._collect()
        collected.machines = Machine.get_suitable_machines(self.version_range, run_nightly, run_master)

        if collected.machines is None and not collected.not_empty:  # todo reconsider
            raise EmptyMachineListException()

        collected |= self._add_packs_used(collected.tests)
        return collected

    def _add_packs_used(self, tests: set[str]):
        return self._add_packs_from_tested_integrations(tests) | self._add_packs_from_test_playbooks(tests)

    def _add_packs_from_tested_integrations(self, tests: set[str]) -> CollectedTests:  # only called in _add_packs_used
        # todo is it used in the new version?
        logging.info(f'searching for integrations used in test playbooks, '
                     f'to make sure the integration packs are installed')
        collected = []

        for test in tests:
            for integration in self.conf.tests_to_integrations.get(test, ()):
                if pack := self.id_set.integration_to_pack.get(integration):  # todo what if not?
                    collected.append(self._collect_pack(pack, CollectionReason.PACK_MATCHES_INTEGRATION))

        return CollectedTests.union(*collected)

    def _collect_pack(self, name: str, reason: CollectionReason, reason_description: str) -> CollectedTests:
        pack = ContentItem(CONTENT_PATH / 'Packs' / name / 'pack_metadata.json')
        return CollectedTests(tests=None, packs=(name,), reason=reason, reason_description=reason_description,
                              id_set=self.id_set, version_range=pack.version_range)

    def _add_packs_from_test_playbooks(self, tests: set[str]):  # only called in _add_packs_used
        logging.info(f'searching for packs under which test playbooks are saved, to make sure they are installed')
        collected = []

        for test in tests:
            if pack := self.id_set.test_playbooks_to_pack[test]:  # todo is okay to fail when tpb is not in id-set?
                collected.append(
                    self._collect_pack(pack, reason=CollectionReason.PACK_MATCHES_TEST, reason_description='')
                )
        return CollectedTests.union(*collected)


def get_changed_files(branch_name: str):
    repo = Repo()
    repo.git.checkout(branch_name)

    git_util = GitUtil(repo)  # todo provide path or use the one above
    prev_ver = MASTER
    if str(git_util.repo.active_branch == MASTER):
        # 2 instead of 1, as gitlab creates an extra commit when merging
        prev_ver = str(next(islice(git_util.repo.iter_commits(), 2, 3)))  # returns 2nd latest commit todo test

        # prev_ver = str(tuple(repo.iter_commits())[2]) # todo remove after testing previous line

    added_files = git_util.added_files(prev_ver=prev_ver)
    modified_files = git_util.modified_files(prev_ver=prev_ver)
    renamed_files = {new_file_path for _, new_file_path in git_util.renamed_files(prev_ver=prev_ver)}
    deleted_files = git_util.deleted_files(prev_ver=prev_ver)  # todo necessary?

    return added_files | modified_files | renamed_files | deleted_files


class NoPackException(Exception):
    def __init__(self, path: Path):
        self.message = f'Could not find a pack for {str(path)}'
        super().__init__(self.message)


def find_pack(path: Path) -> Path:
    """
    >>> find_pack(Path('root/Packs/MyPack/Integrations/MyIntegration/MyIntegration.yml'))
    PosixPath('root/Packs/MyPack')
    >>> find_pack(Path('Packs/MyPack/Scripts/MyScript/MyScript.py')).name
    'MyPack'
    """
    if 'Packs' not in path.parts:
        raise NoPackException(path)
    return path.parents[len(path.parts) - (path.parts.index('Packs')) - 3]


class NoTestsToCollect(Exception):
    def __init__(self, path: Path, reason: str):
        self.message = f'No tests to collect for {str(path)}: {reason}'
        super().__init__(self.message)


class BranchTestCollector(TestCollector):
    def __init__(self, version_range: VersionRange, branch_name: str, marketplace: MarketplaceVersions):
        super().__init__(version_range, marketplace)
        self.branch_name = branch_name

    def _collect(self) -> CollectedTests:
        # None filter is for empty tests, returned by
        collected = []
        for path in get_changed_files(self.branch_name):
            try:
                collected.append(self._collect_single(path))
            except NoTestsToCollect as e:
                logging.warning(e.message)
        collected = CollectedTests.union(*collected)  # todo
        if not collected:
            raise NotImplementedError()  # todo return sanity tests
        return collected

    def _collect_single(self, path) -> CollectedTests:
        file_type = find_type_by_path(path)
        try:
            content_item = ContentItem(path)

        except NoPackException as e:
            # files that are supposed to not be in a pack, and are ignored.
            if path in {}:  # todo handle non-content items, exclude list
                raise NoTestsToCollect(path, e.message)
            raise  # files that are either supposed to be in a pack, or should not be ignored.

        match file_type:
            case FileType.PACK_IGNORE | FileType.SECRET_IGNORE | FileType.DOC_FILE | FileType.README:
                raise NoTestsToCollect(path, f'ignored type ({file_type}')

            case FileType.INTEGRATION:
                if path.suffix not in INTEGRATION_SCRIPT_COLLECTED_FILE_TYPES:
                    raise ValueError(f'unexpected file extension ({path.suffix}) for integration')

                integration_id = content_item.id_

                return CollectedTests(tests=self.conf.integrations_to_tests[integration_id],
                                      packs=content_item.pack_tuple, reason=CollectionReason.INTEGRATION_CHANGED,
                                      id_set=self.id_set, version_range=, reason_description=f'{integration_id=}')

            case FileType.SCRIPT | FileType.PLAYBOOK:
                if file_type == FileType.SCRIPT and path.suffix not in INTEGRATION_SCRIPT_COLLECTED_FILE_TYPES \
                        or file_type == FileType.PLAYBOOK and path.suffix != '.yml':
                    raise ValueError(f'unexpected file extension ({path.suffix}) for {file_type=}')

                try:
                    tests = content_item.tests
                    reason = CollectionReason.SCRIPT_CHANGED

                except NoTestsConfiguredException:
                    tests = self.id_set.test_playbooks_to_pack.get(content_item.id_)
                    reason = CollectionReason.SCRIPT_CHANGED_NO_TESTS
                    if not tests:
                        # todo is this necessary?
                        logging.debug(f'{file_type.value} {str(path)} has `No Tests` configured,'
                                      f' and no tests in id_set')

                return CollectedTests(tests=tests, packs=content_item.pack_tuple, reason=reason, id_set=self.id_set,
                                      version_range=, reason_description=None)

            case FileType.IMAGE | FileType.DESCRIPTION:  # todo readme shows twice
                return CollectedTests(tests=None, packs=content_item.pack_tuple,
                                      reason=CollectionReason.NON_CODE_FILE_CHANGED, id_set=self.id_set, version_range=,
                                      reason_description=f'{FileType=}')

            case FileType.TEST_PLAYBOOK:  # todo what to do with playbook readme?
                if not path.suffix != '.yml':  # todo is this necessary?
                    raise ValueError(f'unexpected file extension ({path.suffix}) for playbook')

                if (test_id := content_item.id_) in self.conf.test_ids:
                    return CollectedTests(tests=(test_id,), packs=content_item.pack_tuple,
                                          reason=CollectionReason.TEST_PLAYBOOK_CHANGED, id_set=self.id_set,
                                          version_range=)  # todo machines

            case FileType.REPUTATION:  # todo reputationjson
                pass  # todo

            case FileType.MAPPER:
                if tests := (self.conf.incoming_mapper_to_test.get(content_item.id_)):
                    return CollectedTests(tests=tests, packs=content_item.pack_tuple,
                                          reason=CollectionReason.MAPPER_CHANGED, id_set=self.id_set, version_range=,
                                          reason_description=content_item.name)
                    )
                    # todo machines

                    return CollectedTests(tests=tests, packs=content_item.pack_tuple,
                                          reason=CollectionReason.NON_CODE_FILE_CHANGED, id_set=self.id_set,
                                          version_range=,
                                          reason_description=f'no specific tests for {content_item.name} were found')  # todo machines

                case
                FileType.CLASSIFIER:  # todo what about old_classifier?
                pass  # todo

            case FileType.README | FileType.METADATA | FileType.RELEASE_NOTES | FileType.RELEASE_NOTES_CONFIG | \
                 FileType.IMAGE | FileType.DESCRIPTION | FileType.INCIDENT_TYPE | FileType.INCIDENT_FIELD | \
                 FileType.INDICATOR_FIELD | FileType.LAYOUT | FileType.WIDGET | FileType.DASHBOARD | FileType.REPORT | \
                 FileType.PARSING_RULE | FileType.MODELING_RULE | FileType.CORRELATION_RULE | \
                 FileType.XSIAM_DASHBOARD | FileType.XSIAM_REPORT | FileType.REPORT | FileType.GENERIC_TYPE | \
                 FileType.GENERIC_FIELD | FileType.GENERIC_MODULE | FileType.GENERIC_DEFINITION | \
                 FileType.PRE_PROCESS_RULES | FileType.JOB | FileType.CONNECTION:
                return CollectedTests(tests=None, packs=pack_tuple, reason=CollectionReason.NON_CODE_FILE_CHANGED,
                                      id_set=self.id_set, version_range=, reason_description=str(path))
                # todo rn_config?
                # todo layout container, xsiam config?

            case None:
                raise RuntimeError(f'could not find file_type for {path}')

            case _:
                raise NotImplementedError(f'Unexpected filetype {file_type}')

        # todo usage before assignment?
        return CollectedTests(tests=tests, packs=packs, reason=reason, id_set=self.id_set, version_range=,
                              reason_description=reason_description)


class NightlyTestCollector(TestCollector):
    def _collect(self) -> CollectedTests:
        tests_by_marketplace = self._tests_matching_marketplace_value()
        packs_by_marketplace = self._packs_matching_marketplace_value()

        collected: list[CollectedTests] = [
            tests_by_marketplace,
            packs_by_marketplace,
        ]

        if self.marketplace == MarketplaceVersions.MarketplaceV2:
            collected.append(self.id_set.get_marketplace_v2_tests())
        # todo is there a similar list for the marketplacev1?

        return CollectedTests.union(*collected)

    def _tests_matching_marketplace_value(self) -> CollectedTests:
        marketplace_string = self.marketplace.value  # todo is necessary?
        logging.info(f'collecting test playbooks by their marketplace field, searching for {marketplace_string}')
        tests = []

        for playbook in self.id_set.test_playbooks:
            if marketplace_string in playbook.marketplaces and playbook.tests:
                tests.extend(playbook.tests)

        return CollectedTests(tests=tests, packs=None, reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              id_set=self.id_set, version_range=, reason_description=f'({marketplace_string})')

    def _packs_matching_marketplace_value(self) -> CollectedTests:
        # todo make sure we have a validation, that pack_metadata.marketplaces includes
        marketplace_string = self.marketplace.value
        logging.info(f'collecting packs by their marketplace field, searching for {marketplace_string}')

        packs = tuple(
            pack.id_ for pack in self.id_set.packs if marketplace_string in (pack.marketplaces or ())
        )
        # todo what's the default behavior for a missing marketplace value?

        return CollectedTests(tests=None, packs=packs, reason=CollectionReason.MARKETPLACE_VERSION_BY_VALUE,
                              id_set=self.id_set, version_range=, reason_description=f'({marketplace_string})')


class UploadCollector(TestCollector):
    # todo today we collect packs, not tests
    def _collect(self) -> CollectedTests:
        pass


class NoTestsConfiguredException(Exception):
    """ used when an integration has no tests configured """

    # todo log test collection reasons
    def __init__(self, content_id: str):
        self.id_ = content_id  # todo use or remove


if __name__ == '__main__':
    sys.path.append(str(CONTENT_PATH))
    collector = NightlyTestCollector(  # todo replace with real usage
        marketplace=MarketplaceVersions.XSOAR,
        version_range=VersionRange(Machine.V6_2.value, Machine.V6_6.value)
    )
    collector.collect(True, True)
