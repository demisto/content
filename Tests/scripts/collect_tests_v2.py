import os
import sys
from abc import ABC, abstractmethod
from dataclasses import field
from distutils.version import Version
from enum import Enum
from itertools import chain, islice
from pathlib import Path
from typing import Any, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.common.tools import get_file
from git import Repo
from packaging import version

from Tests.scripts.utils import logging_wrapper as logging

git_util = GitUtil()

MASTER = 'master'
CONTENT_PATH = Path(__file__).absolute().parent.parent

ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_ID_SET_PATH = ARTIFACTS_PATH / 'id_set.json'
ARTIFACTS_CONF_PATH = ARTIFACTS_PATH / 'conf.json'


class CollectionReason(Enum):
    MARKETPLACE_VERSION_BY_VALUE = 'value of the test `marketplace` field'
    MARKETPLACE_VERSION_SECTION = 'listed under conf.json marketplace-specific section'


class DictBased:
    def __init__(self, dict_: dict):
        self.content = dict_

    def get(self, key: str, default: Any = None, warn_if_missing: bool = True):
        if key not in self.content and warn_if_missing:
            logging.warning(f'attempted to access key {key}, which does not exist in conf.json')
        return self.content.get(key, default)

    def __getitem__(self, key):
        return self.content[key]


class DictFileBased(DictBased):
    def __init__(self, path: Path):
        self.path = path
        super().__init__(get_file(path, path.suffix[1:]))


@dataclass
class VersionRange:
    min_version: Version
    max_version: Version

    def __contains__(self, item):
        return self.min_version <= item <= self.max_version

    def __ge__(self, other):
        return self.min_version >= other

    def __le__(self, other):
        return self.max_version <= other

    def __repr__(self):
        return f'{self.min_version} -> {self.max_version}'


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


class TestConf(DictFileBased):
    __test__ = False  # prevents pytest from running it

    def __init__(self):
        super().__init__(ARTIFACTS_CONF_PATH)
        self.tests = tuple(TestConfItem(value) for value in self['scripts'])  # todo is used?
        self.tests_to_integrations = {test['playbookID']: to_tuple(test['integrations']) for test in self.tests}

    def get_skipped_integrations(self):
        return tuple(self.get('skipped_integrations', {}).keys())

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
        self.id_ = id_
        self.name = self.content['name']
        self.file_path = self.content['file_path']
        self.pack = self.content['pack']

    @property
    def marketplaces(self):
        if values := self.content.get('marketplaces'):
            return tuple(MarketplaceVersions(v) for v in values)

    @property
    def from_version(self):
        if value := self.content.get('fromversion'):
            return Version(value)

    @property
    def to_version(self):
        if value := self.content.get('toversion'):
            return Version(value)

    @property
    def integrations(self):
        return to_tuple(self.content.get('integrations'))


class CollectedTests:
    tests: set[str] = field(default_factory=set)
    packs: set[str] = field(default_factory=set)
    machines: Optional[tuple[Machine]] = None

    @property
    def not_empty(self):
        return any((self.tests, self.packs))

    def __or__(self, other: 'CollectedTests') -> 'CollectedTests':
        self.tests.update(other.tests)
        self.packs.update(other.packs)
        if self.machines is not None or other.machines is not None:
            self.machines = (self.machines or set()) | (other.machines or set())

        return self

    @staticmethod
    def union(collected_tests: tuple['CollectedTests']):
        result = CollectedTests()
        for other in collected_tests:
            result |= other
        return result

    def add(
            self, test_name: Optional[str],
            pack_id: Optional[str],
            reason: CollectionReason,
            reason_description: str = '',
            add_pack: bool = True,
            add_test: bool = True,
    ):
        logging.info(f'collected {pack_id=} {test_name=}, {reason.value=} {reason_description}')
        if add_test:
            if not test_name:
                raise ValueError('cannot add a test without its name')
            self.tests.add(test_name)

        if add_pack:
            if not pack_id:
                raise ValueError('cannot add pack without its id')
            self.packs.add(pack_id)

    def add_iterable(
            self,
            tests: Optional[tuple[str]],
            pack_ids: Optional[tuple[str]],
            reason: CollectionReason,
            reason_description: str = '',
            add_pack: bool = True,
            add_test: bool = True,
    ):
        if tests and pack_ids:
            if len(tests) != len(pack_ids):
                raise ValueError(f'if both have values, {len(tests)=} must be equal to {len(pack_ids)=}')
        elif tests:
            pack_ids = (None,) * len(pack_ids)
        elif pack_ids:
            tests = (None,) * len(pack_ids)

        for i in range(len(tests)):
            self.add(tests[i], pack_ids[i], reason, reason_description, add_pack, add_test)


class IdSet(DictFileBased):
    def __init__(self, version_range: VersionRange, marketplace: MarketplaceVersions):
        super().__init__(ARTIFACTS_ID_SET_PATH)
        self.version_range = version_range
        self.marketplace = marketplace

        self.scripts = self._parse_items(self['scripts'])
        self.integrations = self._parse_items(self['integrations'])
        self.test_playbooks = self._parse_items(self['TestPlaybooks'])

        self.id_to_item = {}

        for content_item in chain(self.scripts, self.integrations, self.test_playbooks):
            if content_item.id_ in self.id_to_item:
                raise ValueError(f'{content_item.id_=} already in collected-item id-to-item dict')
            self.id_to_item[content_item.id_] = content_item

    def get_test_playbooks_by_marketplace_section(self):
        """  returns test playbooks by the section under which they're saved in conf.json, regardless of their value """
        match self.marketplace:
            case MarketplaceVersions.XSOAR:
                tests = self['tests']
            case MarketplaceVersions.MarketplaceV2:
                tests = self['test_marketplacev2']
            case _:
                raise NotImplementedError(f'Unexpected Marketplace value {self.marketplace.value}')

        collected = CollectedTests()
        collected.add_iterable(tests, None, CollectionReason.MARKETPLACE_VERSION_SECTION, self.marketplace.value)
        return collected

    def _parse_items(self, dictionaries: list[dict]) -> tuple[IdSetItem]:
        result = []
        for dict_ in dictionaries:
            for id_, values in dict_.items():
                for value in values:  # may be multiple, for different server versions
                    item = IdSetItem(id_, value)

                    if \
                            (item.from_version and item.from_version > self.version_range) or (
                                    item.from_version and item.from_version < self.version_range):
                        logging.debug(f'skipping {item.id_=} as {item.from_version} not in {self.version_range}')
                        continue

                    if id_ in self.id_to_item:
                        raise ValueError(f'{id_=} already in self.id_to_item')

                    result.append(item)
                    self.id_to_item[id_] = item
        return tuple(result)


def to_tuple(value: Optional[str | list]) -> tuple:
    if not value:
        return ()
    if isinstance(value, str):
        return value,
    return tuple(value)


class EmptyMachineListException(Exception):
    pass


class InvalidVersionException(Exception):
    pass


class TestConfItem:
    def __init__(self, value: dict):
        self.content = value

    @property
    def integrations(self):
        return to_tuple(self.content['integrations'])

    @property
    def playbook_id(self) -> tuple[str]:
        return to_tuple(self.content['playbookID'])

    @property
    def from_version(self) -> Optional[Version]:
        if value := self.content.get('fromversion'):
            return Version(value)

    @property
    def to_version(self) -> Optional[Version]:
        if value := self.content.get('toversion'):
            return Version(value)

    @property
    def is_mockable(self):
        return self.content.get('is_mockable')


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

        collected.machines = Machine.get_suitable_machines(
            run_nightly,
            run_master,
        )

        if collected.machines is None and not collected.not_empty:
            raise EmptyMachineListException()

        return collected


def get_changed_files(branch_name: str):
    repo = Repo()
    repo.git.checkout(branch_name)

    git_util = GitUtil(repo)  # todo provide path
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


class BranchTestCollector(TestCollector):
    def __init__(self, branch_name: str, marketplace: MarketplaceVersions):
        super().__init__(marketplace, self.min_version, self.max_version)
        self.branch_name = branch_name

    def _collect(self) -> CollectedTests:
        changed_files = get_changed_files(self.branch_name)
        # todo
        pass


class NightlyTestCollector(TestCollector):
    def _collect(self) -> CollectedTests:
        by_marketplace_value = self.tests_matching_marketplace_value()
        by_marketplace_section = self.id_set.get_test_playbooks_by_marketplace_section()  # todo does this belong here or in id_set?

        return by_marketplace_value | by_marketplace_section

    def tests_matching_marketplace_value(self) -> CollectedTests:
        marketplace_string = self.marketplace.value  # todo is necessary?
        logging.info(f'collecting test playbooks by their marketplace field, searching for {marketplace_string}')
        collected = CollectedTests()

        for playbook in self.id_set.test_playbooks:
            if marketplace_string in playbook.marketplaces:
                collected.add(playbook.name, playbook.pack,
                              CollectionReason.MARKETPLACE_VERSION_BY_VALUE, marketplace_string)

        return collected


class UploadCollector(TestCollector):
    # todo today we collect packs, not tests
    def _collect(self) -> CollectedTests:
        pass


# todo log test collection reasons
class NoTestsException(Exception):
    def __init__(self, content_id: str):
        self.id_ = content_id  # todo use or remove


class ContentItem(DictFileBased):
    def __init__(self, path: Path):
        super().__init__(path)

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
            raise NoTestsException(self.id_)
        return tests


if __name__ == '__main__':
    sys.path.append(str(CONTENT_PATH))
    version_range = VersionRange(Machine.V6_2.value,
                                 Machine.V6_6.value)
    collector = NightlyTestCollector(marketplace=MarketplaceVersions.XSOAR, version_range=version_range)
    conf = TestConf()
