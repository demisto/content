import os
from functools import lru_cache

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from itertools import islice
from pathlib import Path
from typing import Any, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.common.tools import JSON_Handler, get_file

from git import Repo
from packaging import version

from Tests.scripts.utils import logging_wrapper as logging

MASTER = 'master'

git = GitUtil()
json = JSON_Handler()

CONTENT_PATH = Path(__file__).absolute().parent.parent

ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_ID_SET_PATH = ARTIFACTS_PATH / 'id_set.json'
ARTIFACTS_CONF_PATH = ARTIFACTS_PATH / 'conf.json'


class DictBased:
    def __init__(self, path: Path):
        self.path = path
        self.content = get_file(path, path.suffix[1:])

    def get(self, key: str, default: Any = None, warn_if_missing: bool = True):
        if key not in self.content and warn_if_missing:
            logging.warning(f'attempted to access key {key}, which does not exist in conf.json')
        return self.content.get(key, default)

    def __getitem__(self, key):
        return self.content(key)


class Machine(Enum):
    V6_2 = version.Version('6.2')
    V6_5 = version.Version('6.5')
    V6_6 = version.Version('6.6')
    MASTER = 'master'
    NIGHTLY = 'nightly'

    @staticmethod
    def get_relevant_versions(
            min_version: version.Version, max_version: version.Version, run_nightly: bool, run_master: bool
    ) -> tuple['Machine']:
        result = [
            machine for machine in Machine
            if isinstance(machine.value, version.Version) and min_version <= machine.value <= max_version
        ]
        if run_nightly:
            result.append(Machine.NIGHTLY)
        if run_master:
            result.append(Machine.MASTER)

        return tuple(result)


class TestConf(DictBased):
    __test__ = False  # prevents pytest from running it

    def __init__(self, path: Path = ARTIFACTS_CONF_PATH):
        super().__init__(path)

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


class IdSet(DictBased):
    def __init__(self, path: Path = ARTIFACTS_ID_SET_PATH):
        super().__init__(path)
        self.integration_id_to_path = self._integration_to_path()

    @property
    @lru_cache
    def test_playbooks(self):
        return self.get('TestPlaybooks', ())

    @property
    @lru_cache
    def integrations(self):
        return self.get('integrations', ())

    def get_test_playbook(self, id_: str):
        for test_playbook in self.test_playbooks:
            if id_ in test_playbook:
                return test_playbook[id_]

    def get_integration_path(self, id_: str):
        try:
            return self.integration_id_to_path[id_]
        except IndexError:
            logging.critical(f'Could not find integration "{id_}" in the id_set')  # todo handle

    def _integration_to_path(self):  # todo is necessary?
        result = {}
        for integration in self.integrations:  # ['name': {'name':.., 'file_path':...},...]
            for value in integration.values():
                result[value['name']] = value['file_path']
        return result


@dataclass
class CollectedTests:
    tests: set[str]
    packs: set[str]
    machines: Optional[tuple[Machine]] = None

    @property
    def not_empty(self):
        return any((self.tests, self.packs))


class EmptyMachineListException(Exception):
    pass


class InvalidVersionException(Exception):
    pass


class TestCollector(ABC):
    def __init__(self, marketplace: MarketplaceVersions):
        self.tests = set()
        self.packs = set()
        self.min_version = version.Infinity
        self.max_version = version.NegativeInfinity
        self.marketplace = marketplace
        # todo FAILED_

    @abstractmethod
    def _collect(self) -> CollectedTests:
        """
        Collects all relevant tests.
        Every inheriting class implements its own methodology here.
        :return: A CollectedTests object with only the packs to install and tests to run, with machines=None.
        """
        pass

    def _collect_item(self, content_id: str, pack_id: str, add_pack: bool, add_test: bool):
        if add_test:
            self.tests.add(content_id)
        if add_pack:
            self.packs.add(pack_id)

    def collect(self, run_nightly: bool, run_master: bool):
        collected = self._collect()
        default_versions = self.max_version == version.NegativeInfinity or self.min_version == version.Infinity
        if collected.not_empty and default_versions:
            # todo reconsider
            # todo change condition
            raise InvalidVersionException()

        collected.machines = Machine.get_relevant_versions(
            self.min_version,
            self.max_version,
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
        super().__init__(marketplace)
        self.branch_name = branch_name

    def _collect(self) -> CollectedTests:
        changed_files = get_changed_files(self.branch_name)
        # todo
        pass


class NightlyTestCollector(TestCollector):
    def _collect(self) -> CollectedTests:
        pass


class UploadCollector(TestCollector):
    # todo today we collect packs, not tests
    def _collect(self) -> CollectedTests:
        pass


# todo log test collection reasons
class NoTestsException(Exception):
    def __init__(self, content_id: str):
        self.id_ = content_id  # todo use or remove


class ContentItem(DictBased):
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
    id_set = IdSet()
    conf = TestConf()
