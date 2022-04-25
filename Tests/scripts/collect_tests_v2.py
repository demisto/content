import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from itertools import islice
from pathlib import Path
from typing import Any, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.common.tools import JSON_Handler

from git import Repo
from packaging import version

from Tests.scripts.utils import logging_wrapper as logging

MASTER = 'master'

git = GitUtil()
json = JSON_Handler()

CONTENT_PATH = Path(__file__).absolute().parent.parent
sys.path.append(str(CONTENT_PATH))

ARTIFACTS_PATH = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_ID_SET_PATH = ARTIFACTS_PATH / 'id_set.json'
ARTIFACTS_CONF_PATH = ARTIFACTS_PATH / 'conf.json'


class Machine(Enum):
    V6_1 = version.Version('6.1')
    V6_2 = version.Version('6.2')
    V6_5 = version.Version('6.5')
    V6_6 = version.Version('6.6')
    MASTER = 'master'
    NIGHTLY = 'nightly'

    @staticmethod
    def get_relevant_versions(
            min_version: version.Version, max_version: version.Version, run_nightly: bool, run_master: bool
    ) -> tuple[__class__]:
        result = [
            machine for machine in Machine
            if isinstance(machine.value, version.Version) and min_version <= machine.value <= max_version
        ]
        if run_nightly:
            result.append(Machine.NIGHTLY)
        if run_master:
            result.append(Machine.MASTER)

        return tuple(result)


class TestConf:
    __test__ = False  # prevents pytest from running it

    def __init__(self, conf: dict):
        self._conf = conf

    def _get(self, key: str, default: Any = None):
        if key not in self._conf:
            logging.warning(f'attempted to access key {key}, which does not exist in conf.json')
        return self._conf.get(key, default)

    def get_skipped_integrations(self):
        return tuple(self._get('skipped_integrations', {}).keys())

    def get_skipped_tests(self):
        return tuple(self._get('skipped_tests', {}).keys())

    def get_private_tests(self) -> tuple:
        return tuple(self._get('private_tests', ()))

    def get_tests(self) -> dict:
        return self._get('tests', {})

    def get_xsiam_tests(self):
        return self._get('test_marketplacev2')  # todo what's the type here? Add default.


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
    def __init__(self):
        self.tests = set()
        self.packs = set()
        self.min_version = version.Infinity
        self.max_version = version.NegativeInfinity
        with ARTIFACTS_ID_SET_PATH.open() as file:
            self.id_set = json.load(file)
        with ARTIFACTS_CONF_PATH.open() as file:
            self.conf = TestConf(json.load(file))

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
        # prev_ver = str(tuple(repo.iter_commits())[2]) # todo remove after testing next line

        prev_ver = str(next(islice(git_util.repo.iter_commits(), 2, 3)))  # returns 2nd latest commit todo test

    added_files = git_util.added_files(prev_ver=prev_ver)
    modified_files = git_util.modified_files(prev_ver=prev_ver)
    renamed_files = {new_file_path for _, new_file_path in git_util.renamed_files(prev_ver=prev_ver)}
    deleted_files = git_util.deleted_files(prev_ver=prev_ver)  # todo necessary?

    return added_files | modified_files | renamed_files | deleted_files


class BranchTestCollector(TestCollector):
    def __init__(self, id_set_file: Path, branch_name: str):
        super().__init__(id_set_file)
        self.branch_name = branch_name

    def _collect(self) -> CollectedTests:
        changed_files = get_changed_files(self.branch_name)
        # todo
        pass


class NightlyTestCollector(TestCollector):
    def _collect(self) -> CollectedTests:
        pass
