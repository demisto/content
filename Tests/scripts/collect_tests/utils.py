from dataclasses import dataclass
from enum import Enum
from logging import getLogger
from pathlib import Path
from typing import Any, Optional

from demisto_sdk.commands.common.tools import json, yaml
from packaging import version
from packaging.version import Version

from Tests.scripts.collect_tests.constants import PACKS_PATH
from Tests.scripts.collect_tests.exceptions import (DeprecatedPackException,
                                                    InexistentPackException,
                                                    InvalidPackNameException,
                                                    NonDictException,
                                                    NoTestsConfiguredException,
                                                    NotUnderPackException,
                                                    SkippedPackException)

logger = getLogger('test_collection')  # todo is this the right way?


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


def to_tuple(value: Optional[str | list]) -> Optional[tuple]:
    if value is None:
        return value
    if not value:
        return ()
    if isinstance(value, str):
        return value,
    return tuple(value)
