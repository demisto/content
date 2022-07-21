from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions, FileType
from demisto_sdk.commands.common.tools import json, yaml
from exceptions import (
    DeprecatedPackException,
    InvalidPackNameException,
    NonDictException,
    NonexistentPackException,
    NoTestsConfiguredException,
    NotUnderPackException,
    SkippedPackException,
    UnsupportedPackException,
)
from logger import logger
from packaging import version
from packaging.version import Version
from path_manager import PathManager


def find_pack_folder(path: Path) -> Path:
    """
    >>> find_pack_folder(Path('root/Packs/MyPack/Integrations/MyIntegration/MyIntegration.yml'))
    PosixPath('root/Packs/MyPack')
    >>> find_pack_folder(Path('Packs/MyPack1/Scripts/MyScript/MyScript.py')).name
    'MyPack1'
    >>> find_pack_folder(Path('Packs/MyPack2/Scripts/MyScript')).name
    'MyPack2'
    >>> find_pack_folder(Path('Packs/MyPack3/Scripts')).name
    'MyPack3'
    >>> find_pack_folder(Path('Packs/MyPack4')).name
    'MyPack4'
    """
    if 'Packs' not in path.parts:
        raise NotUnderPackException(path)
    if path.parent.name == 'Packs':
        return path
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
    V6_5 = Version('6.5')
    V6_6 = Version('6.6')
    V6_8 = Version('6.8')
    MASTER = 'master'
    NIGHTLY = 'nightly'

    @staticmethod
    def numeric_machines() -> tuple['Machine', ...]:
        return tuple(machine for machine in Machine if isinstance(machine.value, Version))

    @staticmethod
    def get_suitable_machines(version_range: Optional[VersionRange], run_nightly: bool, run_master: bool) \
            -> tuple['Machine', ...]:
        result: list[Machine] = []

        if not version_range:
            version_range = VersionRange(version.NegativeInfinity, version.Infinity)

        result.extend(machine for machine in Machine.numeric_machines() if machine.value in version_range)

        if run_nightly:
            result.append(Machine.NIGHTLY)
        if run_master:
            result.append(Machine.MASTER)

        return tuple(result)

    def __repr__(self):
        return f'Server {self.value}'


class DictBased:
    def __init__(self, dict_: dict):
        if not isinstance(dict_, dict):
            raise ValueError('DictBased must be initialized with a dict')
        self.content = dict_
        self.from_version = self._calculate_from_version()
        self.to_version = self._calculate_to_version()
        self.version_range = VersionRange(self.from_version, self.to_version)
        self.marketplaces: Optional[tuple[MarketplaceVersions, ...]] = \
            tuple(MarketplaceVersions(v) for v in self.get('marketplaces', (), warn_if_missing=False)) or None

    def get(self, key: str, default: Any = None, warn_if_missing: bool = True, warning_comment: str = ''):
        if key not in self.content and warn_if_missing:
            suffix = f' ({warning_comment})' if warning_comment else ''
            logger.warning(f'attempted to access nonexistent key {key}{suffix}')
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
    def __init__(self, path: Path, is_infrastructure: bool = False):
        if not path.exists():
            raise FileNotFoundError(path)
        try:
            PackManager.relative_to_packs(path)
        except NotUnderPackException:
            if is_infrastructure:
                pass
            else:
                raise  # todo remove

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
        self.pack_path = find_pack_folder(self.path)
        self.deprecated = self.get('deprecated', warn_if_missing=False)

    @property
    def id_(self) -> Optional[str]:  # property as pack_metadata (for example) doesn't have this field
        return self['commonfields']['id'] if 'commonfields' in self.content else self['id']

    @property
    def pack_folder_name_tuple(self) -> tuple[str]:
        return self.pack_path.name,

    @property
    def name(self) -> str:
        id_ = self.get('id', '', warn_if_missing=False)
        return self.get('name', default='', warn_if_missing=False, warning_comment=id_)

    @property
    def tests(self) -> list[str]:
        tests = self.get('tests', [], warn_if_missing=False)
        if len(tests) == 1 and 'no tests' in tests[0].lower():
            raise NoTestsConfiguredException(self.id_)
        return tests

    @property
    def pack_id(self):
        return self.pack_path.name


class PackManager:
    skipped_packs = {'DeprecatedContent', 'NonSupported', 'ApiModules'}

    def __init__(self, path_manager: PathManager):
        self.packs_path = path_manager.packs_path

        self.deprecated_packs: set[str] = set()
        self.pack_id_to_pack_metadata: dict[str, ContentItem] = {}  # NOTE: The ID of a pack is the name of its folder.
        self.pack_id_to_pack_name_field: dict[str, str] = {}

        for pack_folder in (
            pack_folder
            for pack_folder in self.packs_path.iterdir()
            if pack_folder.is_dir()
        ):
            metadata = ContentItem(pack_folder / 'pack_metadata.json')
            self.pack_id_to_pack_metadata[pack_folder.name] = metadata
            self.pack_id_to_pack_name_field[pack_folder.name] = metadata.name

            if metadata.deprecated:
                self.deprecated_packs.add(pack_folder)

        self.pack_ids: set[str] = set(self.pack_id_to_pack_metadata.keys())
        self.pack_name_to_pack_folder_name: dict[str, str] = {v: k for k, v in self.pack_id_to_pack_name_field.items()}

    def get_pack_by_path(self, path: Path) -> ContentItem:
        return self.pack_id_to_pack_metadata[path.name]

    def __getitem__(self, pack_folder_name: str) -> ContentItem:
        return self.pack_id_to_pack_metadata[pack_folder_name]

    def __iter__(self):
        yield from self.pack_id_to_pack_metadata.values()

    @staticmethod
    def relative_to_packs(path: Path | str):
        if isinstance(path, str):
            path = Path(path)
        parts = path.parts
        if 'Packs' not in parts:
            raise NotUnderPackException(path)
        return Path(*path.parts[path.parts.index('Packs') + 1:])

    def validate_pack(self, pack: str) -> None:
        """raises InvalidPackException if the pack name is not valid."""
        if not pack:
            raise InvalidPackNameException(pack)
        if pack in PackManager.skipped_packs:
            raise SkippedPackException(pack)
        if pack in self.deprecated_packs:
            raise DeprecatedPackException(pack)
        if pack not in self.pack_ids:
            logger.error(f'nonexistent pack {pack}')
            raise NonexistentPackException(pack)
        if not (support_level := self[pack].get('support')):
            raise ValueError(f'pack {pack} has no support level (`support`) field or value')
        if support_level.lower() != 'xsoar':
            raise UnsupportedPackException(pack)


def to_tuple(value: Optional[str | list]) -> Optional[tuple]:
    if value is None:
        return value
    if not value:
        return ()
    if isinstance(value, str):
        return value,
    return tuple(value)


def find_yml_content_type(yml_path: Path):
    return {
        'Playbooks': FileType.PLAYBOOK,
        'TestPlaybooks': FileType.TEST_PLAYBOOK,
    }.get(yml_path.parent.name) or {
        'Integrations': FileType.INTEGRATION,
        'Scripts': FileType.SCRIPT,
    }.get(
        yml_path.parents[1].name
    )
