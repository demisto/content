from configparser import ConfigParser, MissingSectionHeaderError
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from demisto_sdk.commands.common.constants import FileType, MarketplaceVersions
from demisto_sdk.commands.common.tools import json, yaml
from exceptions import (BlankPackNameException, DeprecatedPackException,
                        NonDictException, NonexistentPackException,
                        NoTestsConfiguredException, NotUnderPackException,
                        SkippedPackException, UnsupportedPackException)
from logger import logger
from packaging import version
from packaging._structures import InfinityType, NegativeInfinityType
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
    min_version: Version | NegativeInfinityType
    max_version: Version | InfinityType

    def __contains__(self, item):
        return self.min_version <= item <= self.max_version

    def __repr__(self):
        return f'{self.min_version} -> {self.max_version}'

    def __or__(self, other: Optional['VersionRange']) -> 'VersionRange':
        if other is None or other.is_default or self.is_default:
            return self

        self.min_version = min(self.min_version, other.min_version)
        self.max_version = max(self.max_version, other.max_version)

        return self

    @property
    def is_default(self):
        """
        :return: whether the range is (-Infinity -> Infinity)
        """
        return self.min_version == version.NegativeInfinity and self.max_version == version.Infinity


class Machine(Enum):
    """
    Represents an XSOAR version.
    Serves as the single source of truth for versions used for collect_tests.
    """
    V6_5 = Version('6.5')
    V6_6 = Version('6.6')
    V6_8 = Version('6.8')
    MASTER = 'master'
    NIGHTLY = 'nightly'

    @staticmethod
    def numeric_machines() -> tuple['Machine', ...]:
        return tuple(machine for machine in Machine if isinstance(machine.value, Version))

    @staticmethod
    def get_suitable_machines(version_range: Optional[VersionRange], run_nightly: bool) -> tuple['Machine', ...]:
        """

        :param version_range: range of versions. If None, all versions are returned.
        :param run_nightly: whether a nightly machine is required
        :return: Master, as well as all Machine items matching the input.
        """
        result: list[Machine] = [Machine.MASTER]

        if not version_range:
            version_range = VersionRange(version.NegativeInfinity, version.Infinity)

        result.extend(machine for machine in Machine.numeric_machines() if machine.value in version_range)

        if run_nightly:
            result.append(Machine.NIGHTLY)

        return tuple(result)

    def __str__(self):
        return f'Server {self.value}'


class DictBased:
    """
    Represents a dictionary-based object, parsing common properties
    """

    def __init__(self, dict_: dict):
        if not isinstance(dict_, dict):
            raise ValueError('DictBased must be initialized with a dict')
        self.content = dict_
        self.from_version: Version | NegativeInfinityType = self._calculate_from_version()
        self.to_version: Version | InfinityType = self._calculate_to_version()
        self.version_range = VersionRange(self.from_version, self.to_version)
        self.marketplaces: Optional[tuple[MarketplaceVersions, ...]] = \
            tuple(MarketplaceVersions(v) for v in self.get('marketplaces', (), warn_if_missing=False)) or None

    def get(self, key: str, default: Any = None, warn_if_missing: bool = True, warning_comment: str = ''):
        """
        allows fetching an attribute, with or without logging (useful for debug purposes)
        """
        if key not in self.content and warn_if_missing:
            suffix = f' ({warning_comment})' if warning_comment else ''
            logger.warning(f'attempted to access nonexistent key {key}{suffix}')
        return self.content.get(key, default)

    def __getitem__(self, key):
        return self.content[key]

    def _calculate_from_version(self) -> Version | NegativeInfinityType:
        # all three options are equivalent
        if value := (
                self.get('fromversion', warn_if_missing=False)
                or self.get('fromVersion', warn_if_missing=False)
                or self.get('fromServerVersion', warn_if_missing=False)
        ):
            return Version(value)
        return version.NegativeInfinity

    def _calculate_to_version(self) -> Version | InfinityType:
        # all three options are equivalent
        if value := (
                self.get('toversion', warn_if_missing=False)
                or self.get('toVersion', warn_if_missing=False)
                or self.get('toServerVersion', warn_if_missing=False)
        ):
            return Version(value)
        return version.Infinity


class DictFileBased(DictBased):
    """
    Represents a dictfile (json, yml), allowing access to common attributes (see DictBased)
    raising a NonDictException when called with an unsupported extension.
    """

    def __init__(self, path: Path, is_infrastructure: bool = False):
        if not path.exists():
            raise FileNotFoundError(path)
        try:
            PackManager.relative_to_packs(path)
        except NotUnderPackException:
            if not is_infrastructure:
                raise

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
    """
    Represents a dict-based content item (yml, json), providing access to common attributes.
    """

    def __init__(self, path: Path):
        super().__init__(path)
        self.pack_path = find_pack_folder(self.path)
        self.deprecated = self.get('deprecated', warn_if_missing=False)

    @property
    def id_(self) -> Optional[str]:  # Optional as pack_metadata (for example) doesn't have this field
        return self['commonfields']['id'] if 'commonfields' in self.content else self['id']

    @property
    def name(self) -> str:
        id_ = self.get('id', '', warn_if_missing=False)
        return self.get('name', default='', warn_if_missing=False, warning_comment=id_)

    @property
    def tests(self) -> list[str]:
        tests = self.get('tests', [], warn_if_missing=False)
        if len(tests) == 1 and 'no tests' in tests[0].lower():
            raise NoTestsConfiguredException(self.id_ or str(self.path))
        return tests

    @property
    def pack_id(self):
        return self.pack_path.name


def read_skipped_test_playbooks(pack_folder: Path) -> set[str]:
    """
    :param pack_folder: containing .pack_ignore
    :return: all file names of test playbooks skipped under the .pack_ignore.
    """
    file_prefix = 'file:'

    skipped_playbooks = set()
    config = ConfigParser(allow_no_value=True)
    config.read(pack_folder / '.pack_ignore')

    try:
        for section in filter(lambda s: s.startswith(file_prefix), config.sections()):
            file_name = section[(len(file_prefix)):]

            for key in filter(lambda k: k == 'ignore', config[section]):
                if config[section][key] == 'auto-test':
                    skipped_playbooks.add(file_name)

    except MissingSectionHeaderError:  # no `ignore` header
        pass

    return skipped_playbooks


class PackManager:
    skipped_packs = {'DeprecatedContent', 'NonSupported', 'ApiModules'}

    def __init__(self, path_manager: PathManager):
        self.packs_path = path_manager.packs_path
        self.deprecated_packs: set[str] = set()
        self._pack_id_to_pack_metadata: dict[str, ContentItem] = {}  # NOTE: The ID of a pack is its folder name
        self._pack_id_to_skipped_test_playbooks: dict[str, set[str]] = {}

        for pack_folder in (pack_folder for pack_folder in self.packs_path.iterdir() if pack_folder.is_dir()):
            metadata = ContentItem(pack_folder / 'pack_metadata.json')
            pack_id = pack_folder.name

            self._pack_id_to_skipped_test_playbooks[pack_id] = read_skipped_test_playbooks(pack_folder)

            self._pack_id_to_pack_metadata[pack_id] = metadata
            if metadata.deprecated:
                self.deprecated_packs.add(pack_id)

        self.pack_ids: set[str] = set(self._pack_id_to_pack_metadata.keys())

    def __getitem__(self, pack_id: str) -> ContentItem:
        return self._pack_id_to_pack_metadata[pack_id]

    def __iter__(self):
        yield from self._pack_id_to_pack_metadata.values()

    def is_test_skipped_in_pack_ignore(self, test_file_name: str, pack_id: str):
        return test_file_name in self._pack_id_to_skipped_test_playbooks[pack_id]

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
        if pack in ALWAYS_INSTALLED_PACKS:
            return
        if not pack:
            raise BlankPackNameException(pack)
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


def find_yml_content_type(yml_path: Path) -> Optional[FileType]:
    """
    :param yml_path: path to some yml of a content item
    :return: matching FileType, based on the yml path
    """
    return {'Playbooks': FileType.PLAYBOOK, 'TestPlaybooks': FileType.TEST_PLAYBOOK}.get(yml_path.parent.name) or \
           {'Integrations': FileType.INTEGRATION, 'Scripts': FileType.SCRIPT, }.get(yml_path.parents[1].name)
