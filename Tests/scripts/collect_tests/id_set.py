from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions
from logger import logger

from Tests.scripts.collect_tests.utils import (DictBased, DictFileBased,
                                               PackManager, to_tuple)


class IdSetItem(DictBased):
    def __init__(self, id_: Optional[str], dict_: dict):
        super().__init__(dict_)
        self.id_: Optional[str] = id_  # None for packs, as they don't have it.
        self.file_path: str = self.get('file_path', warn_if_missing=False)  # packs have no file_path value
        self.name: str = self.get('name', '', warning_comment=Path(self.file_path or '').name)

        # None for packs, that have no id.
        self.pack_id: Optional[str] = self.get('pack', warning_comment=self.file_path) if id_ else None

        # hidden for pack_name_to_pack_metadata, deprecated for content items
        self.deprecated: Optional[bool] = \
            self.get('deprecated', warn_if_missing=False) or self.get('hidden', warn_if_missing=False)

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

    @property
    def pack_name_tuple(self) -> tuple[str]:
        return self.pack_id,


class IdSet(DictFileBased):
    def __init__(self, marketplace: MarketplaceVersions, id_set_path: Path):
        super().__init__(id_set_path, is_infrastructure=True)
        self.marketplace = marketplace

        # Content items mentioned in the file
        self.id_to_script = self._parse_items('scripts')
        self.id_to_integration = self._parse_items('integrations')
        self.id_to_test_playbook = self._parse_items('TestPlaybooks')
        self.name_to_pack = {name: IdSetItem(None, value) for name, value in self['Packs'].items()}

        self.implemented_scripts_to_tests = defaultdict(list)
        self.implemented_playbooks_to_tests = defaultdict(list)

        for test in self.test_playbooks:
            for script in test.implementing_scripts:
                self.implemented_scripts_to_tests[script].append(test)
            for playbook in test.implementing_playbooks:
                self.implemented_playbooks_to_tests[playbook].append(test)

        # the folder under where a pack is saved serves as its id
        self.integration_to_pack_id: dict[str, str] = {integration.name: integration.pack_id
                                                       for integration in self.integrations}
        self.scripts_to_pack_id: dict[str, str] = {script.name: script.pack_id
                                                   for script in self.scripts}
        self.test_playbooks_to_pack_id: dict[str, str] = {test.name: test.pack_id
                                                          for test in self.test_playbooks}

    @property
    def artifact_iterator(self) -> Iterable[IdSetItem]:
        """ returns an iterator for all content items EXCLUDING PACKS """
        for content_type, values in self.content.items():
            if isinstance(values, list):
                for list_item in values:
                    for id_, value in list_item.items():
                        yield IdSetItem(id_, value)
            elif content_type == 'Packs':
                continue  # Packs are skipped as they have no ID.
            else:
                raise RuntimeError(f'unexpected id_set values for {content_type}. expected a list, got {type(values)}')

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

                for value in values:  # may have multiple values for different from/to versions
                    item = IdSetItem(id_, value)

                    if item.pack_id in PackManager.skipped_packs:
                        logger.info(f'skipping {id_=} as the {item.pack_id} pack is skipped')
                        continue

                    if existing := result.get(id_):
                        # Some content items have multiple copies, each supporting different versions. We use the newer.
                        if item.to_version <= existing.to_version and item.from_version <= existing.from_version:
                            logger.info(f'skipping duplicate of {item.name} as its version range {item.version_range} '
                                        f'is older than of the existing one, {existing.version_range}')
                            continue

                    result[id_] = item
        return result
