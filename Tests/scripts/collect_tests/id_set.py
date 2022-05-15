from collections import defaultdict
from logging import getLogger
from typing import Iterable, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions

from Tests.scripts.collect_tests.constants import \
    DEBUG_ID_SET_PATH  # todo remove
from Tests.scripts.collect_tests.utils import (DictBased, DictFileBased,
                                               PackManager)

logger = getLogger('test_collection')  # todo is this the right way?


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
