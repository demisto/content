from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from demisto_sdk.commands.common.constants import MarketplaceVersions
from demisto_sdk.commands.content_graph.interface.neo4j.neo4j_graph import Neo4jContentGraphInterface
from demisto_sdk.commands.content_graph.common import ContentType
from demisto_sdk.commands.content_graph.objects.content_item import ContentItem


from Tests.scripts.collect_tests.constants import \
    SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK
from Tests.scripts.collect_tests.exceptions import NotUnderPackException
from Tests.scripts.collect_tests.logger import logger
from Tests.scripts.collect_tests.utils import (DictBased, DictFileBased,
                                               PackManager, find_pack_folder,
                                               to_tuple)


class IdSetItem(DictBased):
    """
    Represents an ID-Set item (pack or content item).
    See the IdSet class to see how it's parsed.
    """

    def __init__(self, id_: Optional[str], dict_: dict):
        super().__init__(dict_)
        self.id_: Optional[str] = id_  # None for packs, as they don't have it.
        self.file_path_str: str = self.get('file_path', warn_if_missing=False)  # packs have no file_path value
        self.path: Optional[Path] = Path(self.file_path_str) if self.file_path_str else None
        self.name: str = self.get('name', '', warning_comment=self.file_path_str or '')

        # None for packs, that have no id.
        self.pack_id: Optional[str] = self.get('pack', warning_comment=self.file_path_str) if id_ else None
        self.pack_path: Optional[Path] = self._calculate_pack_path(self.path)

        if self.pack_path and self.pack_path.name != self.pack_id:
            logger.warning(f'{self.pack_path.name=}!={self.pack_id} for content item {self.id_=} {self.name=}')

        # hidden for pack_name_to_pack_metadata, deprecated for content items
        self.deprecated: Optional[bool] = \
            self.get('deprecated', warn_if_missing=False) or self.get('hidden', warn_if_missing=False)

    @classmethod
    def from_model(cls, model: ContentItem):
        return cls(id_=model.object_id,
                   dict_=model.to_id_set_entity(),
                   )

    @property
    def integrations(self):
        return to_tuple(self.get('integrations', (), warn_if_missing=False))

    @property
    def tests(self):
        return self.get('tests', ())

    @property
    def implementing_scripts(self) -> tuple[str, ...]:
        return tuple(self.get('implementing_scripts', (), warn_if_missing=False))

    @property
    def implementing_playbooks(self) -> tuple[str, ...]:
        return tuple(self.get('implementing_playbooks', (), warn_if_missing=False))

    @staticmethod
    def _calculate_pack_path(path: Optional[Path]) -> Optional[Path]:
        if not path:
            return None

        try:
            return find_pack_folder(path)

        except NotUnderPackException:
            if path.name in SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK:
                logger.info(f'{path=} is not under a pack, '
                            'but is part of SKIPPED_CONTENT_ITEMS__NOT_UNDER_PACK, skipping')
                return None
            else:
                raise

    @property
    def implementing_integrations(self) -> tuple[str, ...]:
        result: set[str] = set()
        # command_to_integrations maps commands to either a single integration, or a list of them
        # e.g. { command1: integration1,
        #        command2: [integration1, integration2, ...] }
        for command, integrations in self.get('command_to_integration', {}, warn_if_missing=False).items():
            result.update(
                (integrations,) if isinstance(integrations, str)
                else integrations
            )
        return tuple(sorted(result))


class IdSet(DictFileBased):
    """
    Allows access to the IdSet and the content it holds (using IdSetItem objects)
    """

    def __init__(self, marketplace: MarketplaceVersions, id_set_path: Path):
        super().__init__(id_set_path, is_infrastructure=True)
        self.marketplace = marketplace

        self.id_to_integration: dict[str, IdSetItem] = self._parse_items('integrations')
        self.id_to_script: dict[str, IdSetItem] = self._parse_items('scripts')
        self.id_to_test_playbook: dict[str, IdSetItem] = self._parse_items('TestPlaybooks')
        self.path_to_modeling_rule: dict[str, IdSetItem] = self._parse_items('ModelingRules')

        self.implemented_scripts_to_tests: dict[str, list] = defaultdict(list)
        self.implemented_playbooks_to_tests: dict[str, list] = defaultdict(list)

        for test in self.test_playbooks:
            for script in test.implementing_scripts:
                self.implemented_scripts_to_tests[script].append(test)
            for playbook in test.implementing_playbooks:
                self.implemented_playbooks_to_tests[playbook].append(test)

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
    def modeling_rules(self) -> Iterable[IdSetItem]:
        yield from self.path_to_modeling_rule.values()

    def _parse_items(self, key: str) -> dict[str, IdSetItem]:
        result: dict[str, IdSetItem] = {}
        if self.get(key):
            for dict_ in self[key]:
                for id_, values in dict_.items():
                    if isinstance(values, dict):
                        values = (values,)

                    for value in values:  # may have multiple values for different from/to versions
                        item = IdSetItem(id_, value)

                        if item.pack_id in PackManager.skipped_packs:
                            logger.debug(f'skipping {id_=} as the {item.pack_id} pack is skipped')
                            continue

                        if existing := result.get(id_):
                            # Some content items have multiple copies, each supporting different versions.
                            # We use the newer.
                            if item.to_version <= existing.to_version and item.from_version <= existing.from_version:
                                logger.debug(f'skipping duplicate of {item.name} as its version range '
                                             f'{item.version_range} is older than of the existing one, '
                                             f'{existing.version_range}')
                                continue

                        result[id_] = item
        return result


class Graph:
    def __init__(self, marketplace: MarketplaceVersions) -> None:
        self.marketplace = marketplace
        with Neo4jContentGraphInterface() as content_graph_interface:
            integrations = content_graph_interface.search(marketplace=marketplace,
                                                          content_type=ContentType.INTEGRATION)
            scripts = content_graph_interface.search(marketplace=marketplace,
                                                     content_type=ContentType.SCRIPT)
            test_playbooks = content_graph_interface.search(marketplace=marketplace,
                                                            content_type=ContentType.TEST_PLAYBOOK)
            playbooks = content_graph_interface.search(marketplace=marketplace,
                                                       content_type=ContentType.PLAYBOOK)
            modeling_rules = content_graph_interface.search(marketplace=marketplace,
                                                            content_type=ContentType.MODELING_RULE)
            # maps content_items to test playbook where they are used recursively

            self.id_to_integration = {integration.object_id: IdSetItem.from_model(integration) for integration in integrations}
            self.id_to_script = {script.object_id: IdSetItem.from_model(script) for script in scripts}
            self.id_to_test_playbook = {
                test_playbook.object_id: IdSetItem.from_model(test_playbook) for test_playbook in test_playbooks}
            self.path_to_modeling_rule = {
                modeling_rule.path: IdSetItem.from_model(modeling_rule) for modeling_rule in modeling_rules
            }
            self.implemented_playbooks_to_tests = {playbook.object_id: [IdSetItem.from_model(test) for test in playbook.tested_by]
                                                   for playbook in playbooks}
            self.implemented_scripts_to_tests = {script.object_id: [IdSetItem.from_model(test) for test in script.tested_by]
                                                 for script in scripts}

            self.test_playbooks = self.id_to_test_playbook.values()
            self.modeling_rules = self.path_to_modeling_rule.values()

    @property
    def artifact_iterator(self) -> Iterable[IdSetItem]:
        """ returns an iterator for all content items EXCLUDING PACKS """
        with Neo4jContentGraphInterface() as content_graph_interface:
            content_items = content_graph_interface.search(self.marketplace, content_type=ContentType.BASE_CONTENT)
            for content_item in content_items:
                if content_item.content_type not in {ContentType.COMMAND, ContentType.PACK}:
                    yield IdSetItem.from_model(content_item)
