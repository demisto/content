from unittest.mock import patch
import networkx as nx

from Tests.Marketplace.packs_dependencies import calculate_single_pack_dependencies


def find_pack_display_name_mock(pack_folder_name):
    return pack_folder_name


class TestCalculateSinglePackDependencies:
    @classmethod
    def setup_class(cls):
        patch('demisto_sdk.commands.find_dependencies.find_dependencies.find_pack_display_name',
              side_effect=find_pack_display_name_mock)
        patch('Tests.scripts.utils.log_util.install_logging')
        graph = nx.DiGraph()
        graph.add_node('pack1', mandatory_for_packs=[])
        graph.add_node('pack2', mandatory_for_packs=[])
        graph.add_node('pack3', mandatory_for_packs=[])
        graph.add_node('pack4', mandatory_for_packs=[])
        graph.add_node('pack5', mandatory_for_packs=[])
        graph.add_edge('pack1', 'pack2')
        graph.add_edge('pack2', 'pack3')
        graph.add_edge('pack1', 'pack4')
        graph.nodes()['pack4']['mandatory_for_packs'].append('pack1')

        dependencies = calculate_single_pack_dependencies('pack1', graph)
        cls.first_level_dependencies, cls.all_level_dependencies, _ = dependencies

    def test_calculate_single_pack_dependencies_first_level_dependencies(self):
        """
        Given
            - A full dependency graph where:
                - pack1 -> pack2 -> pack3
                - pack1 -> pack4
                - pack4 is mandatory for pack1
                - pack5 and pack1 are not a dependency for any pack
        When
            - Running `calculate_single_pack_dependencies` to extract the first and all levels dependencies
        Then
            - Ensure first level dependencies for pack1 are only pack2 and pack4
        """
        all_nodes = {'pack1', 'pack2', 'pack3', 'pack4', 'pack5'}
        expected_first_level_dependencies = {'pack2', 'pack4'}
        for node in expected_first_level_dependencies:
            assert node in self.first_level_dependencies
        for node in all_nodes - expected_first_level_dependencies:
            assert node not in self.first_level_dependencies

    def test_calculate_single_pack_dependencies_all_levels_dependencies(self):
        """
        Given
            - A full dependency graph where:
                - pack1 -> pack2 -> pack3
                - pack1 -> pack4
                - pack4 is mandatory for pack1
                - pack5 and pack1 are not a dependency for any pack
        When
            - Running `calculate_single_pack_dependencies` to extract the first and all levels dependencies
        Then
            - Ensure all levels dependencies for pack1 are pack2, pack3 and pack4 only
        """
        all_nodes = {'pack1', 'pack2', 'pack3', 'pack4', 'pack5'}
        expected_all_level_dependencies = {'pack2', 'pack3', 'pack4'}
        for node in expected_all_level_dependencies:
            assert node in self.all_level_dependencies
        for node in all_nodes - expected_all_level_dependencies:
            assert node not in self.all_level_dependencies

    def test_calculate_single_pack_dependencies_mandatory_dependencies(self):
        """
        Given
            - A full dependency graph where:
                - pack1 -> pack2 -> pack3
                - pack1 -> pack4
                - pack4 is mandatory for pack1
                - pack5 and pack1 are not a dependency for any pack
        When
            - Running `calculate_single_pack_dependencies` to extract the first and all levels dependencies
        Then
            - pack4 is mandatory for pack1 and that there are no other mandatory dependencies
        """
        expected_mandatory_dependency = 'pack4'
        assert self.first_level_dependencies[expected_mandatory_dependency]['mandatory']
        for node in self.first_level_dependencies:
            if node != expected_mandatory_dependency:
                assert not self.first_level_dependencies[node]['mandatory']
