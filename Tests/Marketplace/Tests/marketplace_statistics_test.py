import pytest
import os
from Tests.Marketplace.marketplace_statistics import PackStatisticsHandler
from Tests.Marketplace.marketplace_services import Pack, load_json
from Tests.Marketplace.marketplace_constants import Metadata, PackTags


@pytest.fixture(scope="module")
def dummy_pack_metadata():
    """ Fixture for dummy pack_metadata.json file that is part of pack folder in content repo.
    """
    dummy_pack_metadata_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data",
                                            "user_pack_metadata.json")
    pack_metadata = load_json(dummy_pack_metadata_path)
    return pack_metadata


class TestPackStatisticsHandler:
    @pytest.fixture(scope="function", autouse=True)
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="Test Pack Name", pack_path="dummy_path")

    def test_search_rank_new_tag(self, dummy_pack_metadata, dummy_pack):
        """
        Given a certified new pack (created less than 30 days ago)
        Then: add "New" tag and raise the searchRank
        """

        dummy_pack._tags = {PackTags.NEW}
        search_rank = PackStatisticsHandler.calculate_search_rank(dummy_pack._tags, "", {})

        assert search_rank == 10

    def test_search_rank_certified(self, dummy_pack_metadata, dummy_pack):
        """
        Given a certified pack that was created more than 30 days ago
        Then: remove "New" tag and make sure the searchRank is reduced
        """
        search_rank = PackStatisticsHandler.calculate_search_rank(set(), Metadata.CERTIFIED, {})

        assert search_rank == 10

    def test_deprecated_pack_search_rank(self, dummy_pack_metadata, dummy_pack):
        """
        Given: a certified pack
        When: All the integrations in it are deprecated.
        Then: calculate the search rank
        """
        content_items = {
            "integration": [
                {
                    "name": "packname (Deprecated)",
                    "description": "packs description",
                    "category": "Endpoint",
                    "commands": [
                        {
                            "name": "command1",
                            "description": "command 1 description"
                        }
                    ]
                }
            ],
            "playbook": [
                {
                    "name": "test plakbook",
                    "description": "test playbook description"
                }
            ]
        }
        search_rank = PackStatisticsHandler.calculate_search_rank(set(), Metadata.CERTIFIED, content_items)
        assert search_rank == -40

    def test_part_deprecated_pack_search_rank(self, dummy_pack_metadata, dummy_pack):
        """
        Given: a certified pack
        When: Only one of the two integrations is deprecated.
        Then: calculate the search rank
        """
        content_items = {
            "integration": [
                {
                    "name": "packname (Deprecated)",
                    "description": "packs description",
                    "category": "Endpoint",
                    "commands": [
                        {
                            "name": "command1",
                            "description": "command 1 description"
                        }
                    ]
                },
                {
                    "name": "packname2",
                    "description": "packs description",
                    "category": "Endpoint",
                    "commands": [
                        {
                            "name": "command1",
                            "description": "command 1 description"
                        }
                    ]
                },

            ],
            "playbook": [
                {
                    "name": "test plakbook",
                    "description": "test playbook description"
                }
            ]
        }
        search_rank = PackStatisticsHandler.calculate_search_rank(set(), Metadata.CERTIFIED, content_items)
        assert search_rank == 10
