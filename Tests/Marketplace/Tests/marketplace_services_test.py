import pytest
from Tests.Marketplace.marketplace_services import Pack

# disable-secrets-detection-start
USER_PACK_METADATA = {
    "name": "Test Pack Name",
    "description": "Description of test pack",
    "support": "demisto",
    "serverMinVersion": "5.5.0",
    "currentVersion": "2.3.0",
    "author": "Dev",
    "url": "https://test.com",
    "email": "test@test.com",
    "categories": [
        "Messaging"
    ],
    "tags": [
        "tag1",
        "tag2"
    ],
    "created": "2020-03-07T12:35:55Z",
    "updated": "2020-03-07T12:35:55Z",
    "beta": False,
    "deprecated": False,
    "certification": "certified",
    "useCases": [
        "usecase1"
    ],
    "keywords": [
        "keyword1",
        "keyword2"
    ],
    "price": "120",
    "dependencies": {}
}


class TestMetadata:
    def test_validate_fields_of_parsed_metadata(self):
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=USER_PACK_METADATA, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={})
        assert parsed_metadata['name'] == 'Test Pack Name'
        assert parsed_metadata['id'] == 'test_pack_id'
        assert parsed_metadata['description'] == 'Description of test pack'
        assert 'created' in parsed_metadata
        assert 'updated' in parsed_metadata
        assert parsed_metadata['legacy']
        assert parsed_metadata['support'] == 'demisto'
        assert parsed_metadata['supportDetails']['url'] == 'https://test.com'
        assert parsed_metadata['supportDetails']['email'] == 'test@test.com'
        assert 'authorImage' in parsed_metadata
        assert not parsed_metadata['beta']
        assert not parsed_metadata['deprecated']
        assert 'certification' in parsed_metadata
        assert parsed_metadata['price'] == 120
        assert parsed_metadata['serverMinVersion'] == '5.5.0'
        assert 'serverLicense' in parsed_metadata
        assert parsed_metadata['currentVersion'] == '2.3.0'
        assert parsed_metadata['tags'] == ["tag1", "tag2"]
        assert parsed_metadata['categories'] == ["Messaging"]
        assert parsed_metadata['contentItems'] == {}
        assert 'integrations' in parsed_metadata
        assert parsed_metadata['useCases'] == ["usecase1"]
        assert parsed_metadata['keywords'] == ["keyword1", "keyword2"]
        assert 'dependencies' in parsed_metadata

    @pytest.mark.parametrize("empty_metadata", [{}, []])
    def test_parsed_metadata_empty_input(self, empty_metadata):
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=empty_metadata, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={})

        assert parsed_metadata['name'] == "test_pack_id"
        assert parsed_metadata['id'] == "test_pack_id"
        assert parsed_metadata['description'] == "test_pack_id"
        assert parsed_metadata['supportDetails'] == {}


class TestVersionSorting:
    @pytest.fixture(scope="class")
    def dummy_pack(self):
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_not_existing_changelog_json(self, mocker, dummy_pack):
        mocker.patch("os.path.exists", return_value=False)
        latest_version = dummy_pack.latest_version
        assert latest_version == "1.0.0"
# disable-secrets-detection-end
