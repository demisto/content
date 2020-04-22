import pytest
import json
import os
from Tests.Marketplace.marketplace_services import Pack, Metadata, input_to_list, get_valid_bool, convert_price, \
    get_higher_server_version


@pytest.fixture(scope="module")
def dummy_pack_metadata():
    dummy_pack_metadata_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data",
                                            "user_pack_metadata.json")
    with open(dummy_pack_metadata_path, 'r') as dummy_metadata_file:
        pack_metadata = json.load(dummy_metadata_file)

    return pack_metadata


class TestMetadataParsing:
    def test_validate_all_fields_of_parsed_metadata(self, dummy_pack_metadata):
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=dummy_pack_metadata, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="5.5.0")
        assert parsed_metadata['name'] == 'Test Pack Name'
        assert parsed_metadata['id'] == 'test_pack_id'
        assert parsed_metadata['description'] == 'Description of test pack'
        assert 'created' in parsed_metadata
        assert 'updated' in parsed_metadata
        assert parsed_metadata['legacy']
        assert parsed_metadata['support'] == 'xsoar'
        assert parsed_metadata['supportDetails']['url'] == 'https://test.com'
        assert parsed_metadata['supportDetails']['email'] == 'test@test.com'
        assert parsed_metadata['author'] == 'Cortex XSOAR'
        assert 'authorImage' in parsed_metadata
        assert not parsed_metadata['beta']
        assert not parsed_metadata['deprecated']
        assert 'certification' in parsed_metadata
        assert parsed_metadata['price'] == 0
        assert parsed_metadata['serverMinVersion'] == '5.5.0'
        assert 'serverLicense' in parsed_metadata
        assert parsed_metadata['currentVersion'] == '2.3.0'
        assert parsed_metadata['tags'] == ["Tag Number One", "Tag Number Two"]
        assert parsed_metadata['categories'] == ["Messaging"]
        assert parsed_metadata['contentItems'] == {}
        assert 'integrations' in parsed_metadata
        assert parsed_metadata['useCases'] == ["Some Use Case"]
        assert parsed_metadata['keywords'] == ["dummy keyword", "Additional dummy keyword"]
        assert 'dependencies' in parsed_metadata

    def test_parsed_metadata_empty_input(self):
        parsed_metadata = Pack._parse_pack_metadata(user_metadata={}, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="dummy_server_version")

        assert parsed_metadata['name'] == "test_pack_id"
        assert parsed_metadata['id'] == "test_pack_id"
        assert parsed_metadata['description'] == "test_pack_id"
        assert parsed_metadata['legacy']
        assert parsed_metadata['support'] == Metadata.XSOAR_SUPPORT
        assert parsed_metadata['supportDetails']['url'] == Metadata.XSOAR_SUPPORT_URL
        assert parsed_metadata['author'] == Metadata.XSOAR_AUTHOR
        assert not parsed_metadata['beta']
        assert not parsed_metadata['deprecated']
        assert parsed_metadata['certification'] == Metadata.CERTIFIED
        assert parsed_metadata['price'] == 0
        assert parsed_metadata['serverMinVersion'] == "dummy_server_version"

    @pytest.mark.parametrize("pack_metadata_input,expected",
                             [({"price": "120"}, 120), ({"price": 120}, 120), ({"price": "FF"}, 0)])
    def test_parsed_metadata_with_price(self, pack_metadata_input, expected, mocker):
        mocker.patch("Tests.Marketplace.marketplace_services.print_warning")
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=pack_metadata_input, pack_content_items={},
                                                    pack_id="test_pack_id", integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="dummy_server_version")

        assert parsed_metadata['price'] == expected


class TestParsingInternalFunctions:
    @pytest.mark.parametrize("support_url, support_email",
                             [("", ""), (None, None), (None, ""), ("", None)])
    def test_empty_create_support_section_with_xsoar_support(self, support_url, support_email):
        support_details = Pack._create_support_section(support_type="xsoar", support_url=support_url,
                                                       support_email=support_email)
        expected_result = {'url': Metadata.XSOAR_SUPPORT_URL}

        assert support_details == expected_result

    @pytest.mark.parametrize("support_type,support_url, support_email",
                             [
                                 ("partner", "", ""), ("partner", None, None),
                                 ("partner", None, ""), ("partner", "", None),
                                 ("developer", "", ""), ("developer", None, None),
                                 ("developer", None, ""), ("developer", "", None),
                                 ("nonsupported", "", ""), ("nonsupported", None, None),
                                 ("nonsupported", None, ""), ("nonsupported", "", None)
                             ])
    def test_empty_create_support_section_with_other_support(self, support_type, support_url, support_email):
        support_details = Pack._create_support_section(support_type=support_type, support_url=support_url,
                                                       support_email=support_email)

        assert support_details == {}

    @pytest.mark.parametrize("author", [None, "", Metadata.XSOAR_AUTHOR])
    def test_get_author_xsoar_support(self, author):
        result_author = Pack._get_author(support_type="xsoar", author=author)

        assert result_author == Metadata.XSOAR_AUTHOR

    @pytest.mark.parametrize("author, expected", [("", ""), ("dummy_author", "dummy_author")])
    def test_get_author_non_xsoar_support(self, author, expected):
        result_author = Pack._get_author(support_type="partner", author=author)

        assert result_author == expected


class TestHelperFunctions:
    @pytest.mark.parametrize("input_data,capitalize_input,expected_result",
                             [
                                 (["some data", "some other data"], False, ["some data", "some other data"]),
                                 (["some data", "some other data"], True, ["Some Data", "Some Other Data"]),
                                 ([], False, []),
                                 ([], True, []),
                                 ("", False, []),
                                 ("", True, [])
                             ])
    def test_input_to_list(self, input_data, capitalize_input, expected_result):
        result = input_to_list(input_data=input_data, capitalize_input=capitalize_input)

        assert result == expected_result

    @pytest.mark.parametrize("bool_input,expected",
                             [
                                 (True, True), (False, False), ("True", True), ("False", False),
                                 ("Yes", True), ("No", False), (1, True), (0, False)
                             ])
    def test_get_valid_bool(self, bool_input, expected):
        bool_result = get_valid_bool(bool_input=bool_input)

        assert bool_result == expected

    @pytest.mark.parametrize("price_value_input,expected_price",
                             [
                                 ("", 0), ("0", 0), ("120", 120), ("not integer", 0)
                             ])
    def test_convert_price(self, price_value_input, expected_price, mocker):
        mocker.patch("Tests.Marketplace.marketplace_services.print_warning")
        price_result = convert_price(pack_id="dummy_id", price_value_input=price_value_input)

        assert price_result == expected_price

    @pytest.mark.parametrize("current_string_version,compared_content_item,expected_result",
                             [
                                 ("1.2.3", {"fromversion": "2.1.0"}, "2.1.0"),
                                 ("1.2.3", {"fromVersion": "2.1.0"}, "2.1.0"),
                                 ("5.5.2", {"fromversion": "2.1.0"}, "5.5.2"),
                                 ("5.5.2", {"fromVersion": "2.1.0"}, "5.5.2"),
                                 ("5.5.0", {}, "5.5.0"),
                                 ("1.0.0", {}, "1.0.0")
                             ])
    def test_get_higher_server_version(self, current_string_version, compared_content_item, expected_result):
        result = get_higher_server_version(current_string_version=current_string_version,
                                           compared_content_item=compared_content_item, pack_name="dummy")

        assert result == expected_result


class TestVersionSorting:
    @pytest.fixture(scope="class")
    def dummy_pack(self):
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_not_existing_changelog_json(self, mocker, dummy_pack):
        mocker.patch("os.path.exists", return_value=False)
        latest_version = dummy_pack.latest_version
        assert latest_version == "1.0.0"
