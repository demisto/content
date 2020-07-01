import pytest
import json
import os
import random
from unittest.mock import mock_open
from Tests.Marketplace.marketplace_services import Pack, Metadata, input_to_list, get_valid_bool, convert_price, \
    get_higher_server_version, GCPConfig


@pytest.fixture(scope="module")
def dummy_pack_metadata():
    """ Fixture for dummy pack_metadata.json file that is part of pack folder  in content repo.
    """
    dummy_pack_metadata_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data",
                                            "user_pack_metadata.json")
    with open(dummy_pack_metadata_path, 'r') as dummy_metadata_file:
        pack_metadata = json.load(dummy_metadata_file)

    return pack_metadata


class TestMetadataParsing:
    """ Class for validating parsing of pack_metadata.json (metadata.json will be created from parsed result).
    """

    def test_validate_all_fields_of_parsed_metadata(self, dummy_pack_metadata):
        """ Test function for existence of all fields in metadata. Important to maintain it according to #19786 issue.

        """
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=dummy_pack_metadata, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="5.5.0",
                                                    build_number="dummy_build_number", commit_hash="dummy_commit")
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
        assert 'certification' in parsed_metadata
        assert parsed_metadata['price'] == 0
        assert parsed_metadata['serverMinVersion'] == '5.5.0'
        assert parsed_metadata['currentVersion'] == '2.3.0'
        assert parsed_metadata['versionInfo'] == "dummy_build_number"
        assert parsed_metadata['commit'] == "dummy_commit"
        assert parsed_metadata['tags'] == ["tag number one", "Tag number two"]
        assert parsed_metadata['categories'] == ["Messaging"]
        assert parsed_metadata['contentItems'] == {}
        assert 'integrations' in parsed_metadata
        assert parsed_metadata['useCases'] == ["Some Use Case"]
        assert parsed_metadata['keywords'] == ["dummy keyword", "Additional dummy keyword"]
        assert 'dependencies' in parsed_metadata

    def test_parsed_metadata_empty_input(self):
        """ Test for empty pack_metadata.json and validating that support, support details and author are set correctly
            to XSOAR defaults value of Metadata class.
        """
        parsed_metadata = Pack._parse_pack_metadata(user_metadata={}, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="dummy_server_version",
                                                    build_number="dummy_build_number", commit_hash="dummy_hash")

        assert parsed_metadata['name'] == "test_pack_id"
        assert parsed_metadata['id'] == "test_pack_id"
        assert parsed_metadata['description'] == "test_pack_id"
        assert parsed_metadata['legacy']
        assert parsed_metadata['support'] == Metadata.XSOAR_SUPPORT
        assert parsed_metadata['supportDetails']['url'] == Metadata.XSOAR_SUPPORT_URL
        assert parsed_metadata['author'] == Metadata.XSOAR_AUTHOR
        assert parsed_metadata['certification'] == Metadata.CERTIFIED
        assert parsed_metadata['price'] == 0
        assert parsed_metadata['serverMinVersion'] == "dummy_server_version"

    @pytest.mark.parametrize("pack_metadata_input,expected",
                             [({"price": "120"}, 120), ({"price": 120}, 120), ({"price": "FF"}, 0)])
    def test_parsed_metadata_with_price(self, pack_metadata_input, expected, mocker):
        """ Price field is not mandatory field and needs to be set to integer value.

        """
        mocker.patch("Tests.Marketplace.marketplace_services.print_warning")
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=pack_metadata_input, pack_content_items={},
                                                    pack_id="test_pack_id", integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="dummy_server_version",
                                                    build_number="dummy_build_number", commit_hash="dummy_hash")

        assert parsed_metadata['price'] == expected


class TestParsingInternalFunctions:
    """ Test class for internal functions that are used in _parse_pack_metadata static method.

    """

    @pytest.mark.parametrize("support_url, support_email",
                             [("", ""), (None, None), (None, ""), ("", None)])
    def test_empty_create_support_section_with_xsoar_support(self, support_url, support_email):
        """ Test the case when support type is set to xsoar and returns XSOAR support default details.
        Currently is only returned url field. May include XSOAR support email in the future.
        """
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
        """ Tests case when support is set to non xsoar, one of following: partner, developer or nonsupported.
            Expected not do override the url with XSOAR default support url and email if it be included eventually.

        """
        support_details = Pack._create_support_section(support_type=support_type, support_url=support_url,
                                                       support_email=support_email)

        assert support_details == {}

    @pytest.mark.parametrize("author", [None, "", Metadata.XSOAR_AUTHOR])
    def test_get_author_xsoar_support(self, author):
        """ Tests case when support is set to xsoar. Expected result should be Cortex XSOAR.
        """
        result_author = Pack._get_author(support_type="xsoar", author=author)

        assert result_author == Metadata.XSOAR_AUTHOR

    @pytest.mark.parametrize("author, expected", [("", ""), ("dummy_author", "dummy_author")])
    def test_get_author_non_xsoar_support(self, author, expected):
        """ Test case when support is set to non xsoar, in that case partner. Expected behavior is not to override
        author str that was received as input.
        """
        result_author = Pack._get_author(support_type="partner", author=author)

        assert result_author == expected

    @pytest.mark.parametrize("support_type, certification", [("xsoar", None), ("xsoar", ""), ("xsoar", "verified")])
    def test_get_certification_xsoar_support(self, support_type, certification):
        """ Tests case when support is set to xsoar. Expected result should be certified certification.
        """
        result_certification = Pack._get_certification(support_type=support_type, certification=certification)

        assert result_certification == Metadata.CERTIFIED

    @pytest.mark.parametrize("support_type, certification", [("partner", None), ("developer", "")])
    def test_get_certification_non_xsoar_support_empty(self, support_type, certification):
        """ Tests case when support is set to non xsoar. Expected result should empty certification string.
        """
        result_certification = Pack._get_certification(support_type=support_type, certification=certification)

        assert result_certification == ""

    def test_get_certification_non_xsoar_support(self):
        """ Tests case when support is set to partner with certified value.
            Expected result should be certified certification.
        """
        result_certification = Pack._get_certification(support_type="partner", certification="certified")

        assert result_certification == Metadata.CERTIFIED


class TestHelperFunctions:
    """ Class for testing helper functions that are used in marketplace_services and upload_packs modules.
    """

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
        """ Test for capitalize_input flag. In case it is set to True, expeted result should include all list items,
            to be capitalized strings. The main use of it is in metadata, where fields like Tags should be capitalized.

        """
        result = input_to_list(input_data=input_data, capitalize_input=capitalize_input)

        assert result == expected_result

    @pytest.mark.parametrize("bool_input,expected",
                             [
                                 (True, True), (False, False), ("True", True), ("False", False),
                                 ("Yes", True), ("No", False), (1, True), (0, False)
                             ])
    def test_get_valid_bool(self, bool_input, expected):
        """ Test for several edge cases that can be received as input to get_valid_bool function.
        """
        bool_result = get_valid_bool(bool_input=bool_input)

        assert bool_result == expected

    @pytest.mark.parametrize("price_value_input,expected_price",
                             [
                                 ("", 0), ("0", 0), ("120", 120), ("not integer", 0)
                             ])
    def test_convert_price(self, price_value_input, expected_price, mocker):
        """ Tests that convert price is not failing to convert given input
        """
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
        """ Tests the comparison of server versions (that are collected in collect_content_items function.
            Higher server semantic version should be returned.
        """
        result = get_higher_server_version(current_string_version=current_string_version,
                                           compared_content_item=compared_content_item, pack_name="dummy")

        assert result == expected_result


class TestVersionSorting:
    """ Class for sorting of changelog.json versions

    """

    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_not_existing_changelog_json(self, mocker, dummy_pack):
        """ In case changelog.json doesn't exists, expected result should be initial version 1.0.0
        """
        mocker.patch("os.path.exists", return_value=False)
        latest_version = dummy_pack.latest_version
        assert latest_version == "1.0.0"


class TestChangelogCreation:
    """ Test class for changelog.json creation step.

    """

    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        dummy_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
        sample_pack = Pack(pack_name="TestPack", pack_path=dummy_path)
        sample_pack.description = 'Sample description'
        sample_pack.current_version = '1.0.0'
        return sample_pack

    def test_prepare_release_notes_first_run(self, mocker, dummy_pack):
        """ In case changelog.json doesn't exists, expected result should be initial version 1.0.0
        """
        mocker.patch("os.path.exists", return_value=False)
        dummy_path = 'Irrelevant/Test/Path'
        build_number = random.randint(0, 100000)
        task_status, not_updated_build = Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path,
                                                                    build_number=build_number)
        assert task_status is True
        assert not_updated_build is False

    def test_prepare_release_notes_upgrade_version(self, mocker, dummy_pack):
        """
           Given:
               - Valid new version and valid current changelog found in index.
           When:
               - Upgrading versions and adding to changelog.json
           Then:
               - return True
       """
        dummy_pack.current_version = '2.0.2'
        mocker.patch("Tests.Marketplace.marketplace_services.print_color")
        mocker.patch("os.path.exists", return_value=True)
        dir_list = ['1_0_1.md', '2_0_2.md', '2_0_0.md']
        mocker.patch("os.listdir", return_value=dir_list)
        original_changelog = '''{
            "1.0.0": {
                "releaseNotes": "First release notes",
                "displayName": "1.0.0",
                "released": "2020-05-05T13:39:33Z"
            },
            "2.0.0": {
                "releaseNotes": "Second release notes",
                "displayName": "2.0.0",
                "released": "2020-06-05T13:39:33Z"
            }
        }'''
        mocker.patch('builtins.open', mock_open(read_data=original_changelog))
        dummy_path = 'Irrelevant/Test/Path'
        build_number = random.randint(0, 100000)
        task_status, not_updated_build = Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path,
                                                                    build_number=build_number)
        assert task_status is True
        assert not_updated_build is False

    def test_prepare_release_notes_upgrade_version_mismatch(self, mocker, dummy_pack):
        """
           Given:
               - Invalid new version and valid current changelog found in index. Mismatching versions.
           When:
               - Upgrading versions and adding to changelog.json
           Then:
               - return False
       """
        dummy_pack.current_version = '2.0.0'
        mocker.patch("Tests.Marketplace.marketplace_services.print_error")
        mocker.patch("Tests.Marketplace.marketplace_services.print_color")
        mocker.patch("os.path.exists", return_value=True)
        dir_list = ['1_0_1.md', '2_0_2.md', '2_0_0.md']
        mocker.patch("os.listdir", return_value=dir_list)
        original_changelog = '''{
            "1.0.0": {
                "releaseNotes": "First release notes",
                "displayName": "1.0.0",
                "released": "2020-05-05T13:39:33Z"
            },
            "2.0.0": {
                "releaseNotes": "Second release notes",
                "displayName": "2.0.0",
                "released": "2020-06-05T13:39:33Z"
            }
        }'''
        mocker.patch('builtins.open', mock_open(read_data=original_changelog))
        dummy_path = 'Irrelevant/Test/Path'
        build_number = random.randint(0, 100000)
        task_status, not_updated_build = Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path,
                                                                    build_number=build_number)
        assert task_status is False
        assert not_updated_build is False

    def test_prepare_release_notes_upgrade_version_dup(self, mocker, dummy_pack):
        """
           Given:
               - Valid new version and valid current changelog found in index with existing version.
           When:
               - Not updating versions and adding to changelog.json
           Then:
               - return True
       """
        dummy_pack.current_version = '2.0.0'
        mocker.patch("os.path.exists", return_value=True)
        mocker.patch("Tests.Marketplace.marketplace_services.print_warning")
        mocker.patch("Tests.Marketplace.marketplace_services.print_color")
        dir_list = ['1_0_1.md', '2_0_0.md']
        mocker.patch("os.listdir", return_value=dir_list)
        original_changelog = '''{
            "1.0.0": {
                "releaseNotes": "First release notes",
                "displayName": "1.0.0",
                "released": "2020-05-05T13:39:33Z"
            },
            "2.0.0": {
                "releaseNotes": "Second release notes",
                "displayName": "2.0.0",
                "released": "2020-06-05T13:39:33Z"
            }
        }'''
        mocker.patch('builtins.open', mock_open(read_data=original_changelog))
        dummy_path = 'Irrelevant/Test/Path'
        build_number = random.randint(0, 100000)
        task_status, not_updated_build = Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path,
                                                                    build_number=build_number)
        assert task_status is True
        assert not_updated_build is False

    def test_clean_release_notes_lines(self):
        original_rn = '''
### Integration
- __SomeIntegration__
This is visible
<!-- This is not -->
'''
        expected_rn = '''
### Integration
- __SomeIntegration__
This is visible

'''
        clean_rn = Pack._clean_release_notes(original_rn)
        assert expected_rn == clean_rn

    def test_create_changelog_entry_new(self):
        """
           Given:
               - release notes, display version and build number
           When:
               - new changelog entry must created
           Then:
               - return changelog entry with release notes and without R letter in display name
       """
        release_notes = "dummy release notes"
        version_display_name = "1.2.3"
        build_number = "5555"
        version_changelog = Pack._create_changelog_entry(release_notes=release_notes,
                                                         version_display_name=version_display_name,
                                                         build_number=build_number, new_version=True)

        assert version_changelog['releaseNotes'] == "dummy release notes"
        assert version_changelog['displayName'] == f'{version_display_name} - {build_number}'

    def test_create_changelog_entry_existing(self):
        """
           Given:
               - release notes, display version and build number
           When:
               - changelog entry already exists
           Then:
               - return changelog entry with release notes and R letter appended in display name
       """
        release_notes = "dummy release notes"
        version_display_name = "1.2.3"
        build_number = "5555"
        version_changelog = Pack._create_changelog_entry(release_notes=release_notes,
                                                         version_display_name=version_display_name,
                                                         build_number=build_number, new_version=False)

        assert version_changelog['releaseNotes'] == "dummy release notes"
        assert version_changelog['displayName'] == f'{version_display_name} - R{build_number}'


class TestImagesUpload:
    """ Test class for integration images upload.

    """

    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    @pytest.mark.parametrize("integration_name,expected_result", [
        ("Have I Been Pwned? v2",
         [{'name': 'Have I Been Pwned? v2', 'imagePath': 'content/packs/TestPack/HaveIBeenPwned%3Fv2_image.png'}]),
        ("Have I Been Pwned! v2",
         [{'name': 'Have I Been Pwned! v2', 'imagePath': 'content/packs/TestPack/HaveIBeenPwned%21v2_image.png'}]),
        ("Have I Been Pwned$ v2",
         [{'name': 'Have I Been Pwned$ v2', 'imagePath': 'content/packs/TestPack/HaveIBeenPwned%24v2_image.png'}]),
        ("Integration!@#$ Name^%$",
         [{'name': 'Integration!@#$ Name^%$',
           'imagePath': 'content/packs/TestPack/Integration%21%40%23%24Name%5E%25%24_image.png'}])
    ])
    def test_upload_integration_images_with_special_character(self, mocker, dummy_pack, integration_name,
                                                              expected_result):
        """
           Given:
               - Integration name with special characters.
           When:
               - When pack has integration with special character.
           Then:
               - return encoded url
       """
        temp_image_name = f'{integration_name.replace(" ", "")}_image.png'
        search_for_images_return_value = [{'display_name': integration_name,
                                           'image_path': f'/path/{temp_image_name}'}]
        mocker.patch("marketplace_services_test.Pack._search_for_images", return_value=search_for_images_return_value)
        mocker.patch('builtins.open', mock_open(read_data="image_data"))
        mocker.patch("Tests.Marketplace.marketplace_services.print")
        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.blob.return_value.name = os.path.join(GCPConfig.STORAGE_BASE_PATH, "TestPack",
                                                                   temp_image_name)
        task_status, integration_images = dummy_pack.upload_integration_images(storage_bucket=dummy_storage_bucket)

        assert task_status
        assert len(expected_result) == len(integration_images)
        assert integration_images == expected_result

    @pytest.mark.parametrize("integration_name,expected_result", [
        ("Integration Name",
         [{'name': 'Integration Name', 'imagePath': 'content/packs/TestPack/IntegrationName_image.png'}]),
        ("IntegrationName",
         [{'name': 'IntegrationName', 'imagePath': 'content/packs/TestPack/IntegrationName_image.png'}])
    ])
    def test_upload_integration_images_without_special_character(self, mocker, dummy_pack, integration_name,
                                                                 expected_result):
        """
           Given:
               - Integration name without special characters.
           When:
               - When pack has integration no special character.
           Then:
               - validate that encoded url did not change the original url.
       """
        temp_image_name = f'{integration_name.replace(" ", "")}_image.png'
        search_for_images_return_value = [{'display_name': integration_name,
                                           'image_path': f'/path/{temp_image_name}'}]
        mocker.patch("marketplace_services_test.Pack._search_for_images", return_value=search_for_images_return_value)
        mocker.patch("builtins.open", mock_open(read_data="image_data"))
        mocker.patch("Tests.Marketplace.marketplace_services.print")
        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.blob.return_value.name = os.path.join(GCPConfig.STORAGE_BASE_PATH, "TestPack",
                                                                   temp_image_name)
        task_status, integration_images = dummy_pack.upload_integration_images(storage_bucket=dummy_storage_bucket)

        assert task_status
        assert len(expected_result) == len(integration_images)
        assert integration_images == expected_result


class TestLoadUserMetadata:
    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_load_user_metadata_with_missing_file(self, mocker, dummy_pack):
        """
           Given:
               - Pack with missing pack metadata.
           When:
               - Pack is invalid.
           Then:
               - Task should not fail with referenced before assignment error.
       """
        mocker.patch("os.path.exists", return_value=False)
        print_error_mock = mocker.patch("Tests.Marketplace.marketplace_services.print_error")
        task_status, user_metadata = dummy_pack.load_user_metadata()

        assert print_error_mock.call_count == 1
        assert not task_status
        assert user_metadata == {}
