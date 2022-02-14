
# type: ignore[attr-defined]

import shutil
import pytest
import json
import os
import random
import glob
from unittest.mock import mock_open
from mock_open import MockOpen
from google.cloud.storage.blob import Blob
from packaging.version import Version
from freezegun import freeze_time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any

# pylint: disable=no-member


from Tests.Marketplace.marketplace_services import Pack, input_to_list, get_valid_bool, convert_price, \
    get_updated_server_version, load_json, \
    store_successful_and_failed_packs_in_ci_artifacts, is_ignored_pack_file, \
    is_the_only_rn_in_block
from Tests.Marketplace.marketplace_constants import PackStatus, PackFolders, Metadata, GCPConfig, BucketUploadFlow, \
    PACKS_FOLDER, PackTags

CHANGELOG_DATA_INITIAL_VERSION = {
    "1.0.0": {
        "releaseNotes": "Sample description",
        "displayName": "1.0.0 - 62492",
        "released": "2020-12-21T12:10:55Z"
    }
}
CHANGELOG_DATA_MULTIPLE_VERSIONS = {
    "1.0.0": {
        "releaseNotes": "Sample description",
        "displayName": "1.0.0 - 62492",
        "released": "2020-12-21T12:10:55Z"
    },
    "1.1.0": {
        "releaseNotes": "Sample description2",
        "displayName": "1.1.0 - 64321",
        "released": "2021-01-20T12:10:55Z"
    }
}
TEST_METADATA = {
    "description": "description",
    "created": "2020-04-14T00:00:00Z",
    "updated": "2020-11-24T08:08:35Z",
}

AGGREGATED_CHANGELOG = {
    "1.0.1": {
        "releaseNotes": "dummy release notes",
        "displayName": "1.0.0 - 264879",
        "released": "2020-05-05T13:39:33Z"
    },
    "1.0.3": {
        'releaseNotes': 'dummy release notes\ndummy release notes\n',
        'displayName': '1.0.3 - 264879',
        'released': '2021-01-27T23:01:58Z'
    }
}

DUMMY_PACKS_DICT = {'HelloWorld': '', 'ServiceNow': '', 'Ipstack': '', 'Active_Directory_Query': '', 'SlackV2': '',
                    'CommonTypes': '', 'CommonPlaybooks': ''}


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

    @pytest.fixture(scope="function", autouse=True)
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="Test Pack Name", pack_path="dummy_path")

    def test_validate_all_fields_of_parsed_metadata(self, dummy_pack, dummy_pack_metadata):
        """ Test function for existence of all fields in metadata. Important to maintain it according to #19786 issue.
        """
        dummy_pack._description = 'Description of test pack'
        dummy_pack._server_min_version = Metadata.SERVER_DEFAULT_MIN_VERSION
        dummy_pack._downloads_count = 10
        dummy_pack._displayed_integration_images = []
        dummy_pack._user_metadata = dummy_pack_metadata
        dummy_pack._enhance_pack_attributes(
            index_folder_path="", pack_was_modified=False,
            dependencies_metadata_dict={}, statistics_handler=None
        )
        parsed_metadata = dummy_pack._parse_pack_metadata(build_number="dummy_build_number", commit_hash="dummy_commit")

        assert parsed_metadata['name'] == 'Test Pack Name'
        assert parsed_metadata['id'] == 'Test Pack Name'
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
        assert parsed_metadata['serverMinVersion'] == '6.0.0'
        assert parsed_metadata['currentVersion'] == '2.3.0'
        assert parsed_metadata['versionInfo'] == "dummy_build_number"
        assert parsed_metadata['commit'] == "dummy_commit"
        assert set(parsed_metadata['tags']) == {"tag number one", "Tag number two", PackTags.NEW, PackTags.USE_CASE}
        assert len(parsed_metadata['tags']) == 4
        assert parsed_metadata['categories'] == ["Messaging"]
        assert 'contentItems' in parsed_metadata
        assert 'integrations' in parsed_metadata
        assert parsed_metadata['useCases'] == ["Some Use Case"]
        assert parsed_metadata['keywords'] == ["dummy keyword", "Additional dummy keyword"]
        assert parsed_metadata['downloads'] == 10
        assert parsed_metadata['searchRank'] == 20
        assert 'dependencies' in parsed_metadata

    def test_enhance_pack_attributes(self, dummy_pack, dummy_pack_metadata):
        """ Test function for existence of all fields in metadata. Important to maintain it according to #19786 issue.
        """
        dummy_pack._displayed_integration_images = []
        dummy_pack._user_metadata = dummy_pack_metadata
        dummy_pack._enhance_pack_attributes(
            index_folder_path="", pack_was_modified=False, dependencies_metadata_dict={}, statistics_handler=None
        )

        assert dummy_pack._pack_name == 'Test Pack Name'
        assert dummy_pack.create_date
        assert dummy_pack.update_date
        assert dummy_pack._legacy
        assert dummy_pack._support_type == Metadata.XSOAR_SUPPORT
        assert dummy_pack._support_details['url'] == 'https://test.com'
        assert dummy_pack._support_details['email'] == 'test@test.com'
        assert dummy_pack._author == Metadata.XSOAR_AUTHOR
        assert dummy_pack._certification == Metadata.CERTIFIED
        assert dummy_pack._price == 0
        assert dummy_pack._use_cases == ["Some Use Case"]
        assert dummy_pack._tags == {"tag number one", "Tag number two", PackTags.NEW, PackTags.USE_CASE}
        assert dummy_pack._categories == ["Messaging"]
        assert dummy_pack._keywords == ["dummy keyword", "Additional dummy keyword"]

    def test_enhance_pack_attributes_empty_input(self, dummy_pack):
        """ Test for empty pack_metadata.json and validating that support, support details and author are set correctly
            to XSOAR defaults value of Metadata class.
        """

        dummy_pack._displayed_integration_images = []
        dummy_pack._user_metadata = {}
        dummy_pack._enhance_pack_attributes(
            index_folder_path="", pack_was_modified=False, dependencies_metadata_dict={}, statistics_handler=None
        )

        assert dummy_pack._support_type == Metadata.XSOAR_SUPPORT
        assert dummy_pack._support_details['url'] == Metadata.XSOAR_SUPPORT_URL
        assert dummy_pack._certification == Metadata.CERTIFIED
        assert dummy_pack._author == Metadata.XSOAR_AUTHOR

    @pytest.mark.parametrize("raw_price,expected", [("120", 120), (120, 120), ("FF", 0)])
    def test_convert_price(self, raw_price, expected, mocker):
        """ Price field is not mandatory field and needs to be set to integer value.

        """
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        assert convert_price("pack_name", raw_price) == expected

    def test_use_case_tag_added_to_tags(self, dummy_pack_metadata, dummy_pack):
        """
           Given:
               - Pack metadata file with use case.
           When:
               - Running parse_pack_metadada
           Then:
               - Ensure the `Use Case` tag was added to tags.

       """
        dummy_pack._use_cases = ['Phishing']
        tags = dummy_pack._collect_pack_tags(dummy_pack_metadata, [], [])

        assert PackTags.USE_CASE in tags

    @pytest.mark.parametrize('is_feed_pack', [True, False])
    def test_tim_tag_added_to_tags(self, dummy_pack_metadata, dummy_pack, is_feed_pack):
        """ Test 'TIM' tag is added if is_feed_pack is True
        """
        dummy_pack.is_feed = is_feed_pack
        tags = dummy_pack._collect_pack_tags(dummy_pack_metadata, [], [])

        if is_feed_pack:
            assert PackTags.TIM in tags
        else:
            assert PackTags.TIM not in tags

    def test_new_tag_added_to_tags(self, dummy_pack_metadata, dummy_pack):
        """ Test 'New' tag is added
        """
        dummy_pack._create_date = (datetime.utcnow() - timedelta(5)).strftime(Metadata.DATE_FORMAT)
        tags = dummy_pack._collect_pack_tags(dummy_pack_metadata, [], [])

        assert PackTags.NEW in tags

    def test_new_tag_removed_from_tags(self, dummy_pack_metadata, dummy_pack):
        """ Test 'New' tag is removed
        """
        dummy_pack._create_date = (datetime.utcnow() - timedelta(35)).strftime(Metadata.DATE_FORMAT)
        dummy_pack._tags = {PackTags.NEW}
        tags = dummy_pack._collect_pack_tags(dummy_pack_metadata, [], [])

        assert PackTags.NEW not in tags

    def test_section_tags_added(self, dummy_pack_metadata, dummy_pack):
        """
        Given:
            Pack
        When:
            Parsing a pack metadata
        Then:
            add the 'Featured' landingPage section tag and raise the searchRank
        """
        section_tags = {
            "sections": [
                "Trending",
                "Featured",
                "Getting Started"
            ],
            "Featured": [
                "Test Pack Name"
            ]
        }
        tags = dummy_pack._collect_pack_tags(dummy_pack_metadata, section_tags, [])
        assert 'Featured' in tags


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

    @pytest.mark.parametrize("support_type, certification", [("community", None), ("developer", "")])
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

    @pytest.mark.parametrize("pack_integration_images, display_dependencies_images, expected", [
        ([], [], []),
        ([], ["DummyPack"],
         [{"name": "DummyIntegration", "imagePath": "content/packs/DummyPack/DummyIntegration_image.png"}]),
        ([{"name": "DummyIntegration", "imagePath": "content/packs/DummyPack/DummyIntegration_image.png"}],
         ["DummyPack", "DummyPack2"],
         [{"name": "DummyIntegration", "imagePath": "content/packs/DummyPack/DummyIntegration_image.png"},
          {"name": "DummyIntegration2", "imagePath": "content/packs/DummyPack2/DummyIntegration_image.png"}]),
        ([{"name": "DummyIntegration2", "imagePath": "content/packs/DummyPack2/DummyIntegration_image.png"}],
         ["DummyPack2"],
         [{"name": "DummyIntegration2", "imagePath": "content/packs/DummyPack2/DummyIntegration_image.png"}])
    ])
    def test_get_all_pack_images(self, pack_integration_images, display_dependencies_images, expected):
        """
           Tests that all the pack's images are being collected without duplication, according to the pack dependencies,
           and without the contribution details suffix if exists.
           All test cases getting the same dependencies_data (all level pack's dependencies data) dictionary.
           Given:
               - Empty pack_integration_images, empty display_dependencies_images
               - Empty pack_integration_images, display_dependencies_images with one pack
               - pack_integration_images with DummyIntegration, display_dependencies_images DummyPack1 and DummyPack2
               - pack_integration_images with DummyIntegration2 without contribution details suffix,
                 display_dependencies_images DummyPack2

           When:
               - Getting all pack images when formatting pack's metadata.

           Then:
               - Validates that all_pack_images is empty.
               - Validates that all_pack_images list was updated according to the packs dependencies.
               - Validates that all_pack_images list was updated without duplications.
               - Validates that all_pack_images list was updated without the contribution details suffix.
       """

        dependencies_data = {
            "DummyPack": {
                "integrations": [{
                    "name": "DummyIntegration",
                    "imagePath": "content/packs/DummyPack/DummyIntegration_image.png"}]},
            "DummyPack2": {
                "integrations": [{
                    "name": "DummyIntegration2 (Partner Contribution)",
                    "imagePath": "content/packs/DummyPack2/DummyIntegration_image.png"}]}}

        all_pack_images = Pack._get_all_pack_images(pack_integration_images, display_dependencies_images,
                                                    dependencies_data, display_dependencies_images)

        assert expected == all_pack_images


class TestHelperFunctions:
    """ Class for testing helper functions that are used in marketplace_services and upload_packs modules.
    """

    @pytest.mark.parametrize('modified_file_path_parts, expected_result', [
        (['Packs', 'A', PackFolders.INTEGRATIONS.value, 'A', 'test_data', 'a.json'], True),
        (['Packs', 'A', PackFolders.TEST_PLAYBOOKS.value, 'playbook-wow.yml'], True),
        (['Packs', 'A', '.pack-ignore'], True),
        (['Packs', 'A', '.secrets-ignore'], True),
        (['Packs', 'A', PackFolders.PLAYBOOKS.value, 'playbook-wow_README.md'], True),
        (['Packs', 'A', PackFolders.INTEGRATIONS.value, 'A', 'README.md'], True),
        (['Packs', 'A', PackFolders.INTEGRATIONS.value, 'A', 'A_test.py'], True),
        (['Packs', 'A', PackFolders.INTEGRATIONS.value, 'A', 'commands.txt'], True),
        (['Packs', 'A', PackFolders.SCRIPTS.value, 'A', 'Pipfile'], True),
        (['Packs', 'A', PackFolders.SCRIPTS.value, 'A', 'Pipfile.lock'], True),
        (['Packs', 'A', Pack.README], False),
        (['Packs', 'A', Pack.USER_METADATA], False),
        (['Packs', 'A', PackFolders.INTEGRATIONS.value, 'A', 'A.py'], False)
    ])
    def test_is_ignored_pack_file(self, modified_file_path_parts, expected_result, mocker):
        mocker.patch.object(glob, 'glob', return_value=['Packs/A/Integrations/A/test_data/a.json'])
        mocker.patch.object(os.path, 'isdir', return_value=True)
        assert is_ignored_pack_file(modified_file_path_parts) is expected_result

    @pytest.mark.parametrize("input_data,capitalize_input,expected_result",
                             [
                                 (["some data", "some other data"], False, ["some data", "some other data"]),
                                 (["some data", "some other data"], True, ["Some Data", "Some Other Data"]),
                                 (["HIPAA Breach Notification"], True, ["HIPAA Breach Notification"]),
                                 (["HIPAA breach Notification"], True, ["HIPAA Breach Notification"]),
                                 (["INPUT IS ALREADY UPPERCASE"], True, ["INPUT IS ALREADY UPPERCASE"]),
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
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        price_result = convert_price(pack_id="dummy_id", price_value_input=price_value_input)

        assert price_result == expected_price

    @pytest.mark.parametrize("current_string_version,compared_content_item,expected_result",
                             [
                                 ("1.2.3", {"fromversion": "2.1.0"}, "1.2.3"),
                                 ("1.2.3", {"fromVersion": "2.1.0"}, "1.2.3"),
                                 ("5.5.2", {"fromversion": "2.1.0"}, "2.1.0"),
                                 ("5.5.2", {"fromVersion": "2.1.0"}, "2.1.0"),
                                 ("5.5.0", {}, "5.5.0"),
                                 ("1.0.0", {}, "1.0.0")
                             ])
    def test_get_updated_server_version(self, current_string_version, compared_content_item, expected_result):
        """ Tests the comparison of server versions (that are collected in collect_content_items function.
            Lower server semantic version should be returned.
        """
        result = get_updated_server_version(current_string_version=current_string_version,
                                            compared_content_item=compared_content_item, pack_name="dummy")

        assert result == expected_result

    @pytest.mark.parametrize('yaml_context, yaml_type, is_actually_feed',
                             [
                                 # Check is_feed by Integration
                                 ({'category': 'TIM', 'configuration': [{'display': 'Services'}],
                                   'script': {'commands': [], 'dockerimage': 'bla', 'feed': True}},
                                  'Integration', True),
                                 ({'category': 'TIM', 'configuration': [{'display': 'Services'}],
                                   'script': {'commands': [], 'dockerimage': 'bla', 'feed': False}},
                                  'Integration', False),
                                 # Checks no feed parameter
                                 ({'category': 'NotTIM', 'configuration': [{'display': 'Services'}],
                                   'script': {'commands': [], 'dockerimage': 'bla'}},
                                  'Integration', False),

                                 # Check is_feed by playbook
                                 ({'id': 'TIM - Example', 'version': -1, 'fromversion': '5.5.0',
                                   'name': 'TIM - Example', 'description': 'This is a playbook TIM example'},
                                  'Playbook', True),
                                 ({'id': 'NotTIM - Example', 'version': -1, 'fromversion': '5.5.0',
                                   'name': 'NotTIM - Example', 'description': 'This is a playbook which is not TIM'},
                                  'Playbook', False)
                             ])
    def test_is_feed(self, yaml_context, yaml_type, is_actually_feed):
        """ Tests that is_feed for pack changes if it has a playbook that starts with "TIM " or an integration with
            script.feed==true
        """
        dummy_pack = Pack(pack_name="TestPack", pack_path="dummy_path")
        dummy_pack.is_feed_pack(yaml_context, yaml_type)
        assert dummy_pack.is_feed == is_actually_feed

    def test_remove_unwanted_files(self):
        """
           Given:
               - Pack name & path.
           When:
               - Preparing packs before uploading to marketplace.
           Then:
               - Assert `TestPlaybooks` directory was deleted from pack.
               - Assert `Integrations` directory was not deleted from pack.

       """
        os.mkdir('Tests/Marketplace/Tests/test_data/pack_to_test')
        os.mkdir('Tests/Marketplace/Tests/test_data/pack_to_test/TestPlaybooks')
        os.mkdir('Tests/Marketplace/Tests/test_data/pack_to_test/Integrations')
        os.mkdir('Tests/Marketplace/Tests/test_data/pack_to_test/TestPlaybooks/NonCircleTests')
        test_pack = Pack(pack_name="pack_to_test", pack_path='Tests/Marketplace/Tests/test_data/pack_to_test')
        test_pack.remove_unwanted_files()
        assert not os.path.isdir('Tests/Marketplace/Tests/test_data/pack_to_test/TestPlaybooks')
        assert os.path.isdir('Tests/Marketplace/Tests/test_data/pack_to_test/Integrations')
        shutil.rmtree('Tests/Marketplace/Tests/test_data/pack_to_test')


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
        task_status, not_updated_build = \
            Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path, build_number=build_number)

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

        dummy_pack.current_version = '2.0.2'
        open_mocker = MockOpen()
        dummy_path = 'Irrelevant/Test/Path'
        open_mocker[os.path.join(dummy_path, dummy_pack.name, Pack.CHANGELOG_JSON)].read_data = original_changelog
        open_mocker[os.path.join(dummy_pack.path, Pack.RELEASE_NOTES, '2_0_2.md')].read_data = 'wow'
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        mocker.patch("os.path.exists", return_value=True)
        dir_list = ['1_0_1.md', '2_0_2.md', '2_0_0.md']
        mocker.patch("os.listdir", return_value=dir_list)
        mocker.patch('builtins.open', open_mocker)
        build_number = random.randint(0, 100000)
        task_status, not_updated_build = \
            Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path, build_number=build_number)

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
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
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
        task_status, not_updated_build = \
            Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path, build_number=build_number)

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
        mocker.patch("Tests.Marketplace.marketplace_services")
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
        task_status, not_updated_build = \
            Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path, build_number=build_number)

        assert task_status is True
        assert not_updated_build is False

    @pytest.mark.parametrize('version, boolean_value', [('1.0.1', True), ('1.0.2', False), ('1.0.3', False)])
    def test_is_the_only_rn_in_block(self, mocker, dummy_pack, version, boolean_value):
        """
           Given:
               - A version number and current changelog found in index.
           When:
               - Attempting to modify an existing release note and checking if it appears with other versions
                in the changelog under tha same key, therefore should be re-aggregated, or not.
           Then:
               - Return True if there are no other aggregated release notes with it in the changelog,
                and false otherwise.
        """
        release_notes_dir = 'Irrelevant/Test/Path'
        dir_list = ['1_0_1.md', '1_0_2.md', '1_0_3.md']
        mocker.patch("os.listdir", return_value=dir_list)
        assert is_the_only_rn_in_block(release_notes_dir, version, AGGREGATED_CHANGELOG) == boolean_value

    def test_get_same_block_versions(self, mocker, dummy_pack):
        """
           Given:
               - A version number that appears in the changelog file along with other release notes in the same block,
                under a key that represents the highest version among those, and current changelog found in index
           When:
               - Attempting to re-aggregate all the release notes that are under the same key in the changelog,
                when one of those has been modified.
           Then:
               - Return all the versions and their modified release notes that are in the same block, as in
                under the same version key in the changelog file.
        """
        release_notes_dir = 'Irrelevant/Test/Path'
        version = '1.0.2'
        higher_nearest_version = '1.0.3'
        dir_list = ['1_0_1.md', '1_0_2.md', '1_0_3.md']
        mocker.patch("os.listdir", return_value=dir_list)
        modified_rn_file = 'modified dummy release notes'
        mocker.patch("builtins.open", mock_open(read_data=modified_rn_file))
        same_block_versions_dict = {'1.0.2': modified_rn_file, '1.0.3': modified_rn_file}
        assert dummy_pack.get_same_block_versions(release_notes_dir, version, AGGREGATED_CHANGELOG) == \
               (same_block_versions_dict, higher_nearest_version)

    def test_get_modified_release_notes_lines(self, mocker, dummy_pack):
        """
           Given:
               - Modified release note file and valid current changelog found in index.
           When:
               - Fixing an existing release notes file.
           Then:
               - Assert the returned release notes lines contains the modified release note.
        """

        release_notes_dir = 'Irrelevant/Test/Path'
        changelog_latest_rn_versions = ['1.0.3']
        modified_rn_files = ['1_0_2.md']
        modified_rn_lines = 'dummy release notes\nmodified dummy release notes'
        modified_rn_file = 'modified dummy release notes'
        mocker.patch("builtins.open", mock_open(read_data=modified_rn_file))
        same_block_version_dict = {'1.0.2': "dummy release notes", '1.0.3': "dummy release notes"}
        higher_version = '1.0.3'
        mocker.patch("Tests.Marketplace.marketplace_services.Pack.get_same_block_versions",
                     return_value=(same_block_version_dict, higher_version))
        mocker.patch("Tests.Marketplace.marketplace_services.aggregate_release_notes_for_marketplace",
                     return_value=modified_rn_lines)
        modified_versions_dict = dummy_pack.get_modified_release_notes_lines(
            release_notes_dir, changelog_latest_rn_versions, AGGREGATED_CHANGELOG, modified_rn_files)
        assert modified_versions_dict == {'1.0.3': modified_rn_lines}

    def test_update_changelog_entry(self, dummy_pack):
        """
           Given:
               - Changelog from production bucket, a version that is a key of an entry in the changelog and rn lines
                to update the entry with.
           When:
               - Modifying an exiting rn.
           Then:
               - The entry will keep all the other data other than the modified part.
        """
        entry = dummy_pack._get_updated_changelog_entry(AGGREGATED_CHANGELOG, '1.0.1', 'updated_rn')
        assert entry['releaseNotes'] == 'updated_rn'
        assert entry['displayName'] == AGGREGATED_CHANGELOG['1.0.1']['displayName']
        assert entry['released'] == AGGREGATED_CHANGELOG['1.0.1']['released']

    def test_assert_production_bucket_version_matches_release_notes_version_positive(self, dummy_pack):
        """
           Given:
               - Changelog from production bucket and the current branch's latest version of a given pack
           When:
               - current branch's latest version is higher than the production bucket version
           Then:
               - assertion should pass, since this branch probably adds a new version to the pack
       """
        changelog = {
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
        }
        branch_latest_version = '2.0.1'
        Pack.assert_upload_bucket_version_matches_release_notes_version(dummy_pack,
                                                                        changelog,
                                                                        branch_latest_version)

    def test_assert_production_bucket_version_matches_release_notes_version_negative(self, dummy_pack):
        """
           Given:
               - Changelog from production bucket and the current branch's latest version of a given pack
           When:
               - current branch's latest version is lower than the production bucket version
           Then:
               - assertion should fail since this branch is not updated from master
       """
        changelog = {
            '1.0.0': {
                'releaseNotes': 'First release notes',
                'displayName': '1.0.0',
                'released': '2020-05-05T13:39:33Z'
            },
            '2.0.0': {
                'releaseNotes': 'Second release notes',
                'displayName': '2.0.0',
                'released': '2020-06-05T13:39:33Z'
            }
        }
        branch_latest_version = '1.9.9'
        with pytest.raises(AssertionError) as excinfo:
            Pack.assert_upload_bucket_version_matches_release_notes_version(dummy_pack,
                                                                            changelog,
                                                                            branch_latest_version)
            assert 'Version mismatch detected between production bucket and current branch' in str(excinfo.value)
            assert 'Production bucket version: 2.0.0' in str(excinfo.value)
            assert f'current branch version: {branch_latest_version}' in str(excinfo.value)

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

    def test_create_changelog_entry_new(self, dummy_pack):
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
        version_changelog = dummy_pack._create_changelog_entry(release_notes=release_notes,
                                                               version_display_name=version_display_name,
                                                               build_number=build_number, new_version=True)

        assert version_changelog['releaseNotes'] == "dummy release notes"
        assert version_changelog['displayName'] == f'{version_display_name} - {build_number}'

    def test_create_changelog_entry_existing(self, dummy_pack):
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
        version_changelog = dummy_pack._create_changelog_entry(release_notes=release_notes,
                                                               version_display_name=version_display_name,
                                                               build_number=build_number, new_version=False,
                                                               pack_was_modified=True)

        assert version_changelog['releaseNotes'] == "dummy release notes"
        assert version_changelog['displayName'] == f'{version_display_name} - R{build_number}'

    def test_create_changelog_entry_initial(self, dummy_pack):
        """
           Given:
               - release notes, display version and build number
           When:
               - initial changelog entry must created
           Then:
               - return changelog entry with release notes and without R letter in display name
       """
        release_notes = "dummy release notes"
        version_display_name = "1.0.0"
        build_number = "5555"
        version_changelog = dummy_pack._create_changelog_entry(release_notes=release_notes,
                                                               version_display_name=version_display_name,
                                                               build_number=build_number, new_version=False,
                                                               initial_release=True)

        assert version_changelog['releaseNotes'] == "dummy release notes"

    def test_create_changelog_entry_modified_pack(self, dummy_pack):
        """
           Given:
               - release notes, display version and build number
           When:
               - pack was modified but a new version wasn't created
           Then:
               - return changelog entry with release notes and with R letter in display name
       """
        release_notes = "dummy release notes"
        version_display_name = "1.0.0"
        build_number = "5555"
        version_changelog = dummy_pack._create_changelog_entry(release_notes=release_notes,
                                                               version_display_name=version_display_name,
                                                               build_number=build_number, new_version=False,
                                                               pack_was_modified=True)

        assert version_changelog['releaseNotes'] == "dummy release notes"
        assert version_changelog['displayName'] == f'{version_display_name} - R{build_number}'

    def test_create_changelog_entry_pack_wasnt_modified(self, dummy_pack):
        """
           Given:
               - release notes, display version and build number
           When:
               - pack wasn't modified
           Then:
               - return an empty dict
       """
        release_notes = "dummy release notes"
        version_display_name = "1.0.0"
        build_number = "5555"
        version_changelog = dummy_pack._create_changelog_entry(release_notes=release_notes,
                                                               version_display_name=version_display_name,
                                                               build_number=build_number, new_version=False,
                                                               pack_was_modified=False)

        assert not version_changelog

    @staticmethod
    def dummy_pack_changelog(changelog_data):
        temp_changelog_file = os.path.join(os.getcwd(), 'dummy_changelog.json')
        with open(temp_changelog_file, 'w', ) as changelog_file:
            changelog_file.write(json.dumps(changelog_data))
        return str(temp_changelog_file)

    @staticmethod
    def dummy_pack_metadata(metadata_data):
        temp_metadata_file = os.path.join(os.getcwd(), 'dummy_metadata.json')
        with open(temp_metadata_file, 'w', ) as changelog_file:
            changelog_file.write(json.dumps(metadata_data))
        return str(temp_metadata_file)

    @staticmethod
    def mock_os_path_join(path, *paths):
        if not str(path).startswith('changelog') and not str(path).startswith('metadata'):
            if paths:
                return path + '/' + '/'.join(paths)
            return path

        path_to_non_existing_changelog = 'dummy_path'
        if path == 'metadata':
            return TestChangelogCreation.dummy_pack_metadata(TEST_METADATA)
        if path == 'changelog_init_exist':
            return TestChangelogCreation.dummy_pack_changelog(CHANGELOG_DATA_INITIAL_VERSION)
        if path == 'changelog_new_exist':
            return TestChangelogCreation.dummy_pack_changelog(CHANGELOG_DATA_MULTIPLE_VERSIONS)
        if path in ['changelog_not_exist', 'metadata_not_exist']:
            return path_to_non_existing_changelog

    @freeze_time("2020-11-04T13:34:14.75Z")
    @pytest.mark.parametrize('is_metadata_exist, expected_date', [
        ('metadata', '2020-04-14T00:00:00Z'),
        ('metadata_not_exist', '2020-11-04T13:34:14Z')
    ])
    def test_handle_pack_create_date_changelog_exist(self, mocker, dummy_pack, is_metadata_exist, expected_date):
        """
           Given:
               - existing 1.0.0 changelog, pack created_date
               - not existing 1.0.0 changelog, datetime.utcnow
           When:
               - changelog entry already exists
               - changelog entry not exists

           Then:
           - return the released field from the changelog file
           - return datetime.utcnow
       """
        from Tests.Marketplace.marketplace_services import os
        mocker.patch.object(os.path, 'join', side_effect=self.mock_os_path_join)
        pack_created_date = dummy_pack._get_pack_creation_date(is_metadata_exist)
        if is_metadata_exist == 'metadata':
            os.remove(os.path.join(os.getcwd(), 'dummy_metadata.json'))
        assert pack_created_date == expected_date

    @freeze_time("2020-11-04T13:34:14.75Z")
    @pytest.mark.parametrize('metadata_path, is_within_time_delta', [
        ('metadata', False),
        ('metadata_not_exist', True)
    ])
    def test_pack_created_in_time_delta(self, mocker, dummy_pack, metadata_path, is_within_time_delta):
        """
           Given:
               - existing 1.0.0 changelog, pack created_date
               - not existing 1.0.0 changelog, datetime.utcnow
           When:
               - changelog entry already exists
               - changelog entry not exists

           Then:
           - return the released field from the changelog file
           - return datetime.utcnow
       """
        from Tests.Marketplace.marketplace_services import os
        mocker.patch.object(os.path, 'join', side_effect=self.mock_os_path_join)
        three_months_delta = timedelta(days=90)
        response = Pack.pack_created_in_time_delta(dummy_pack.name, three_months_delta, metadata_path)
        assert response == is_within_time_delta
        try:
            os.remove(os.path.join(os.getcwd(), 'dummy_metadata.json'))
        except Exception:
            pass

    @freeze_time("2020-11-04T13:34:14.75Z")
    @pytest.mark.parametrize('is_changelog_exist, expected_date', [
        ('changelog_new_exist', '2021-01-20T12:10:55Z'),
        ('changelog_not_exist', '2020-11-04T13:34:14Z')
    ])
    def test_handle_pack_update_date_changelog_exist(self, mocker, dummy_pack, is_changelog_exist, expected_date):
        """
           Given:
               - existing changelog with 2 versions
               - not existing changelog, datetime.utcnow
           When:
               - changelog entry already exists
               - changelog entry not exists
           Then:
           - return the released field from the changelog file
           - return datetime.utcnow
       """
        from Tests.Marketplace.marketplace_services import os
        mocker.patch.object(os.path, 'join', side_effect=self.mock_os_path_join)
        pack_update_date = dummy_pack._get_pack_update_date(is_changelog_exist, False)
        if is_changelog_exist == 'changelog_new_exist':
            os.remove(os.path.join(os.getcwd(), 'dummy_changelog.json'))
        assert pack_update_date == expected_date


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
                                           'image_path': f'/path/{temp_image_name}',
                                           'integration_path_basename': 'fake_unified_integration_path'}]
        mocker.patch("marketplace_services_test.Pack._search_for_images", return_value=search_for_images_return_value)
        mocker.patch("marketplace_services_test.Pack.need_to_upload_integration_image", return_value=True)
        mocker.patch('builtins.open', mock_open(read_data="image_data"))
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        dummy_storage_bucket = mocker.MagicMock()
        dummy_file = mocker.MagicMock()
        dummy_file.a_path = os.path.join(PACKS_FOLDER, "TestPack", temp_image_name)
        dummy_storage_bucket.blob.return_value.name = os.path.join(GCPConfig.CONTENT_PACKS_PATH, "TestPack",
                                                                   temp_image_name)
        task_status = dummy_pack.upload_integration_images(dummy_storage_bucket, GCPConfig.CONTENT_PACKS_PATH,
                                                           [dummy_file],
                                                           True)

        assert task_status
        assert len(dummy_pack._displayed_integration_images) == len(expected_result)
        assert dummy_pack._displayed_integration_images == expected_result

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
                                           'image_path': f'/path/{temp_image_name}',
                                           'integration_path_basename': 'fake_unified_integration_path'}]
        mocker.patch("marketplace_services_test.Pack._search_for_images", return_value=search_for_images_return_value)
        mocker.patch("marketplace_services_test.Pack.need_to_upload_integration_image", return_value=True)
        mocker.patch("builtins.open", mock_open(read_data="image_data"))
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        dummy_storage_bucket = mocker.MagicMock()
        dummy_file = mocker.MagicMock()
        dummy_file.a_path = os.path.join(PACKS_FOLDER, "TestPack", temp_image_name)
        dummy_storage_bucket.blob.return_value.name = os.path.join(GCPConfig.CONTENT_PACKS_PATH, "TestPack",
                                                                   temp_image_name)
        task_status = dummy_pack.upload_integration_images(dummy_storage_bucket, GCPConfig.CONTENT_PACKS_PATH,
                                                           [dummy_file], True)

        assert task_status
        assert len(dummy_pack._displayed_integration_images) == len(expected_result)
        assert dummy_pack._displayed_integration_images == expected_result

    @pytest.mark.parametrize("display_name", [
        'Integration Name (Developer Contribution)',
        'Integration Name (Community Contribution) ',
        'Integration Name',
        'Integration Name (Partner Contribution)',
        'Integration Name(Partner Contribution)'
    ])
    def test_remove_contrib_suffix_from_name(self, dummy_pack, display_name):
        """
           Given:
               - Integration name.
           When:
               - Uploading integrations images to gcs.
           Then:
               - Validates that the contribution details were removed
       """

        assert "Integration Name" == dummy_pack.remove_contrib_suffix_from_name(display_name)

    def test_copy_integration_images(self, mocker, dummy_pack):
        """
           Given:
               - Integration image.
           When:
               - Performing copy and upload of all the pack's integration images
           Then:
               - Validate that the image has been copied from build bucket to prod bucket
       """
        dummy_build_bucket = mocker.MagicMock()
        dummy_prod_bucket = mocker.MagicMock()
        blob_name = "content/packs/TestPack/IntegrationName_image.png"
        dummy_build_bucket.list_blobs.return_value = [Blob(blob_name, dummy_build_bucket)]
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        dummy_build_bucket.copy_blob.return_value = Blob('copied_blob', dummy_prod_bucket)
        images_data = {"TestPack": {BucketUploadFlow.INTEGRATIONS: [os.path.basename(blob_name)]}}
        task_status = dummy_pack.copy_integration_images(dummy_prod_bucket, dummy_build_bucket, images_data,
                                                         GCPConfig.CONTENT_PACKS_PATH, GCPConfig.BUILD_BASE_PATH)
        assert task_status

    def test_copy_author_image(self, mocker, dummy_pack):
        """
           Given:
               - Author image.
           When:
               - Performing copy and upload of the pack's author image
           Then:
               - Validate that the image has been copied from build bucket to prod bucket
       """
        dummy_build_bucket = mocker.MagicMock()
        dummy_prod_bucket = mocker.MagicMock()
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        blob_name = "content/packs/TestPack/Author_image.png"
        images_data = {"TestPack": {BucketUploadFlow.AUTHOR: True}}
        dummy_build_bucket.copy_blob.return_value = Blob(blob_name, dummy_prod_bucket)
        task_status = dummy_pack.copy_author_image(dummy_prod_bucket, dummy_build_bucket, images_data,
                                                   GCPConfig.CONTENT_PACKS_PATH, GCPConfig.BUILD_BASE_PATH)
        assert task_status


class TestCopyAndUploadToStorage:
    """ Test class for copying and uploading a pack to storage.

    """

    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_copy_and_upload_to_storage_not_found(self, mocker, dummy_pack):
        """
           Given:
               - A pack with latest version that is missing from the build bucket.
           When:
               - Checking the latest version in the build bucket before copying it to the production bucket.
           Then:
               - Validate that the upload task had failed and that the pack isn't skipped
       """
        dummy_build_bucket = mocker.MagicMock()
        dummy_prod_bucket = mocker.MagicMock()
        mocker.patch("Tests.Marketplace.marketplace_services.logging")

        # case: latest version is not in build bucket
        dummy_pack.latest_version = "2.0.0"
        dummy_build_bucket.list_blobs.return_value = []
        successful_packs_dict = {
            dummy_pack.name: {
                BucketUploadFlow.STATUS: "",
                BucketUploadFlow.AGGREGATED: "False",
                BucketUploadFlow.LATEST_VERSION: dummy_pack.latest_version
            }
        }

        task_status, skipped_pack = dummy_pack.copy_and_upload_to_storage(
            dummy_prod_bucket, dummy_build_bucket, successful_packs_dict,
            GCPConfig.CONTENT_PACKS_PATH, GCPConfig.BUILD_BASE_PATH
        )
        assert not task_status
        assert not skipped_pack

    def test_copy_and_upload_to_storage_skip(self, mocker, dummy_pack):
        """
           Given:
               - A pack with latest version that exists both in build and production bucket.
           When:
               - Checking the latest version in the production bucket before copying the latest one from the build
                bucket
           Then:
               - Validate that the upload task succeeded and that the pack was skipped (it already existed)
       """
        dummy_build_bucket = mocker.MagicMock()
        dummy_prod_bucket = mocker.MagicMock()
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        task_status, skipped_pack = dummy_pack.copy_and_upload_to_storage(dummy_prod_bucket, dummy_build_bucket, {},
                                                                          GCPConfig.CONTENT_PACKS_PATH,
                                                                          GCPConfig.BUILD_BASE_PATH)
        assert task_status
        assert skipped_pack

    def test_copy_and_upload_to_storage_upload(self, mocker, dummy_pack):
        """
           Given:
               - A pack with latest version that exists in the build bucket but not in the production bucket.
           When:
               - Copying the pack from the build bucket to the production bucket.
           Then:
               - Validate that the task succeeds and that the pack isn't skipped
       """
        dummy_build_bucket = mocker.MagicMock()
        dummy_prod_bucket = mocker.MagicMock()
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        blob_name = "content/packs/TestPack/2.0.0/TestPack.zip"
        dummy_pack.latest_version = "2.0.0"
        dummy_build_bucket.list_blobs.return_value = [Blob(blob_name, dummy_build_bucket)]
        dummy_build_bucket.copy_blob.return_value = Blob(blob_name, dummy_prod_bucket)
        task_status, skipped_pack = dummy_pack.copy_and_upload_to_storage(
            dummy_prod_bucket, dummy_build_bucket, {
                "TestPack": {
                    BucketUploadFlow.STATUS: "status1",
                    BucketUploadFlow.AGGREGATED: "False",
                    BucketUploadFlow.LATEST_VERSION: dummy_pack.latest_version
                }
            }, GCPConfig.CONTENT_PACKS_PATH, GCPConfig.BUILD_BASE_PATH
        )
        assert task_status
        assert not skipped_pack


class TestLoadUserMetadata:
    @pytest.fixture(scope="function")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_load_user_metadata(self, dummy_pack, dummy_pack_metadata, tmp_path):
        """
        Given:
            - A pack with metadata containing pack data like eula link
        When:
            - Loading the file data into the pack object
        Then:
            - Ensure eula link appears in the pack object metadata
        """
        metadata_path = os.path.join(tmp_path, 'pack_metadata.json')
        dummy_pack._pack_path = tmp_path
        with open(metadata_path, 'w') as metadata_file:
            metadata_file.write(json.dumps(dummy_pack_metadata))
        dummy_pack.load_user_metadata()
        loaded_metadata = dummy_pack.user_metadata

        assert loaded_metadata['eulaLink'] == 'https://my.eula.com'

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
        logging_mock = mocker.patch("Tests.Marketplace.marketplace_services.logging.error")
        task_status = dummy_pack.load_user_metadata()

        assert logging_mock.call_count == 1
        assert not task_status
        assert not dummy_pack.user_metadata


class TestSetDependencies:

    @staticmethod
    def get_pack_metadata():
        metadata_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data', 'metadata.json')
        with open(metadata_path, 'r') as metadata_file:
            pack_metadata = json.load(metadata_file)

        return pack_metadata

    def test_set_dependencies_new_dependencies(self):
        """
           Given:
               - Pack with user dependencies
               - New generated dependencies
           When:
               - Formatting metadata
           Then:
               - The dependencies in the metadata file should be merged with the generated ones
       """
        from Tests.Marketplace.marketplace_services import Pack

        metadata = self.get_pack_metadata()
        generated_dependencies = {
            'ImpossibleTraveler': {
                'dependencies': {
                    'HelloWorld': {
                        'mandatory': False,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'HelloWorld',
                        'certification': 'certified'
                    },
                    'ServiceNow': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'ServiceNow',
                        'certification': 'certified'
                    },
                    'Ipstack': {
                        'mandatory': False,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Ipstack',
                        'certification': 'certified'
                    },
                    'Active_Directory_Query': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Active Directory Query v2',
                        'certification': 'certified'
                    }
                }
            }
        }

        p = Pack('ImpossibleTraveler', 'dummy_path')
        dependencies = json.dumps(metadata['dependencies'])
        dependencies = json.loads(dependencies)
        dependencies.update(generated_dependencies['ImpossibleTraveler']['dependencies'])
        p._user_metadata = metadata
        p.set_pack_dependencies(generated_dependencies, DUMMY_PACKS_DICT)

        assert p.user_metadata['dependencies'] == dependencies

    def test_set_dependencies_no_user_dependencies(self):
        """
           Given:
               - Pack without user dependencies
               - New generated dependencies
           When:
               - Formatting metadata
           Then:
               - The dependencies in the metadata file should be the generated ones
       """
        from Tests.Marketplace.marketplace_services import Pack

        metadata = self.get_pack_metadata()

        generated_dependencies = {
            'ImpossibleTraveler': {
                'dependencies': {
                    'HelloWorld': {
                        'mandatory': False,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'HelloWorld',
                        'certification': 'certified'
                    },
                    'ServiceNow': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'ServiceNow',
                        'certification': 'certified'
                    },
                    'Ipstack': {
                        'mandatory': False,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Ipstack',
                        'certification': 'certified'
                    },
                    'Active_Directory_Query': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Active Directory Query v2',
                        'certification': 'certified'
                    }
                }
            }
        }

        metadata['dependencies'] = {}
        p = Pack('ImpossibleTraveler', 'dummy_path')
        p._user_metadata = metadata
        p.set_pack_dependencies(generated_dependencies, DUMMY_PACKS_DICT)

        assert p.user_metadata['dependencies'] == generated_dependencies['ImpossibleTraveler']['dependencies']

    def test_set_dependencies_no_generated_dependencies(self):
        """
           Given:
               - Pack with user dependencies
               - No generated dependencies
           When:
               - Formatting metadata
           Then:
               - The dependencies in the metadata file should be the user ones
       """
        from Tests.Marketplace.marketplace_services import Pack

        metadata = self.get_pack_metadata()
        dependencies = metadata['dependencies']
        p = Pack('ImpossibleTraveler', 'dummy_path')
        p._user_metadata = metadata
        p.set_pack_dependencies({}, {})
        assert p.user_metadata['dependencies'] == dependencies

    def test_set_dependencies_core_pack(self):
        """
           Given:
               - Core pack with new dependencies
               - No mandatory dependencies that are not core packs
           When:
               - Formatting metadata
           Then:
               - The dependencies in the metadata file should be merged
       """
        from Tests.Marketplace.marketplace_services import Pack

        metadata = self.get_pack_metadata()

        generated_dependencies = {
            'HelloWorld': {
                'dependencies': {
                    'CommonPlaybooks': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Common Playbooks',
                        'certification': 'certified'
                    }
                }
            }
        }

        metadata['dependencies'] = {}
        metadata['name'] = 'HelloWorld'
        metadata['id'] = 'HelloWorld'
        p = Pack('HelloWorld', 'dummy_path')
        p._user_metadata = metadata
        dependencies = json.dumps(generated_dependencies['HelloWorld']['dependencies'])
        dependencies = json.loads(dependencies)

        p.set_pack_dependencies(generated_dependencies, DUMMY_PACKS_DICT)

        assert p.user_metadata['dependencies'] == dependencies

    def test_set_dependencies_core_pack_new_mandatory_dependency(self):
        """
           Given:
               - Core pack with new dependencies
               - Mandatory dependencies that are not core packs
           When:
               - Formatting metadata
           Then:
               - An exception should be raised
       """
        from Tests.Marketplace.marketplace_services import Pack

        metadata = self.get_pack_metadata()

        generated_dependencies = {
            'HelloWorld': {
                'dependencies': {
                    'CommonPlaybooks': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'ServiceNow',
                        'certification': 'certified'
                    },
                    'SlackV2': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Ipstack',
                        'certification': 'certified'
                    }
                }
            }
        }

        metadata['dependencies'] = {}
        p = Pack('HelloWorld', 'dummy_path')
        p._user_metadata = metadata

        with pytest.raises(Exception) as e:
            p.set_pack_dependencies(generated_dependencies, DUMMY_PACKS_DICT)

        assert str(e.value) == "New mandatory dependencies ['SlackV2'] were found in the core pack HelloWorld"

    def test_set_dependencies_core_pack_mandatory_dependency_override(self):
        """
           Given:
               - Core pack with new dependencies
               - Mandatory dependencies that are not core packs that were overridden in the user metadata
           When:
               - Formatting metadata
           Then:
               - Metadata should be formatted correctly
       """
        from Tests.Marketplace.marketplace_services import Pack

        metadata = self.get_pack_metadata()

        generated_dependencies = {
            'HelloWorld': {
                'dependencies': {
                    'CommonPlaybooks': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'ServiceNow',
                        'certification': 'certified'
                    },
                    'Ipstack': {
                        'mandatory': True,
                        'minVersion': '1.0.0',
                        'author': 'Cortex XSOAR',
                        'name': 'Ipstack',
                        'certification': 'certified'
                    }
                }
            }
        }

        p = Pack('HelloWorld', 'dummy_path')
        user_dependencies = metadata['dependencies']
        dependencies = json.dumps(generated_dependencies['HelloWorld']['dependencies'])
        dependencies = json.loads(dependencies)
        dependencies.update(user_dependencies)
        p._user_metadata = metadata

        p.set_pack_dependencies(generated_dependencies, DUMMY_PACKS_DICT)

        assert p.user_metadata['dependencies'] == dependencies


class TestReleaseNotes:
    """ Test class for all the handling of release notes of a given pack.

    """

    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    def test_get_changelog_latest_rn(self, mocker, dummy_pack):
        """
           Given:
               - Changelog file with two release notes
           When:
               - Getting the latest version in the changelog file
           Then:
               - Verify that the changelog file content is as expected
               - Verify that the latest release notes version is 2.0.0 (the latest)
       """
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
        original_changelog_dict = {
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
        }
        mocker.patch('builtins.open', mock_open(read_data=original_changelog))
        mocker.patch('os.path.exists', return_value=True)
        changelog, changelog_latest_rn_version, changelog_latest_rn = dummy_pack.get_changelog_latest_rn('fake_path')
        assert changelog == original_changelog_dict
        assert changelog_latest_rn_version == Version('2.0.0')
        assert changelog_latest_rn == "Second release notes"

    def test_create_local_changelog(self, mocker, dummy_pack):
        """
           Given:
               - Changelog file path of the given pack withing the index dir
           When:
               - Creating the local changelog under the pack path
           Then:
               - Verify that the local changelog file has been created successfully
       """
        mocker.patch('os.path.exists', return_value=True)
        build_index_folder_path = 'fake_build_index_folder_path'
        build_changelog_index_path = os.path.join(build_index_folder_path, dummy_pack.name, Pack.CHANGELOG_JSON)
        pack_changelog_path = os.path.join(dummy_pack.path, Pack.CHANGELOG_JSON)
        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('Tests.Marketplace.marketplace_services.logging')
        mocker.patch('shutil.copyfile')
        task_status = dummy_pack.create_local_changelog(build_index_folder_path)
        shutil_copyfile_call_count = shutil.copyfile.call_count
        shutil_copyfile_call_args = shutil.copyfile.call_args_list[0][1]
        assert shutil_copyfile_call_count == 1
        assert shutil_copyfile_call_args == {'src': build_changelog_index_path, 'dst': pack_changelog_path}
        assert task_status

    def test_get_release_notes_lines_aggregate(self, mocker, dummy_pack):
        """
           Given:
               - 3 release notes files, 1.0.0 is the latest rn, 1.1.0 and 2.0.0 are new rn files
           When:
               - Creating the release notes for the new version (2.0.0)
           Then:
               - Verify that the rn of 1.1.0 and 2.0.0 are aggregated
       """
        rn_one = '''
#### Integrations
##### CrowdStrike Falcon Intel v2
- wow1
        '''
        rn_two = '''
#### Integrations
##### CrowdStrike Falcon Intel v2
- wow2
        '''
        aggregated_rn = "\n#### Integrations\n##### CrowdStrike Falcon Intel v2\n- wow1\n- wow2\n"
        open_mocker = MockOpen()
        mocker.patch('os.listdir', return_value=['1_0_0.md', '1_1_0.md', '2_0_0.md'])
        open_mocker['rn_dir_fake_path/1_1_0.md'].read_data = rn_one
        open_mocker['rn_dir_fake_path/2_0_0.md'].read_data = rn_two
        mocker.patch('builtins.open', open_mocker)
        rn_lines, latest_rn, new_versions = \
            dummy_pack.get_release_notes_lines('rn_dir_fake_path', Version('1.0.0'), '')
        assert latest_rn == '2.0.0'
        assert rn_lines == aggregated_rn
        assert new_versions == ['1.1.0', '2.0.0']

    def test_get_release_notes_lines_updated_rn(self, mocker, dummy_pack):
        """
           Given:
               - 2 release notes files, 1.0.0 and 1.0.1 which is the latest rn and exists in the changelog
           When:
               - Creating the release notes for version 1.0.1
           Then:
               - Verify that the rn are the same
       """
        rn = '''
#### Integrations
##### CrowdStrike Falcon Intel v2
- wow1
        '''
        mocker.patch('builtins.open', mock_open(read_data=rn))
        mocker.patch('os.listdir', return_value=['1_0_0.md', '1_0_1.md'])
        rn_lines, latest_rn, new_versions = \
            dummy_pack.get_release_notes_lines('rn_dir_fake_path', Version('1.0.1'), rn)
        assert latest_rn == '1.0.1'
        assert rn_lines == rn
        assert new_versions == []

    def test_get_release_notes_lines_no_rn(self, mocker, dummy_pack):
        """
           Given:
               - 2 release notes files, 1.0.0 and 1.0.1 which is the latest rn and exists in the changelog
           When:
               - Creating the release notes for version 1.0.1
           Then:
               - Verify that the rn are the same
       """
        changelog_latest_rn = '''
#### Integrations
##### CrowdStrike Falcon Intel v2
- wow1
- wow2
        '''

        mocker.patch('os.listdir', return_value=['1_0_0.md', '1_0_1.md'])
        rn_lines, latest_rn, new_versions = \
            dummy_pack.get_release_notes_lines('wow', Version('1.0.1'), changelog_latest_rn)
        assert latest_rn == '1.0.1'
        assert rn_lines == changelog_latest_rn
        assert new_versions == []

    CHANGELOG_ENTRY_CONTAINS_BC_VERSION_INPUTS = [(Version('0.0.0'), Version('1.0.0'), [], dict(), dict()),
                                                  (
                                                      Version('0.0.0'), Version('1.0.0'),
                                                      [Version('1.0.1')], {'1.0.1': 'BC text'}, dict()),
                                                  (
                                                      Version('0.0.0'), Version('1.0.0'),
                                                      [Version('1.0.0')], {'1.0.0': None},
                                                      {'1.0.0': None}),
                                                  (
                                                      Version('2.3.1'), Version('2.4.0'),
                                                      [Version('2.3.1')], {'2.3.1': 'BC text'},
                                                      dict()),
                                                  (Version('2.3.1'), Version('2.4.0'),
                                                   [Version('2.3.1'), Version('2.3.2')],
                                                   {'2.3.1': None, '2.3.2': 'BC Text 232'}, {'2.3.2': 'BC Text 232'})]

    @pytest.mark.parametrize('predecessor_version, rn_version, bc_versions_list,bc_version_to_text, expected',
                             CHANGELOG_ENTRY_CONTAINS_BC_VERSION_INPUTS)
    def test_changelog_entry_contains_bc_version(self, predecessor_version: Version, rn_version: Version,
                                                 bc_versions_list: List[Version], bc_version_to_text, expected):
        """
           Given:
           - predecessor_version: Predecessor version of the changelog entry.
           - rn_version: RN version of the current processed changelog entry
            When:
            - Checking whether current 'rn_version' contains a BC version.
            Case a: Pack does not contain any BC versions.
            Case b: Pack contains BC versions, but not between 'predecessor_version' to 'rn_version' range.
            Case c: Pack contains BC versions, and it is the exact 'rn_version'.
            Case d: Pack contains BC versions, and it is the exact 'predecessor_version'.
            Case e: Pack contains BC versions, and it is the between 'predecessor_version' to 'rn_version' range.
           Then:
           Validate expected bool is returned.
           Case a: Validate false is returned.
           Case b: Validate false is returned.
           Case c: Validate true is returned, because there is a BC version that matches the
                   rule 'predecessor_version' < bc_version <= 'rn_version' (equals to 'rn_version').
           Case d: Validate false is returned, because there is no BC version that matches the
                   rule 'predecessor_version' < bc_version <= 'rn_version' (equals to 'predecessor_version' which is
                   outside range).
           Case e: Validate true is returned, because there is a BC version that matches the
                   rule 'predecessor_version' < bc_version <= 'rn_version' (above 'predecessor_version',
                   below 'rn_version').
       """
        assert Pack._changelog_entry_bc_versions(predecessor_version, rn_version, bc_versions_list,
                                                 bc_version_to_text) == expected

    def test_breaking_changes_versions_to_text(self, tmpdir):
        """
        Given:
        - Release notes directory (class field)

        When:
        - Creating dict of BC version to mapping. Including all possibilities:
        1) RN does not have corresponding config file.
        2) RN has corresponding config file, breakingChanges is set to true, text does not exist.
        3) RN has corresponding config file, breakingChanges is set to true, text exists.
        4) RN has corresponding config file, breakingChanges is set to false, text does not exist.
        5) RN has corresponding config file, breakingChanges is set to false, text exists.

        Then:
        - Ensure expected mapping is done.
        case 2 contains only breakingChanges: True entry.
        case 3 contains both breakingChanges: True and text entries.

        """
        rn_dir = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_1', 'some RN to see it is filtered by its extension')
        create_rn_config_file(rn_dir, '1_0_2', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_0_3', {'breakingChanges': True, 'breakingChangesNotes': 'this is BC'})
        create_rn_config_file(rn_dir, '1_0_4', {'breakingChanges': False})
        create_rn_config_file(rn_dir, '1_0_5', {'breakingChanges': False, 'breakingChangesNotes': 'this is BC'})

        expected: Dict[str, Optional[str]] = {'1.0.2': None, '1.0.3': 'this is BC'}

        assert Pack._breaking_changes_versions_to_text(rn_dir) == expected

    SPLIT_BC_VERSIONS_WITH_AND_WITHOUT_TEXT_INPUTS = [(dict(), ([], [])),
                                                      ({'1.0.2': 'bc text 1'}, (['bc text 1'], [])),
                                                      ({'1.0.2': None}, ([], ['1.0.2'])),
                                                      ({'1.0.2': None, '1.0.4': None, '1.0.5': 'txt1', '1.0.6': 'txt2'},
                                                       (['txt1', 'txt2'], ['1.0.2', '1.0.4'])),
                                                      ]

    @pytest.mark.parametrize('bc_versions, expected', SPLIT_BC_VERSIONS_WITH_AND_WITHOUT_TEXT_INPUTS)
    def test_split_bc_versions_with_and_without_text(self, bc_versions: Dict[str, Optional[str]],
                                                     expected: Tuple[List[str], List[str]]):
        """
        Given:
        - 'bc_versions': Dict of BC versions to text.

        When:
        - Splitting 'bc_versions' to two lists of versions with/without text.

        Then:
        - Ensure expected results are returned.
        """
        assert Pack._split_bc_versions_with_and_without_text(bc_versions) == expected

    def test_get_release_notes_concat_str_non_empty(self, tmpdir):
        """
        Given:
        - 'bc_versions': Dict of BC versions to text.

        When:
        - Splitting 'bc_versions' to two lists of versions with/without text.

        Then:
        - Ensure expected results are returned.
        """
        rn_dir: str = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_1', 'txt1')
        create_rn_file(rn_dir, '1_0_2', 'txt2')
        assert Pack._get_release_notes_concat_str(rn_dir, ['1_0_1.md', '1_0_2.md']) == '\ntxt1\ntxt2'

    def test_get_release_notes_concat_str_empty(self):
        """
        Given:
        - 'bc_versions': Empty dict of BC versions to text.

        When:
        - Splitting 'bc_versions' to two lists of versions with/without text.

        Then:
        - Ensure empty results are returned.
        """
        assert Pack._get_release_notes_concat_str('', []) == ''

    def test_handle_many_bc_versions_some_with_text(self, dummy_pack, tmpdir):
        """
        Given:
        - 'text_of_bc_versions': Text of BC versions containing specific BC text.
        - 'bc_versions_without_text': BC versions that do not contain specific BC text

        When:
        - Handling a case were one aggregated changelog entry contains both BCs with text and without text.

        Then:
        - Ensure expected test is returned
        """
        rn_dir: str = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_2', 'no bc1')
        create_rn_file(rn_dir, '1_0_6', 'no bc2')
        text_of_bc_versions: List[str] = ['txt1', 'txt2']
        bc_versions_without_text: List[str] = ['1.0.2', '1.0.6']

        expected_concat_str: str = 'txt1\ntxt2\nno bc1\nno bc2'
        assert dummy_pack._handle_many_bc_versions_some_with_text(rn_dir, text_of_bc_versions,
                                                                  bc_versions_without_text) == expected_concat_str

    CALCULATE_BC_TEXT_NON_MIXED_CASES_INPUTS = [(dict(), None), ({'1.0.2': None}, None), ({'1.0.2': 'txt1'}, 'txt1'),
                                                ({'1.0.2': 'txt1', '1.0.4': 'txt5'}, 'txt1\ntxt5')]

    @pytest.mark.parametrize('bc_version_to_text, expected', CALCULATE_BC_TEXT_NON_MIXED_CASES_INPUTS)
    def test_calculate_bc_text_non_mixed_cases(self, dummy_pack, bc_version_to_text: Dict[str, Optional[str]],
                                               expected: Optional[str]):
        """
        Given:
        - 'text_of_bc_versions': Text of BC versions containing specific BC text.

        When:
        - Calculating text for changelog entry
        Case a: Only one BC in aggregated changelog entry:
        Case b: More than one BC in aggregated entry, all of them containing text.

        Then:
        - Ensure expected text is returned.

        """
        assert dummy_pack._calculate_bc_text('', bc_version_to_text) == expected

    def test_calculate_bc_text_mixed_case(self, dummy_pack, tmpdir):
        """
        Given:
        - 'text_of_bc_versions': Text of BC versions containing specific BC text.

        When:
        - Handling a case were one aggregated changelog entry contains both BCs with text and without text.

        Then:
        - Ensure expected text is returned
        """
        rn_dir: str = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        create_rn_file(rn_dir, '1_0_2', 'bc notes without bc text')
        create_rn_file(rn_dir, '1_0_6', 'RN for 1_0_6')
        create_rn_config_file(rn_dir, '1_0_2', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_0_6', {'breakingChanges': True, 'breakingChangesNotes': 'bc txt2'})

        expected_text: str = 'bc txt2\nbc notes without bc text'
        assert dummy_pack._calculate_bc_text(rn_dir, {'1_0_2': None, '1_0_6': 'bc txt2'}) == expected_text

    def test_add_bc_entries_if_needed(self, dummy_pack, tmpdir):
        """
       Given:
       - changelog: Changelog file data represented as a dictionary.

        When:
        - Updating 'breakingChanges' entry for each changelog dict entry.

       Then:
        - Validate changelog 'breakingChanges' field for each entries are updated as expected. This test includes
          all four types of possible changes:
          a) Entry without breaking changes, changes to entry with breaking changes.
          b) Entry without breaking changes, changes to entry with breaking changes containing BC text.
          c) Entry without breaking changes, does not change.
          d) Entry with breaking changes, changes to entry without breaking changes.
          e) Entry with breaking changes, changes to entry with BC text.
          f) Entry with breaking changes, changes to entry without BC text.
       """
        rn_dir = f'{tmpdir}/ReleaseNotes'
        os.mkdir(rn_dir)
        for i in range(17, 26):
            create_rn_file(rn_dir, f'1.12.{i}', f'RN of 1.12.{i}')
        create_rn_config_file(rn_dir, '1_12_20', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_12_22', {'breakingChanges': True})
        create_rn_config_file(rn_dir, '1_12_24', {'breakingChanges': True, 'breakingChangesNotes': 'bc 24'})
        create_rn_config_file(rn_dir, '1_12_25', {'breakingChanges': True, 'breakingChangesNotes': 'bc 25'})
        changelog: Dict[str, Any] = {
            '1.12.20': {
                'releaseNotes': 'RN of 1.12.20',
                'displayName': '1.12.18 - 392682',
                'released': '2021-07-05T02:00:02Z',
                'breakingChanges': True
            },
            '1.12.17': {
                'releaseNotes': 'RN of 1.12.17',
                'displayName': '1.12.17 - 392184',
                'released': '2021-07-02T23:15:52Z',
                'breakingChanges': True
            },
            '1.12.16': {
                'releaseNotes': 'RN of 1.12.16',
                'displayName': '1.12.16 - 391562',
                'released': '2021-06-30T23:32:59Z'
            },
            '1.12.23': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z'
            },
            '1.12.24': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True
            },
            '1.12.25': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
            }
        }
        expected_changelog: Dict[str, Any] = {
            '1.12.20': {
                'releaseNotes': 'RN of 1.12.20',
                'displayName': '1.12.18 - 392682',
                'released': '2021-07-05T02:00:02Z',
                'breakingChanges': True
            },
            '1.12.17': {
                'releaseNotes': 'RN of 1.12.17',
                'displayName': '1.12.17 - 392184',
                'released': '2021-07-02T23:15:52Z'
            },
            '1.12.16': {
                'releaseNotes': 'RN of 1.12.16',
                'displayName': '1.12.16 - 391562',
                'released': '2021-06-30T23:32:59Z'
            },
            '1.12.23': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True
            },
            '1.12.24': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True,
                'breakingChangesNotes': 'bc 24'
            },
            '1.12.25': {
                'releaseNotes': 'RN of 1.12.23',
                'displayName': '1.12.23 - 393823',
                'released': '2021-07-06T23:27:59Z',
                'breakingChanges': True,
                'breakingChangesNotes': 'bc 25'
            }
        }
        dummy_pack.add_bc_entries_if_needed(rn_dir, changelog)
        assert changelog == expected_changelog

    def test_add_bc_entries_if_needed_rn_dir_does_not_exist(self, dummy_pack):
        """
       Given:
       - Changelog

        When:
        - Updating changelog entries with BC entries. RN dir does not exist

       Then:
        - Ensure no modification is done to the changelog.
       """
        changelog: Dict = {'a': 1}
        dummy_pack.add_bc_entries_if_needed('not_real_path', changelog)
        assert changelog == {'a': 1}

    FAILED_PACKS_DICT = {
        'TestPack': {'status': 'wow1'},
        'TestPack2': {'status': 'wow2'}
    }

    @pytest.mark.parametrize('failed_packs_dict, task_status, status', [
        ({'TestPack': {'status': 'wow1'}, 'TestPack2': {'status': 'wow2'}}, True, 'wow1'),
        ({'TestPack2': {'status': 'wow2'}}, False, str())
    ])
    def test_is_failed_to_upload(self, failed_packs_dict, task_status, status, dummy_pack):
        """
           Given:
               - A dict of failed packs and a pack which is in the failed packs dict
               - A dict of failed packs and a pack which is not in the failed packs dict
           When:
               - Checking if the pack is in the failed packs dict
           Then:
               - The pack is in the dict, task status is True and right status is returned
               - The pack is not in the dict, task status is False and the empty status is returned
       """
        task_stat, pack_stat = dummy_pack.is_failed_to_upload(failed_packs_dict)
        assert task_stat == task_status
        assert pack_stat == status


class TestStoreInCircleCIArtifacts:
    """ Test the store_successful_and_failed_packs_in_ci_artifacts function

    """
    FAILED_PACK_DICT = {
        BucketUploadFlow.STATUS: PackStatus.FAILED_UPLOADING_PACK.name,
        BucketUploadFlow.AGGREGATED: 'False'
    }
    SUCCESSFUL_PACK_DICT = {
        BucketUploadFlow.STATUS: PackStatus.SUCCESS.name,
        BucketUploadFlow.AGGREGATED: '[1.0.0, 1.0.1] => 1.0.1',
        BucketUploadFlow.LATEST_VERSION: '1.0.1'
    }

    @staticmethod
    def get_successful_packs():
        successful_packs = [
            Pack(pack_name='TestPack1', pack_path='.'),
            Pack(pack_name='TestPack2', pack_path='.'),
        ]
        for pack in successful_packs:
            pack._status = PackStatus.SUCCESS.name
            pack._aggregated = True
            pack._aggregation_str = '[1.0.0, 1.0.1] => 1.0.1'
            pack.latest_version = '1.0.1'
        return successful_packs

    @staticmethod
    def get_failed_packs():
        failed_packs = [
            Pack(pack_name='TestPack3', pack_path='.'),
            Pack(pack_name='TestPack4', pack_path='.'),
        ]
        for pack in failed_packs:
            pack._status = PackStatus.FAILED_UPLOADING_PACK.name
            pack._aggregated = False
        return failed_packs

    @staticmethod
    def get_updated_private_packs():
        return ['TestPack5', 'TestPack6']

    def test_store_successful_and_failed_packs_in_ci_artifacts_both(self, tmp_path):
        """
           Given:
               - Successful packs list - TestPack1 , TestPack2
               - Failed packs list - TestPack3 , TestPack4
               - Private updated packs list - TestPack5 , TestPack6
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $ARTIFACTS_FOLDER/packs_results.json file
           Then:
               - Verify that the file content contains the successful, failed and private
                packs TestPack1, TestPack2 & TestPack3, TestPack4, TestPack5 & TestPack6 respectively.
       """
        successful_packs = self.get_successful_packs()
        failed_packs = self.get_failed_packs()
        updated_private_packs = self.get_updated_private_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, successful_packs, failed_packs,
            updated_private_packs
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.FAILED_PACKS}': {
                    'TestPack3': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT,
                    'TestPack4': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT
                },
                f'{BucketUploadFlow.SUCCESSFUL_PACKS}': {
                    'TestPack1': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT,
                    'TestPack2': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT
                },
                f'{BucketUploadFlow.SUCCESSFUL_PRIVATE_PACKS}': {
                    'TestPack5': {},
                    'TestPack6': {}
                },
            }
        }

    def test_store_successful_and_failed_packs_in_ci_artifacts_successful_only(self, tmp_path):
        """
           Given:
               - Successful packs list - TestPack1, TestPack2
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $ARTIFACTS_FOLDER/packs_results.json file
           Then:
               - Verify that the file content contains the successful packs TestPack1 & TestPack2.
       """
        successful_packs = self.get_successful_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, successful_packs, list(), list()
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.SUCCESSFUL_PACKS}': {
                    'TestPack1': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT,
                    'TestPack2': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT
                }
            }
        }

    def test_store_successful_and_failed_packs_in_ci_artifacts_failed_only(self, tmp_path):
        """
           Given:
               - Failed packs list - TestPack3 , TestPack4
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $ARTIFACTS_FOLDER/packs_results.json file
           Then:
               - Verify that the file content contains the failed packs TestPack & TestPack4.
       """
        failed_packs = self.get_failed_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, list(), failed_packs, list()
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.FAILED_PACKS}': {
                    'TestPack3': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT,
                    'TestPack4': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT
                }
            }
        }

    def test_store_successful_and_failed_packs_in_ci_artifacts_updated_private_packs_only(self, tmp_path):
        """
           Given:
               - Updated private packs list - TestPack5 , TestPack6
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $ARTIFACTS_FOLDER/packs_results.json file
           Then:
               - Verify that the file content contains the successful packs TestPack5 & TestPack6.
       """
        updated_private_packs = self.get_updated_private_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, list(), list(), updated_private_packs
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.SUCCESSFUL_PRIVATE_PACKS}': {
                    'TestPack5': {},
                    'TestPack6': {}
                }
            }
        }


class TestGetSuccessfulAndFailedPacks:
    """ Test the get_successful_and_failed_packs function

    """

    def test_get_successful_and_failed_packs(self, tmp_path):
        """
           Given:
               - File that doesn't exist
               - Empty JSON file
               - Valid JSON file
           When:
               - Loading the file of all failed packs from Prepare Content step in Create Instances job
           Then:
               - Verify that we get an empty dictionary
               - Verify that we get an empty dictionary
               - Verify that we get the expected dictionary
       """
        from Tests.Marketplace.marketplace_services import get_upload_data
        file = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)

        # Case 1: assert file does not exist
        successful, failed, private_packs, images = get_upload_data(
            file, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING
        )
        assert successful == {}
        assert failed == {}
        assert private_packs == {}
        assert images == {}

        # Case 2: assert empty file
        with open(file, "w") as f:
            f.write('')
        successful, failed, private_packs, images = get_upload_data(
            file, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING
        )
        assert successful == {}
        assert failed == {}
        assert private_packs == {}
        assert images == {}

        # Case 3: assert valid file
        with open(file, "w") as f:
            f.write(json.dumps({
                f"{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}": {
                    f"{BucketUploadFlow.FAILED_PACKS}": {
                        "TestPack2": {
                            f"{BucketUploadFlow.STATUS}": "status2",
                            f"{BucketUploadFlow.AGGREGATED}": False
                        }
                    },
                    f"{BucketUploadFlow.SUCCESSFUL_PACKS}": {
                        "TestPack1": {
                            f"{BucketUploadFlow.STATUS}": "status1",
                            f"{BucketUploadFlow.AGGREGATED}": True
                        }
                    },
                    f"{BucketUploadFlow.SUCCESSFUL_PRIVATE_PACKS}": {
                        "TestPack3": {
                            f"{BucketUploadFlow.STATUS}": "status3",
                            f"{BucketUploadFlow.AGGREGATED}": True
                        }
                    },
                    f"{BucketUploadFlow.IMAGES}": {
                        "TestPack1": {
                            f"{BucketUploadFlow.AUTHOR}": True,
                            f"{BucketUploadFlow.INTEGRATIONS}": ["integration_image.png"]
                        }
                    }
                }
            }))
        successful, failed, private_packs, images = get_upload_data(
            file, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING
        )
        assert successful == {"TestPack1": {
            f"{BucketUploadFlow.STATUS}": "status1",
            f"{BucketUploadFlow.AGGREGATED}": True
        }}
        successful_list = [*successful]
        ans = 'TestPack1' in successful_list
        assert ans

        assert failed == {"TestPack2": {
            f"{BucketUploadFlow.STATUS}": "status2",
            f"{BucketUploadFlow.AGGREGATED}": False}
        }
        failed_list = [*failed]
        ans = 'TestPack2' in failed_list
        assert ans

        assert "TestPack1" in images
        test_pack_images = images.get("TestPack1", {})
        assert BucketUploadFlow.AUTHOR in test_pack_images
        assert test_pack_images.get(BucketUploadFlow.AUTHOR, False)
        assert BucketUploadFlow.INTEGRATIONS in test_pack_images
        integration_images = test_pack_images.get(BucketUploadFlow.INTEGRATIONS, [])
        assert len(integration_images) == 1
        assert integration_images[0] == "integration_image.png"

        assert private_packs == {"TestPack3": {
            f"{BucketUploadFlow.STATUS}": "status3",
            f"{BucketUploadFlow.AGGREGATED}": True
        }}
        private_successful_list = [*private_packs]
        ans = 'TestPack3' in private_successful_list
        assert ans


class TestImageClassification:
    """ Test class for all image classifications.
    """

    @pytest.fixture(scope="class")
    def dummy_pack(self):
        """ dummy pack fixture
        """
        return Pack(pack_name="TestPack", pack_path="dummy_path")

    @pytest.mark.parametrize('file_path, result', [
        ('Packs/TestPack/Author_image.png', False),
        ('Packs/TestPack/Integration_image.png', True),
        ('Packs/TestPack/Integration_image.jpeg', False),
        ('Integration_image.png', False),
        ('Integration_pic.png', False),
    ])
    def test_is_integration_image(self, file_path, result, dummy_pack):
        """
           Given:
               - File path of an author image.
               - File path of an integration image.
               - File path of an integration image with the wrong extension.
               - File path not starting with Packs/TestPack
               - File path not containing the 'image' constant
            When:
            - Checking whether the image in integration image or not
           Then:
               - Validate that the answer is False
               - Validate that the answer is True
               - Validate that the answer is False
               - Validate that the answer is False
               - Validate that the answer is False
       """
        assert dummy_pack.is_integration_image(file_path) is result

    @pytest.mark.parametrize('file_path, result', [
        ('Packs/TestPack/Author_image.png', True),
        ('Packs/TestPack/Author_image.jpeg', False),
        ('Packs/TestPack/Integration_image.png', False),
        ('Author_image.png', False)
    ])
    def test_is_author_image(self, file_path, result, dummy_pack):
        """
           Given:
               - File path of an author image.
               - File path of an author image with bad suffix.
               - File path of an integration image.
               - File path not starting with Packs/TestPack
            When:
            - Checking whether the image in integration image or not
           Then:
               - Validate that the answer is True
               - Validate that the answer is False
               - Validate that the answer is False
               - Validate that the answer is False
       """
        assert dummy_pack.is_author_image(file_path) is result


def create_rn_config_file(rn_dir: str, version: str, data: Dict):
    with open(f'{rn_dir}/{version}.json', 'w') as f:
        f.write(json.dumps(data))


def create_rn_file(rn_dir: str, version: str, text: str):
    with open(f'{rn_dir}/{version}.md', 'w') as f:
        f.write(text)
