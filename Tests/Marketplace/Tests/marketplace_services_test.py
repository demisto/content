import shutil
import pytest
import json
import os
import random
from unittest.mock import mock_open
from mock_open import MockOpen
from google.cloud.storage.blob import Blob
from distutils.version import LooseVersion

from Tests.Marketplace.marketplace_services import Pack, Metadata, input_to_list, get_valid_bool, convert_price, \
    get_higher_server_version, GCPConfig, BucketUploadFlow, PackStatus, load_json, \
    store_successful_and_failed_packs_in_ci_artifacts, PACKS_FOLDER


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
                                                    build_number="dummy_build_number", commit_hash="dummy_commit",
                                                    downloads_count=10)
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
        assert parsed_metadata['tags'] == ["tag number one", "Tag number two", "Use Case"]
        assert parsed_metadata['categories'] == ["Messaging"]
        assert parsed_metadata['contentItems'] == {}
        assert 'integrations' in parsed_metadata
        assert parsed_metadata['useCases'] == ["Some Use Case"]
        assert parsed_metadata['keywords'] == ["dummy keyword", "Additional dummy keyword"]
        assert parsed_metadata['downloads'] == 10
        assert 'dependencies' in parsed_metadata

    def test_parsed_metadata_empty_input(self):
        """ Test for empty pack_metadata.json and validating that support, support details and author are set correctly
            to XSOAR defaults value of Metadata class.
        """
        parsed_metadata = Pack._parse_pack_metadata(user_metadata={}, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="dummy_server_version",
                                                    build_number="dummy_build_number", commit_hash="dummy_hash",
                                                    downloads_count=10)

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
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=pack_metadata_input, pack_content_items={},
                                                    pack_id="test_pack_id", integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="dummy_server_version",
                                                    build_number="dummy_build_number", commit_hash="dummy_hash",
                                                    downloads_count=10)

        assert parsed_metadata['price'] == expected

    def test_use_case_tag_added_to_metadata(self, dummy_pack_metadata):
        """
           Given:
               - Pack metadata file with use case.
           When:
               - Running parse_pack_metadada
           Then:
               - Ensure the `Use Case` tag was added to tags.

       """
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=dummy_pack_metadata, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="5.5.0",
                                                    build_number="dummy_build_number", commit_hash="dummy_commit",
                                                    downloads_count=10, is_feed_pack=False)

        assert parsed_metadata['tags'] == ["tag number one", "Tag number two", 'Use Case']

    @pytest.mark.parametrize('is_feed_pack, tags',
                             [(True, ["tag number one", "Tag number two", 'TIM']),
                              (False, ["tag number one", "Tag number two"])
                              ])
    def test_tim_tag_added_to_feed_pack(self, dummy_pack_metadata, is_feed_pack, tags):
        """ Test 'TIM' tag is added if is_feed_pack is True
        """
        parsed_metadata = Pack._parse_pack_metadata(user_metadata=dummy_pack_metadata, pack_content_items={},
                                                    pack_id='test_pack_id', integration_images=[], author_image="",
                                                    dependencies_data={}, server_min_version="5.5.0",
                                                    build_number="dummy_build_number", commit_hash="dummy_commit",
                                                    downloads_count=10, is_feed_pack=True)

        assert parsed_metadata['tags'] == ["tag number one", "Tag number two", 'Use Case', 'TIM']


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
        task_status, not_updated_build = Pack.prepare_release_notes(self=dummy_pack, index_folder_path=dummy_path,
                                                                    build_number=build_number)
        assert task_status is True
        assert not_updated_build is False

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
        mocker.patch("marketplace_services_test.Pack._search_for_images", return_value=(search_for_images_return_value,
                                                                                        search_for_images_return_value))
        mocker.patch('builtins.open', mock_open(read_data="image_data"))
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        dummy_storage_bucket = mocker.MagicMock()
        dummy_content_repo = mocker.MagicMock()
        dummy_commit = mocker.MagicMock()
        dummy_content_repo.commit.return_value = dummy_commit
        dummy_file = mocker.MagicMock()
        dummy_commit.diff.return_value = [dummy_file]
        dummy_file.a_path = os.path.join(PACKS_FOLDER, "TestPack", temp_image_name)
        fake_hash = 'fake_hash'
        dummy_storage_bucket.blob.return_value.name = os.path.join(GCPConfig.STORAGE_BASE_PATH, "TestPack",
                                                                   temp_image_name)
        task_status, integration_images = dummy_pack.upload_integration_images(dummy_storage_bucket, fake_hash,
                                                                               fake_hash, dummy_content_repo)

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
        mocker.patch("marketplace_services_test.Pack._search_for_images", return_value=(search_for_images_return_value,
                                                                                        search_for_images_return_value))
        mocker.patch("builtins.open", mock_open(read_data="image_data"))
        mocker.patch("Tests.Marketplace.marketplace_services.logging")
        dummy_storage_bucket = mocker.MagicMock()
        dummy_content_repo = mocker.MagicMock()
        dummy_commit = mocker.MagicMock()
        dummy_content_repo.commit.return_value = dummy_commit
        dummy_file = mocker.MagicMock()
        dummy_commit.diff.return_value = [dummy_file]
        dummy_file.a_path = os.path.join(PACKS_FOLDER, "TestPack", temp_image_name)
        fake_hash = 'fake_hash'
        dummy_storage_bucket.blob.return_value.name = os.path.join(GCPConfig.STORAGE_BASE_PATH, "TestPack",
                                                                   temp_image_name)
        task_status, integration_images = dummy_pack.upload_integration_images(dummy_storage_bucket, fake_hash,
                                                                               fake_hash, dummy_content_repo)

        assert task_status
        assert len(expected_result) == len(integration_images)
        assert integration_images == expected_result

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
        images_data = {"TestPack": {BucketUploadFlow.INTEGRATION: [os.path.basename(blob_name)]}}
        task_status = dummy_pack.copy_integration_images(dummy_prod_bucket, dummy_build_bucket, images_data)
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
        task_status = dummy_pack.copy_author_image(dummy_prod_bucket, dummy_build_bucket, images_data)
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
        dummy_build_bucket.list_blobs.return_value = []
        task_status, skipped_pack = dummy_pack.copy_and_upload_to_storage(dummy_prod_bucket, dummy_build_bucket,
                                                                          '2.0.0', {})
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
        blob_name = "content/packs/TestPack/2.0.0/TestPack.zip"
        dummy_build_bucket.list_blobs.return_value = [Blob(blob_name, dummy_build_bucket)]
        dummy_prod_bucket.list_blobs.return_value = [Blob(blob_name, dummy_prod_bucket)]
        task_status, skipped_pack = dummy_pack.copy_and_upload_to_storage(dummy_prod_bucket, dummy_build_bucket,
                                                                          '2.0.0', {})
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
        dummy_build_bucket.list_blobs.return_value = [Blob(blob_name, dummy_build_bucket)]
        dummy_build_bucket.copy_blob.return_value = Blob(blob_name, dummy_prod_bucket)
        task_status, skipped_pack = dummy_pack.copy_and_upload_to_storage(dummy_prod_bucket, dummy_build_bucket,
                                                                          '2.0.0', {"TestPack": {"status": "status1",
                                                                                                 "aggregated": True}})
        assert task_status
        assert not skipped_pack


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
        logging_mock = mocker.patch("Tests.Marketplace.marketplace_services.logging.error")
        task_status, user_metadata = dummy_pack.load_user_metadata()

        assert logging_mock.call_count == 1
        assert not task_status
        assert user_metadata == {}


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

        p.set_pack_dependencies(metadata, generated_dependencies)

        assert metadata['dependencies'] == dependencies

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

        p.set_pack_dependencies(metadata, generated_dependencies)

        assert metadata['dependencies'] == generated_dependencies['ImpossibleTraveler']['dependencies']

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
        p.set_pack_dependencies(metadata, {})

        assert metadata['dependencies'] == dependencies

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
                        'name': 'ServiceNow',
                        'certification': 'certified'
                    }
                }
            }
        }

        metadata['dependencies'] = {}
        metadata['name'] = 'HelloWorld'
        metadata['id'] = 'HelloWorld'
        p = Pack('HelloWorld', 'dummy_path')
        dependencies = json.dumps(generated_dependencies['HelloWorld']['dependencies'])
        dependencies = json.loads(dependencies)

        p.set_pack_dependencies(metadata, generated_dependencies)

        assert metadata['dependencies'] == dependencies

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

        with pytest.raises(Exception) as e:
            p.set_pack_dependencies(metadata, generated_dependencies)

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

        p.set_pack_dependencies(metadata, generated_dependencies)

        assert metadata['dependencies'] == dependencies


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
        changelog, changelog_latest_rn_version = dummy_pack.get_changelog_latest_rn('fake_path')
        assert changelog == original_changelog_dict
        assert changelog_latest_rn_version == LooseVersion('2.0.0')

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
        rn_lines, latest_rn = dummy_pack.get_release_notes_lines('rn_dir_fake_path', LooseVersion('1.0.0'))
        assert latest_rn == '2.0.0'
        assert rn_lines == aggregated_rn

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
        rn_lines, latest_rn = dummy_pack.get_release_notes_lines('rn_dir_fake_path', LooseVersion('1.0.1'))
        assert latest_rn == '1.0.1'
        assert rn_lines == rn

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
        f'{BucketUploadFlow.STATUS}': PackStatus.FAILED_UPLOADING_PACK.name,
        f'{BucketUploadFlow.AGGREGATED}': 'False'
    }
    SUCCESSFUL_PACK_DICT = {
        f'{BucketUploadFlow.STATUS}': PackStatus.SUCCESS.name,
        f'{BucketUploadFlow.AGGREGATED}': '[1.0.0, 1.0.1] => 1.0.1'
    }

    @staticmethod
    def get_successful_packs():
        successful_packs = [Pack(pack_name='A', pack_path='.'), Pack(pack_name='B', pack_path='.')]
        for pack in successful_packs:
            pack._status = PackStatus.SUCCESS.name
            pack._aggregated = True
            pack._aggregation_str = '[1.0.0, 1.0.1] => 1.0.1'
        return successful_packs

    @staticmethod
    def get_failed_packs():
        failed_packs = [Pack(pack_name='C', pack_path='.'), Pack(pack_name='D', pack_path='.')]
        for pack in failed_packs:
            pack._status = PackStatus.FAILED_UPLOADING_PACK.name
            pack._aggregated = False
        return failed_packs

    def test_store_successful_and_failed_packs_in_ci_artifacts_both(self, tmp_path):
        """
           Given:
               - Successful packs list - A,B
               - Failed packs list - C,D
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $CIRCLE_ARTIFACTS/packs_results.json file
           Then:
               - Verify that the file content contains the successful and failed packs A, B & C, D respectively.
       """
        successful_packs = self.get_successful_packs()
        failed_packs = self.get_failed_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, successful_packs, failed_packs
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.FAILED_PACKS}': {
                    'C': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT,
                    'D': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT
                },
                f'{BucketUploadFlow.SUCCESSFUL_PACKS}': {
                    'A': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT,
                    'B': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT
                }
            }
        }

    def test_store_successful_and_failed_packs_in_ci_artifacts_successful_only(self, tmp_path):
        """
           Given:
               - Successful packs list - A,B
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $CIRCLE_ARTIFACTS/packs_results.json file
           Then:
               - Verify that the file content contains the successful packs A & B.
       """
        successful_packs = self.get_successful_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, successful_packs, list()
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.SUCCESSFUL_PACKS}': {
                    'A': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT,
                    'B': TestStoreInCircleCIArtifacts.SUCCESSFUL_PACK_DICT
                }
            }
        }

    def test_store_successful_and_failed_packs_in_ci_artifacts_failed_only(self, tmp_path):
        """
           Given:
               - Failed packs list - C,D
               - A path to the circle ci artifacts dir
           When:
               - Storing the packs results in the $CIRCLE_ARTIFACTS/packs_results.json file
           Then:
               - Verify that the file content contains the failed packs C & D.
       """
        failed_packs = self.get_failed_packs()
        packs_results_file_path = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)
        store_successful_and_failed_packs_in_ci_artifacts(
            packs_results_file_path, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING, list(), failed_packs
        )
        packs_results_file = load_json(packs_results_file_path)
        assert packs_results_file == {
            f'{BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING}': {
                f'{BucketUploadFlow.FAILED_PACKS}': {
                    'C': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT,
                    'D': TestStoreInCircleCIArtifacts.FAILED_PACK_DICT
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
        from Tests.Marketplace.marketplace_services import get_successful_and_failed_packs
        file = os.path.join(tmp_path, BucketUploadFlow.PACKS_RESULTS_FILE)

        # Case 1: assert file does not exist
        successful, failed, images = get_successful_and_failed_packs(file, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING)
        assert successful == {}
        assert failed == {}
        assert images == {}

        # Case 2: assert empty file
        with open(file, "w") as f:
            f.write('')
        successful, failed, imges = get_successful_and_failed_packs(file, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING)
        assert successful == {}
        assert failed == {}
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
                    f"{BucketUploadFlow.IMAGES}": {
                        "TestPack1": {
                            f"{BucketUploadFlow.AUTHOR}": True,
                            f"{BucketUploadFlow.INTEGRATION}": ["integration_image.png"]
                        }
                    }
                }
            }))
        successful, failed, images = get_successful_and_failed_packs(file, BucketUploadFlow.PREPARE_CONTENT_FOR_TESTING)
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
        assert BucketUploadFlow.INTEGRATION in test_pack_images
        integration_images = test_pack_images.get(BucketUploadFlow.INTEGRATION, [])
        assert len(integration_images) == 1
        assert integration_images[0] == "integration_image.png"


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
