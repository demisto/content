# type: ignore[attr-defined]
# pylint: disable=no-member
import copy
import json
import os

import pytest
from unittest.mock import patch
from Tests.Marketplace.upload_packs import get_packs_names, get_updated_private_packs, is_private_packs_updated

from Tests.Marketplace.marketplace_services import Pack


# disable-secrets-detection-start


class TestModifiedPacks:
    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ("pack1,pack2,pack1", {"pack1", "pack2"}),
        ("pack1, pack2,  pack3", {"pack1", "pack2", "pack3"})
    ])
    def test_get_packs_names_specific(self, packs_names_input, expected_result):
        modified_packs = get_packs_names(packs_names_input)

        assert modified_packs == expected_result


# disable-secrets-detection-end


class FakeDirEntry:
    def __init__(self, path, name, is_directory=True):
        self.name = name
        self.path = path
        self.is_directory = is_directory

    def is_dir(self):
        return self.is_directory

    @staticmethod
    def isdir(path):
        return path == 'mock_path'


def scan_dir(dirs=None):
    if dirs:
        return [FakeDirEntry(dir_[0], dir_[1]) for dir_ in dirs]

    return [FakeDirEntry('mock_path', 'mock_dir'), FakeDirEntry('mock_path2', 'mock_file')]


class TestUpdateIndex:
    def test_update_index_folder_new_version(self, mocker):
        """
        Scenario: Update the bucket index when a pack is updated (new version)

        Given
        - Pack exists in the index folder
        - Pack has a new version

        When
        - Updating the bucket index

        Then
        - Ensure new metadata files are created for the new version
        - Ensure previous metadata files are not deleted
        - Ensure other files in the index are removed and replaced
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=['Index/HelloWorld/metadata-1.0.1.json',
                                                'Index/HelloWorld/metadata-1.0.0.json',
                                                'Index/HelloWorld/metadata-2.0.0.json'])
        mocker.patch('os.listdir', return_value=['HelloWorld'])
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata-1.0.1.json', 'metadata-1.0.1.json'),
                               ('Index/HelloWorld/metadata-1.0.0.json', 'metadata-1.0.0.json'),
                               ('Index/HelloWorld/metadata-2.0.0.json', 'metadata-2.0.0.json'),
                               ('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])

        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '2.0.1',
                                         pack_versions_to_keep=['1.0.1', '1.0.0', '2.0.0'])

        expected_remove_args = ['Index/HelloWorld/metadata.json',
                                'Index/HelloWorld/changelog.json', 'Index/HelloWorld/README.md']
        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-2.0.1.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        remove_call_args = os.remove.call_args_list
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 3
        assert copy_call_count == 4
        for call_arg in remove_call_args:
            assert call_arg[0][0] in expected_remove_args
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

    def test_update_index_folder_new_pack(self, mocker):
        """
        Scenario: Update the bucket index when a new pack is created

        Given
        - Pack does not in the index folder

        When
        - Updating the bucket index

        Then
        - Ensure new metadata files are created for the new pack
        - Ensure other files in the index are copied
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=[])
        mocker.patch('os.listdir', return_value=[])
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])

        mocker.patch('os.scandir', return_value=pack_dirs)

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '1.0.0', pack_versions_to_keep=[])

        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-1.0.0.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 0
        assert copy_call_count == 4
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

    def test_update_index_folder_multiple_versions(self, mocker):
        """
        Scenario: Update the bucket index when a pack is not updated (same version)
                  and has multiple versions

        Given
        - Pack exists in the index folder
        - Pack has multiple versions
        - Pack is not updated

        When
        - Updating the bucket index

        Then
        - Ensure no new metadata files are created for the new version
        - Ensure current metadata files are replaced
        - Ensure previous metadata files are not deleted
        - Ensure other files in the index are removed and replaced
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=['Index/HelloWorld/metadata-1.0.1.json',
                                                'Index/HelloWorld/metadata-1.0.0.json',
                                                'Index/HelloWorld/metadata-2.0.0.json'])
        mocker.patch('os.listdir', return_value=['HelloWorld'])
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata-1.0.1.json', 'metadata-1.0.1.json'),
                               ('Index/HelloWorld/metadata-1.0.0.json', 'metadata-1.0.0.json'),
                               ('Index/HelloWorld/metadata-2.0.0.json', 'metadata-2.0.0.json'),
                               ('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])

        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '2.0.0')

        expected_remove_args = ['Index/HelloWorld/metadata-2.0.0.json', 'Index/HelloWorld/metadata.json',
                                'Index/HelloWorld/changelog.json', 'Index/HelloWorld/README.md']
        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-2.0.0.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        remove_call_args = os.remove.call_args_list
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 4
        assert copy_call_count == 4
        for call_arg in remove_call_args:
            assert call_arg[0][0] in expected_remove_args
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

    def test_update_index_folder_one_version(self, mocker):
        """
        Scenario: Update the bucket index when a pack is not updated (same version)

        Given
        - Pack exists in the index folder
        - Pack is not updated
        - Pack has one version

        When
        - Updating the bucket index

        Then
        - Ensure no new metadata files are created for the new version
        - Ensure current metadata files are replaced
        - Ensure other files in the index are removed and replaced
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=['Index/HelloWorld/metadata-1.0.0.json'])
        mocker.patch('os.listdir', return_value=['HelloWorld'])
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata-1.0.0.json', 'metadata-1.0.0.json'),
                               ('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])
        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '1.0.0')

        expected_remove_args = ['Index/HelloWorld/metadata-1.0.0.json', 'Index/HelloWorld/metadata.json',
                                'Index/HelloWorld/changelog.json', 'Index/HelloWorld/README.md']
        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-1.0.0.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        remove_call_args = os.remove.call_args_list
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 4
        assert copy_call_count == 4
        for call_arg in remove_call_args:
            assert call_arg[0][0] in expected_remove_args
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

    def test_update_index_folder_not_versioned(self, mocker):
        """
        Scenario: Update the bucket index when a pack is not versioned

        Given
        - Pack exists in the index folder
        - The pack is not versioned (no metadata-<version>.json in the index)

        When
        - Updating the bucket index

        Then
        - Ensure a metadata file is created with the version name
        - Ensure current metadata files are replaced
        - Ensure previous metadata files are not deleted
        - Ensure other files in the index are removed and replaced
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=[])
        mocker.patch('os.listdir', return_value=['HelloWorld'])
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])
        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '1.0.0')

        expected_remove_args = ['Index/HelloWorld/metadata.json', 'Index/HelloWorld/changelog.json',
                                'Index/HelloWorld/README.md']
        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-1.0.0.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        remove_call_args = os.remove.call_args_list
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 3
        assert copy_call_count == 4
        for call_arg in remove_call_args:
            assert call_arg[0][0] in expected_remove_args
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

    def test_update_index_folder_no_version(self, mocker):
        """
        Scenario: Update the bucket index when a pack has no version

        Given
        - Pack exists in the index folder
        - The pack is has no version (e.g. private pack which we do not have details for)

        When
        - Updating the bucket index

        Then
        - Ensure no new metadata files are created
        - Ensure previous metadata files are not deleted
        - Ensure other files in the index are removed and replaced
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=['Index/HelloWorld/metadata-1.0.1.json',
                                                'Index/HelloWorld/metadata-1.0.0.json',
                                                'Index/HelloWorld/metadata-2.0.0.json'])
        mocker.patch('os.listdir', return_value=['HelloWorld'])
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])
        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld')

        expected_remove_args = ['Index/HelloWorld/metadata.json', 'Index/HelloWorld/changelog.json',
                                'Index/HelloWorld/README.md']
        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        remove_call_args = os.remove.call_args_list
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 3
        assert copy_call_count == 3
        for call_arg in remove_call_args:
            assert call_arg[0][0] in expected_remove_args
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args


class TestCleanPacks:
    """ Test for clean_non_existing_packs function scenarios.
    """

    @patch.dict('os.environ', {'CI': 'true', 'CI_COMMIT_BRANCH': 'dummy_branch'})
    def test_clean_non_existing_packs_skip_non_master(self, mocker):
        """
        Scenario: running clean_non_existing_packs function on CI environment but not on master branch

        Given
        - production bucket input
        - dummy_branch branch env variable
        - CI env variable (ensures that script is executed in circle CI)

        When
        - running clean_non_existing_packs in circle CI env but not in master branch

        Then
        - Ensure that task is skipped and blob form master bucket are not deleted
        """
        from Tests.Marketplace.upload_packs import clean_non_existing_packs
        from Tests.Marketplace.marketplace_constants import GCPConfig

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET

        skipped_cleanup = clean_non_existing_packs(index_folder_path="dummy_index_path", private_packs=[],
                                                   storage_bucket=dummy_storage_bucket,
                                                   storage_base_path=GCPConfig.PRODUCTION_STORAGE_BASE_PATH,
                                                   content_packs=[])

        assert skipped_cleanup

    @patch.dict('os.environ', {'CI': 'true', 'CI_COMMIT_BRANCH': 'master'})
    def test_clean_non_existing_packs_skip_non_production_bucket(self, mocker):
        """
        Scenario: running clean_non_existing_packs function on CI environment on master branch but not on production
        bucket

        Given
        - non production bucket input
        - master branch env variable
        - CI env variable (ensures that script is executed in circle CI)

        When
        - running clean_non_existing_packs in circle CI master branch with non production bucket

        Then
        - Ensure that task is skipped and blob form master bucket are not deleted
        """
        from Tests.Marketplace.upload_packs import clean_non_existing_packs
        from Tests.Marketplace.marketplace_constants import GCPConfig

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = "dummy_bucket"

        skipped_cleanup = clean_non_existing_packs(index_folder_path="dummy_index_path", private_packs=[],
                                                   storage_bucket=dummy_storage_bucket,
                                                   storage_base_path=GCPConfig.PRODUCTION_STORAGE_BASE_PATH,
                                                   content_packs=[])

        assert skipped_cleanup

    @patch.dict('os.environ', {'CI': 'true', 'CI_COMMIT_BRANCH': 'master'})
    def test_clean_non_existing_packs(self, mocker):
        """
         Scenario: deleting pack that is not part of content repo or paid packs from index

         Given
         - valid pack from content repo
         - valid pack from private bucket
         - not valid pack that may be located in bucket and in the index

         When
         - pack was deleted from content repo

         Then
         - Ensure that not valid pack is deleted from index
         """
        from Tests.Marketplace.upload_packs import clean_non_existing_packs
        from Tests.Marketplace.marketplace_constants import GCPConfig
        import os
        import shutil

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET

        index_folder_path = "dummy_index_path"
        public_pack = "public_pack"
        private_pack = "private_pack"
        invalid_pack = "invalid_pack"

        dirs = scan_dir([
            (os.path.join(index_folder_path, public_pack), public_pack, True),
            (os.path.join(index_folder_path, private_pack), private_pack, True),
            (os.path.join(index_folder_path, invalid_pack), invalid_pack, True)
        ])

        mocker.patch("Tests.Marketplace.upload_packs.os.listdir", return_value=[public_pack])
        mocker.patch("Tests.Marketplace.upload_packs.os.scandir", return_value=dirs)
        mocker.patch('Tests.Marketplace.upload_packs.shutil.rmtree')
        mocker.patch("Tests.Marketplace.upload_packs.logging.warning")

        private_packs = [{'id': private_pack, 'price': 120}]

        skipped_cleanup = clean_non_existing_packs(
            index_folder_path=index_folder_path,
            private_packs=private_packs,
            storage_bucket=dummy_storage_bucket,
            storage_base_path=GCPConfig.PRODUCTION_STORAGE_BASE_PATH,
            content_packs=[Pack("public_pack", "/dummy_path"), Pack("private_pack", "/dummy_path")]
        )

        assert not skipped_cleanup
        shutil.rmtree.assert_called_with(os.path.join(index_folder_path, invalid_pack))


class TestCorepacksFiles:
    def test_corepacks_files_upload(self, mocker):
        """
        Test the upload flow of the corepacks files in the build bucket.
        """
        from Tests.Marketplace.upload_packs import create_corepacks_config
        from Tests.Marketplace.marketplace_constants import GCPConfig
        import os
        import shutil

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = GCPConfig.CI_BUILD_BUCKET
        index_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')

        build_number = '123456'
        corepacks_version = 'corepacks-8.3.0.json'
        pack1 = 'pack_1'
        pack2 = 'pack_2'

        # Create a temp artifacts dir for the corepacks files:
        artifacts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')
        os.makedirs(artifacts_dir, exist_ok=True)

        corepacks_list = [pack1, pack2]
        mocker.patch("Tests.Marketplace.marketplace_constants.GCPConfig.get_core_packs", return_value=corepacks_list)
        mocker.patch("Tests.Marketplace.marketplace_constants.GCPConfig.get_core_packs_to_upgrade",
                     return_value=[pack1])
        mocker.patch("Tests.Marketplace.marketplace_constants.GCPConfig.get_core_packs_unlocked_files",
                     return_value=[corepacks_version])

        create_corepacks_config(storage_bucket=dummy_storage_bucket, build_number=build_number,
                                index_folder_path=index_folder_path, artifacts_dir=artifacts_dir,
                                storage_base_path=GCPConfig.PRODUCTION_STORAGE_BASE_PATH)

        # Assert that the required files were created:
        assert set(os.listdir(artifacts_dir)) == {corepacks_version, GCPConfig.CORE_PACK_FILE_NAME}

        # Assert that the paths in the corepacks.json file are the full paths:
        with open(os.path.join(artifacts_dir, GCPConfig.CORE_PACK_FILE_NAME), 'r') as corepacks_file:
            corepacks_file_contents = json.load(corepacks_file)
            pack_paths = corepacks_file_contents.get('corePacks')
            assert set(pack_paths) == {'https://storage.googleapis.com/marketplace-ci-build/content/packs/pack_1/1.4.0'
                                       '/pack_1.zip',
                                       'https://storage.googleapis.com/marketplace-ci-build/content/packs/pack_2/2.2.3'
                                       '/pack_2.zip'}

        # Assert that the paths in the versioned corepacks file are relative paths:
        with open(os.path.join(artifacts_dir, corepacks_version), 'r') as corepacks_file:
            corepacks_file_contents = json.load(corepacks_file)
            pack_paths = corepacks_file_contents.get('corePacks')
            assert set(pack_paths) == {'pack_1/1.4.0/pack_1.zip', 'pack_2/2.2.3/pack_2.zip'}

        # Remove the temp artifacts dir that was created for testing:
        shutil.rmtree(artifacts_dir)

    def test_should_override_locked_corepacks_file(self, mocker):
        """
        When:
            - running the should_override_locked_corepacks_file command
        Given:
            1. A server version in the corepacks_override file that does not exist in the versions-metadata file
            2. A valid server version in the corepacks_override file, but a file version that is not greater than the
                file version in the versions-metadata file.
            3. The marketplace to override the corepacks file to, doesn't match the current marketplace.
            4. A valid server version and a file version greater than the file version in the versions-metadata file.
        Then:
            1. Assert that the result returned from the function is False
            2. Assert that the result returned from the function is False
            3. Assert that the result returned from the function is False
            4. Assert that the result returned from the function is True
        """

        from Tests.Marketplace.upload_packs import should_override_locked_corepacks_file
        from Tests.Marketplace.marketplace_constants import GCPConfig

        versions_metadata = {
            "8.2.0": {
                "core_packs_file": "corepacks-8.2.0.json",
                "core_packs_file_is_locked": True,
                "file_version": "1"
            }
        }
        mocker.patch.object(GCPConfig, "core_packs_file_versions", versions_metadata)

        # Case 1
        corepacks_override = {
            "server_version": "8.3.0",
            "file_version": "1",
            "updated_corepacks_content":
                {
                    "corePacks": [],
                    "upgradeCorePacks": [],
                    "buildNumber": "123"
                }
        }
        mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
        assert not should_override_locked_corepacks_file()

        # Case 2
        corepacks_override = {
            "server_version": "8.2.0",
            "file_version": "1",
            "updated_corepacks_content":
                {
                    "corePacks": [],
                    "upgradeCorePacks": [],
                    "buildNumber": "123"
                }
        }
        mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
        assert not should_override_locked_corepacks_file()

        # Case 3
        corepacks_override = {
            "server_version": "8.2.0",
            "file_version": "1",
            "marketplaces": [
                "xsoar"
            ],
            "updated_corepacks_content":
                {
                    "corePacks": [],
                    "upgradeCorePacks": [],
                    "buildNumber": "123"
            }
        }
        mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
        assert not should_override_locked_corepacks_file(marketplace='marketplacev2')

        # Case 4
        corepacks_override = {
            "server_version": "8.2.0",
            "file_version": "2",
            "updated_corepacks_content":
                {
                    "corePacks": [],
                    "upgradeCorePacks": [],
                    "buildNumber": "123"
                }
        }
        mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)
        assert should_override_locked_corepacks_file()

    def test_override_locked_corepacks_file(self, mocker):
        """
        Test the override_locked_corepacks_file function.
        """
        from Tests.Marketplace.upload_packs import override_locked_corepacks_file
        from Tests.Marketplace.marketplace_constants import GCPConfig
        import shutil

        # Create a temp artifacts dir for the corepacks files:
        artifacts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')
        os.makedirs(artifacts_dir, exist_ok=True)

        corepacks_override = {
            "server_version": "8.2.0",
            "file_version": "2",
            "updated_corepacks_content":
                {
                    "corePacks": ['pack1', 'pack2'],
                    "upgradeCorePacks": ['pack3'],
                    "buildNumber": "123"
                }
        }
        mocker.patch.object(GCPConfig, "corepacks_override_contents", corepacks_override)

        versions_metadata_content = {
            "version_map": {
                "8.2.0": {
                    "core_packs_file": "corepacks-8.2.0.json",
                    "core_packs_file_is_locked": True,
                    "file_version": "1"
                }
            }
        }
        mocker.patch.object(GCPConfig, "versions_metadata_contents", versions_metadata_content)

        override_locked_corepacks_file(build_number='456', artifacts_dir=artifacts_dir)

        # Assert that the file was created in the artifacts folder with the build number as expected:
        with open(os.path.join(artifacts_dir, 'corepacks-8.2.0.json'), 'r') as corepacks_file:
            corepacks_file_contents = json.load(corepacks_file)
            assert corepacks_file_contents.get('buildNumber') == '456'
            assert corepacks_file_contents.get('corePacks') == ['pack1', 'pack2']

        # Assert that the versions-metadata file was updated with the required file version:
        assert GCPConfig.versions_metadata_contents.get('version_map').get('8.2.0').get('file_version') == '2'

        # Remove the temp artifacts dir that was created for testing:
        shutil.rmtree(artifacts_dir)


class TestUpdatedPrivatePacks:

    @staticmethod
    def get_pack_metadata():
        metadata_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data', 'metadata.json')
        with open(metadata_path, 'r') as metadata_file:
            pack_metadata = json.load(metadata_file)

        return pack_metadata

    @staticmethod
    def get_index_folder_path():
        index_json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')
        return index_json_path

    def test_content_commit_hash_diff(self):
        """
         Scenario: as part of upload packs flow, we want to find all private packs that were updated during current
         build run.

         Given
         - valid public index json
         - valid 3 metadata of private packs

         When
         - 2 packs were not updated during current build run
         - 1 pack was updated during current build run - has (in metadata file) an updated different contentCommitHash

         Then
         - Ensure that only the last pack was recognized as updated private pack
         """

        index_folder_path = self.get_index_folder_path()
        private_packs = []

        # index json has no contentCommitHash for this pack
        metadata_no_commit_hash = self.get_pack_metadata()
        metadata_no_commit_hash.update({"contentCommitHash": ""})
        metadata_no_commit_hash.update({"id": "first_non_updated_pack"})
        private_packs.append(metadata_no_commit_hash)

        # index json has the same contentCommitHash for this pack (nothing was updated)
        metadata_not_updated_commit_hash = self.get_pack_metadata()
        metadata_not_updated_commit_hash.update({"contentCommitHash": "111"})
        metadata_not_updated_commit_hash.update({"id": "second_non_updated_pack"})
        private_packs.append(metadata_not_updated_commit_hash)

        # index json has an old contentCommitHash for this pack (should be recognize as an updated pack)
        metadata_updated_commit_hash = self.get_pack_metadata()
        metadata_updated_commit_hash.update({"contentCommitHash": "222"})
        metadata_updated_commit_hash.update({"id": "updated_pack"})
        private_packs.append(metadata_updated_commit_hash)

        updated_private_packs = get_updated_private_packs(private_packs, index_folder_path)
        assert len(updated_private_packs) == 1
        assert updated_private_packs[0] == "updated_pack" and updated_private_packs[0] != "first_non_updated_pack" and \
            updated_private_packs[0] != "second_non_updated_pack"

    def test_is_private_packs_updated(self, mocker):
        """
         Scenario: as part of upload packs flow, we want to check if there is at least one private pack was updated
         by comparing "content commit hash" in the public index and in the private index files.

         Given
         - valid public index json
         - valid private index json

         When
         - first check - there is no private pack that changed.
         - second check - private pack was deleted
         - third check - one commit hash was changed.
         - forth check - private pack was added

         Then
         - Ensure that the function recognises successfully the updated private pack.
         """
        index_folder_path = self.get_index_folder_path()
        index_file_path = os.path.join(index_folder_path, "index.json")
        with open(index_file_path, 'r') as public_index_json_file:
            public_index_json = json.load(public_index_json_file)

        private_index_json = copy.deepcopy(public_index_json)
        mocker.patch('Tests.Marketplace.upload_packs.load_json', return_value=private_index_json)
        assert not is_private_packs_updated(public_index_json, index_file_path)

        # private pack was deleted
        del private_index_json.get("packs")[0]
        mocker.patch('Tests.Marketplace.upload_packs.load_json', return_value=private_index_json)
        assert is_private_packs_updated(public_index_json, index_file_path)

        # changed content commit hash of one private pack
        private_index_json.get("packs").append({"id": "first_non_updated_pack", "contentCommitHash": "111"})
        mocker.patch('Tests.Marketplace.upload_packs.load_json', return_value=private_index_json)
        assert is_private_packs_updated(public_index_json, index_file_path)

        # private pack was added
        private_index_json.get("packs").append({"id": "new_private_pack", "contentCommitHash": "111"})
        mocker.patch('Tests.Marketplace.upload_packs.load_json', return_value=private_index_json)
        assert is_private_packs_updated(public_index_json, index_file_path)

    def test_update_index_folder_remove_old_versions(self, mocker):
        """
        Scenario: Update the bucket index when a pack is updated (new version), and has old pack versions.

        Given
        - Pack exists in the index folder
        - Pack has a new version
        - Pack has old versions to remove

        When
        - Updating the bucket index

        Then
        - Ensure new metadata files are created for the new version
        - Ensure previous metadata files are not deleted
        - Ensure other files in the index are removed and replaced, including old versions metadata.
        """
        from Tests.Marketplace import upload_packs
        import shutil
        import os

        mocker.patch('glob.glob', return_value=['Index/HelloWorld/metadata-1.0.1.json',
                                                'Index/HelloWorld/metadata-1.0.0.json',
                                                'Index/HelloWorld/metadata-2.0.0.json'])
        mocker.patch('os.listdir', return_value=['HelloWorld'])
        mocker.patch('os.path.isdir', return_value=True)
        mocker.patch('os.remove')
        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata-1.0.1.json', 'metadata-1.0.1.json'),
                               ('Index/HelloWorld/metadata-1.0.0.json', 'metadata-1.0.0.json'),
                               ('Index/HelloWorld/metadata-2.0.0.json', 'metadata-2.0.0.json'),
                               ('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])

        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '2.0.1',
                                         pack_versions_to_keep=['2.0.1', '2.0.0'])

        expected_remove_args = ['Index/HelloWorld/metadata.json',
                                'Index/HelloWorld/changelog.json', 'Index/HelloWorld/README.md',
                                'Index/HelloWorld/metadata-1.0.1.json', 'Index/HelloWorld/metadata-1.0.0.json']
        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-2.0.1.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        remove_call_count = os.remove.call_count
        remove_call_args = os.remove.call_args_list
        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert remove_call_count == 5
        assert copy_call_count == 4
        for call_arg in remove_call_args:
            assert call_arg[0][0] in expected_remove_args
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args
