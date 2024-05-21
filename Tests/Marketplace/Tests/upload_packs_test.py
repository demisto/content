# type: ignore[attr-defined]
# pylint: disable=no-member
import json
import os

import pytest
from unittest.mock import patch
from Tests.Marketplace.upload_packs import (get_packs_ids_to_upload, get_packs_ids_to_upload_and_update)

from Tests.Marketplace.marketplace_services import Pack
from Tests.Marketplace.marketplace_constants import Metadata

# disable-secrets-detection-start


class TestModifiedPacks:
    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ("pack1,pack2,pack1", {"pack1", "pack2"}),
        ("pack1, pack2,  pack3", {"pack1", "pack2", "pack3"})
    ])
    def test_get_packs_names_specific(self, packs_names_input, expected_result):
        modified_packs = get_packs_ids_to_upload(packs_names_input)

        assert modified_packs == expected_result

    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ('{"packs_to_upload": ["pack1", "pack2"], "packs_to_update_metadata": ["pack3"]}',
         ({'pack1', 'pack2'}, {'pack3'})),
        ('{"packs_to_upload": ["pack1", "pack2", "pack2"], "packs_to_update_metadata": ["pack3"]}',
         ({'pack1', 'pack2'}, {'pack3'}))
    ])
    def test_get_packs_ids_to_upload_and_update(self, packs_names_input, expected_result):
        modified_packs = get_packs_ids_to_upload_and_update(packs_names_input)

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


class TestUpdateIndexAndPack:

    statistics_metadata = {
        Metadata.DOWNLOADS: 0,
        Metadata.SEARCH_RANK: None,
        Metadata.TAGS: [],
        Metadata.INTEGRATIONS: None,
    }

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
        """
        from Tests.Marketplace import upload_packs
        import shutil

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

        dummy_pack = Pack('HelloWorld', 'HelloWorld', is_modified=True)
        dummy_pack.current_version = '2.0.1'
        upload_packs.update_index_folder('Index', dummy_pack,
                                         pack_versions_to_keep=['1.0.1', '1.0.0', '2.0.0'])

        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-2.0.1.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

        assert copy_call_count == 4
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

        mocker.patch('shutil.copy')
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])

        mocker.patch('os.scandir', return_value=pack_dirs)

        dummy_pack = Pack('HelloWorld', 'HelloWorld', is_modified=True)
        dummy_pack.current_version = '1.0.0'
        upload_packs.update_index_folder('Index', dummy_pack, pack_versions_to_keep=[])

        expected_copy_args = [('HelloWorld/metadata.json', 'Index/HelloWorld'),
                              ('HelloWorld/metadata.json', 'Index/HelloWorld/metadata-1.0.0.json'),
                              ('HelloWorld/changelog.json', 'Index/HelloWorld'),
                              ('HelloWorld/README.md', 'Index/HelloWorld')]

        copy_call_count = shutil.copy.call_count
        copy_call_args = shutil.copy.call_args_list

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
        - Ensure current metadata files are updated
        """
        from Tests.Marketplace import upload_packs

        logging_mock = mocker.patch("Tests.Marketplace.marketplace_services.logging.debug")
        json_write_mock = mocker.patch.object(upload_packs, 'json_write', return_value=None)
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

        dummy_pack = Pack('HelloWorld', 'HelloWorld', is_modified=False, is_metadata_updated=False)
        dummy_pack.current_version = '2.0.0'
        upload_packs.update_index_folder('Index', dummy_pack)

        expected_copy_args = [('Index/HelloWorld/metadata.json', self.statistics_metadata),
                              ('Index/HelloWorld/metadata-2.0.0.json', self.statistics_metadata)]

        copy_call_count = json_write_mock.call_count
        copy_call_args = json_write_mock.call_args_list

        assert copy_call_count == 2
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

        assert any(
            call_args == ((
                "Updating metadata only with statistics because self._pack_name='HelloWorld' "
                "self.is_modified=False self.is_metadata_updated=False"),)
            for call_args, _ in logging_mock.call_args_list
        )

    def test_update_index_folder_one_version(self, mocker):
        """
        Scenario: Update the bucket index when a pack is not updated (same version) but metadata_updated.

        Given
        - Pack exists in the index folder
        - Pack is not updated
        - Pack has one version
        - Pack's metadata field was changed

        When
        - Updating the bucket index

        Then
        - Ensure no new metadata file is created for the new version
        - Ensure current metadata files are updated
        """
        from Tests.Marketplace import upload_packs

        logging_mock = mocker.patch("Tests.Marketplace.marketplace_services.logging.debug")
        json_write_mock = mocker.patch.object(upload_packs, 'json_write', return_value=None)
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata-1.0.0.json', 'metadata-1.0.0.json'),
                               ('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])
        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        dummy_pack = Pack('HelloWorld', 'HelloWorld', is_modified=False, is_metadata_updated=True)
        dummy_pack.current_version = '1.0.0'
        upload_packs.update_index_folder('Index', dummy_pack)

        expected_copy_args = [('Index/HelloWorld/metadata.json', self.statistics_metadata),
                              ('Index/HelloWorld/metadata-1.0.0.json', self.statistics_metadata)]

        copy_call_count = json_write_mock.call_count
        copy_call_args = json_write_mock.call_args_list

        assert copy_call_count == 2
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

        assert any(
            call_args == ((
                "Updating metadata with statistics and metadata changes because self._pack_name='HelloWorld' "
                "self.is_modified=False self.is_metadata_updated=True"),)
            for call_args, _ in logging_mock.call_args_list
        )

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
        - Ensure current metadata files are updated
        """
        from Tests.Marketplace import upload_packs

        json_write_mock = mocker.patch.object(upload_packs, 'json_write', return_value=None)
        mocker.patch('os.path.exists')
        pack_dirs = scan_dir([('HelloWorld/metadata.json', 'metadata.json'),
                              ('HelloWorld/changelog.json', 'changelog.json'),
                              ('HelloWorld/README.md', 'README.md')])
        index_dirs = scan_dir([('Index/HelloWorld/metadata.json', 'metadata.json'),
                               ('Index/HelloWorld/changelog.json', 'changelog.json'),
                               ('Index/HelloWorld/README.md', 'README.md')])
        mocker.patch('os.scandir', side_effect=[index_dirs, pack_dirs])

        dummy_pack = Pack('HelloWorld', 'HelloWorld', is_modified=False)
        dummy_pack.current_version = '1.0.0'
        upload_packs.update_index_folder('Index', dummy_pack)

        expected_copy_args = [('Index/HelloWorld/metadata.json', self.statistics_metadata),
                              ('Index/HelloWorld/metadata-1.0.0.json', self.statistics_metadata)]

        copy_call_count = json_write_mock.call_count
        copy_call_args = json_write_mock.call_args_list

        assert copy_call_count == 2
        for call_arg in copy_call_args:
            assert call_arg[0] in expected_copy_args

    def test_download_and_extract_pack(self, mocker):
        """
            Given:
                - A pack version exists in the storage bucket.
            When:
                - Downloading and extracting the pack.
            Then:
                - Ensure the pack is downloaded and extracted successfully.
        """
        from zipfile import ZipFile
        from Tests.Marketplace.marketplace_constants import GCPConfig
        from Tests.Marketplace.upload_packs import download_and_extract_pack

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET

        pack_version = "2.0.0"
        storage_base_path = GCPConfig.CONTENT_PACKS_PATH
        extract_destination_path = "/path/to/save"
        pack_name = 'HelloWorld'
        dummy_storage_bucket = mocker.MagicMock()

        pack_path = os.path.join(storage_base_path, pack_name, pack_version, f"{pack_name}.zip")
        mocker.patch.object(ZipFile, '__init__', return_value=None)
        mocker.patch.object(ZipFile, 'extractall')

        task_status = download_and_extract_pack(pack_name, pack_version, dummy_storage_bucket, extract_destination_path,
                                                storage_base_path=GCPConfig.PRODUCTION_STORAGE_BASE_PATH)
        assert task_status
        dummy_storage_bucket.blob.assert_called_once_with(pack_path)
        dummy_storage_bucket.blob.return_value.exists.assert_called_once()
        dummy_storage_bucket.blob.return_value.download_to_filename.assert_called_once_with(
            os.path.join(extract_destination_path, f"{pack_name}.zip"))
        ZipFile.extractall.assert_called_once_with(os.path.join(extract_destination_path, pack_name))


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

        skipped_cleanup = clean_non_existing_packs(index_folder_path="dummy_index_path",
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

        skipped_cleanup = clean_non_existing_packs(index_folder_path="dummy_index_path",
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
        invalid_pack = "invalid_pack"

        dirs = scan_dir([
            (os.path.join(index_folder_path, public_pack), public_pack, True),
            (os.path.join(index_folder_path, invalid_pack), invalid_pack, True)
        ])

        mocker.patch("Tests.Marketplace.upload_packs.os.listdir", return_value=[public_pack])
        mocker.patch("Tests.Marketplace.upload_packs.os.scandir", return_value=dirs)
        mocker.patch('Tests.Marketplace.upload_packs.shutil.rmtree')
        mocker.patch("Tests.Marketplace.upload_packs.logging.warning")

        skipped_cleanup = clean_non_existing_packs(
            index_folder_path=index_folder_path,
            storage_bucket=dummy_storage_bucket,
            storage_base_path=GCPConfig.PRODUCTION_STORAGE_BASE_PATH,
            content_packs=[Pack("public_pack", "/dummy_path"), Pack("private_pack",
                                                                    "/dummy_path")]
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
        with open(os.path.join(artifacts_dir, GCPConfig.CORE_PACK_FILE_NAME)) as corepacks_file:
            corepacks_file_contents = json.load(corepacks_file)
            pack_paths = corepacks_file_contents.get('corePacks')
            assert set(pack_paths) == {'https://storage.googleapis.com/marketplace-ci-build/content/packs'
                                       '/pack_1/1.4.0/pack_1.zip',
                                       'https://storage.googleapis.com/marketplace-ci-build/content/packs'
                                       '/pack_2/2.2.3/pack_2.zip'}

        # Assert that the paths in the versioned corepacks file are relative paths:
        with open(os.path.join(artifacts_dir, corepacks_version)) as corepacks_file:
            corepacks_file_contents = json.load(corepacks_file)
            pack_paths = corepacks_file_contents.get('corePacks')
            assert set(pack_paths) == {'pack_1/1.4.0/pack_1.zip', 'pack_2/2.2.3/pack_2.zip'}

        # Remove the temp artifacts dir that was created for testing:
        shutil.rmtree(artifacts_dir)


class TestUpdatedPrivatePacks:

    @staticmethod
    def get_pack_metadata():
        metadata_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data', 'metadata.json')
        with open(metadata_path) as metadata_file:
            pack_metadata = json.load(metadata_file)

        return pack_metadata

    @staticmethod
    def get_index_folder_path():
        index_json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')
        return index_json_path
