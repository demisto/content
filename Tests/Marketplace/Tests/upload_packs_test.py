import pytest
from unittest.mock import patch
from Tests.Marketplace.upload_packs import get_modified_packs


# disable-secrets-detection-start
class TestModifiedPacks:
    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ("pack1,pack2,pack1", {"pack1", "pack2"}),
        ("pack1, pack2,  pack3", {"pack1", "pack2", "pack3"})
    ])
    def test_get_modified_packs_specific(self, packs_names_input, expected_result):
        modified_packs = get_modified_packs(packs_names_input)

        assert modified_packs == expected_result

    @pytest.mark.parametrize("packs_names_input", [None, ""])
    def test_get_modified_packs_empty(self, mocker, packs_names_input):
        modified_packs_return_value = ("Packs/Pack1/pack_metadata.json\n"
                                       "Packs/Pack1/Integrations/Integration1/CHANGELOG.md\n"
                                       "Packs/Pack2/pack_metadata.json\n")
        mocker.patch('Tests.Marketplace.upload_packs.run_command', return_value=modified_packs_return_value)
        modified_packs = get_modified_packs(target_packs="modified")

        assert modified_packs == {"Pack1", "Pack2"}


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
        return True if path == 'mock_path' else False


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

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '2.0.1')

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

        upload_packs.update_index_folder('Index', 'HelloWorld', 'HelloWorld', '1.0.0')

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


class TestPrivatePacks:
    def test_add_private_packs_to_index(self, mocker):
        from Tests.Marketplace import upload_packs

        dirs = scan_dir()
        mocker.patch('os.scandir', return_value=dirs)
        mocker.patch('os.path.isdir', side_effect=FakeDirEntry.isdir)
        mocker.patch.object(upload_packs, 'update_index_folder')

        upload_packs.add_private_packs_to_index('test', 'private_test')

        index_call_args = upload_packs.update_index_folder.call_args[0]
        index_call_count = upload_packs.update_index_folder.call_count

        assert index_call_count == 1
        assert index_call_args[0] == 'test'
        assert index_call_args[1] == 'mock_dir'
        assert index_call_args[2] == 'mock_path'

    def test_get_private_packs(self, mocker):
        import os
        from Tests.Marketplace import upload_packs, marketplace_services

        mocker.patch('glob.glob', return_value=[os.path.join(marketplace_services.CONTENT_ROOT_PATH,
                                                             'Tests', 'Marketplace', 'Tests',
                                                             'test_data', 'metadata.json')])

        private_packs = upload_packs.get_private_packs('path')

        assert private_packs == [{'id': 'ImpossibleTraveler', 'price': 100}]

    def test_get_private_packs_empty(self, mocker):
        from Tests.Marketplace import upload_packs

        mocker.patch('glob.glob', return_value=[])
        mocker.patch("Tests.Marketplace.upload_packs.print_warning")

        private_packs = upload_packs.get_private_packs('path')

        assert private_packs == []

    def test_get_private_packs_error(self, mocker):
        from Tests.Marketplace import upload_packs

        mocker.patch('glob.glob', side_effect=InterruptedError)
        mocker.patch("Tests.Marketplace.upload_packs.print_warning")

        private_packs = upload_packs.get_private_packs('path')

        assert private_packs == []


class TestCleanPacks:
    """ Test for clean_non_existing_packs function scenarios.
    """

    @patch.dict('os.environ', {'CI': 'true', 'CIRCLE_BRANCH': 'dummy_branch'})
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
        from Tests.Marketplace.marketplace_services import GCPConfig

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET

        skipped_cleanup = clean_non_existing_packs(index_folder_path="dummy_index_path", private_packs=[],
                                                   storage_bucket=dummy_storage_bucket)

        assert skipped_cleanup

    @patch.dict('os.environ', {'CI': 'true', 'CIRCLE_BRANCH': 'master'})
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

        dummy_storage_bucket = mocker.MagicMock()
        dummy_storage_bucket.name = "dummy_bucket"

        skipped_cleanup = clean_non_existing_packs(index_folder_path="dummy_index_path", private_packs=[],
                                                   storage_bucket=dummy_storage_bucket)

        assert skipped_cleanup

    @patch.dict('os.environ', {'CI': 'true', 'CIRCLE_BRANCH': 'master'})
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
        from Tests.Marketplace.marketplace_services import GCPConfig
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
        mocker.patch("Tests.Marketplace.upload_packs.print_warning")

        private_packs = [{'id': private_pack, 'price': 120}]

        skipped_cleanup = clean_non_existing_packs(index_folder_path=index_folder_path, private_packs=private_packs,
                                                   storage_bucket=dummy_storage_bucket)

        assert not skipped_cleanup
        shutil.rmtree.assert_called_once_with(os.path.join(index_folder_path, invalid_pack))
