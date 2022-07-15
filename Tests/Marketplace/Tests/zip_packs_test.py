# type: ignore[attr-defined]
# pylint: disable=no-member

import pytest

from Tests.Marketplace.zip_packs import get_latest_pack_zip_from_pack_files, zip_packs,\
    remove_test_playbooks_if_exist, remove_test_playbooks_from_signatures, get_zipped_packs_names,\
    copy_zipped_packs_to_artifacts


class TestZipPacks:
    BLOB_NAMES = [
        'content/packs/Slack/1.0.0/Slack.zip',
        'content/packs/Slack/1.0.2/Slack.zip',
        'content/packs/Slack/1.0.1/Slack.zip',
        'content/packs/SlackSheker/2.0.0/SlackSheker.zip',
        'content/packs/Slack/Slack.png',
        'content/packs/SlackSheker/SlackSheker.png'
    ]

    BLOB_NAMES_NO_ZIP = [
        'content/packs/SlackSheker/2.0.0/SlackSheker.zip',
        'content/packs/Slack/Slack.png',
        'content/packs/SlackSheker/SlackSheker.png'
    ]

    def test_get_latest_pack_zip_from_blob(self):
        """
        Given:
            List of blobs

        When:
            Getting the pack to download

        Then:
            Return the correct pack zip blob
        """

        blob_name = get_latest_pack_zip_from_pack_files('Slack', TestZipPacks.BLOB_NAMES)
        assert blob_name == 'content/packs/Slack/1.0.2/Slack.zip'

    def test_get_zipped_packs_name(self, mocker):
        """
        Given:
            Some general path information of the packs and the build
        When:
            There is a valid pack which should be stored in the created dictionary
        Then:
            Create a dict which has one dictionary of the found pack
        """
        from Tests.Marketplace import zip_packs
        list_dir_result = ['Slack', 'ApiModules', 'python_file.py']
        pack_files = TestZipPacks.BLOB_NAMES
        mocker.patch.object(zip_packs, 'get_files_in_dir', return_value=pack_files)
        mocker.patch('os.listdir', return_value=list_dir_result)
        mocker.patch('os.path.isdir', return_value=True)
        zipped_packs = get_zipped_packs_names('content')

        assert zipped_packs == {'Slack': 'content/packs/Slack/1.0.2/Slack.zip'}

    def test_get_zipped_packs_name_no_zipped_packs(self, mocker):
        """
        Given:
            Some general path information of the packs and the build
        When:
            There are no valid packs in the packs directory
        Then:
            exit since no packs were found
        """
        with pytest.raises(Exception):
            from Tests.Marketplace import zip_packs
            list_dir_result = ['ApiModules', 'python_file.py']
            pack_files = TestZipPacks.BLOB_NAMES
            mocker.patch.object(zip_packs, 'get_files_in_dir', return_value=pack_files)
            mocker.patch('os.listdir', return_value=list_dir_result)
            mocker.patch('os.path.isdir', return_value=True)
            get_zipped_packs_names('content')

    def test_get_zipped_packs_name_no_latest_zip(self, mocker):
        """
        Given:
            Some general path information of the packs and the build
        When:
            There are is one valid pack but it has no valid zip files
        Then:
            exit since no zipped packs were found
        """
        with pytest.raises(Exception):
            from Tests.Marketplace import zip_packs
            list_dir_result = ['Slack', 'ApiModules', 'python_file.py']
            pack_files = TestZipPacks.BLOB_NAMES_NO_ZIP
            mocker.patch.object(zip_packs, 'get_files_in_dir', return_value=pack_files)
            mocker.patch('os.listdir', return_value=list_dir_result)
            mocker.patch('os.path.isdir', return_value=True)
            get_zipped_packs_names('content')

    def test_copy_zipped_packs_to_artifacts(self, mocker):
        """
        Given:
            A dict containing information about a single pack
        When:
            The information is valid
        Then:
            make a single call to the copy function
        """
        import shutil
        zipped_packs = {'Slack': 'content/packs/Slack/1.0.1/Slack.zip'}
        artifacts_path = 'dummy_path'
        mocker.patch.object(shutil, 'copy', side_effect=None)
        mocker.patch('os.path.exists', return_value=True)

        copy_zipped_packs_to_artifacts(zipped_packs, artifacts_path)

        assert shutil.copy.call_count == 1

    def test_copy_zipped_packs_to_artifacts_no_zipped_packs(self, mocker):
        """
        Given:
            A dict containing no information about packs
        When:
            There are no packs to copy
        Then:
            make no calls to the copy function
        """
        import shutil
        zipped_packs = {}
        artifacts_path = 'dummy_path'
        mocker.patch.object(shutil, 'copy', side_effect=None)
        mocker.patch('os.path.exists', return_value=True)

        copy_zipped_packs_to_artifacts(zipped_packs, artifacts_path)

        assert shutil.copy.call_count == 0

    def test_zip_packs(self, mocker):
        """
        Given:
            Packs zips in the zip folder

        When:
            Zipping into zip of zips

        Then:
            Zip the packs correctly
        """
        from zipfile import ZipFile

        mocker.patch.object(ZipFile, '__init__', return_value=None)
        mocker.patch.object(ZipFile, 'write')
        mocker.patch.object(ZipFile, 'close')
        packs = {'Slack': 'path/Slack.zip'}

        zip_packs(packs, 'oklol')

        assert ZipFile.write.call_args[0][0] == 'path/Slack.zip'
        assert ZipFile.write.call_args[0][1] == 'Slack.zip'

    def test_remove_test_playbooks_if_exist(self, mocker):
        from zipfile import ZipFile
        import shutil
        """
        Given:
            Removing test playbooks from packs

        When:
            Zipping packs

        Then:
            The zip should be without TestPlaybooks
        """
        files = ['README.md', 'changelog.json', 'metadata.json', 'ReleaseNotes/1_0_1.md',
                 'Playbooks/playbook-oylo.yml', 'TestPlaybooks/playbook-oylo.yml',
                 'Scripts/script-TaniumAskQuestion.yml', 'Integrations/integration-shtak.yml']
        mocker.patch.object(ZipFile, '__init__', return_value=None)
        mocker.patch.object(ZipFile, 'write')
        mocker.patch.object(ZipFile, 'close')
        mocker.patch.object(ZipFile, 'namelist', return_value=files)
        mocker.patch.object(ZipFile, 'extractall')
        mocker.patch('os.remove')
        mocker.patch('shutil.make_archive')
        mocker.patch('os.mkdir')

        remove_test_playbooks_if_exist('dest', [{'name': 'path'}])

        extract_args = ZipFile.extractall.call_args[1]['members']
        archive_args = shutil.make_archive.call_args[0]

        assert list(extract_args) == [file_ for file_ in files if 'TestPlaybooks' not in file_]
        assert archive_args[0] == 'dest/name'

    def test_remove_test_playbooks_if_exist_no_test_playbooks(self, mocker):
        from zipfile import ZipFile

        """
        Given:
            Removing test playbooks from packs

        When:
            Zipping packs, the pack doesn't have TestPlaybooks

        Then:
            TestPlaybooks should not be removed
        """
        files = ['README.md', 'changelog.json', 'metadata.json', 'ReleaseNotes/1_0_1.md',
                 'Playbooks/playbook-oylo.yml', 'Scripts/script-TaniumAskQuestion.yml',
                 'Integrations/integration-shtak.yml']
        mocker.patch.object(ZipFile, '__init__', return_value=None)
        mocker.patch.object(ZipFile, 'namelist', return_value=files)
        mocker.patch.object(ZipFile, 'extractall')

        remove_test_playbooks_if_exist('dest', [{'name': 'path'}])

        assert ZipFile.extractall.call_count == 0

    def test_remove_test_playbooks_from_signatures(self, mocker):
        import json
        from unittest.mock import mock_open
        """
        Given:
            Removing test playbooks from packs

        When:
            Zipping packs

        Then:
            Signatures should be updated to have no test playbooks
        """

        files = ['Integrations/integration-VirusTotal_5.5.yml', 'changelog.json', 'metadata.json',
                 'ReleaseNotes/1_0_1.md', 'TestPlaybooks/playbook-VirusTotal_detonate_file.yml', 'README.md',
                 'Scripts/script-TaniumAskQuestion.yml', 'Playbooks/playbook-Detonate_File-VirusTotal.yml',
                 'Integrations/integration-shtak.yml', 'TestPlaybooks/playbook-VirusTotal_preferred_vendors_test.yml',
                 "TestPlaybooks/playbook-virusTotal-test.yml"]

        sigs = json.dumps({
            "Integrations/integration-VirusTotal_5.5.yml": "a123",
            "Playbooks/playbook-Detonate_File-VirusTotal.yml": "b123",
            "README.md": "c123",
            "TestPlaybooks/playbook-VirusTotal_detonate_file.yml": "d123",
            "TestPlaybooks/playbook-VirusTotal_preferred_vendors_test.yml": "e123",
            "TestPlaybooks/playbook-virusTotal-test.yml": "f123",
            "changelog.json": "g123",
            "metadata.json": "h123"
        })

        mocker.patch('os.path.isfile', return_value=True)
        mocker.patch('builtins.open', mock_open(read_data=sigs))
        mocker.patch.object(json, 'dump')

        remove_test_playbooks_from_signatures('path', files)
        dump_args = json.dump.call_args[0][0]

        assert dump_args == {
            "Integrations/integration-VirusTotal_5.5.yml": "a123",
            "Playbooks/playbook-Detonate_File-VirusTotal.yml": "b123",
            "README.md": "c123",
            "changelog.json": "g123",
            "metadata.json": "h123"
        }
