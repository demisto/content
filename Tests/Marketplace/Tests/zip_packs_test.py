import pytest

from Tests.Marketplace.zip_packs import get_latest_pack_zip_from_blob, zip_packs,\
    remove_test_playbooks_if_exist, remove_test_playbooks_from_signatures, BUILD_GCP_PATH, get_zipped_packs_names,\
    copy_to_other_dir


class TestZipPacks:
    BLOB_NAMES = [
        'content/packs/Slack/1.0.0/Slack.zip',
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

        blob_name = get_latest_pack_zip_from_blob('Slack', TestZipPacks.BLOB_NAMES)
        assert blob_name == 'content/packs/Slack/1.0.1/Slack.zip'

    def test_get_zipped_packs_name(self, mocker):
        from Tests.Marketplace import zip_packs
        listdir_result = ['Slack', 'ApiModules', 'python_file.py']
        pack_files = TestZipPacks.BLOB_NAMES
        mocker.patch.object(zip_packs, 'get_pack_files', return_value=pack_files)
        mocker.patch('os.listdir', return_value=listdir_result)
        mocker.patch('os.path.isdir', return_value=True)
        zipped_packs = get_zipped_packs_names('content', BUILD_GCP_PATH, 'builds')

        assert zipped_packs == [{'Slack': 'content/packs/Slack/1.0.1/Slack.zip'}]

    def test_get_zipped_packs_name_no_zipped_packs(self, mocker):
        with pytest.raises(SystemExit) as sys_exit:
            from Tests.Marketplace import zip_packs
            listdir_result = ['ApiModules', 'python_file.py']
            pack_files = TestZipPacks.BLOB_NAMES
            mocker.patch.object(zip_packs, 'get_pack_files', return_value=pack_files)
            mocker.patch('os.listdir', return_value=listdir_result)
            mocker.patch('os.path.isdir', return_value=True)
            get_zipped_packs_names('content', BUILD_GCP_PATH, 'builds')

            assert sys_exit.value.code == 1

    def test_get_zipped_packs_name_no_latest_zip(self, mocker):
        with pytest.raises(SystemExit) as sys_exit:
            from Tests.Marketplace import zip_packs
            listdir_result = ['Slack', 'ApiModules', 'python_file.py']
            pack_files = TestZipPacks.BLOB_NAMES_NO_ZIP
            mocker.patch.object(zip_packs, 'get_pack_files', return_value=pack_files)
            mocker.patch('os.listdir', return_value=listdir_result)
            mocker.patch('os.path.isdir', return_value=True)
            get_zipped_packs_names('content', BUILD_GCP_PATH, 'builds')

            assert sys_exit.value.code == 1

    def test_copy_to_other_dir(self, mocker):
        import shutil
        zipped_packs = [{'Slack': 'content/packs/Slack/1.0.1/Slack.zip'}]
        mocker.patch.object(shutil, 'copy', side_effect=None)
        mocker.patch('os.path.exists', return_value=True)

        copy_to_other_dir(zipped_packs)

        assert shutil.copy.call_count == 1

    def test_copy_to_other_dir_no_zipped_packs(self, mocker):
        import shutil
        zipped_packs = []
        mocker.patch.object(shutil, 'copy', side_effect=None)
        mocker.patch('os.path.exists', return_value=True)

        copy_to_other_dir(zipped_packs)

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
        packs = [{'Slack': 'path/Slack.zip'}]

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
