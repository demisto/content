import json

import pytest
import os

from Tests.Marketplace.marketplace_constants import CONTENT_ROOT_PATH, PACKS_FOLDER, IGNORED_FILES, GCPConfig


# disable-secrets-detection-start
class TestGetPackNames:
    """
       Given:
           - A csv list of pack names (ids)
       When:
           - Getting the pack paths
       Then:
           - Verify that we got the same packs
   """

    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ("pack1,pack2,pack1", {"pack1", "pack2"}),
        ("pack1, pack2,  pack3", {"pack1", "pack2", "pack3"})
    ])
    def test_get_pack_names_specific(self, packs_names_input, expected_result):
        from Tests.Marketplace.copy_and_upload_packs import get_pack_names
        modified_packs = get_pack_names(packs_names_input)

        assert modified_packs == expected_result

    def test_get_pack_names_all(self):
        """
           Given:
               - content repo path, packs folder path, ignored files list
           When:
               - Trying to get the pack names of all packs in content repo
           Then:
               - Verify that we got all packs in content repo
       """
        from Tests.Marketplace.copy_and_upload_packs import get_pack_names
        packs_full_path = os.path.join(CONTENT_ROOT_PATH, PACKS_FOLDER)  # full path to Packs folder in content repo
        expected_pack_names = {p for p in os.listdir(packs_full_path) if p not in IGNORED_FILES}
        assert get_pack_names('all') == expected_pack_names


class TestRegex:
    BUILD_BASE_PATH = f"{GCPConfig.GCS_PUBLIC_URL}/{GCPConfig.CI_BUILD_BUCKET}/content/builds"
    BUILD_PATTERN = "upload-packs-build-flow/169013/content/packs"

    @pytest.mark.parametrize("gcs_path, latest_zip_suffix", [
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/CommonWidgets/1.0.5/CommonWidgets.zip",
         "CommonWidgets/1.0.5/CommonWidgets.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/Malware/1.2.4/Malware.zip",
         "Malware/1.2.4/Malware.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/HelloWorld/1.1.11/HelloWorld.zip",
         "HelloWorld/1.1.11/HelloWorld.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/CommonDashboards/1.0.0/CommonDashboards.zip",
         "CommonDashboards/1.0.0/CommonDashboards.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/AutoFocus/1.1.9/AutoFocus.zip",
         "AutoFocus/1.1.9/AutoFocus.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/UrlScan/1.0.5/UrlScan.zip",
         "UrlScan/1.0.5/UrlScan.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/AccessInvestigation/1.2.2/AccessInvestigation.zip",
         "AccessInvestigation/1.2.2/AccessInvestigation.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/Phishing/1.10.7/Phishing.zip",
         "Phishing/1.10.7/Phishing.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/FeedTAXII/1.0.5/FeedTAXII.zip",
         "FeedTAXII/1.0.5/FeedTAXII.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/WhereIsTheEgg/1.0.0/WhereIsTheEgg.zip",
         "WhereIsTheEgg/1.0.0/WhereIsTheEgg.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/TIM_Processing/1.1.6/TIM_Processing.zip",
         "TIM_Processing/1.1.6/TIM_Processing.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/DemistoRESTAPI/1.1.2/DemistoRESTAPI.zip",
         "DemistoRESTAPI/1.1.2/DemistoRESTAPI.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/CommonPlaybooks/1.8.5/CommonPlaybooks.zip",
         "CommonPlaybooks/1.8.5/CommonPlaybooks.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/Base/1.3.24/Base.zip",
         "Base/1.3.24/Base.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/rasterize/1.0.4/rasterize.zip",
         "rasterize/1.0.4/rasterize.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/VirusTotal/1.0.1/VirusTotal.zip",
         "VirusTotal/1.0.1/VirusTotal.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/DemistoLocking/1.0.0/DemistoLocking.zip",
         "DemistoLocking/1.0.0/DemistoLocking.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/TIM_SIEM/1.0.3/TIM_SIEM.zip",
         "TIM_SIEM/1.0.3/TIM_SIEM.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/ExportIndicators/1.0.0/ExportIndicators.zip",
         "ExportIndicators/1.0.0/ExportIndicators.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/DefaultPlaybook/1.0.2/DefaultPlaybook.zip",
         "DefaultPlaybook/1.0.2/DefaultPlaybook.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/CommonTypes/2.2.1/CommonTypes.zip",
         "CommonTypes/2.2.1/CommonTypes.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/ImageOCR/1.0.1/ImageOCR.zip",
         "ImageOCR/1.0.1/ImageOCR.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/CommonScripts/1.2.69/CommonScripts.zip",
         "CommonScripts/1.2.69/CommonScripts.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/Active_Directory_Query/1.0.7/Active_Directory_Query.zip",
         "Active_Directory_Query/1.0.7/Active_Directory_Query.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/CommonReports/1.0.1/CommonReports.zip",
         "CommonReports/1.0.1/CommonReports.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/Whois/1.1.6/Whois.zip",
         "Whois/1.1.6/Whois.zip"),
        (f"{BUILD_BASE_PATH}/{BUILD_PATTERN}/Blockade.io/1.0.0/Blockade.io.zip",
         "Blockade.io/1.0.0/Blockade.io.zip"),
        (f"{GCPConfig.GCS_PUBLIC_URL}/oproxy-dev.appspot.com/wow/content/packs/TIM-wow_a/99.98.99/TIM-wow_a.zip",
         "TIM-wow_a/99.98.99/TIM-wow_a.zip")
    ])
    def test_latest_zip_regex(self, gcs_path, latest_zip_suffix):
        """ Testing all of our corepacks paths to make sure we are not missing one of them, last test is for a
        generic bucket.

           Given:
               - A path of latest version pack in a gcs bucket
           When:
               - Searching for the pack latest zip suffix
           Then:
               - Getting the expected suffix
       """
        from Tests.Marketplace.copy_and_upload_packs import LATEST_ZIP_REGEX
        assert LATEST_ZIP_REGEX.findall(gcs_path)[0] == latest_zip_suffix


class TestCorepacksFiles:
    from unittest.mock import MagicMock, patch

    @staticmethod
    def get_index_folder_path():
        index_json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')
        return index_json_path

    def test_corepacks_files_upload(self, mocker):
        """
        Test the upload flow of the corepacks files in the private bucket.
        """
        from Tests.Marketplace.copy_and_upload_packs import upload_core_packs_config
        from Tests.Marketplace.marketplace_constants import GCPConfig
        import os
        import shutil
        from google.cloud import storage

        production_bucket = mocker.MagicMock(spec=storage.bucket.Bucket)
        production_bucket.name = GCPConfig.PRODUCTION_BUCKET

        # mock_blob = mocker.MagicMock()
        a = mocker.patch('google.cloud.storage.bucket.Bucket.blob')

        # production_bucket.patch('google.cloud.storage.bucket.Bucket.blob')
        production_bucket_blob = mocker.MagicMock(spec=storage.blob.Blob)
        # production_bucket_blob.exists.return_value = True
        # production_bucket_blob.download_to_filename.return_value = True

        # production_bucket_blob.upload_from_string.return_value = True
        # production_buck_blobet.name = 'corepacks.json'
        production_bucket_blob.public_url = 'http://www.example.com'
        production_bucket_blob.bucket.name = 'bucket-name'
        b = mocker.patch.object(production_bucket_blob, 'upload_from_string')
        mocker.return_value = production_bucket_blob

        build_bucket = mocker.MagicMock()
        build_bucket.name = GCPConfig.CI_BUILD_BUCKET

        build_bucket_base_path = 'dummy-build-bucket-path'

        corepacks_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data', 'corepacks_files',
                                      'corepacks.json')
        with open(corepacks_file, 'r') as public_index_json_file:
            corepacks_file_contents = json.load(public_index_json_file)

        mocker.patch('Tests.Marketplace.copy_and_upload_packs.load_json', return_value=corepacks_file_contents)

        corepacks_version = 'corepacks-8.3.0.json'
        mocker.patch("Tests.Marketplace.marketplace_constants.GCPConfig.get_core_packs_unlocked_files",
                     return_value=[])
                     # return_value=[corepacks_version])

        build_number = '123456'
        extract_destination_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')
        # os.makedirs(extract_destination_path, exist_ok=True)

        upload_core_packs_config(production_bucket, build_number, extract_destination_path,
                                 build_bucket, GCPConfig.PRODUCTION_STORAGE_BASE_PATH, build_bucket_base_path)

        # Asserting that corepacks file was downloaded, processed and uploaded successfully

        core_packs_data = {
            "corePacks": [
                "https://storage.googleapis.com/marketplace-dist/content/packs/pack_1/1.4.0/pack_1.zip",
                "https://storage.googleapis.com/marketplace-dist/content/packs/pack_2/2.2.3/pack_2.zip"
            ],
            "upgradeCorePacks": [
                "pack_1"
            ],
            "buildNumber": "123456"
        }


        production_bucket_blob.upload_from_string.assert_called_once_with(
            json.dumps(core_packs_data, indent=4)
        )
        print('daniel')


    @patch('google.cloud.storage.blob.Blob.exists')
    @patch('google.cloud.storage.blob.Blob.download_to_filename')
    @patch('google.cloud.storage.blob.Blob.upload_from_string')
    @patch('google.cloud.storage.bucket.Bucket.blob')
    @patch('google.cloud.storage.bucket.Bucket.copy_blob')
    def test_upload_core_packs_config(self, mock_copy_blob, mock_blob, mock_upload, mock_download, mock_exists):
        # Mocking arguments
        from unittest.mock import MagicMock, patch
        from Tests.Marketplace.copy_and_upload_packs import upload_core_packs_config
        from Tests.Marketplace.marketplace_constants import GCPConfig



        from google.cloud import storage
        production_bucket = MagicMock(spec=storage.bucket.Bucket)
        build_bucket = MagicMock(spec=storage.bucket.Bucket)
        build_number = '123'
        extract_destination_path = '/extract/path'
        storage_base_path = '/storage/base/path'
        build_bucket_base_path = '/build/bucket/base/path'

        # Mocking corepacks file and related methods
        core_packs_data = {
            'corePacks': ['path/to/corepack.zip'],
            'upgradeCorePacks': [],
            'buildNumber': build_number
        }
        mock_corepacks_blob = MagicMock(spec=storage.blob.Blob)
        mock_corepacks_blob.exists.return_value = True
        mock_corepacks_blob.download_to_filename.return_value = True
        mock_corepacks_blob.upload_from_string.return_value = True
        mock_corepacks_blob.name = 'corepacks.json'
        mock_corepacks_blob.public_url = 'http://www.example.com'
        mock_corepacks_blob.bucket.name = 'bucket-name'
        mock_blob.return_value = mock_corepacks_blob

        # Mocking unlocked files and related methods
        mock_get_core_packs_unlocked_files = MagicMock(return_value=['file1.json', 'file2.yml'])
        with patch('Tests.Marketplace.marketplace_constants.GCPConfig.GCPConfig.get_core_packs_unlocked_files', mock_get_core_packs_unlocked_files):
            mock_unlocked_file = MagicMock(spec=storage.blob.Blob)
            mock_unlocked_file.exists.return_value = True
            mock_build_blob = MagicMock(spec=storage.blob.Blob)
            mock_build_blob.exists.return_value = True
            mock_build_blob.name = 'file1.json'
            mock_build_blob.bucket.name = 'build-bucket-name'
            mock_copy_blob.return_value = mock_unlocked_file
            mock_blob.side_effect = [mock_build_blob, mock_unlocked_file]

            # Running the method under test
            upload_core_packs_config(production_bucket, build_number, extract_destination_path, build_bucket,
                                     storage_base_path, build_bucket_base_path)

        # Asserting that corepacks file was downloaded, processed and uploaded successfully
        mock_corepacks_blob.download_to_filename.assert_called_once_with(
            os.path.join(extract_destination_path, 'corepacks.json')
        )
        mock_corepacks_blob.upload_from_string.assert_called_once_with(
            json.dumps(core_packs_data, indent=4)
        )

        # Asserting that unlocked files were copied to production bucket
        mock_build_blob.copy_blob.assert_called_once_with(
            blob=mock_build_blob, destination_bucket=production_bucket,
            new_name=os.path.join(storage_base_path, 'file1.json')
        )
        mock_unlocked_file.copy_blob.assert_called_once_with(
            blob=mock_unlocked_file, destination_bucket=production_bucket,
            new_name=os.path.join(storage_base_path, 'file2.yml')
        )

# disable-secrets-detection-end
