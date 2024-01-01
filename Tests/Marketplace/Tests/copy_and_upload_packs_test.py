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

    def test_upload_core_packs_config(self, mocker):
        """
        When:
            Calling the upload_core_packs_config function
        Given:
            The default corepacks.json file and one versioned corepacks file corepacks-8.3.0.json, that should be copied
            from the build bucket to the production bucket.
        Then:
            - For the corepacks.json file, assert that the file is downloaded from the build bucket, modified according
              to the full paths as required in the production bucket, and then uploaded to the production bucket.
            - For the versioned corepacks file, assert that the file is copied from the build bucket as is.
        """
        from Tests.Marketplace.copy_and_upload_packs import upload_core_packs_config
        from Tests.Marketplace.marketplace_constants import GCPConfig
        import json

        production_bucket = mocker.MagicMock()
        production_bucket.name = GCPConfig.PRODUCTION_BUCKET

        production_bucket_blob = mocker.MagicMock()
        mocker.patch.object(production_bucket_blob, 'upload_from_string')
        production_bucket.blob.return_value = production_bucket_blob

        build_bucket = mocker.MagicMock()
        build_bucket.name = GCPConfig.CI_BUILD_BUCKET

        build_bucket_base_path = 'dummy-build-bucket-path'
        corepacks_version = 'corepacks-8.3.0.json'
        build_number = '123456'

        corepacks_file = {
            "corePacks": [
                "https://storage.googleapis.com/marketplace-ci-build/content/packs/pack_1/1.4.0/pack_1.zip",
                "https://storage.googleapis.com/marketplace-ci-build/content/packs/pack_2/2.2.3/pack_2.zip"
            ],
            "upgradeCorePacks": [
                "pack_1"
            ],
            "buildNumber": "123456"
        }

        mocker.patch('Tests.Marketplace.copy_and_upload_packs.load_json', return_value=corepacks_file)

        mocker.patch("Tests.Marketplace.marketplace_constants.GCPConfig.get_core_packs_unlocked_files",
                     return_value=[corepacks_version])

        upload_core_packs_config(production_bucket, build_number, '',
                                 build_bucket, GCPConfig.PRODUCTION_STORAGE_BASE_PATH, build_bucket_base_path)

        # Assert that corepacks.json file was processed and uploaded successfully
        corepacks_expected_data = {
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
            json.dumps(corepacks_expected_data, indent=4)
        )

        # Assert that the versioned corepacks-8.3.0.json file was copied from the build bucket to the production bucket
        build_bucket.copy_blob.assert_called_once()

# disable-secrets-detection-end
