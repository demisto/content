from Tests.Marketplace.zip_packs import download_packs_from_gcp, get_pack_zip_from_blob, zip_packs


class TestZipPacks:
    class FakeBlob:
        def __init__(self, name):
            self.name = name

        def download_to_filename(self, dest):
            pass

    class FakeDirEntry:
        def __init__(self, name, path):
            self.name = name
            self.path = path

    class FakeBucket:
        @staticmethod
        def list_blobs(prefix):
            return TestZipPacks.BLOBS

    BLOBS = [
        FakeBlob('content/packs/Slack/1.0.0/Slack.zip'),
        FakeBlob('content/packs/Slack/Slack.png')
    ]

    def test_get_pack_zip_from_blob(self):
        """
        Given:
            blobs of a specific pack

        When:
            Getting the pack to download

        Then:
            Return the pack zip blob
        """

        blob = get_pack_zip_from_blob(TestZipPacks.BLOBS)

        assert blob.name == 'content/packs/Slack/1.0.0/Slack.zip'

    def test_download_packs_from_gcp(self, mocker):
        """
        Given:
            Packs in the content repo and a GCP bucket

        When:
            Downloading the packs from the bucket

        Then:
            Download the packs correctly
        """
        packs = [
            TestZipPacks.FakeDirEntry('Slack', 'Packs/Slack'),
            TestZipPacks.FakeDirEntry('ApiModules', 'Packs/ApiModules'),
            TestZipPacks.FakeDirEntry('Base', 'Packs/Base')
        ]

        bucket = TestZipPacks.FakeBucket()
        blob = TestZipPacks.BLOBS[0]

        mocker.patch('os.scandir', return_value=packs)
        mocker.patch.object(bucket, 'list_blobs', side_effect=TestZipPacks.FakeBucket.list_blobs)
        mocker.patch.object(blob, 'download_to_filename')

        zipped_packs = download_packs_from_gcp(bucket, 'path', '', '')

        assert bucket.list_blobs.call_count == 1
        assert blob.download_to_filename.call_count == 1
        assert blob.download_to_filename.call_args[0][0] == 'path/Slack.zip'
        assert zipped_packs == [{'Slack': 'path/Slack.zip'}]

    def test_download_packs_from_gcp_similar_name(self, mocker):
        from Tests.Marketplace.marketplace_services import Pack
        """
        Given:
            Packs in the content repo and a GCP bucket containing similar names

        When:
            Downloading the packs from the bucket

        Then:
            Search for the packs correctly
        """
        packs = [
            TestZipPacks.FakeDirEntry('VirusTotal', 'Packs/VirusTotal'),
            TestZipPacks.FakeDirEntry('VirusTotal-Private_API', 'Packs/VirusTotal-Private_API')
        ]

        bucket = TestZipPacks.FakeBucket()
        blob = TestZipPacks.BLOBS[0]

        mocker.patch('os.scandir', return_value=packs)
        mocker.patch.object(bucket, 'list_blobs', side_effect=TestZipPacks.FakeBucket.list_blobs)
        mocker.patch.object(blob, 'download_to_filename')
        mocker.patch.object(Pack, '_get_latest_version', return_value='1.0.0')

        download_packs_from_gcp(bucket, 'path', '', '')
        call_arg_1 = bucket.list_blobs.call_args_list[0][1]['prefix']
        call_arg_2 = bucket.list_blobs.call_args_list[1][1]['prefix']

        assert bucket.list_blobs.call_count == 2
        assert call_arg_1 == 'content/packs/VirusTotal/1.0.0'
        assert call_arg_2 == 'content/packs/VirusTotal-Private_API/1.0.0'

    def test_zip_packs(self, mocker):
        from zipfile import ZipFile

        mocker.patch.object(ZipFile, '__init__', return_value=None)
        mocker.patch.object(ZipFile, 'write')
        mocker.patch.object(ZipFile, 'close')

        packs = [{'Slack': 'path/Slack.zip'}]

        success = zip_packs(packs, 'oklol')

        assert ZipFile.write.call_args[0][0] == 'path/Slack.zip'
        assert ZipFile.write.call_args[0][1] == 'Slack.zip'
        assert success is True
