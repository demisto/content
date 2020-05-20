from Tests.Marketplace.zip_packs import download_packs_from_gcp, get_latest_version_blob, zip_packs


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
        FakeBlob('content/packs/Slack/1.0.1/Slack.zip'),
        FakeBlob('content/packs/Slack/Slack.png')
    ]

    def test_get_latest_version_blob(self):
        """
        Given:
            blobs of a specific pack

        When:
            Getting the pack to download

        Then:
            Return the latest version blob
        """

        blob = get_latest_version_blob(TestZipPacks.BLOBS)

        assert blob.name == 'content/packs/Slack/1.0.1/Slack.zip'

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
            TestZipPacks.FakeDirEntry('ApiModules', 'Packs/ApiModules')
        ]

        bucket = TestZipPacks.FakeBucket()
        blob = TestZipPacks.BLOBS[1]

        mocker.patch('os.scandir', return_value=packs)
        mocker.patch.object(bucket, 'list_blobs', side_effect=TestZipPacks.FakeBucket.list_blobs)
        mocker.patch.object(blob, 'download_to_filename')

        zipped_packs = download_packs_from_gcp(bucket, 'path', '', '')

        assert bucket.list_blobs.call_count == 1
        assert blob.download_to_filename.call_count == 1
        assert blob.download_to_filename.call_args[0][0] == 'path/Slack.zip'
        assert zipped_packs == [{'Slack': 'path/Slack.zip'}]

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
