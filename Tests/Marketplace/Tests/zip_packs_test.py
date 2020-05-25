from Tests.Marketplace.zip_packs import download_packs_from_gcp, get_latest_pack_zip_from_blob, zip_packs


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
        FakeBlob('content/packs/SlackSheker/2.0.0/SlackSheker.zip'),
        FakeBlob('content/packs/Slack/Slack.png'),
        FakeBlob('content/packs/SlackSheker/SlackSheker.png')
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

        blob = get_latest_pack_zip_from_blob('Slack', TestZipPacks.BLOBS)

        assert blob.name == 'content/packs/Slack/1.0.1/Slack.zip'

    def test_download_packs_from_gcp(self, mocker):
        from Tests.Marketplace import zip_packs
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
            TestZipPacks.FakeDirEntry('SlackFake', 'Packs/SlackFake'),
            TestZipPacks.FakeDirEntry('ApiModules', 'Packs/ApiModules'),
        ]

        bucket = TestZipPacks.FakeBucket()

        mocker.patch('os.scandir', return_value=packs)
        mocker.patch.object(bucket, 'list_blobs', side_effect=TestZipPacks.FakeBucket.list_blobs)
        mocker.patch.object(zip_packs, 'executor_submit')

        zipped_packs = download_packs_from_gcp(bucket, zip_packs.BUILD_GCP_PATH, 'path', '', '')

        assert bucket.list_blobs.call_count == 2
        assert zip_packs.executor_submit.call_count == 1
        assert zip_packs.executor_submit.call_args[0][1] == 'path/Slack.zip'
        assert zipped_packs == [{'Slack': 'path/Slack.zip'}]

    def test_zip_packs(self, mocker):
        from zipfile import ZipFile

        mocker.patch.object(ZipFile, '__init__', return_value=None)
        mocker.patch.object(ZipFile, 'write')
        mocker.patch.object(ZipFile, 'close')

        packs = [{'Slack': 'path/Slack.zip'}]

        zip_packs(packs, 'oklol')

        assert ZipFile.write.call_args[0][0] == 'path/Slack.zip'
        assert ZipFile.write.call_args[0][1] == 'Slack.zip'
