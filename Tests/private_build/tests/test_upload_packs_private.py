

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


class TestPrivatePacks:
    def test_add_private_packs_to_index(self, mocker):
        from Tests.private_build import upload_packs_private

        dirs = scan_dir()
        mocker.patch('os.scandir', return_value=dirs)
        mocker.patch('os.path.isdir', side_effect=FakeDirEntry.isdir)
        mocker.patch.object(upload_packs_private, 'update_index_folder')

        upload_packs_private.add_private_packs_to_index('test', 'private_test')

        index_call_args = upload_packs_private.update_index_folder.call_args[0]
        index_call_count = upload_packs_private.update_index_folder.call_count

        assert index_call_count == 1
        assert index_call_args[0] == 'test'
        assert index_call_args[1] == 'mock_dir'
        assert index_call_args[2] == 'mock_path'

    def test_get_private_packs(self, mocker):
        import os
        from Tests.Marketplace import marketplace_services
        from Tests.private_build import upload_packs_private

        mocker.patch('glob.glob', return_value=[os.path.join(marketplace_services.CONTENT_ROOT_PATH,
                                                             'Tests', 'Marketplace', 'Tests',
                                                             'test_data', 'metadata.json')])

        private_packs = upload_packs_private.get_private_packs('path', )

        assert private_packs == [{'id': 'ImpossibleTraveler',
                                  'price': 100,
                                  'vendorId': None,
                                  'vendorName': None,
                                  'contentCommitHash': "",
                                  }]

    def test_get_private_packs_empty(self, mocker):
        from Tests.private_build import upload_packs_private

        mocker.patch('glob.glob', return_value=[])
        mocker.patch("Tests.Marketplace.upload_packs.logging.warning")

        private_packs = upload_packs_private.get_private_packs('path')

        assert private_packs == []

    def test_get_private_packs_error(self, mocker):
        from Tests.private_build import upload_packs_private

        mocker.patch('glob.glob', side_effect=InterruptedError)
        mocker.patch("Tests.Marketplace.upload_packs.logging.warning")

        private_packs = upload_packs_private.get_private_packs('path')

        assert private_packs == []
