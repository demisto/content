import pytest
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
        modified_packs = get_modified_packs()

        assert modified_packs == {"Pack1", "Pack2"}
# disable-secrets-detection-end


class TestPrivatePacks:
    class FakeDirEntry:
        def __init__(self, name, path):
            self.name = name
            self.path = path

        @staticmethod
        def is_dir(path):
            return True if path == 'mock_path' else False

    def scan_dir(self):
        dir_entries = [self.FakeDirEntry('mock_dir', 'mock_path'),
                       self.FakeDirEntry('mock_file', 'mock_path2')]

        return dir_entries

    def test_add_private_packs_to_index(self, mocker):
        from Tests.Marketplace import upload_packs

        dirs = self.scan_dir()
        mocker.patch('os.scandir', return_value=dirs)
        mocker.patch('os.path.isdir', side_effect=self.FakeDirEntry.is_dir)
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

        private_packs = upload_packs.get_private_packs('path')

        assert private_packs == []

    def test_get_private_packs_error(self, mocker):
        from Tests.Marketplace import upload_packs

        mocker.patch('glob.glob', side_effect=InterruptedError)

        private_packs = upload_packs.get_private_packs('path')

        assert private_packs == []
