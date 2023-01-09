import demistomock as demisto
from RepopulateFiles import parse_attachment_entries, find_attachment_entry, main
from unittest import mock


class TestRepopulateFiles:
    def test_parse_attachment_entries(self):
        entries = [
            {'ContentsFormat': 'text', 'Tags': None, 'Brand': 'Builtin', 'HumanReadable': None, 'ID': '588@11',
             'FileID': '', 'IgnoreAutoExtract': False, 'Evidence': False, 'EntryContext': None, 'Contents': '509',
             'File': '12', 'EvidenceID': '', 'FileMetadata': {'size': '42'}, 'ImportantEntryContext': None},
            {'ContentsFormat': 'text', 'Tags': None, 'Brand': 'Builtin', 'HumanReadable': None, 'ID': '638@11',
             'FileID': '', 'IgnoreAutoExtract': False, 'Evidence': False, 'EntryContext': None, 'Contents': '511',
             'File': '34', 'EvidenceID': '', 'FileMetadata': {'type': 'PDF'}, 'ImportantEntryContext': None}
        ]

        entry_context = parse_attachment_entries(entries)
        assert len(entry_context) == 2
        assert entry_context[0].get('Size') == '42'
        assert entry_context[1].get('Type') == 'PDF'

    def test_find_attachment_entry(self, mocker):
        file_ents = [
            {
                'Size': 4,
                'SHA1': '70c881d4a26984ddce795f6f71817c9cf4480e79',
                'SHA256': '61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4',
                'SHA512': '1b86355f13a7f0b90c8b6053c0254399994dfbb3843e08d603e292ca13b8f672'
                          'ed5e58791c10f3e36daec9699cc2fbdc88b4fe116efa7fce016938b787043818',
                'Name': 'test.txt',
                'SSDeep': '3:tt:j',
                'EntryID': '3@202',
                'Info': 'ASCII text, with no line terminators',
                'Type': 'txt',
                'MD5': '74b87337454200d4d33f80c4663dc5e5',
                'Extension': 'txt'
            },
            {
                'Size': 7818,
                'SHA1': '0cb2f5653c6c4fb6bc3235e1200af9126b9067b0',
                'SHA256': '0207199f975738fe798d36263998563bdc52bd59b226730c0d5e481646247c9a',
                'Name': 'test.yml',
                'SSDeep': '192:Ik4PaoJcQfmBLTh7qX0QLAhl8G5wmIxtH5hnTG:IkKamFOBLTh4UHiNo',
                'EntryID': '18@200',
                'Info': 'Python script, ASCII text executable',
                'Type': 'yml',
                'MD5': '3e8ba0bbe4cba711550deeeb48812861'
            }
        ]

        attachment_ent = {
            'description': '',
            'isTempPath': False,
            'name': 'test.txt',
            'path': '201_915f7adb-fcd8-4e09-81df-9353ae3858df_test.txt',
            'showMediaFile': False,
            'type': 'text/plain'
        }

        with mock.patch('builtins.open', mock.mock_open(read_data=b'aaaa')):
            ent = find_attachment_entry(file_ents, attachment_ent)
            assert ent.get('Size') == 4
            assert ent.get('SHA256') == '61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4'

    def test_main_no_entries(self, mocker):
        mocker.patch('RepopulateFiles.demisto.executeCommand', return_value=None)
        main()

    def test_main_file_entries(self, mocker):
        mocker.patch(
            'RepopulateFiles.demisto.executeCommand',
            return_value=[
                {
                    'Type': 3,
                    'Contents': '',
                    'ContentsFormat': '',
                    'ID': '3@202',
                    'File': 'test.txt',
                    'FileID': '461760d2-0962-40b4-84ac-667f6d662efa',
                    'FileMetadata': {
                        'type': 'txt',
                        'size': 4,
                        'md5': '74b87337454200d4d33f80c4663dc5e5',
                        'sha1': '70c881d4a26984ddce795f6f71817c9cf4480e79',
                        'sha256': '61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4',
                        'sha512': '1b86355f13a7f0b90c8b6053c0254399994dfbb3843e08d603e292ca13b8f672'
                                  'ed5e58791c10f3e36daec9699cc2fbdc88b4fe116efa7fce016938b787043818',
                        'ssdeep': '3:tt:j',
                        'isMediaFile': False,
                        'info': 'ASCII text, with no line terminators'}}])

        mocker.patch('RepopulateFiles.demisto.incident',
                     return_value={'attachment': [{'description': '',
                                                   'isTempPath': False,
                                                   'name': 'test.txt',
                                                   'path': '202_c046d6af-e9d2-4308-8c35-f487a520de5f_test.txt',
                                                   'showMediaFile': False,
                                                   'type': 'text/plain'}]})

        mocker.patch.object(demisto, 'results')

        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]

        assert results['Contents'] == [{
            'Name': 'test.txt',
            'MD5': '74b87337454200d4d33f80c4663dc5e5',
            'SHA1': '70c881d4a26984ddce795f6f71817c9cf4480e79',
            'SHA256': '61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4',
            'SHA512': '1b86355f13a7f0b90c8b6053c0254399994dfbb3843e08d603e292ca13b8f672'
                      'ed5e58791c10f3e36daec9699cc2fbdc88b4fe116efa7fce016938b787043818',
            'SSDeep': '3:tt:j',
            'Size': 4,
            'Info': 'ASCII text, with no line terminators',
            'Type': 'txt',
            'Extension': 'txt',
            'EntryID': '3@202'
        }]

    def test_main_attachment_entries(self, mocker):
        mocker.patch(
            'RepopulateFiles.demisto.executeCommand',
            return_value=[
                {
                    'Type': 3,
                    'Contents': '',
                    'ContentsFormat': '',
                    'ID': '3@202',
                    'File': 'test.txt',
                    'FileID': '461760d2-0962-40b4-84ac-667f6d662efa',
                    'FileMetadata': {
                        'type': 'txt',
                        'size': 4,
                        'md5': '74b87337454200d4d33f80c4663dc5e5',
                        'sha1': '70c881d4a26984ddce795f6f71817c9cf4480e79',
                        'sha256': '61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4',
                        'ssdeep': '3:tt:j',
                        'isMediaFile': False,
                        'info': 'ASCII text, with no line terminators'}}])

        mocker.patch('RepopulateFiles.demisto.incident',
                     return_value={'attachment': [{'description': '',
                                                   'isTempPath': False,
                                                   'name': 'test.txt',
                                                   'path': '202_c046d6af-e9d2-4308-8c35-f487a520de5f_test.txt',
                                                   'showMediaFile': False,
                                                   'type': 'text/plain'}]})

        mocker.patch.object(demisto, 'results')

        with mock.patch('builtins.open', mock.mock_open(read_data=b'aaaa')):
            main()

        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]

        assert results['Contents'] == [{
            'Name': 'test.txt',
            'MD5': '74b87337454200d4d33f80c4663dc5e5',
            'SHA1': '70c881d4a26984ddce795f6f71817c9cf4480e79',
            'SHA256': '61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4',
            'SHA512': '1b86355f13a7f0b90c8b6053c0254399994dfbb3843e08d603e292ca13b8f672'
                      'ed5e58791c10f3e36daec9699cc2fbdc88b4fe116efa7fce016938b787043818',
            'SSDeep': '3:tt:j',
            'Size': 4,
            'Info': 'ASCII text, with no line terminators',
            'Type': 'txt',
            'Extension': 'txt',
            'EntryID': '3@202'
        }
        ]
