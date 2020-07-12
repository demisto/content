import os

import pytest
from magic import Magic

from PcapFileExtractor import (InclusiveExclusive, filter_files, main,
                               upload_files)

OUTPUTS = [
    {
        'FileMD5': 'dca7766edd1e4976cac5e64fcaeec1fd',
        'FileSHA1': 'e1a60d05cd5b6b1bae28e7e5c0b368be6b48c2b5',
        'FileSHA256': '39c9534e5fa6fecd3ac083ffd6256c2cc9a58f9f1058cb2e472d1782040231f9',
        'FileName': 'rfc1350.txt',
        'FileSize': 24599,
        'FileExtension': '.txt'
    }
]


def test_extract_files(tmpdir):
    """
    Given
    - Valid Pcap File.
    When
    - Extracting the file from the pcap.
    Then
    - ensure file is being extracted correctly.
    - ensure outputs are correct.
    """

    file_path = './TestData/tftp_rrq.pcap'
    results = upload_files(file_path, tmpdir)
    assert 'Pcap Extracted Files' in results.readable_output
    assert OUTPUTS == results.outputs
    assert os.path.isfile(os.path.join(tmpdir, 'rfc1350.txt'))


class TestFilter:
    @pytest.mark.parametrize(
        'files, types, type_from_magic, exclusive_or_inclusive, expected', [
            (['./png_file.png'], ['image/png'], 'image/png', InclusiveExclusive.EXCLUSIVE, []),
            (['./png_file.png'], ['image/png'], 'image/png', InclusiveExclusive.INCLUSIVE, ['./png_file.png']),
            (['./png_file.mp3'], ['sound/mp3'], 'image/png', InclusiveExclusive.INCLUSIVE, [])
        ])
    def test_types(self, files, types, type_from_magic, exclusive_or_inclusive, expected, mocker):
        """
        Given:
        - inputs to filter_files concentrating on the types branch, as well with excepted files output

        When:
        - filtering files

        Then:
        - Validate the file list that got back is the same as expected.
        """
        mocker.patch.object(Magic, 'from_file', return_value=type_from_magic)
        assert expected == filter_files('/.', files, types=types, types_inclusive_or_exclusive=exclusive_or_inclusive)

    @pytest.mark.parametrize(
        'files, extensions, exclusive_or_inclusive, expected', [
            (['./png_file.png'], ['.png'], InclusiveExclusive.EXCLUSIVE, []),
            (['./png_file.png'], ['.png'], InclusiveExclusive.INCLUSIVE, ['./png_file.png']),
            (['./png_file.mp3'], ['sound/mp3'], InclusiveExclusive.INCLUSIVE, [])
        ])
    def test_extensions(self, files, extensions, exclusive_or_inclusive, expected):
        """
        Given:
        - inputs to filter_files concentrating on the extensions branch, as well with excepted files output

        When:
        - filtering files

        Then:
        - Validate the file list that got back is the same as expected.
        """
        assert expected == filter_files('/.', files, extensions=extensions,
                                        extensions_inclusive_or_exclusive=exclusive_or_inclusive)


@pytest.mark.skip('Problem with the docker')
def test_decryption(mocker):
    file_path = './TestData/wpa-Induction.pcap'
    password = 'Induction'
    mocker.patch('PcapFileExtractor.get_file_path_from_id', return_value=(file_path, 'wpa-Induction.pcap'))
    main('111', wpa_password=password)
