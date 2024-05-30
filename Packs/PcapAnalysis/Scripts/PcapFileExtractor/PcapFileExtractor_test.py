import os

import pytest

from CommonServerPython import CommandResults
from PcapFileExtractor import filter_files, upload_files, INCLUSIVE, EXCLUSIVE
from magic import Magic
from pytest import raises
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
    if type(results) is CommandResults:     # Otherwise 'results' has not 'readable_output' or 'outputs' attributes.
        assert 'Pcap Extracted Files' in results.readable_output
        assert OUTPUTS == results.outputs
    assert os.path.isfile(os.path.join(tmpdir, 'rfc1350.txt'))


class TestFilter:
    @pytest.mark.parametrize(
        'files, types, type_from_magic, exclusive_or_inclusive, expected', [
            (['./png_file.png'], ['image/png'], 'image/png', EXCLUSIVE, []),
            (['./png_file.png'], ['image/png'], 'image/png', INCLUSIVE, ['./png_file.png']),
            (['./png_file.mp3'], ['sound/mp3'], 'image/png', INCLUSIVE, [])
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
        assert expected == filter_files('/.', files, types=types, inclusive_or_exclusive=exclusive_or_inclusive)

    @pytest.mark.parametrize(
        'files, extensions, exclusive_or_inclusive, expected', [
            (['./png_file.png'], {'.png'}, EXCLUSIVE, []),
            (['./png_file.png'], {'.png'}, INCLUSIVE, ['./png_file.png']),
            (['./png_file.mp3'], {'sound/mp3'}, INCLUSIVE, [])
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
                                        inclusive_or_exclusive=exclusive_or_inclusive)


def test_decryption_wpa_pwd(tmpdir):
    """
    Given:
    - A PCAP file protected with WPA-PWD
    - A password to the file

    When:
    - Running PcapFileExtractor with WPA-PWD protected file

    Then:
    - Validate results output that the files are exported and returned to CortexSOAR
    """
    file_path = './TestData/wpa-Induction.pcap'
    password = 'Induction'
    results = upload_files(file_path, tmpdir, wpa_pwd=password)
    assert 5 == len(results.outputs)


def test_decryption_rsa(tmpdir):
    """
    Given:
    - A PCAP file with ssl encryption
    - A Key file for the pcap

    When:
    - Running PcapFileExtractor with TLS protected file and key

    Then:
    - Validate results output that the files are exported and returned to CortexSOAR
    """
    file_path = './TestData/rsa.cap'
    key_path = './TestData/rsa.key'
    results = upload_files(file_path, tmpdir, rsa_path=key_path)
    assert 5 == len(results.outputs)


def test_assertion_types_and_extension(tmpdir):
    """
    Given:
    - both types and extensions arguments

    When:
    - Running script

    Then:
    - Validate AssertionError is raises as you shouldn't supply them both.
    """
    with raises(AssertionError):
        upload_files('', tmpdir, types='1,2,3', extensions='1,2,3')
