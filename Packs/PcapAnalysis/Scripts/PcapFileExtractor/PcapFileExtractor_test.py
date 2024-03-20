import os

import pytest

from CommonServerPython import CommandResults
from PcapFileExtractor import filter_files, upload_files, INCLUSIVE, EXCLUSIVE
from magic import Magic
from pytest import raises
OUTPUTS = [
    {
        'FileMD5': '6e3a2e46a6c0e0e101b4f2f39830e38b',
        'FileSHA1': '7ce55583ec108e013cd820b6a2e7ae053f0a8863',
        'FileSHA256': 'f33c934f04a2d862a1918aa8dd374752ced3108936ea04e2b736a4976159f0ff',
        'FileName': 'default',
        'FileSize': 346,
        'FileExtension': ''
    },
    {
        'FileMD5': '6e3a2e46a6c0e0e101b4f2f39830e38b',
        'FileSHA1': '7ce55583ec108e013cd820b6a2e7ae053f0a8863',
        'FileSHA256': 'f33c934f04a2d862a1918aa8dd374752ced3108936ea04e2b736a4976159f0ff',
        'FileName': 'default(1)',
        'FileSize': 346,
        'FileExtension': ''
    }
]


def test_extract_files(tmpdir):
    """1
    Given
    - Valid Pcap File.
    When
    - Extracting the file from the pcap.
    Then
    - ensure file is being extracted correctly.
    - ensure outputs are correct.
    """

    file_path = './TestData/tftp-dup.pcap'
    results = upload_files(file_path, tmpdir)
    if type(results) is CommandResults:     # Otherwise 'results' has not 'readable_output' or 'outputs' attributes.
        assert 'Pcap Extracted Files' in results.readable_output
        assert OUTPUTS == results.outputs
    assert os.path.isfile(os.path.join(tmpdir, 'default'))


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
