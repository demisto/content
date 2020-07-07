import os

from PcapFileExtractor import upload_files

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

    file_path = 'TestData/tftp_rrq.pcap'
    results = upload_files(file_path=file_path, dir_path=tmpdir)
    assert 'Pcap Extracted Files' in results.readable_output
    assert OUTPUTS == results.outputs
    assert os.path.isfile(os.path.join(tmpdir, 'rfc1350.txt'))
