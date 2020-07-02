from tempfile import mkdtemp
import os

from PcapFileExtractor import find_files_protocol, extract_files


def test_find_protocol():
    file_path = './TestData/tftp_rrq.pcap'
    protocol, _ = find_files_protocol(file_path)
    assert 'tftp' == protocol


def test_extract_files():
    dir_path = mkdtemp()
    file_path = './TestData/tftp_rrq.pcap'
    extract_files(file_path, dir_path)
    assert os.path.isfile(f'{dir_path}/rfc1350.txt')
