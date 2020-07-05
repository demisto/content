import os

from PcapFileExtractor import find_files_packets, upload_files


def test_find_protocol():
    file_path = './TestData/tftp_rrq.pcap'
    protocol, _ = find_files_packets(file_path)
    assert 'tftp' == protocol


def test_extract_files(tmpdir):
    file_path = 'TestData/tftp_rrq.pcap'
    results = upload_files(file_path=file_path, dir_path=tmpdir)
    assert 'Pcap Extracted Files' in results.readable_output
    assert os.path.isfile(os.path.join(tmpdir, 'rfc1350.txt'))
