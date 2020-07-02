from PcapFileExtractor import find_files_protocol


def test_find_protocol():
    file_path = './TestData/tftp_rrq.pcap'
    protocol, _ = find_files_protocol(file_path)
    assert 'tftp' == protocol

