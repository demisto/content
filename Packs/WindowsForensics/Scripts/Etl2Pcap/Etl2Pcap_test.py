import os
import Etl2Pcap as etl2pcap


def test_etl_to_pcap():
    output_path = './test_data/pcap.pcap'
    etl2pcap.etl_to_pcap('./test_data/etl_example.etl', output_path)
    assert os.path.isfile(output_path)
