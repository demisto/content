import demistomock as demisto
import json


def test_main(mocker):
    """
    Given:
    - PCAP values are given with control parameters

    When:
    - Running PcapExtractStreams

    Then:
    - Validate results output that returned to CortexSOAR
    """
    from PcapExtractStreams import main

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for t in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'value': t['value'],
            'path': t.get('path'),
            'pcap_type': t.get('pcap_type'),
            'bin2txt_mode': t.get('bin2txt_mode'),
            'pcap_filter': t.get('pcap_filter'),
            'rsa_decrypt_key': t.get('rsa_decrypt_key'),
            'wpa_password': t.get('wpa_password'),
            'filter_keys': t.get('filter_keys'),
            'error_action': t.get('error_action'),
            'server_ports': t.get('server_ports'),
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(t['result'])
