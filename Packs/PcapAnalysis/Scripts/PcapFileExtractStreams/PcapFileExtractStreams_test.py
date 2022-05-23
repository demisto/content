import demistomock as demisto
import json


def side_effect_demisto_getFilePath(entry_id):
    return {'path': entry_id}


def test_main(mocker):
    """
    Given:
    - PCAP files are given with control parameters

    When:
    - Running PcapFileExtractStreams

    Then:
    - Validate results output that returned to CortexSOAR
    """
    from PcapFileExtractStreams import main

    mocker.patch.object(demisto, 'getFilePath', side_effect=side_effect_demisto_getFilePath)

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for t in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'entry_id': t['entry_id'],
            'bin2txt_mode': t.get('bin2txt_mode'),
            'pcap_filter': t.get('pcap_filter'),
            'rsa_decrypt_key': t.get('rsa_decrypt_key'),
            'wpa_password': t.get('wpa_password'),
            'filter_keys': t.get('filter_keys'),
            'verbose': t.get('verbose'),
            'server_ports': t.get('server_ports'),
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1

        results = demisto.results.call_args[0][0]
        contents = results['Contents']
        assert json.dumps(contents) == json.dumps(t['contents'])
