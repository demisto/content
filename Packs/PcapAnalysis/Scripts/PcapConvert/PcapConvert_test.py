import demistomock as demisto
import json


def test_main(mocker):
    """
    Given:
    - PCAP values are given with control parameters

    When:
    - Running PcapConvert

    Then:
    - Validate results output that returned to CortexSOAR
    """
    from PcapConvert import main

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for t in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'value': t['value'],
            'path': t.get('path'),
            'pcap_type': t.get('pcap_type'),
            'error_action': t.get('error_action')
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(t['result'])
