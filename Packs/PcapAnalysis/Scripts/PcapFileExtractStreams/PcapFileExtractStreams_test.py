import demistomock as demisto
import json


def equals_object(obj1, obj2) -> bool:
    if type(obj1) is not type(obj2):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for _i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


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

    with open('./test_data/test-1.json') as f:
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
        assert equals_object(contents, t['contents'])
