import demistomock as demisto
import json
import sys


def side_effect_sys_exit(code):
    pass


def test_main(mocker):
    from FileCreateAndUploadV2 import main

    mocker.patch.object(sys, 'exit', side_effect=side_effect_sys_exit)

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for eval in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'filename': eval['filename'],
            'data': eval.get('data'),
            'data_encoding': eval.get('data_encoding'),
            'entryId': eval.get('entryId')
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert (eval['ok'] and results['Type'] == 3) or ((not eval['ok']) and results['Type'] != 3)
