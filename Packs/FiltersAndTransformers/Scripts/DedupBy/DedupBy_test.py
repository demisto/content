import demistomock as demisto
import DedupBy
import json


def test_1(mocker):
    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for case in test_list:
        value = case['value']
        expected = case['result']
        for args in case.get('args') or [{}]:
            keys = args.get('keys')

            mocker.patch.object(demisto, 'args', return_value={
                'value': value,
                'keys': keys
            })
            mocker.patch.object(DedupBy, 'return_results')
            DedupBy.main()
            assert DedupBy.return_results.call_count == 1
            ret = DedupBy.return_results.call_args[0][0]
            assert json.dumps(ret) == json.dumps(expected)
