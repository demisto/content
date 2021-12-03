import demistomock as demisto
import json


def test_main(mocker):
    from MapPattern import main

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for t in test_list:
        for pattern in t['patterns']:
            mocker.patch.object(demisto, 'args', return_value={
                'value': pattern['value'],
                'algorithm': t['algorithm'],
                'caseless': t['caseless'],
                'priority': t['priority'],
                'context': t['context'],
                'flags': t['flags'],
                'comparison_fields': t['comparison_fields'],
                'mappings': t['mappings']
            })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(pattern['result'])
