import demistomock as demisto
import json


def test_main(mocker):
    from RegexExpand import main

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    for t in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'value': t.get('value'),
            'regex': t.get('regex'),
            'text': t.get('text'),
            'template': t.get('template'),
            'template_type': t.get('template_type'),
            'value_takes': t.get('value_takes'),
            'flags': t.get('flags'),
            'search_limit': t.get('search_limit')
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]

        lhs = results
        rhs = t['result']
        assert json.dumps(lhs) == json.dumps(rhs)
