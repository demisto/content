import demistomock as demisto
import json


def side_effect_demisto_dt(obj, dt):
    if dt == '.=val.toUpperCase()':
        return obj.upper()
    elif dt == '.=true':
        return True
    elif dt == '.=null':
        return None
    return None


def test_main(mocker):
    from RegexReplace import main

    with open('./test_data/test-1.json') as f:
        test_list = json.load(f)

    mocker.patch.object(demisto, 'dt', side_effect=side_effect_demisto_dt)

    for t in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'value': t.get('value'),
            'regex': t.get('regex'),
            'output_format': t.get('output_format'),
            'ignore_case': t.get('ignore_case'),
            'multi_line': t.get('multi_line'),
            'period_matches_newline': t.get('period_matches_newline'),
            'action_dt': t.get('action_dt'),
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(t['result'])
