import demistomock as demisto
import json


def side_effect_demisto_dt(ctx, dt):
    def _get_value(ctx, dt):
        if isinstance(ctx, list):
            ret = []
            for obj in ctx:
                ret.append(side_effect_demisto_dt(obj, dt))
            return ret
        elif isinstance(ctx, dict):
            parts = dt.split('.')
            for part in parts:
                if ctx and part in ctx:
                    ctx = ctx[part]
                else:
                    return None
            return ctx
        return None

    if dt == '.Size=val+1':
        return _get_value(ctx, 'Size') + 1
    return _get_value(ctx, dt)


def test_main(mocker):
    from ExtFilter import main

    with open('./test_data/test-1.json') as f:
        test_list = json.load(f)

    mocker.patch.object(demisto, 'dt', side_effect=side_effect_demisto_dt)

    for t in test_list:
        for eval in t['eval']:
            mocker.patch.object(demisto, 'args', return_value={
                'value': eval['value'],
                'path': t.get('path'),
                'operation': t.get('operation'),
                'filter': t.get('filter'),
                'ctx_demisto': t.get('ctx_demisto'),
                'ctx_inputs': t.get('ctx_inputs'),
                'ctx_lists': t.get('ctx_lists'),
                'ctx_incident': t.get('ctx_incident')
            })
            mocker.patch.object(demisto, 'results')
            main()
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]
            '''
            if json.dumps(results) != json.dumps(eval['result']):
                print(json.dumps(t, indent=2))
                print(json.dumps(results, indent=2))
            '''
            assert json.dumps(results) == json.dumps(eval['result'])
