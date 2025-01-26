import demistomock as demisto
from SetWithTemplate import main
import json


class SideEffectExecuteCommand:
    def __init__(self, obj):
        self.__obj = obj

    def execute_command(self, cmd, args, fail_on_error):
        val = None
        if cmd == 'getList':
            try:
                name = args['listName']
                if isinstance(self.__obj, dict):
                    val = self.__obj.get(name)

                if val is None:
                    val = demisto.get(self.__obj, name)
            except Exception:
                pass

        if val is None:
            if fail_on_error:
                raise ValueError('not found')
            else:
                return False, None
        else:
            if fail_on_error:
                raise ValueError('not found')
            else:
                return True, val


class TestSetWithTemplate:
    def __side_effect_demisto_dt(self, obj, dt):
        if isinstance(obj, dict):
            val = obj.get(dt)
            if val is not None:
                return val

        if dt.startswith('.'):
            key = dt[1:]
            return demisto.get(obj, key) if key else obj
        else:
            return demisto.get(obj, dt)

    def test_main(self, mocker):
        with open('./test_data/test.json') as f:
            test_list = json.load(f)

        mocker.patch.object(demisto, 'dt', side_effect=self.__side_effect_demisto_dt)

        for t in test_list:
            mocker.patch('SetWithTemplate.execute_command', side_effect=SideEffectExecuteCommand(t.get('lists')).execute_command)
            mocker.patch.object(demisto, 'incident', return_value=t.get('incident'))
            mocker.patch.dict(demisto.callingContext, {'context.PlaybookInputs': t.get('inputs')})
            mocker.patch.object(demisto, 'args', return_value=t['args'])
            mocker.patch.object(demisto, 'results')
            main()
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]
            entry_context = results.get('EntryContext')
            assert json.dumps(entry_context) == json.dumps(t['entry_context'])
