import demistomock as demisto
from FormatTemplate import main
import json


class TestFormatTemplate:
    def __side_effect_demisto_dt(self, obj, dt):
        return demisto.get(obj, dt)

    def test_main(self, mocker):
        with open('./test_data/test.json') as f:
            test_list = json.load(f)

        mocker.patch.object(demisto, 'dt', side_effect=self.__side_effect_demisto_dt)

        for t in test_list:
            mocker.patch.object(demisto, 'args', return_value=t['args'])
            mocker.patch.object(demisto, 'results')
            main()
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]
            assert json.dumps(results) == json.dumps(t['results'])
