import demistomock as demisto
from TimeComponents import main
import json
import datetime
import pytest


class TestTimeComponents:
    @pytest.mark.freeze_time('2022-01-23 12:34:56')
    def test_main(self, mocker, monkeypatch):
        with open('./test_data/test.json', 'r') as f:
            test_list = json.load(f)

        assert datetime.datetime.utcnow() == datetime.datetime(2022, 1, 23, 12, 34, 56)

        for test_case in test_list:
            mocker.patch.object(demisto, 'args', return_value=test_case['args'])
            mocker.patch.object(demisto, 'results')
            main()
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]

            assert len(results) == len(test_case['results'])

            if isinstance(results, dict):
                for k, v in results.items():
                    if isinstance(results[k], float):
                        assert int(results[k]) == int(test_case['results'][k])
                    else:
                        assert results[k] == test_case['results'][k]
            else:
                assert json.dumps(results) == json.dumps(test_case['results'])
