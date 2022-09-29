import demistomock as demisto
from TimeComponents import main
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock


class TestTimeComponents:
    def test_main(self, mocker, monkeypatch):
        with open('./test_data/test.json', 'r') as f:
            test_list = json.load(f)

        datetime_mock = MagicMock(spec=datetime, wraps=datetime)
        datetime_mock.utcnow.return_value = datetime(2022, 1, 23, 12, 34, 56, tzinfo=timezone.utc)
        monkeypatch.setattr("TimeComponents.datetime", datetime_mock)

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
                        assert json.dumps({k: int(results[k])}) == json.dumps({k :int(test_case['results'][k])})
                    else:
                        assert json.dumps({k: results[k]}) == json.dumps({k :test_case['results'][k]})
            else:
                assert json.dumps(results) == json.dumps(test_case['results'])
