import demistomock as demisto
import TimeComponents
import json
import freezegun
from datetime import datetime, UTC


class TestTimeComponents:
    @freezegun.freeze_time('2022-01-23 12:34:56')
    def test_real_time(self, mocker, monkeypatch):
        now = datetime(2022, 1, 23, 12, 34, 56, tzinfo=UTC)
        assert now == TimeComponents.parse_date_time_value(None).astimezone(UTC)

        now = datetime(2022, 1, 23, 12, 34, 56, tzinfo=UTC)
        assert now == TimeComponents.parse_date_time_value('now').astimezone(UTC)

    @freezegun.freeze_time('2022-01-23 12:34:56')
    def test_main(self, mocker, monkeypatch):
        with open('./test_data/test.json') as f:
            test_list = json.load(f)

        for test_case in test_list:
            mocker.patch.object(demisto, 'args', return_value=test_case['args'])
            mocker.patch.object(demisto, 'results')
            TimeComponents.main()
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]

            r = results
            t = test_case['results']
            if isinstance(results, dict):
                r = {k: int(v) if isinstance(v, float) else v for k, v in results.items()}
                t = {k: int(v) if isinstance(v, float) else v for k, v in test_case['results'].items()}
            rstr = json.dumps(r)
            tstr = json.dumps(t)
            if rstr != tstr:
                print(test_case.get('comments'))
                assert rstr == tstr
