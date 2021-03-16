import pytest

from VirusTotal_V3_Premium import get_last_run_time, get_time_range_object
import freezegun
from datetime import datetime


class TestHelpers:
    @freezegun.freeze_time('2020-01-01T20:00:00Z')
    def test_get_last_run_time_first_fetch(self):
        params = {'first_fetch': '3 days'}
        assert get_last_run_time(params=params, last_run={}) == datetime(2019, 12, 29, 22, 0)

    def test_get_last_run_time_with_last_run(self):
        assert get_last_run_time(last_run={'date': '2020-01-01T20:00:00'}) == datetime(2020, 1, 1, 20, 0)

    @freezegun.freeze_time('2020-01-01T20:00:00Z')
    @pytest.mark.parametrize('start_time, end_time, start_epoch, end_epoch', [
        ('3 days', None, 1577656800, 1577908800),
        ('3 days', 'today', 1577656800, 1577916000),
        ('2020-01-01T20:00:00', '2020-01-01T22:00:00', 1577908800, 1577916000)
    ])
    def test_get_time_range_object(self, start_time, end_time, start_epoch, end_epoch):
        assert get_time_range_object(start_time, end_time) == {'start': start_epoch, 'end': end_epoch}

    @pytest.mark.parametrize('start_time, end_time', [
        ('not a real date', None),
        ('not a real date', 'not a real date'),
        (None, 'today')
    ])
    def test_get_time_range_object_raise_error(self, start_time, end_time):
        with pytest.raises(AssertionError):
            get_time_range_object(start_time, end_time)

    def test_get_time_range_object_empty_case(self):
        assert get_time_range_object('', '') == {}
