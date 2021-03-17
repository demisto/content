import json

import pytest
from dateparser import parse

from VirusTotal_V3_Premium import get_last_run_time, get_time_range_object, decrease_data_size, fetch_incidents, Client
import freezegun
from datetime import datetime, timedelta


class TestTimeHelpers:
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


class TestDecreaceDataSize:
    full_attributes_to_remove = {'attributes': {
        'last_analysis_results': 'data',
        'pe_info': 'data',
        'crowdsourced_ids_results': 'data',
        'autostart_locations': 'data',
        'sandbox_verdicts': 'data',
        'sigma_analysis_summary': 'data',
        'popular_threat_classification': 'data',
        'packers': 'data',
        'malware_config': 'data'
    }}

    def test_decrease_data_size_dict(self):
        assert not decrease_data_size(self.full_attributes_to_remove)['attributes']

    def test_decrease_data_size_dict_list(self):
        assert not decrease_data_size([self.full_attributes_to_remove])[0]['attributes']


class TestFetchIncidents:
    class ClientMock(Client):
        pass

    def test_fetch_incidents_with_new_incident(self, mocker):
        mocker.patch.object(
            self.ClientMock, 'list_notifications',
            return_value={'data': [{'attributes': {'date': 1613473604}}]}
        )
        fetch_time = parse('1613473604')
        incidents, time = fetch_incidents(self.ClientMock, {}, fetch_time)
        assert incidents[0]['occurred'] == '2021-02-16T13:06:44Z'
        assert time == fetch_time + timedelta(seconds=1)

    def test_fetch_incidents_with_no_incidents(self, mocker):
        """fetch time should not change"""
        mocker.patch.object(
            self.ClientMock, 'list_notifications',
            return_value={'data': []}
        )
        fetch_time = parse('1613473604')
        incidents, time = fetch_incidents(self.ClientMock, {}, fetch_time)
        assert not incidents
        assert time == fetch_time
