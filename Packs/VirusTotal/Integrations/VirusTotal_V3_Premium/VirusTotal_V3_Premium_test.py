from datetime import datetime

import pytest
from VirusTotal_V3_Premium import get_last_run_time, \
    get_time_range_object, \
    decrease_data_size, \
    fetch_incidents, \
    Client, convert_epoch_to_readable
from dateparser import parse


class TestTimeHelpers:
    """Will not pass locally, will pass in our build only"""

    def test_get_last_run_time_first_fetch(self, mocker):
        mocker.patch('VirusTotal_V3_Premium.parse', return_value=datetime(2019, 12, 29, 22, 0))
        params = {'first_fetch': '3 days'}
        assert get_last_run_time(params=params, last_run={}) == datetime(2019, 12, 29, 22, 0)

    def test_get_last_run_time_with_last_run(self):
        assert get_last_run_time(last_run={'date': '2020-01-01T20:00:00'}) == datetime(2020, 1, 1, 20, 0)

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


class TestHelpers:
    def test_convert_epoch_to_readable(self):
        key = 'creation_date'
        assert parse(convert_epoch_to_readable({key: 1617056782}, [key])[key])

    def test_convert_epoch_to_readable_no_key(self):
        assert convert_epoch_to_readable({'something_else': 1617056782}) == {
            'something_else': 1617056782}

    def test_convert_epoch_to_readable_key_not_epoch(self):
        assert convert_epoch_to_readable({'creation_date': 'nothing-is-wrong'}, ['creation_date']) == {
            'creation_date': 'nothing-is-wrong'}
