from ThreatConnect_v2 import calculate_freshness_time
from freezegun import freeze_time
import pytest


data_test_calculate_freshness_time = [
    (0, '2020-04-20'),
    (1, '2020-04-19')
]


@freeze_time('2020-04-20')
@pytest.mark.parametrize('freshness, time_out', data_test_calculate_freshness_time)
def test_calculate_freshness_time(freshness, time_out):
    time_out = f'{time_out}T00:00:00Z'
    output = calculate_freshness_time(freshness)
    assert output == time_out, f'calculate_freshness_time({freshness})\n\treturns: {output}\n\tinstead: {time_out}'


