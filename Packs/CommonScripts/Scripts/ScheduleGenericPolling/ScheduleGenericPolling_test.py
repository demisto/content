
from freezegun import freeze_time
import pytest
from ScheduleGenericPolling import calculate_end_time, is_value_sanitized, parseIds


@pytest.mark.parametrize('value, expected_result',
                         [
                             (None, None),
                             ([1, 2, 3], "1,2,3"),
                             (["a", "b", "c"], "a,b,c"),
                         ])
def test_parseIds(value, expected_result):
    result = parseIds(value)
    assert result == expected_result


@pytest.mark.parametrize('value, expected_result',
                         [
                             (0, '2023-04-01 00:00:00'),
                             (17, '2023-04-01 00:17:00'),
                             (70, '2023-04-01 01:10:00'),
                         ])
@freeze_time("2023-04-01 00:00:00")
def test_calculate_end_time(value, expected_result):
    result = calculate_end_time(value)
    assert result == expected_result


@pytest.mark.parametrize('value, expected_result',
                         [
                             ("1234", True),
                             ("additionalPollingCommandArgNames", False),
                             ("ab\" additionalPollingCommandArgNames", False),
                             ("abc\\\" additionalPollingCommandArgNames", False),
                         ])
def test_is_value_sanitized(value, expected_result):
    result = is_value_sanitized(value)
    assert result == expected_result
