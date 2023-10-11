# coding=utf-8

import pytest
from ScheduleGenericPolling import is_value_sanitized


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
