import pytest

from TransformIndicatorToCSFalconIOC import *


CS_IOC_BY_VALUE = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'type': 'ipv4', 'severity': 'High', 'value': '1.2.3.4',
     'action': 'no_action', 'platforms': ['mac'], 'applied_globally': True, 'source': 'Cortex XSOAR'}]

XSOAR_INDICATOR_BY_VALUE = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'indicator_type': 'IP', 'score': 3, 'value': '1.2.3.4'}]

XSOAR_INDICATOR_FILE = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'indicator_type': 'File', 'score': 1,
     'value': '098f6bcd4621d373cade4e832627b4f6'}]

CS_IOC_FILE = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'type': 'md5', 'severity': 'Informational',
     'value': '098f6bcd4621d373cade4e832627b4f6', 'action': 'no_action', 'platforms': ['mac'], 'source': 'Cortex XSOAR',
     'applied_globally': True}]


@pytest.mark.parametrize('args, xsoar_indicator, cs_ioc', [
    ({"query": "value=1.2.3.4", "action": "no_action", "platforms": "mac", "applied_globally": True},
     XSOAR_INDICATOR_BY_VALUE, CS_IOC_BY_VALUE),
    ({"query": "type:File", "action": "no_action", "platforms": "mac", "applied_globally": True}, XSOAR_INDICATOR_FILE,
     CS_IOC_FILE)])
def test_get_indicators_by_query(mocker, args, xsoar_indicator, cs_ioc):
    mocker.patch('TransformIndicatorToCSFalconIOC.execute_command', return_value=xsoar_indicator)
    mocker.patch.object(demisto, 'args', return_value=args)
    assert get_indicators_by_query() == cs_ioc


def test_get_indicators_by_query_no_indicators(mocker):
    mocker.patch('TransformIndicatorToCSFalconIOC.execute_command', return_value=[])
    mocker.patch.object(demisto, 'args', return_value={"query": "value=1.2.3.4", "action": "no_action",
                                                       "platforms": "mac", "applied_globally": True})
    assert get_indicators_by_query() == []
