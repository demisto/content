import pytest

from TransformIndicatorToMSDefenderIOC import *


MSDE_IOC = [
    {'expirationTime': '2022-02-10T17:02:59.193836+02:00', 'creationTimeDateTimeUtc': '2022-01-22T12:55:20.20775+02:00',
     'indicatorType': 'IpAddress', 'lastUpdateTime': '2022-02-03T17:02:59.232834+02:00', 'Severity': 'High',
     'indicatorValue': '1.2.3.4', 'action': 'Alert', 'title': 'XSOAR Indicator title',
     'description': 'XSOAR Indicator description'}]

XSOAR_INDICATOR = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'firstSeen': '2022-01-22T12:55:20.20775+02:00',
     'indicator_type': 'IP', 'lastSeen': '2022-02-03T17:02:59.232834+02:00', 'score': 3,
     'value': '1.2.3.4'}]


@pytest.mark.parametrize('args', [
    ({"query": "value=1.2.3.4", "action": "Alert"}),
    ({"query": "value=1.2.3.4 and indicator_type=IP", "action": "Alert"}),
    ({"query": "value=1.2.3.4 and indicator_type=IP and score=3", "action": "Alert"}),
])
def test_get_indicators_by_query(mocker, args):
    mocker.patch('TransformIndicatorToMSDefenderIOC.execute_command', return_value=XSOAR_INDICATOR)
    mocker.patch.object(demisto, 'args', return_value=args)
    assert get_indicators_by_query() == MSDE_IOC
