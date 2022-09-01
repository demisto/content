import pytest

from TransformIndicatorToMSDefenderIOC import *

MSDE_IOC_BY_VALUE = [
    {'expirationTime': '2022-02-10T17:02:59.193836+02:00', 'creationTimeDateTimeUtc': '2022-01-22T12:55:20.20775+02:00',
     'indicatorType': 'IpAddress', 'lastUpdateTime': '2022-02-03T17:02:59.232834+02:00', 'Severity': 'High',
     'indicatorValue': '1.2.3.4', 'action': 'Alert', 'title': 'XSOAR Indicator title',
     'description': 'XSOAR Indicator description'}]

XSOAR_INDICATOR_BY_VALUE = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'firstSeen': '2022-01-22T12:55:20.20775+02:00',
     'indicator_type': 'IP', 'lastSeen': '2022-02-03T17:02:59.232834+02:00', 'score': 3,
     'value': '1.2.3.4'}]

XSOAR_INDICATOR_FILE = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'firstSeen': '2022-01-22T12:55:20.20775+02:00',
     'indicator_type': 'File', 'lastSeen': '2022-02-03T17:02:59.232834+02:00', 'score': 1,
     'value': '098f6bcd4621d373cade4e832627b4f6'}]

MSDE_IOC_FILE = [
    {'expirationTime': '2022-02-10T17:02:59.193836+02:00', 'creationTimeDateTimeUtc': '2022-01-22T12:55:20.20775+02:00',
     'indicatorType': 'FileMd5', 'lastUpdateTime': '2022-02-03T17:02:59.232834+02:00', 'Severity': 'Informational',
     'indicatorValue': '098f6bcd4621d373cade4e832627b4f6', 'action': 'Alert', 'title': 'XSOAR Indicator title',
     'description': 'XSOAR Indicator description'}]

XSOAR_INDICATOR_URL = [
    {'expiration': '2022-02-10T17:02:59.193836+02:00', 'firstSeen': '2022-01-22T12:55:20.20775+02:00',
     'indicator_type': 'URL', 'lastSeen': '2022-02-03T17:02:59.232834+02:00', 'score': 2,
     'value': 'www.example.com'}]

MSDE_IOC_URL = [
    {'expirationTime': '2022-02-10T17:02:59.193836+02:00', 'creationTimeDateTimeUtc': '2022-01-22T12:55:20.20775+02:00',
     'indicatorType': 'Url', 'lastUpdateTime': '2022-02-03T17:02:59.232834+02:00', 'Severity': 'Medium',
     'indicatorValue': 'www.example.com', 'action': 'Alert', 'title': 'XSOAR Indicator title',
     'description': 'XSOAR Indicator description'}]


@pytest.mark.parametrize('args, xsoar_indicator, msde_ioc', [
    ({"query": "value=1.2.3.4", "action": "Alert"}, XSOAR_INDICATOR_BY_VALUE,
     MSDE_IOC_BY_VALUE),
    ({"query": "indicator_type=FILE", "action": "Alert"}, XSOAR_INDICATOR_FILE, MSDE_IOC_FILE),
    ({"query": "value=www.example.com and indicator_type=URL and score=2", "action": "Alert"},
     XSOAR_INDICATOR_URL, MSDE_IOC_URL),
])
def test_get_indicators_by_query(mocker, args, xsoar_indicator, msde_ioc):
    mocker.patch('TransformIndicatorToMSDefenderIOC.execute_command', return_value=xsoar_indicator)
    mocker.patch.object(demisto, 'args', return_value=args)
    assert get_indicators_by_query() == msde_ioc


def test_get_indicators_by_query_no_indicators(mocker):
    mocker.patch('TransformIndicatorToMSDefenderIOC.execute_command', return_value=[])
    mocker.patch.object(demisto, 'args', return_value={"query": "value=1.2.3.4", "action": "Alert"})
    assert get_indicators_by_query() == []
