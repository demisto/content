"""Armis Integration for Cortex XSOAR - Unit Tests file

This file contains the Pytest Tests for the Armis Integration
"""
import time

import pytest

import CommonServerPython


def test_untag_device_success(requests_mock):
    from Armis import Client, untag_device_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    requests_mock.delete('https://test.com/api/v1/devices/1/tags/', json={})

    client = Client('secret-example', 'https://test.com/api/v1')
    assert untag_device_command(client, '1', 'test-tag') == 'Untagging successful'


def test_untag_device_failure(requests_mock):
    from Armis import Client, untag_device_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    requests_mock.delete('https://test.com/api/v1/devices/1/tags/', json={}, status_code=400)

    client = Client('secret-example', 'https://test.com/api/v1')
    with pytest.raises(CommonServerPython.DemistoException):
        untag_device_command(client, '1', 'test-tag')


def test_tag_device(requests_mock):
    from Armis import Client, tag_device_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    requests_mock.post('https://test.com/api/v1/devices/1/tags/', json={})

    client = Client('secret-example', 'https://test.com/api/v1')
    assert tag_device_command(client, '1', ['test-tag']) == 'Tagging successful'


def test_update_alert_status(requests_mock):
    from Armis import Client, update_alert_status_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    requests_mock.patch('https://test.com/api/v1/alerts/1/', json={})

    client = Client('secret-example', 'https://test.com/api/v1')
    assert update_alert_status_command(client, '1', 'UNHANDLED') == 'Alert status updated successfully'


def test_search_alerts(requests_mock):
    from Armis import Client, search_alerts_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    url = 'https://test.com/api/v1/search/?aql='
    url += '+'.join([
        'in%3Aalerts',
        'timeFrame%3A%223+days%22',
        'riskLevel%3AHigh%2CMedium',
        'status%3AUNHANDLED%2CRESOLVED',
        'type%3A%22Policy+Violation%22',
        'alertId%3A%281%29',
    ])

    mock_results = {
        'data': {
            'results': []
        }
    }

    requests_mock.get(url, json=mock_results)

    client = Client('secret-example', 'https://test.com/api/v1')
    response = search_alerts_command(
        client,
        ['Policy Violation'],
        ['High', 'Medium'],
        ['UNHANDLED', 'RESOLVED'],
        '1',
        '3 days'
    )
    assert response == 'No results found'

    example_alerts = [
        {
            "activityIds": [
                19625045,
                19625223,
                19625984,
                19626169,
                19626680,
                19626818,
                19628162,
                19628359
            ],
            "activityUUIDs": [
                "1-uS23YBAAAC-vCTQOhA",
                "7eut23YBAAAC-vCTkOhB",
                "Oes13HYBAAAC-vCTcel0",
                "T-tU3HYBAAAC-vCTyunu",
                "mevb3HYBAAAC-vCT9-nn",
                "uev33HYBAAAC-vCTa-mg",
                "P-u33XYBAAAC-vCTlOpq",
                "SevT3XYBAAAC-vCTA-o_"
            ],
            "alertId": 1,
            "connectionIds": [
                845993,
                846061,
                846157,
                846308
            ],
            "description": "Smart TV started connection to Corporate Network",
            "deviceIds": [
                165722,
                532
            ],
            "severity": "Medium",
            "status": "Unhandled",
            "time": "2021-01-07T06:39:13.320893+00:00",
            "title": "Smart TV connected to Corporate network",
            "type": "System Policy Violation"
        }
    ]
    mock_results['data']['results'] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_alerts_command(
        client,
        ['Policy Violation'],
        ['High', 'Medium'],
        ['UNHANDLED', 'RESOLVED'],
        '1',
        '3 days'
    )
    assert response.outputs == example_alerts


def test_search_alerts_by_aql(requests_mock):
    from Armis import Client, search_alerts_by_aql_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    url = 'https://test.com/api/v1/search/?aql='
    url += '+'.join([
        'in%3Aalerts',
        'timeFrame%3A%223+days%22',
        'riskLevel%3AHigh%2CMedium',
        'status%3AUNHANDLED%2CRESOLVED',
        'type%3A%22Policy+Violation%22',
    ])

    mock_results = {
        'data': {
            'results': []
        }
    }

    requests_mock.get(url, json=mock_results)

    client = Client('secret-example', 'https://test.com/api/v1')
    response = search_alerts_by_aql_command(
        client,
        'timeFrame:"3 days" riskLevel:High,Medium status:UNHANDLED,RESOLVED type:"Policy Violation"'
    )
    assert response == 'No alerts found'

    example_alerts = [
        {
            "activityIds": [
                19625045,
                19625223,
                19625984,
                19626169,
                19626680,
                19626818,
                19628162,
                19628359
            ],
            "activityUUIDs": [
                "1-uS23YBAAAC-vCTQOhA",
                "7eut23YBAAAC-vCTkOhB",
                "Oes13HYBAAAC-vCTcel0",
                "T-tU3HYBAAAC-vCTyunu",
                "mevb3HYBAAAC-vCT9-nn",
                "uev33HYBAAAC-vCTa-mg",
                "P-u33XYBAAAC-vCTlOpq",
                "SevT3XYBAAAC-vCTA-o_"
            ],
            "alertId": 1,
            "connectionIds": [
                845993,
                846061,
                846157,
                846308
            ],
            "description": "Smart TV started connection to Corporate Network",
            "deviceIds": [
                165722,
                532
            ],
            "severity": "Medium",
            "status": "Unhandled",
            "time": "2021-01-07T06:39:13.320893+00:00",
            "title": "Smart TV connected to Corporate network",
            "type": "System Policy Violation"
        }
    ]
    mock_results['data']['results'] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_alerts_by_aql_command(
        client,
        'timeFrame:"3 days" riskLevel:High,Medium status:UNHANDLED,RESOLVED type:"Policy Violation"'
    )
    assert response.outputs == example_alerts


def test_search_devices(requests_mock):
    from Armis import Client, search_devices_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    url = 'https://test.com/api/v1/search/?aql=in%3Adevices+timeFrame%3A%223+days%22+deviceId%3A%281%29'
    mock_results = {
        'data': {
            'results': []
        }
    }

    requests_mock.get(url, json=mock_results)

    client = Client('secret-example', 'https://test.com/api/v1')
    response = search_devices_command(client, None, '1', None, None, None, None, '3 days')
    assert response == 'No devices found'

    example_alerts = [
        {
            "accessSwitch": None,
            "category": "Network Equipment",
            "dataSources": [
                {
                    "firstSeen": "2021-01-15T03:26:56+00:00",
                    "lastSeen": "2021-01-16T18:16:32+00:00",
                    "name": "Meraki",
                    "types": [
                        "WLC"
                    ]
                }
            ],
            "firstSeen": "2021-01-15T03:26:56+00:00",
            "id": 1,
            "ipAddress": None,
            "ipv6": None,
            "lastSeen": "2021-01-16T18:16:32+00:00",
            "macAddress": "f8:ca:59:53:91:ce",
            "manufacturer": "NetComm Wireless",
            "model": "NetComm device",
            "name": "Aussie Broadband 0079",
            "operatingSystem": None,
            "operatingSystemVersion": None,
            "riskLevel": 5,
            "sensor": {
                "name": "win-wap-tom-Upstairs",
                "type": "Access Point"
            },
            "site": {
                "location": "51 Longview Court, Thomastown Vic 3074",
                "name": "Winslow Workshop - Thomastown"
            },
            "tags": [
                "Access Point",
                "Off Network",
                "SSID=Aussie Broadband 0079"
            ],
            "type": "Access Point Interface",
            "user": "",
            "visibility": "Full"
        }
    ]
    mock_results['data']['results'] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_devices_command(client, None, '1', None, None, None, None, '3 days')
    assert response.outputs == example_alerts


def test_search_devices_by_aql(requests_mock):
    from Armis import Client, search_devices_by_aql_command
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post('https://test.com/api/v1/access_token/?secret_key=secret-example', json=mock_token)

    url = 'https://test.com/api/v1/search/?aql=in%3Adevices+timeFrame%3A%223+days%22+deviceId%3A%281%29'
    mock_results = {
        'data': {
            'results': []
        }
    }

    requests_mock.get(url, json=mock_results)

    client = Client('secret-example', 'https://test.com/api/v1')
    response = search_devices_by_aql_command(client, 'timeFrame:"3 days" deviceId:(1)')
    assert response == 'No devices found'

    example_alerts = [
        {
            "accessSwitch": None,
            "category": "Network Equipment",
            "dataSources": [
                {
                    "firstSeen": "2021-01-15T03:26:56+00:00",
                    "lastSeen": "2021-01-16T18:16:32+00:00",
                    "name": "Meraki",
                    "types": [
                        "WLC"
                    ]
                }
            ],
            "firstSeen": "2021-01-15T03:26:56+00:00",
            "id": 1,
            "ipAddress": None,
            "ipv6": None,
            "lastSeen": "2021-01-16T18:16:32+00:00",
            "macAddress": "f8:ca:59:53:91:ce",
            "manufacturer": "NetComm Wireless",
            "model": "NetComm device",
            "name": "Aussie Broadband 0079",
            "operatingSystem": None,
            "operatingSystemVersion": None,
            "riskLevel": 5,
            "sensor": {
                "name": "win-wap-tom-Upstairs",
                "type": "Access Point"
            },
            "site": {
                "location": "51 Longview Court, Thomastown Vic 3074",
                "name": "Winslow Workshop - Thomastown"
            },
            "tags": [
                "Access Point",
                "Off Network",
                "SSID=Aussie Broadband 0079"
            ],
            "type": "Access Point Interface",
            "user": "",
            "visibility": "Full"
        }
    ]
    mock_results['data']['results'] = example_alerts

    requests_mock.get(url, json=mock_results)
    response = search_devices_by_aql_command(client, 'timeFrame:"3 days" deviceId:(1)')
    assert response.outputs == example_alerts
