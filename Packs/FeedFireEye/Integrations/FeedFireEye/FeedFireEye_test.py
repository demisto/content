import random

import pytest
import requests_mock
from FeedFireEye import Client, STIX21Processor
from freezegun import freeze_time

import demistomock as demisto


def create_client(public_key: str = 'public_key', private_key: str = 'secret_key',
                  polling_timeout: int = 20, insecure: bool = False, proxy: bool = False):
    return Client(public_key, private_key, polling_timeout, insecure, proxy)


def test_get_access_token_with_valid_token_in_context():
    demisto.setIntegrationContext(
        {
            'auth_token': 'Token',
            'expiration_time': 11740347200
        }
    )

    client = create_client()
    assert client.get_access_token() == 'Token'


def test_get_access_token_with_invalid_token_in_context(mocker):
    mocker.patch.object(Client, 'fetch_new_access_token', return_value='New Access Token')
    demisto.setIntegrationContext(
        {
            'auth_token': 'Token',
            'expiration_time': 740347200
        }
    )

    client = create_client()
    assert client.get_access_token() == 'New Access Token'


@freeze_time("1993-06-17 11:00:00 GMT")
def test_parse_access_token_expiration_time():
    for i in range(5):
        random_value = random.randint(0, 1000)
        # 740314800 is the epoch converted time of 1993-06-17 11:00:00
        assert Client.parse_access_token_expiration_time(random_value) - 740314800 == random_value


FETCH_INDICATORS_PACKAGE = [
    (
        'https://api.intelligence.fireeye.com/collections/indicators/objects?length=1000',
        200,
        {
            'objects': [
                {
                    'type': 'indicator'
                },
                {
                    'type': 'relationship',
                    'id': 'relationship1'
                },
                {
                    'type': 'malware',
                    'id': 'malware1'
                },
                {
                    'type': 'indicator'
                },
            ]
        },
        (
            [{'type': 'indicator'}, {'type': 'indicator'}],
            {'relationship1': {'type': 'relationship', 'id': 'relationship1'}},
            {'malware1': {'type': 'malware', 'id': 'malware1'}}
        )
    ),
    (
        'https://api.intelligence.fireeye.com/collections/indicators/objects?length=1000',
        204,
        {},
        ([], {}, {})
    ),
    (
        'https://api.intelligence.fireeye.com/collections/indicators/objects?length=1000',
        202,
        {},
        ([], {}, {})
    )
]


@pytest.mark.parametrize('url, status_code, json_data, expected_result', FETCH_INDICATORS_PACKAGE)
def test_fetch_indicators_from_api(mocker, url, status_code, json_data, expected_result):
    with requests_mock.Mocker() as m:
        mocker.patch.object(Client, 'fetch_new_access_token', return_value='New Access Token')
        mocker.patch.object(demisto, 'info')
        mocker.patch.object(demisto, 'debug')

        m.get(url, status_code=status_code, json=json_data)
        client = create_client()

        fetch_result = client.fetch_all_indicators_from_api(-1)

        for i in range(3):
            assert fetch_result[i] == expected_result[i]

        if status_code == 204:
            assert demisto.info.call_args[0][0] == \
                   'FireEye Feed info - API Status Code: 204 No Content Available for this timeframe.'

        elif status_code != 200:
            assert demisto.debug.call_args[0][0] == \
                   f'FireEye Feed debug - API Status Code: {status_code}' \
                   ' Error Reason: {}'


FETCH_REPORTS_PACKAGE = [
    (
        'https://api.intelligence.fireeye.com/collections/reports/objects?length=100',
        200,
        {
            'objects': [
                {
                    'type': 'report',
                    'id': 'report1'
                },
                {
                    'type': 'report',
                    'id': 'report2'
                },
            ]
        },
        [{'type': 'report', 'id': 'report1'}, {'type': 'report', 'id': 'report2'}]
    ),
    (
        'https://api.intelligence.fireeye.com/collections/reports/objects?length=100',
        204,
        {},
        []
    )
]


@pytest.mark.parametrize('url, status_code, json_data, expected_result', FETCH_REPORTS_PACKAGE)
def test_fetch_reports_from_api(mocker, url, status_code, json_data, expected_result):
    with requests_mock.Mocker() as m:
        mocker.patch.object(Client, 'fetch_new_access_token', return_value='New Access Token')
        mocker.patch.object(demisto, 'debug')

        m.get(url, status_code=status_code, json=json_data)
        client = create_client()

        fetch_result = client.fetch_all_reports_from_api(-1)

        assert fetch_result == expected_result

        if status_code != 200:
            assert demisto.debug.call_args[0][0] == \
                   f'FireEye Feed debug - API Status Code: {status_code}' \
                   ' Error Reason: {}'


PROCESS_INDICATOR_VALUE_PACKAGE = [
    (
        "[file:hashes.MD5='1234' OR "
        "file:hashes.'SHA-1'='12345' OR "
        "file:hashes.'SHA-256'='123456']",
        (
            ['file'],
            ['1234'],
            {
                'MD5': '1234',
                'SHA-1': '12345',
                'SHA-256': '12345'
            }
        )
    ),
    (
        "[domain-name:value='1234.com']",
        (['domain-name'], ['1234.com'], {})
    ),
    (
        "[domain-name:value='1234.com' AND url:value='www.abc.1245.com']",
        (['domain-name', 'url'], ['1234.com', 'www.abc.1245.com'], {})
    )
]


@pytest.mark.parametrize('pattern_value, expected_result', PROCESS_INDICATOR_VALUE_PACKAGE)
def test_process_indicator_value(pattern_value, expected_result):
    process_result = STIX21Processor.process_indicator_value(pattern_value)

    for i in range(2):
        assert process_result[i] == expected_result[i]
