import random
from typing import Optional

import pytest
import requests_mock
from FeedFireEye import Client, STIX21Processor, FE_CONFIDENCE_TO_REPUTATION, parse_timestamp, \
    handle_first_fetch_timestamp
from freezegun import freeze_time

import demistomock as demisto


def create_client(public_key: str = 'public_key', private_key: str = 'secret_key', threshold: int = 70,
                  reputation_interval: int = 30, polling_timeout: int = 20, insecure: bool = False, proxy: bool = False,
                  tags: list = [], tlp_color: Optional[str] = 'AMBER'):
    return Client(public_key, private_key, threshold, reputation_interval, polling_timeout, insecure, proxy)


def test_get_access_token_with_valid_token_in_context():
    """

    Given:
        - Entry context with a valid authentication token

    When:
        - Getting authentication token

    Then:
        - Returns the auth token from context

    """
    demisto.setIntegrationContext(
        {
            'auth_token': 'Token',
            'expiration_time': 11740347200
        }
    )

    client = create_client()
    assert client.get_access_token() == 'Token'


def test_get_access_token_with_invalid_token_in_context(mocker):
    """

    Given:
        - Entry context with an invalid authentication token

    When:
        - Getting authentication token

    Then:
        - Returns a new fetched auth token

    """
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
    """

    Given:
        - Authentication token validity period

    When:
        - Fetching new authentication token

    Then:
        - Returns the expiration time of the newly fetched token

    """
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
            {'malware1': {'type': 'malware', 'id': 'malware1'}},
            None
        )
    ),
    (
        'https://api.intelligence.fireeye.com/collections/indicators/objects?length=1000',
        204,
        {},
        ([], {}, {}, None)
    ),
    (
        'https://api.intelligence.fireeye.com/collections/indicators/objects?length=1000',
        202,
        {},
        ([], {}, {}, None)
    )
]


@pytest.mark.parametrize('url, status_code, json_data, expected_result', FETCH_INDICATORS_PACKAGE)
def test_fetch_indicators_from_api(mocker, url, status_code, json_data, expected_result):
    """

    Given:
        - Response status code
        - Response data

    When:
        - Fetching indicators from API

    Then:
        - Returns the processed tuple of raw indicators, entities and relationships

    """
    with requests_mock.Mocker() as m:
        mocker.patch.object(Client, 'fetch_new_access_token', return_value='New Access Token')
        mocker.patch.object(demisto, 'info')
        mocker.patch.object(demisto, 'debug')

        m.get(url, status_code=status_code, json=json_data)
        client = create_client()

        if status_code in [200, 204]:
            fetch_result = client.fetch_all_indicators_from_api(-1)

            for i in range(4):
                assert fetch_result[i] == expected_result[i]

            if status_code == 204:
                assert demisto.info.call_args[0][0] == \
                       'FireEye Feed info - API Status Code: 204 No Content Available for this timeframe.'

        else:
            with pytest.raises(SystemExit) as e:
                # return_error reached
                client.fetch_all_indicators_from_api(-1)

            if not e:
                assert False


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
        ([{'type': 'report', 'id': 'report1'}, {'type': 'report', 'id': 'report2'}], None)
    ),
    (
        'https://api.intelligence.fireeye.com/collections/reports/objects?length=100',
        204,
        {},
        ([], None)
    )
]


@pytest.mark.parametrize('url, status_code, json_data, expected_result', FETCH_REPORTS_PACKAGE)
def test_fetch_reports_from_api(mocker, url, status_code, json_data, expected_result):
    """

    Given:
        - Response status code
        - Response data

    When:
        - Fetching reports from API

    Then:
        - Returns the processed list of raw reports

    """
    with requests_mock.Mocker() as m:
        mocker.patch.object(Client, 'fetch_new_access_token', return_value='New Access Token')
        mocker.patch.object(demisto, 'debug')

        m.get(url, status_code=status_code, json=json_data)
        client = create_client()

        if status_code == 200:
            fetch_result = client.fetch_all_reports_from_api(-1)
            assert fetch_result == expected_result

        else:
            with pytest.raises(SystemExit) as e:
                # return_error reached
                client.fetch_all_reports_from_api(-1)

            if not e:
                assert False


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
                'SHA-256': '123456'
            }
        )
    ),
    (
        "[file:hashes.'SHA-1'='12345' OR "
        "file:hashes.'SHA-256'='123456']",
        (
            ['file'],
            ['12345'],
            {
                'SHA-1': '12345',
                'SHA-256': '123456'
            }
        )
    ),
    (
        "[file:hashes.'ssdeep'='12345' OR "
        "file:hashes.'SHA-256'='123456']",
        (
            ['file'],
            ['123456'],
            {
                'ssdeep': '12345',
                'SHA-256': '123456'
            }
        )
    ),
    (
        "[file:'fake'='12345' OR "
        "file:hashes.'SHA-1'='123456']",
        (
            ['file'],
            ['123456'],
            {
                'SHA-1': '123456'
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
    """

    Given:
        - Indicator raw value from response

    When:
        - Processing raw indicators to real indicators

    Then:
        - Returns extracted value and hashes

    """
    process_result = STIX21Processor.process_indicator_value(pattern_value)

    for i in range(3):
        assert process_result[i] == expected_result[i]


REPUTATION_CALCULATION_PACKAGE = [
    (100, '1993-05-27T17:43:41.000Z', 70, 30, 3),
    (100, '1992-05-27T17:43:41.000Z', 0, 30, 2),
    (100, '1993-04-27T17:43:41.000Z', 0, 100, 3),
    (51, '1993-04-27T17:43:41.000Z', 50, 100, 3),
    (1, '1993-04-27T17:43:41.000Z', 50, 100, 0),
    (100, '1993-04-27T17:43:41.000Z', 50, 20, 2),
]


@pytest.mark.parametrize('confidence, date, threshold, reputation_interval, expected', REPUTATION_CALCULATION_PACKAGE)
@freeze_time("1993-06-17 11:00:00 GMT")
def test_reputation_calculation(confidence, date, threshold, reputation_interval, expected):
    """

    Given:
        - Confidence level according to FE
        - Indicator publish date

    When:
        - Processing raw indicators to real indicators

    Then:
        - Returns DBot Score

    """
    FE_CONFIDENCE_TO_REPUTATION[3] = threshold
    assert STIX21Processor.calculate_indicator_reputation(confidence, date, reputation_interval) == expected


def test_parse_timestamp():
    """

    Given:
        - Next URL value from FE response

    When:
        - Saving the last timestamp fetched to context

    Then:
        - Returns decoded timestamp

    """
    assert parse_timestamp(
        'https://api.intelligence.fireeye.com/collections/indicators/objects?length=1000&'
        'last_id_modified_timestamp=MTU4MDgwOTIxOTcyODY0NixpbmRpY2F0b3ItLTA5MWI3OWQxLTllOWQtNWExYS04ODMzLTZlNTkyZmNj'
        'MmM1NQ%3D%3D&added_after=1580764458'
    ) == 1580809219


@pytest.mark.parametrize('param_input, expected_result', [
    ('1 month', '737636400'),
    ('2 months', '735044400'),
    ('1 day', '740228400'),
    ('3 weeks', '738500400'),
    ('', None),
    (None, None),

])
@freeze_time("1993-06-17 11:00:00 GMT")
def test_handle_first_fetch_timestamp(mocker, param_input, expected_result):
    """

    Given:
        - first_fetch_timestamp parameter from user input

    When:
        - Calculating the first fetch timestamp value

    Then:
        - str value of the required time, or None if empty

    """
    mocker.patch.object(demisto, 'params', return_value={'first_fetch_timestamp': param_input})
    assert handle_first_fetch_timestamp() == expected_result
