"""Test file for FeedCyCognito Integration."""

import json
import os
import time

import pytest

from FeedCyCognito import (AVAILABLE_ASSET_TYPES, AVAILABLE_HOSTING_TYPES,
                           AVAILABLE_STATUS_TYPES,
                           AVAILABLE_SECURITY_GRADE, BASE_URL, DATE_FORMAT,
                           ERRORS)
from CommonServerPython import arg_to_datetime

DUMMY_TIME = '2022-03-21T07:06:41.000Z'
ASSET_IP_ENDPOINT = '/assets/ip'
CURRENT_TIME = time.time()


def util_load_json(path):
    """Load a json file to python dictionary."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def mocked_client():
    """Create a mock client for testing."""
    from FeedCyCognito import CyCognitoFeedClient

    headers = {
        'Authorization': 'api_token'
    }
    client = CyCognitoFeedClient(
        base_url=BASE_URL,
        headers=headers,
        verify=False,
        proxy=False
    )
    return client


@pytest.mark.parametrize("expected, args", [
    ([{
        'field': 'locations',
        'op': 'in',
        'values': ['IND']
    }, {
        'field': 'hosting-type',
        'op': 'in',
        'values': ['cloud']
    }], {'asset_type': 'ip', 'hosting_type': ['cloud'], 'locations': ['IND']}),
    ([{
        'field': 'locations',
        'op': 'in',
        'values': ['IND']
    }, {
        'field': 'hosting-type',
        'op': 'in',
        'values': ['cloud']
    }], {'asset_type': 'domain', 'hosting_type': ['cloud'], 'locations': ['IND']}),
    ([{
        'field': 'security-grade',
        'op': 'in',
        'values': ['a']
    }], {'asset_type': 'iprange', 'security_grade': ['a']}),
    ([{
        'field': 'first-seen',
        'op': 'between',
        'values': [['2020-01-01T00:00:00Z', arg_to_datetime(CURRENT_TIME).strftime(DATE_FORMAT)]]
    }, {
        'field': 'last-seen',
        'op': 'between',
        'values': [['2020-01-01T00:00:00Z', arg_to_datetime(CURRENT_TIME).strftime(DATE_FORMAT)]]
    }], {'first_seen': "2020-01-01T00:00:00Z", 'last_seen': "2020-01-01T00:00:00Z"})
])
def test_prepare_filters_for_get_indicators(expected, args, mocker):
    """Test case scenario for successful execution of prepare_filters_for_get_indicators function."""
    from FeedCyCognito import prepare_body_filters_for_get_indicators

    mocker.patch('time.time', return_value=CURRENT_TIME)
    assert prepare_body_filters_for_get_indicators(**args) == expected


@pytest.mark.parametrize("err_msg, args", [
    (ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type'), {'asset_type': ''}),
    (ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('test', 'asset_type', AVAILABLE_ASSET_TYPES), {'asset_type': 'test'}),
    (ERRORS['INVALID_PAGE_SIZE'].format('-10'), {'count': '-10', 'asset_type': 'ip'}),
    ('Invalid number: "count"="abc"', {'count': 'abc'}),
    (ERRORS['INVALID_PAGE_SIZE'].format('10000'), {'count': '10000', 'asset_type': 'ip'}),
    ('Invalid number: "offset"="abc"', {'offset': 'abc'}),
    ('Invalid date: "first_seen"="abc"', {'first_seen': 'abc'}),
    ('Invalid date: "last_seen"="abc"', {'last_seen': 'abc'}),
    (ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('test', 'sort_order', ['asc', 'desc']),
     {'sort_order': 'test', 'asset_type': 'ip'}),
    (ERRORS['INVALID_MULTI_SELECT_PARAM'].format('hosting_type', AVAILABLE_HOSTING_TYPES),
     {'hosting_type': 'test', 'asset_type': 'ip'}),
    (ERRORS['INVALID_MULTI_SELECT_PARAM'].format('security_grade',
                                                 [x.upper() for x in AVAILABLE_SECURITY_GRADE]),
     {'security_grade': 'a,e', 'asset_type': 'ip'}),
    (ERRORS['INVALID_MULTI_SELECT_PARAM'].format('status', AVAILABLE_STATUS_TYPES),
     {'status': 'test', 'asset_type': 'ip'})
])
def test_get_indicators_arguments_when_invalid_arguments_provided(err_msg, args, mocked_client):
    """Test case scenario when arguments provided to get_indicators_command are invalid."""
    from FeedCyCognito import get_indicators_command

    with pytest.raises(ValueError) as err:
        get_indicators_command(mocked_client, args)

    assert str(err.value) == err_msg


def test_get_indicators_command_when_valid_response_returned_for_ip(requests_mock, mocked_client):
    """Test case scenario for successful execution of cycognito-get-indicators command."""
    from FeedCyCognito import get_indicators_command

    expected_resp = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                'test_data/get_indicators_success_response_ip.json'))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_indicators_success_hr_ip.md")) as f:
        expected_hr_output = f.read()

    requests_mock.post(BASE_URL + ASSET_IP_ENDPOINT, json=expected_resp)
    resp = get_indicators_command(mocked_client, {'asset_type': 'ip'})
    assert resp.raw_response == expected_resp
    assert resp.readable_output == expected_hr_output


def test_get_indicators_command_when_valid_response_returned_for_domain(requests_mock, mocked_client):
    """Test case scenario for successful execution of cycognito-get-indicators command."""
    from FeedCyCognito import get_indicators_command

    expected_resp = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                'test_data/get_indicators_success_response_domain.json'))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_indicators_success_hr_domain.md")) as f:
        expected_hr_output = f.read()

    requests_mock.post(BASE_URL + '/assets/domain', json=expected_resp)
    resp = get_indicators_command(mocked_client, {'asset_type': 'domain'})
    assert resp.raw_response == expected_resp
    assert resp.readable_output == expected_hr_output


def test_get_indicators_command_when_valid_response_returned_for_cert(requests_mock, mocked_client):
    """Test case scenario for successful execution of cycognito-get-indicators command."""
    from FeedCyCognito import get_indicators_command

    expected_resp = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                'test_data/get_indicators_success_response_cert.json'))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_indicators_success_hr_cert.md")) as f:
        expected_hr_output = f.read()

    requests_mock.post(BASE_URL + '/assets/cert', json=expected_resp)
    resp = get_indicators_command(mocked_client, {'asset_type': 'cert'})
    assert resp.raw_response == expected_resp
    assert resp.readable_output == expected_hr_output


def test_get_indicators_command_when_valid_response_returned_for_iprange(requests_mock, mocked_client):
    """Test case scenario for successful execution of cycognito-get-indicators command."""
    from FeedCyCognito import get_indicators_command

    expected_resp = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                'test_data/get_indicators_success_response_iprange.json'))
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/get_indicators_success_hr_iprange.md")) as f:
        expected_hr_output = f.read()

    requests_mock.post(BASE_URL + '/assets/iprange', json=expected_resp)
    resp = get_indicators_command(mocked_client, {'asset_type': 'iprange'})
    assert resp.raw_response == expected_resp
    assert resp.readable_output == expected_hr_output


def test_get_indicators_command_when_empty_response_returned(requests_mock, mocked_client):
    """Test case scenario for successful execution of cycognito-get-indicators command when empty response returned."""
    from FeedCyCognito import get_indicators_command

    requests_mock.post(BASE_URL + ASSET_IP_ENDPOINT, json=[])
    resp = get_indicators_command(mocked_client, {'asset_type': 'ip'})

    assert resp.raw_response == []
    assert resp.readable_output == '### Indicator Detail:\n #### Asset type: IP\n**No entries.**\n'


def test_test_module(requests_mock, mocked_client):
    """Test case scenario for successful execution of test-module command when valid response returned."""
    from FeedCyCognito import test_module

    requests_mock.post(f"{BASE_URL}{ASSET_IP_ENDPOINT}", json=[], status_code=200)
    assert test_module(mocked_client, {'feed': False}) == 'ok'


@pytest.mark.parametrize("err_msg, args", [
    (ERRORS['INVALID_PAGE_SIZE'].format('-10'), {'max_fetch': '-10', 'asset_type': 'ip', 'feed': False}),
    ('Invalid number: "Max Fetch"="abc"', {'max_fetch': 'abc', 'feed': False}),
    (ERRORS['INVALID_PAGE_SIZE'].format('10000'), {'max_fetch': '10000', 'asset_type': 'ip', 'feed': False}),
    ('Invalid date: "First Fetch Time"="abc"', {'first_fetch': 'abc', 'feed': False}),
    (ERRORS['INVALID_MULTI_SELECT_PARAM'].format('hosting_type', AVAILABLE_HOSTING_TYPES),
     {'hosting_type': 'test', 'asset_type': 'ip', 'feed': False}),
    (ERRORS['INVALID_MULTI_SELECT_PARAM'].format('security_grade',
     [x.upper() for x in AVAILABLE_SECURITY_GRADE]),
     {'security_grade': 'a,e', 'asset_type': 'ip', 'feed': False}),
    (ERRORS['INVALID_COUNTRY_ERROR'].format('invalid_country_name'),
     {'locations': ['invalid_country_name'], 'asset_type': 'ip', 'feed': False})
])
def test_fetch_indicators_when_invalid_arguments_provided(err_msg, args, mocked_client, capfd):
    """Test case scenario when arguments provided to fetch-indicators are invalid."""
    from FeedCyCognito import fetch_indicators_command

    with pytest.raises(ValueError) as err:
        capfd.close()
        fetch_indicators_command(mocked_client, args, {})

    assert str(err.value) == err_msg


def test_fetch_indicators_command_when_valid_response_returned_with_updated_last_run(requests_mock, mocked_client):
    """Test case scenario when valid response returned by fetch-indicators command with updated last run."""
    from FeedCyCognito import fetch_indicators_command

    mock_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_indicator_response.json"))

    indicators = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_indicator_indicators.json"))

    requests_mock.post(BASE_URL + ASSET_IP_ENDPOINT, json=mock_response, status_code=200)

    args = {'asset_type': 'ip', 'max_fetch': 10, 'feed': True, 'first_fetch': '10 days',
            'organizations': 'Acme Holding, Acme Interior', 'security_grade': ['A: Very Strong', 'B: Strong'],
            'hosting_type': ['owned'], 'locations': ["India", "United States"], 'default_mapping': False}
    last_run = {'last_fetch': DUMMY_TIME, 'offset': 2}
    next_run, actual_indicators = fetch_indicators_command(mocked_client, args, last_run)

    assert next_run == {'last_fetch': "2022-03-31T03:39:22.569000Z", 'offset': 0}
    assert actual_indicators == indicators


def test_fetch_indicators_command_when_empty_response_returned_with_last_run(requests_mock, mocked_client):
    """Test case scenario when empty response is returned with same last run as previous."""
    from FeedCyCognito import fetch_indicators_command

    requests_mock.post(BASE_URL + ASSET_IP_ENDPOINT, json=[], status_code=200)

    args = {'asset_type': 'ip', 'max_fetch': 10, 'feed': True, 'locations': ['India']}
    last_run = {'last_fetch': DUMMY_TIME, 'offset': 2}
    next_run, actual_indicators = fetch_indicators_command(mocked_client, args, last_run)

    assert next_run == {'last_fetch': DUMMY_TIME, 'offset': 2}
    assert actual_indicators == []


def test_fetch_indicators_command_when_empty_response_returned_without_last_run(requests_mock, mocked_client):
    """Test case scenario when empty response is returned with empty last run."""
    from FeedCyCognito import fetch_indicators_command

    requests_mock.post(BASE_URL + ASSET_IP_ENDPOINT, json=[], status_code=200)

    args = {'asset_type': 'ip', 'max_fetch': 10, 'feed': True, 'locations': ['India']}
    next_run, actual_indicators = fetch_indicators_command(mocked_client, args, {})

    assert next_run == {}
    assert actual_indicators == []
