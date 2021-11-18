import json
import os

import pytest

from MicrosoftGraphAPI import MsGraphClient, generic_command


def load_test_data(test_data_filename):
    with open(os.path.join('./test_data', test_data_filename)) as f:
        return json.load(f)


@pytest.fixture()
def client(requests_mock):
    requests_mock.post(
        'https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token',
        json={},
    )
    return MsGraphClient(
        app_id='app_id',
        scope='Application.Read.All',
        app_secret='app_secret',
        tenant_id='tenant_id',
        verify=False,
        proxy=False,
    )


def test_generic_command_positive_value_key(requests_mock, client):
    """
    Given:
        - API resource /applications
    When:
        - Running the generic command
    Then:
        - Ensure outputs are as expected
    """
    applications_res = load_test_data('applications.json')
    requests_mock.get(
        'https://graph.microsoft.com/v1.0/applications?$top=10',
        json=applications_res,
    )
    args = {
        'resource': '/applications',
        'odata': '$top=10',

    }
    res = generic_command(client, args)
    assert res.outputs == applications_res.get('value')


def test_generic_command_positive_other_key(requests_mock, client):
    """
    Given:
        - API resource /applications
        - API returns data under other key than value
    When:
        - Running the generic command
    Then:
        - Ensure outputs are as expected
    """
    applications_res = load_test_data('applications.json')
    value = applications_res['value']
    applications_res['not_value'] = value
    applications_res.pop('value', None)
    requests_mock.get(
        'https://graph.microsoft.com/v1.0/applications?$top=10',
        json=applications_res,
    )
    args = {
        'resource': '/applications',
        'odata': '$top=10',

    }
    res = generic_command(client, args)
    assert res.outputs['not_value'][0] == value[0]


def test_generic_command_no_content(requests_mock, client):
    """
    Given:
        - API resource /identityProtection/riskyUsers/dismiss
        - no_content set to `true`
    When:
        - Running the generic command
    Then:
        - Ensure the command does not fail on no content response
    """
    requests_mock.post(
        'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss',
        text='',
    )
    args = {
        'http_method': 'POST',
        'resource': '/identityProtection/riskyUsers/dismiss',
        'no_content': 'true',
        'populate_context': 'false',
    }
    res = generic_command(client, args)
    assert res
