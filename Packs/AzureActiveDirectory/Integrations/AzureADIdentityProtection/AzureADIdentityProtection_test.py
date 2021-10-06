import io
import json

import dateparser
from datetime import datetime

import pytest
from AzureADIdentityProtection import (AADClient, OUTPUTS_PREFIX,
                                       azure_ad_identity_protection_risk_detection_list_command,
                                       azure_ad_identity_protection_risky_users_list_command,
                                       azure_ad_identity_protection_risky_users_history_list_command,
                                       azure_ad_identity_protection_risky_users_confirm_compromised_command,
                                       azure_ad_identity_protection_risky_users_dismiss_command,
                                       parse_list)

dummy_user_id = 'dummy_id'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client(mocker):
    mocker.patch('AzureADIdentityProtection.MicrosoftClient.get_access_token', return_value='token')
    return AADClient(app_id='dummy_app_id',
                     subscription_id='dummy_subscription_id',
                     verify=False,
                     proxy=False,
                     azure_ad_endpoint='https://login.microsoftonline.com')


@pytest.mark.parametrize('command,test_data_file,url_suffix,context_path,kwargs',
                         ((azure_ad_identity_protection_risk_detection_list_command,
                           'test_data/risk_detections_response.json',
                           'riskDetections',
                           'Risks',
                           {}),
                          (azure_ad_identity_protection_risky_users_list_command,
                           'test_data/risky_users_response.json',
                           'RiskyUsers',
                           'RiskyUsers',
                           {}),
                          (azure_ad_identity_protection_risky_users_history_list_command,
                           'test_data/risky_user_history_response.json',
                           f'RiskyUsers/{dummy_user_id}/history',
                           "RiskyUserHistory",
                           {'user_id': dummy_user_id})
                          ))
def test_list_commands(client, requests_mock, command, test_data_file, url_suffix, context_path,
                       kwargs):
    """
    Given:
        - AAD Client
    When:
        - Listing (risks, risky users, user history)
    Then:
        - Verify API request sent as expected
        - Verify command outputs
    """
    with open(test_data_file) as f:
        api_response = json.load(f)

    requests_mock.get(f'{client._base_url}/{url_suffix}?$top=50', json=api_response)
    result = command(client, limit=50, **kwargs)

    expected_values = api_response.get('value')
    actual_values = result.outputs.get(f'{OUTPUTS_PREFIX}.{context_path}(val.id === obj.id)')
    assert actual_values == expected_values

    expected_next_link = api_response.get('@odata.nextLink')
    if expected_next_link:  # risky_users_history_list does not have next link
        actual_next_url = result.outputs.get(f'{OUTPUTS_PREFIX}.NextLink(obj.Description === "{context_path}")', {}) \
            .get('URL')
        assert actual_next_url == expected_next_link


@pytest.mark.parametrize('method,expected_output,url_suffix,kwargs',
                         ((azure_ad_identity_protection_risky_users_confirm_compromised_command,
                           '✅ Confirmed successfully.',
                           'riskyUsers/confirmCompromised',
                           {'user_ids': [dummy_user_id]}
                           ),
                          (azure_ad_identity_protection_risky_users_dismiss_command,
                           '✅ Dismissed successfully.',
                           'riskyUsers/dismiss',
                           {'user_ids': [dummy_user_id]}
                           )
                          )
                         )
def test_status_update_commands(client, requests_mock, method, expected_output, url_suffix, kwargs):
    """
    Given:
        - AAD Client
        - User name whose status we want to update

    When:
        - Calling a user-status-changing method (dismiss, confirm compromised)

    Then:
        - Verify API request sent as expected
        - Verify command outputs
    """

    requests_mock.post(f'{client._base_url}/{url_suffix}', status_code=204)
    result = method(client, **kwargs)
    assert requests_mock.request_history[0].json() == {'userIds': [dummy_user_id]}
    assert result == expected_output


def test_parse_list():
    """
    Given
        - A Microsoft Graph List response (collection of objects)
    When
        - calling parse_list()
    Then
        - Validate output parsing
    """
    with open('test_data/risk_detections_response.json') as f:
        response = json.load(f)

    human_readable_title = "Risks"
    context_path = "Risks_path"

    parsed = parse_list(response, human_readable_title=human_readable_title, context_path=context_path)
    outputs = parsed.outputs
    assert len(outputs) == 2

    values = outputs[f'AADIdentityProtection.{context_path}(val.id === obj.id)'][0]
    assert len(values) == len(response['value'][0])  # all fields parsed

    next_link_dict = outputs[f'AADIdentityProtection.NextLink(obj.Description === "{context_path}")']
    assert next_link_dict == {'Description': context_path,
                              'URL': 'https://graph.microsoft.com/beta/riskDetections?$skiptoken=dummy_skip_token'}
    assert parsed.readable_output.startswith("### Risks (1 result)")


def test_parse_list_empty():
    """
    Given
        - A Microsoft Graph List response (collection of objects)
    When
        - calling parse_list()
    Then
        - Validate output parsing
    """
    empty_response = dict()
    human_readable_title = "Risks"
    context_path = "Risks_path"

    parsed = parse_list(empty_response, human_readable_title=human_readable_title, context_path=context_path)
    outputs = parsed.outputs
    assert outputs == {f'AADIdentityProtection.{context_path}(val.id === obj.id)': []}  # no next_link
    assert f"{human_readable_title} (0 results)" in parsed.readable_output
    assert "**No entries.**" in parsed.readable_output


def test_fetch_all_incidents(mocker):
    """
        Given
            fetch incidents command running for the first time.
        When
            mock the Client's http_request.
        Then
            validate fetch incidents command using the Client gets all 3 relevant incidents
    """
    from AzureADIdentityProtection import create_incidents_from_input
    test_incidents = util_load_json('test_data/incidents.json')
    last_fetch_datetime: datetime = dateparser.parse('2021-07-10T11:02:54Z')
    incidents, last_item_time = create_incidents_from_input(
        test_incidents.get('value', []), last_fetch_datetime=last_fetch_datetime)
    assert len(incidents) == 3
    assert incidents[0].get(
        'name') == 'Azure AD: 17 newCountry adminDismissedAllRiskForUser'
    assert last_item_time == dateparser.parse('2021-07-25T11:02:54Z').replace(tzinfo=None)


def test_fetch_new_incidents(mocker):
    """
        Given
            fetch incidents command running for the first time.
        When
            mock the Client's http_request.
        Then
            validate fetch incidents command using the Client gets all 3 relevant incidents
    """
    from AzureADIdentityProtection import create_incidents_from_input
    test_incidents = util_load_json('test_data/incidents.json')
    last_fetch_datetime: datetime = dateparser.parse('2021-07-20T11:02:54Z')
    incidents, last_item_time = create_incidents_from_input(
        test_incidents.get('value', []), last_fetch_datetime=last_fetch_datetime)
    assert len(incidents) == 1
    assert incidents[0].get(
        'name') == 'Azure AD: 37 newCountry adminDismissedAllRiskForUser'
    assert last_item_time == dateparser.parse('2021-07-25T11:02:54Z').replace(tzinfo=None)
