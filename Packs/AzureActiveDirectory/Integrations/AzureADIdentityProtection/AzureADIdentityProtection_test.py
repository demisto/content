import copy
import io
import json
import random

import dateparser
from datetime import datetime, timedelta

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
            validate fetch incidents command using the Client gets all relevant incidents
    """
    from AzureADIdentityProtection import detections_to_incidents, get_last_fetch_time
    test_incidents = util_load_json('test_data/incidents.json')
    last_run = {
        'latest_detection_found': '2021-07-10T11:02:54Z'
    }
    last_fetch, last_fetch_datetime = get_last_fetch_time(last_run, {})
    incidents, last_item_time = detections_to_incidents(
        test_incidents.get('value', []), last_fetch_datetime=last_fetch_datetime)
    assert len(incidents) == 10
    assert incidents[0].get(
        'name') == 'Azure AD: 17 newCountry adminDismissedAllRiskForUser'
    assert last_item_time == dateparser.parse('2021-07-17T14:11:57Z').replace(tzinfo=None)


def test_fetch_new_incidents(mocker):
    """
        Given
            fetch incidents command running for the first time.
        When
            mock the Client's http_request.
        Then
            validate fetch incidents command using the Client gets all relevant incidents
    """
    from AzureADIdentityProtection import detections_to_incidents, get_last_fetch_time
    test_incidents = util_load_json('test_data/incidents.json')
    last_run = {
        'latest_detection_found': '2021-07-20T11:02:54Z'
    }
    last_fetch, last_fetch_datetime = get_last_fetch_time(last_run, {})
    incidents, last_item_time = detections_to_incidents(
        test_incidents.get('value', []), last_fetch_datetime=last_fetch_datetime)
    assert len(incidents) == 10
    assert incidents[0].get(
        'name') == 'Azure AD: 17 newCountry adminDismissedAllRiskForUser'
    assert last_item_time == dateparser.parse('2021-07-20T11:02:54Z').replace(tzinfo=None)


# set time to 2021-07-29 11:10:00
def test_first_fetch_start_time():
    from AzureADIdentityProtection import get_last_fetch_time
    last_run = {}
    params = {
        "first_fetch": "2 days"
    }
    expected_datetime = datetime.now() - timedelta(days=2)

    last_fetch, last_fetch_datetime = get_last_fetch_time(last_run, params)

    assert expected_datetime - timedelta(minutes=1) < last_fetch_datetime < expected_datetime + timedelta(minutes=1)


def test_non_first_fetch_start_time():
    from AzureADIdentityProtection import get_last_fetch_time
    last_run = {
        "latest_detection_found": '2021-07-28T00:10:00.000Z'
    }
    params = {
        "first_fetch": "2 days"
    }
    last_fetch, last_fetch_datetime = get_last_fetch_time(last_run, params)
    assert last_fetch == '2021-07-28T00:10:00.000'


def test_filter_creation_with_user_filter():
    from AzureADIdentityProtection import build_filter
    last_fetch = '2021-07-28T00:10:00.000'
    params = {
        "first_fetch": "2 days",
        "fetch_filter_expression": "id gt 1234"
    }

    user_filter = params['fetch_filter_expression']
    constructed_filter = build_filter(last_fetch, params)
    assert constructed_filter == f"{user_filter} and detectedDateTime gt {last_fetch}Z"


def test_filter_creation_without_user_filter():
    from AzureADIdentityProtection import build_filter
    last_fetch = '2021-07-28T00:10:00.000'
    params = {
        "first_fetch": "2 days",
        "fetch_filter_expression": ""
    }

    constructed_filter = build_filter(last_fetch, params)
    assert constructed_filter == f"detectedDateTime gt {last_fetch}Z"

    params = {
        "first_fetch": "2 days",
    }

    constructed_filter = build_filter(last_fetch, params)
    assert constructed_filter == f"detectedDateTime gt {last_fetch}Z"


@pytest.mark.parametrize('date_to_test', [('2021-07-28T00:10:00.000Z'), ('2021-07-28T00:10:00Z')])
def test_date_str_to_azure_format_z_suffix(date_to_test):
    """
    Given:
    - A date string that includes a Z at the end

    When:
    - The date string is moved to Azure format

    Then:
    - The result will be a string without a Z at the end
    """
    from AzureADIdentityProtection import date_str_to_azure_format
    assert date_str_to_azure_format(date_to_test)[-1].lower() != 'z'


@pytest.mark.parametrize('date_to_test, expected', [
    ('2021-07-28T00:10:00.123456Z', '2021-07-28T00:10:00.123456'),
    ('2021-07-28T00:10:00.123456789Z', '2021-07-28T00:10:00.123456'),
    ('2021-07-28T00:10:00.123Z', '2021-07-28T00:10:00.123'),
    ('2021-07-28T00:10:00.123456', '2021-07-28T00:10:00.123456'),
    ('2021-07-28T00:10:00.123456789', '2021-07-28T00:10:00.123456'),
    ('2021-07-28T00:10:00.123', '2021-07-28T00:10:00.123')
])
def test_date_str_to_azure_format_with_ms(date_to_test, expected):
    """
    Given:
    - A date string that includes miliseconds, that are less than 6 digits long.

    When:
    - The date string is moved to Azure format

    Then:
    - The result will be a string that contains the same digits as exp
    """
    from AzureADIdentityProtection import date_str_to_azure_format
    assert date_str_to_azure_format(date_to_test) == expected


@pytest.mark.parametrize('date_to_test, expected', [
    ('2021-07-28T00:10:00Z', '2021-07-28T00:10:00.000'),
    ('2021-07-28T00:10:00', '2021-07-28T00:10:00.000'),
])
def test_date_str_to_azure_format_without_ms(date_to_test, expected):
    """
    Given:
    - Two dates, without milliseconds, with and without a Z at the end.

    When:
    - Transforming the dates to Azure format

    Then:
    - Both dates have milliseconds and do not have a Z at the end.
    """
    from AzureADIdentityProtection import date_str_to_azure_format
    assert date_str_to_azure_format(date_to_test) == expected


def test_detections_to_incident():
    """
    Given:
    - 10 detections, sorted by their detection time.
    - 10 detections, shuffled.

    When:
    - Calling detections_to_incidents to parse the detections to incidents on the sorted detections.
    - Calling detections_to_incidents to parse the detections to incidents on the shuffled detections.

    Then:
    - Both calls return 10 incidents, and the latest detection time among the detections.
    """
    from AzureADIdentityProtection import detections_to_incidents, DATE_FORMAT
    detections_in_order = util_load_json('test_data/incidents.json')['value']
    detections_out_of_order = copy.deepcopy(detections_in_order)
    random.shuffle(detections_out_of_order)
    last_fetch_datetime = datetime.strptime('2019-07-28T00:10:00.123456', DATE_FORMAT)
    incidents, latest_incident_time = detections_to_incidents(detections_in_order, last_fetch_datetime)
    latest_incident_time = latest_incident_time.strftime(DATE_FORMAT)

    assert len(incidents) == 10
    assert latest_incident_time == '2021-07-17T14:11:57.000000'

    incidents, latest_incident_time = detections_to_incidents(detections_out_of_order, last_fetch_datetime)
    latest_incident_time = latest_incident_time.strftime(DATE_FORMAT)

    assert len(incidents) == 10
    assert latest_incident_time == '2021-07-17T14:11:57.000000'


def mock_list_detections(limit, filter_expression, user_id, user_principal_name):
    """
    Mocks the request to list detections from the API.
    The mock will manually take into consideration the filter and limit supplied as parameters.
    It also accepts the user_id and user_principal_name, to allow full running of fetch (as the actual function
    receives these parameters).
    """
    from AzureADIdentityProtection import DATE_FORMAT, date_str_to_azure_format
    test_incidents = util_load_json('test_data/incidents.json')
    all_possible_results = test_incidents.get('value')

    start_time = filter_expression.split('gt ')[-1]
    start_time = date_str_to_azure_format(start_time)
    start_time_datetime = datetime.strptime(start_time, DATE_FORMAT)

    incidents_compliant_with_filter = []
    for detection in all_possible_results:
        detection_time = date_str_to_azure_format(detection['detectedDateTime'])
        detection_datetime = datetime.strptime(detection_time, DATE_FORMAT)
        if detection_datetime > start_time_datetime:
            incidents_compliant_with_filter.append(detection)

    incidents_compliant_with_limit = incidents_compliant_with_filter[:limit]

    res = {
        'value': incidents_compliant_with_limit
    }

    return res


def mock_get_last_fetch_time(last_run, params):
    """
    Mocks the function that retrieves the fetch time that should be used.

    Args:
        last_run: the last run's data.
        params: the instance parameters (mocked).

    Returns:
        last_fetch (str): the date of the time to start the fetch from.
        last_fetch_datetime (str): the datetime of the time to start the fetch from.
    """
    from AzureADIdentityProtection import DATE_FORMAT, date_str_to_azure_format
    last_fetch = last_run.get('latest_detection_found')
    if not last_fetch:
        # To handle the fact that we can't freeze the time and still parse relative time expressions such as 2 days
        last_fetch = "2021-07-16T11:08:55.000"

    last_fetch = date_str_to_azure_format(last_fetch)
    last_fetch_datetime: datetime = datetime.strptime(last_fetch, DATE_FORMAT)
    return last_fetch, last_fetch_datetime


def test_fetch_complete_flow(mocker, client):
    """
    Given:
    - A start time of 2021-07-16T11:08:55.000.
    - 10 Possible incidents to fetch, the first 2 with a detection date before the start time.

    When:
    - Running fetch for the first time

    Then:
    - The two incidents before the start time are not fetched.
    - The 5 incidents after them are fetched.
    - The last run is updated with the detection date of the latest incident.

    When:
    - Running fetch for the second time.

    Then:
    - Exactly 3 incidents (the last 3 incidents that can be fetched) are fetched.
    - The first fetched incident is the earliest one not fetched in the previous run.
    - The last run is updated with the detection date of the latest incident.

    When:
    - Running fetch for the third time.

    Then:
    - No incidents are fetched.
    - The fetch end time remains unchanged.
    """
    from AzureADIdentityProtection import fetch_incidents

    mocker.patch('AzureADIdentityProtection.get_last_fetch_time', side_effect=mock_get_last_fetch_time)
    mocker.patch('AzureADIdentityProtection.MicrosoftClient.get_access_token', return_value='token')
    mocker.patch('AzureADIdentityProtection.AADClient.azure_ad_identity_protection_risk_detection_list_raw',
                 side_effect=mock_list_detections)

    mock_params = {
        'max_fetch': 5
    }
    last_run = {}
    mocker.patch('demistomock.params', return_value=mock_params)
    mocker.patch('demistomock.getLastRun', return_value=last_run)

    incidents, last_run = fetch_incidents(client, mock_params)
    first_incident = incidents[0].get('name')
    assert first_incident == 'Azure AD: 37 newCountry adminDismissedAllRiskForUser'
    assert len(incidents) == 5
    assert last_run['latest_detection_found'] == '2021-07-17T14:09:54.000000'

    mocker.patch('demistomock.getLastRun', return_value=last_run)

    incidents, last_run = fetch_incidents(client, mock_params)
    first_incident = incidents[0].get('name')
    assert first_incident == 'Azure AD: 87 newCountry adminDismissedAllRiskForUser'
    assert len(incidents) == 3
    assert last_run['latest_detection_found'] == '2021-07-17T14:11:57.000000'

    mocker.patch('demistomock.getLastRun', return_value=last_run)

    incidents, last_run = fetch_incidents(client, mock_params)
    assert len(incidents) == 0
    assert last_run['latest_detection_found'] == '2021-07-17T14:11:57.000000'
