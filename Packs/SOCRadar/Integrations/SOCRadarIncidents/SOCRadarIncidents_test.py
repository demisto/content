import io
import json

import pytest

from CommonServerPython import arg_to_datetime, DemistoException, IncidentSeverity, CommandResults

SOCRADAR_API_ENDPOINT = 'https://platform.socradar.com/api'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests the test_module validation command.
    """
    from SOCRadarIncidents import Client, test_module

    mock_socradar_api_key = "APIKey"
    mock_socradar_company_id = "0"
    suffix = f'company/{mock_socradar_company_id}/incidents/check/auth?key={mock_socradar_api_key}'
    mock_response = util_load_json('test_data/check_auth_response.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    response = test_module(client)

    assert response == 'ok'


def test_test_module_handles_authorization_error(requests_mock):
    """Tests the test_module validation command authorization error.
    """
    from SOCRadarIncidents import Client, test_module, MESSAGES

    mock_socradar_api_key = "WrongAPIKey"
    mock_socradar_company_id = "0"
    suffix = f'company/{mock_socradar_company_id}/incidents/check/auth?key={mock_socradar_api_key}'
    mock_response = util_load_json('test_data/check_auth_response_auth_error.json')
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response, status_code=401)
    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )
    with pytest.raises(DemistoException, match=MESSAGES['AUTHORIZATION_ERROR']):
        test_module(client)


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar Incidents API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/fetch_incidents_response.json')
    suffix = f'company/{mock_socradar_company_id}/incidents/v2?key={mock_socradar_api_key}' \
             f'&severity=Medium%2CHigh' \
             f'&limit=2' \
             f'&start_date=1594512000'
    requests_mock.get(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    last_run = {
        'last_fetch': 1594512000  # Jul 12, 2020
    }

    mock_first_fetch_time = arg_to_datetime(
        arg='30 days',
        arg_name='First fetch time'
    )

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=2,
        last_run=last_run,
        first_fetch_time=mock_first_fetch_time,
        resolution_status='all',
        fp_status='all',
        severity=['Medium', 'High'],
        incident_main_type=None,
        incident_sub_type=None
    )

    expected_output = util_load_json('test_data/fetch_incidents_expected_output.json')

    assert new_incidents == expected_output
    assert len(new_incidents) <= 2


def test_fetch_incidents_handles_incorrect_severity():
    """Tests the fetch-incidents function incorrect severity error.
    """
    from SOCRadarIncidents import Client, fetch_incidents

    mock_socradar_company_id = "0"
    mock_socradar_api_key = "APIKey"

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    last_run = {
        'last_fetch': 1594512000  # Jul 12, 2020
    }

    mock_first_fetch_time = arg_to_datetime(
        arg='30 days',
        arg_name='First fetch time'
    )

    incorrect_severity_levels = ['Incorrect', 'Severity', 'Levels']

    with pytest.raises(ValueError):
        fetch_incidents(
            client=client,
            max_results=2,
            last_run=last_run,
            first_fetch_time=mock_first_fetch_time,
            resolution_status='all',
            fp_status='all',
            severity=incorrect_severity_levels,
            incident_main_type=None,
            incident_sub_type=None
        )


def test_mark_incident_as_fp(requests_mock):
    """Tests the mark_incident_as_fp_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar mark incident as fp API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarIncidents import Client, mark_incident_as_fp_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/mark_incident_fp_response.json')
    suffix = f'company/{mock_socradar_company_id}/incidents/fp?key={mock_socradar_api_key}'
    requests_mock.post(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'socradar_incident_id': mock_incident_id, 'comments': mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    response = mark_incident_as_fp_command(
        client=client,
        args=mock_args
    )

    expected_output = util_load_json('test_data/mark_incident_fp_expected_output.json')

    assert isinstance(response, CommandResults)
    assert response.raw_response == expected_output


def test_mark_incident_as_fp_handles_error(requests_mock):
    """Tests the mark_incident_as_fp_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar mark incident as fp API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarIncidents import Client, mark_incident_as_fp_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/mark_incident_fp_response_error.json')
    suffix = f'company/{mock_socradar_company_id}/incidents/fp?key={mock_socradar_api_key}'
    requests_mock.post(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'socradar_incident_id': mock_incident_id, 'comments': mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    with pytest.raises(DemistoException):
        mark_incident_as_fp_command(
            client=client,
            args=mock_args
        )


def test_mark_incident_as_resolved(requests_mock):
    """Tests the mark_incident_as_resolved_command function.

 Configures requests_mock instance to generate the appropriate
 SOCRadar mark incident as resolved API response, loaded from a local JSON file. Checks
 the output of the command function with the expected output.
 """
    from SOCRadarIncidents import Client, mark_incident_as_resolved_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/mark_incident_resolved_response.json')
    suffix = f'company/{mock_socradar_company_id}/incidents/resolve?key={mock_socradar_api_key}'
    requests_mock.post(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'socradar_incident_id': mock_incident_id, 'comments': mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    response = mark_incident_as_resolved_command(
        client=client,
        args=mock_args
    )

    expected_output = util_load_json('test_data/mark_incident_resolved_expected_output.json')

    assert isinstance(response, CommandResults)
    assert response.raw_response == expected_output


def test_mark_incident_as_resolved_handles_error(requests_mock):
    """Tests the mark_incident_as_resolved_command function response error.
    """
    from SOCRadarIncidents import Client, mark_incident_as_resolved_command

    mock_socradar_company_id = "0"
    mock_incident_id = 0
    mock_comment = "Mock Comment"
    mock_socradar_api_key = "APIKey"
    mock_response = util_load_json('test_data/mark_incident_resolved_response_error.json')
    suffix = f'company/{mock_socradar_company_id}/incidents/resolve?key={mock_socradar_api_key}'
    requests_mock.post(f'{SOCRADAR_API_ENDPOINT}/{suffix}', json=mock_response)

    mock_args = {'socradar_incident_id': mock_incident_id, 'comments': mock_comment}

    client = Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=mock_socradar_api_key,
        socradar_company_id=mock_socradar_company_id,
        verify=False,
        proxy=False
    )

    with pytest.raises(DemistoException):
        mark_incident_as_resolved_command(
            client=client,
            args=mock_args
        )


CONVERT_DEMISTO_SEVERITY_INPUTS = [
    ('INFO', IncidentSeverity.INFO), ('LOW', IncidentSeverity.LOW), ('MEDIUM', IncidentSeverity.MEDIUM),
    ('HIGH', IncidentSeverity.HIGH), ('UNKNOWN', IncidentSeverity.UNKNOWN)
]


@pytest.mark.parametrize('incident_severity, demisto_severity', CONVERT_DEMISTO_SEVERITY_INPUTS)
def test_convert_to_demisto_severity(incident_severity, demisto_severity):
    from SOCRadarIncidents import convert_to_demisto_severity

    assert convert_to_demisto_severity(incident_severity) == demisto_severity
