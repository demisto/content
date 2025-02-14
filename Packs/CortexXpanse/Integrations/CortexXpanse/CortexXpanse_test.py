"""
Tests module for Cortex Xpanse integration.
"""
import pytest

# Helper Functions


def new_client():
    from CortexXpanse import Client

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorization": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

    return client


def test_format_asm_id_func():
    """Tests format_asm_id helper function.

        Given:
            - Mock JSON pre-formatting from the list_asset_internet_exposure_command function
        When:
            - Sending JSON to format_asm_id function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from CortexXpanse import format_asm_id
    from test_data.raw_response import INTERNET_EXPOSURE_PRE_FORMAT
    from test_data.expected_results import INTERNET_EXPOSURE_POST_FORMAT

    response = format_asm_id(INTERNET_EXPOSURE_PRE_FORMAT)

    assert response == INTERNET_EXPOSURE_POST_FORMAT


def test_list_external_service_command(requests_mock):
    """Tests list_external_service_command command function.

        Given:
            - requests_mock instance to generate the appropriate list_external_service_command API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_external_service_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_external_service_command

    from test_data.raw_response import EXTERNAL_SERVICES_RESPONSE
    from test_data.expected_results import EXTERNAL_SERVICES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_services/',
                       json=EXTERNAL_SERVICES_RESPONSE)

    client = new_client()

    args = {
        'domain': 'testdomain.com',
    }

    response = list_external_service_command(client, args)

    assert response.outputs == EXTERNAL_SERVICES_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalService'
    assert response.outputs_key_field == 'service_id'


def test_get_external_service_command(requests_mock):
    """Tests get_external_service_command command function.

        Given:
            - requests_mock instance to generate the appropriate get_external_service_command API response,
              loaded from a local JSON file.
        When:
            - Running the 'get_external_service_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import get_external_service_command

    from test_data.raw_response import EXTERNAL_SERVICE_RESPONSE
    from test_data.expected_results import EXTERNAL_SERVICE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_service',
                       json=EXTERNAL_SERVICE_RESPONSE)

    client = new_client()

    args = {
        'service_id': '94232f8a-f001-3292-aa65-63fa9d981427'
    }

    response = get_external_service_command(client, args)

    assert response.outputs == EXTERNAL_SERVICE_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalService'
    assert response.outputs_key_field == 'service_id'


def test_list_external_ip_address_range_command(requests_mock):
    """Tests list_external_ip_address_range_command function.

        Given:
            - requests_mock instance to generate the appropriate list_external_ip_address_range_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_external_ip_address_range_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_external_ip_address_range_command

    from test_data.raw_response import EXTERNAL_RANGES_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_ip_address_ranges/',
                       json=EXTERNAL_RANGES_RESPONSE)

    client = new_client()
    args = {}

    response = list_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGES_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalIpAddressRange'
    assert response.outputs_key_field == 'range_id'


def test_get_external_ip_address_range_command(requests_mock):
    """Tests get_external_ip_address_range_command function.

        Given:
            - requests_mock instance to generate the appropriate get_external_ip_address_range_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'get_external_ip_address_range_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import get_external_ip_address_range_command

    from test_data.raw_response import EXTERNAL_RANGE_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_ip_address_range/',
                       json=EXTERNAL_RANGE_RESPONSE)

    client = new_client()
    args = {
        'range_id': '1093124c-ce26-33ba-8fb8-937fecb4c7b6'
    }

    response = get_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGE_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalIpAddressRange'
    assert response.outputs_key_field == 'range_id'


@pytest.mark.parametrize("args", [
    ({'name': 'testdomain.com'}),
    ({"externally_inferred_cves": ["CVE-2020-15778"]}),
    ({"ipv6s": ["2600:1900:4000:9664:0:7::"]}),
    ({"asm_ids": ["3c176460-8735-333c-b618-8262e2fb660c"]}),
    ({"aws_cloud_tags": ["Name:AD Lab"]}),
    ({"gcp_cloud_tags": ["Name:gcp Lab"]}),
    ({"azure_cloud_tags": ["Name:azure Lab"]}),
    ({"has_xdr_agent": "NO"}),
    ({"externally_detected_providers": ["Amazon Web Services"]}),
    ({"has_bu_overrides": "false"}),
    ({"business_units": ["Acme"]}),
    ({"mac_address": ["00:11:22:33:44:55"]}),
    ({"ipv6_address": "1111:2222:33333:4444:5555:6666:7777:8888"}),
    ({"asm_id_list": ["3c176460-8735-333c-b618-8262e2fb660c"]}),
    ({"has_active_external_services": "test"}),
    ({"type": "IP"}),
    ({"ip_address": "1.1.1.1"}),
    ({"business_units_list": "test"}),
    ({"mac_addresses": ["00:11:22:33:44:55"]})
])
def test_list_asset_internet_exposure_command(requests_mock, args):
    """Tests list_asset_internet_exposure_command function.

        Given:
            - requests_mock instance to generate the appropriate list_asset_internet_exposure_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_asset_internet_exposure_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_asset_internet_exposure_command

    from test_data.raw_response import EXTERNAL_EXPOSURES_RESPONSE
    from test_data.expected_results import EXTERNAL_EXPOSURES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_assets_internet_exposure/',
                       json=EXTERNAL_EXPOSURES_RESPONSE)

    client = new_client()

    response = list_asset_internet_exposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response.outputs_prefix == 'ASM.AssetInternetExposure'
    assert response.outputs_key_field == 'asm_ids'


def test_get_asset_internet_exposure_command(requests_mock):
    """Tests get_asset_internet_exposure_command function.

        Given:
            - requests_mock instance to generate the appropriate get_asset_internet_exposure_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'get_asset_internet_exposure_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import get_asset_internet_exposure_command

    from test_data.raw_response import EXTERNAL_EXPOSURE_RESPONSE
    from test_data.expected_results import EXTERNAL_EXPOSURE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_asset_internet_exposure/',
                       json=EXTERNAL_EXPOSURE_RESPONSE)

    client = new_client()
    args = {
        'asm_id': 'testdomain.com'
    }

    response = get_asset_internet_exposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURE_RESULTS
    assert response.outputs_prefix == 'ASM.AssetInternetExposure'
    assert response.outputs_key_field == 'asm_ids'


def test_list_alerts_command(requests_mock):
    """Tests list_alerts_command function.

        Given:
            - requests_mock instance to generate the appropriate list_alerts_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_alerts_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_alerts_command

    from test_data.raw_response import LIST_ALERTS_RESPONSE
    from test_data.expected_results import LIST_ALERTS_RESULTS
    requests_mock.post('https://test.com/public_api/v2/alerts/get_alerts_multi_events/',
                       json=LIST_ALERTS_RESPONSE)

    client = new_client()
    args = {
        'limit': '3',
        'sort_by_creation_time': 'asc',
        'severity': ["critical", "high", "medium", "low"],
        'status': ["new", "reopened", "in_progress"],
        'business_units_list': "test",
        'alert_id_list': ["231", "33", "34"]
    }

    response = list_alerts_command(client, args)

    for alert in response.outputs:
        if 'status' in alert:
            status = alert['status']
            assert status == 'reopened'

    assert response.outputs == LIST_ALERTS_RESULTS
    assert response.outputs_prefix == 'ASM.Alert'
    assert response.outputs_key_field == 'alert_id'


def test_list_attack_surface_rules_command(requests_mock):
    """Tests list_attack_surface_rules_command function.

        Given:
            - requests_mock instance to generate the appropriate list_attack_surface_rules_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_attack_surface_rules_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_attack_surface_rules_command

    from test_data.raw_response import ATTACK_SURFACE_RULES_RAW
    from test_data.expected_results import ATTACK_SURFACE_RULES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/get_attack_surface_rules/',
                       json=ATTACK_SURFACE_RULES_RAW)

    client = new_client()
    args = {
        'enabled_status': 'on',
        'severity': 'high',
        'limit': 2
    }

    response = list_attack_surface_rules_command(client, args)

    assert response.outputs == ATTACK_SURFACE_RULES_RESULTS
    assert response.outputs_prefix == 'ASM.AttackSurfaceRules'
    assert response.outputs_key_field == 'attack_surface_rule_id'


def test_assign_tag_to_assets_command(requests_mock):
    """Tests assign_tag_to_assets_command function.

        Given:
            - requests_mock instance to generate the appropriate assign_tag_to_assets_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'assign_tag_to_assets_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import assign_tag_to_assets_command

    from test_data.raw_response import TAG_APPLY_RAW
    from test_data.expected_results import TAG_APPLY_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/assets_internet_exposure/assign/',
                       json=TAG_APPLY_RAW)

    client = new_client()
    args = {
        'asm_id_list': '11111111-1111-1111-1111-111111111111',
        'tags': 'Test'
    }

    response = assign_tag_to_assets_command(client, args)

    assert response.outputs == TAG_APPLY_RESULTS
    assert response.outputs_prefix == 'ASM.TagAssignment'


def test_remove_tag_to_assets_command(requests_mock):
    """Tests remove_tag_to_assets_command function.

        Given:
            - requests_mock instance to generate the appropriate remove_tag_to_assets_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'assign_tag_to_assets_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import remove_tag_to_assets_command

    from test_data.raw_response import TAG_REMOVE_RAW
    from test_data.expected_results import TAG_REMOVE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/assets_internet_exposure/remove/',
                       json=TAG_REMOVE_RAW)

    client = new_client()
    args = {
        'asm_id_list': '11111111-1111-1111-1111-111111111111',
        'tags': 'Test'
    }

    response = remove_tag_to_assets_command(client, args)

    assert response.outputs == TAG_REMOVE_RESULTS
    assert response.outputs_prefix == 'ASM.TagRemoval'


def test_assign_tag_to_ranges_command(requests_mock):
    """Tests assign_tag_to_ranges_command function.

        Given:
            - requests_mock instance to generate the appropriate assign_tag_to_ranges_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'assign_tag_to_ranges_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import assign_tag_to_ranges_command

    from test_data.raw_response import TAG_APPLY_RAW
    from test_data.expected_results import TAG_APPLY_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/external_ip_address_ranges/assign/',
                       json=TAG_APPLY_RAW)

    client = new_client()
    args = {
        'range_id_list': '11111111-1111-1111-1111-111111111111',
        'tags': 'Test'
    }

    response = assign_tag_to_ranges_command(client, args)

    assert response.outputs == TAG_APPLY_RESULTS
    assert response.outputs_prefix == 'ASM.TagAssignment'


def test_remove_tag_to_ranges_command(requests_mock):
    """Tests remove_tag_to_ranges_command function.

        Given:
            - requests_mock instance to generate the appropriate remove_tag_to_assets_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'remove_tag_to_ranges_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import remove_tag_to_ranges_command

    from test_data.raw_response import TAG_REMOVE_RAW
    from test_data.expected_results import TAG_REMOVE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/external_ip_address_ranges/remove/',
                       json=TAG_REMOVE_RAW)

    client = new_client()
    args = {
        'range_id_list': '11111111-1111-1111-1111-111111111111',
        'tags': 'Test'
    }

    response = remove_tag_to_ranges_command(client, args)

    assert response.outputs == TAG_REMOVE_RESULTS
    assert response.outputs_prefix == 'ASM.TagRemoval'


def test_list_incidents_command(requests_mock):
    """Tests list_incidents_command function.

        Given:
            - requests_mock instance to generate the appropriate list_incidents_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_incidents_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_incidents_command

    from test_data.raw_response import LIST_INCIDENTS_RAW
    from test_data.expected_results import LIST_INCIDENTS_RESULTS
    requests_mock.post('https://test.com/public_api/v1/incidents/get_incidents/',
                       json=LIST_INCIDENTS_RAW)

    client = new_client()
    args = {
        'limit': 1,
        'status': 'new',
        'description': "'Google WebFramework Angular at suppliers.expander.expanse.co:443' detected by ASM on 3 hosts",
        'starred': "false",
        'cloud_management_status': "active",
        'incident_id_list': ["5471"]
    }

    response = list_incidents_command(client, args)

    assert response.outputs == LIST_INCIDENTS_RESULTS
    assert response.outputs_prefix == 'ASM.Incident'
    assert response.outputs_key_field == 'incident_id'


def test_get_incident_command(requests_mock):
    """Tests get_incident_command function.

        Given:
            - requests_mock instance to generate the appropriate update_incident_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'get_incident_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import get_incident_command

    from test_data.raw_response import INCIDENT_GET_RAW
    from test_data.expected_results import INCIDENT_GET_RESULTS
    requests_mock.post('https://test.com/public_api/v1/incidents/get_incident_extra_data/',
                       json=INCIDENT_GET_RAW)

    client = new_client()
    args = {
        'incident_id': 1
    }

    response = get_incident_command(client, args)

    assert response.outputs == INCIDENT_GET_RESULTS
    assert response.outputs_prefix == 'ASM.Incident'


def test_update_incident_command(requests_mock):
    """Tests update_incident_command function.

        Given:
            - requests_mock instance to generate the appropriate update_incident_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'update_incident_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import update_incident_command

    from test_data.raw_response import INCIDENT_UPDATE_RAW
    from test_data.expected_results import INCIDENT_UPDATE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/incidents/update_incident/',
                       json=INCIDENT_UPDATE_RAW)

    client = new_client()
    args = {
        'incident_id': 1,
        'status': 'new'
    }

    response = update_incident_command(client, args)

    assert response.outputs == INCIDENT_UPDATE_RESULTS
    assert response.outputs_prefix == 'ASM.IncidentUpdate'


def test_update_alert_command(requests_mock):
    """Tests update_alert_command function.

        Given:
            - requests_mock instance to generate the appropriate update_alert_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'update_alert_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import update_alert_command

    from test_data.raw_response import ALERT_UPDATE_RAW
    from test_data.expected_results import ALERT_UPDATE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/alerts/update_alerts/',
                       json=ALERT_UPDATE_RAW)

    client = new_client()
    args = {
        'alert_id_list': 602,
        'status': 'new',
        'comment': 'test updating'
    }

    response = update_alert_command(client, args)

    assert response.outputs == ALERT_UPDATE_RESULTS
    assert response.outputs_prefix == 'ASM.UpdatedAlerts'


def test_successfully_add_note_to_asset_command(requests_mock):
    """Tests update_alert_command function.

        Given:
            - requests_mock instance to generate the appropriate update_alert_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'update_alert_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import add_note_to_asset_command

    json_data = {"reply": "succeeded"}
    requests_mock.post('https://test.com/public_api/v1/assets/assets_internet_exposure/annotation',
                       json=json_data)

    client = new_client()
    args = {
        'asset_id': "abcd1234-a1b2-a1b2-a1b2-abcdefg12345",
        'entity_type': 'ip_range',
        'note_to_add': 'Test note adding to asset in Ev2',
        'should_append': 'true'
    }

    response = add_note_to_asset_command(client, args)

    assert response.outputs.get('status') == "succeeded"
    assert response.outputs_prefix == 'ASM.AssetAnnotation'


def test_fetch_incidents(requests_mock):
    """Tests fetch_incidents function.

        Given:
            - requests_mock instance to generate the appropriate fetch_incidents( API response,
              loaded from a local JSON file.
        When:
            - Running the 'fetch_incidents' command.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import fetch_incidents
    import json

    from test_data.raw_response import LIST_ALERTS_RESPONSE
    requests_mock.post('https://test.com/public_api/v2/alerts/get_alerts_multi_events/',
                       json=LIST_ALERTS_RESPONSE)

    client = new_client()

    last_run = {'found_incident_ids': {}, 'limit': 20, 'next_page_token': None, 'time': '2022-08-02T21:25:08Z'}
    incidents = fetch_incidents(
        client=client,
        max_fetch=2,
        last_run=last_run,
        first_fetch_time=1658452708759,
        severity=None,
        status=None,
        tags=None,
        look_back=0)

    assert len(incidents) == 3
    assert incidents[0]['name'] == "Networking Infrastructure"
    assert json.loads(incidents[0]['rawJSON']).pop('local_insert_ts')


def test_list_external_websites_command(requests_mock):
    """Tests list_external_websites_command command function.

        Given:
            - requests_mock instance to generate the appropriate list_external_websites_command API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_external_websites_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import list_external_websites_command

    from test_data.raw_response import EXTERNAL_WEBSITES_RESPONSE
    from test_data.expected_results import EXTERNAL_WEBSITES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_websites/',
                       json=EXTERNAL_WEBSITES_RESPONSE)

    client = new_client()

    args = {
        'authentication': 'Form',
        'limit': 5
    }

    response = list_external_websites_command(client, args)

    assert response.outputs == EXTERNAL_WEBSITES_RESULTS.get('ExternalWebsite', {}).get('websites')
    assert response.outputs_prefix == 'ASM.ExternalWebsite'


@pytest.mark.parametrize('command_name, method_name', [('asm-list-alerts', 'list_alerts_command')])
def test_main_parameters(command_name, method_name, mocker):
    from CortexXpanse import main
    import demistomock as demisto

    params = {
        'first_fetch': '3 days',
        'severity': 'high',
        'status': 'active',
        'tags': ['tag1', 'tag2'],
        'look_back': '5',
        'max_fetch': '10',
        'credentials': {
            'password': 'api_key',
            'identifier': 'auth_id'
        },
        'proxy': False,
        'insecure': False,
        'url': 'https://example.com'
    }
    mocker.patch.object(demisto, 'command', return_value=command_name)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    env_method_mock = mocker.patch(f'CortexXpanse.{method_name}', return_value='OK')
    main()
    assert env_method_mock.called
    assert env_method_mock.return_value == 'OK'


def test_reset_last_run_command_success(mocker):
    import demistomock as demisto
    from CortexXpanse import reset_last_run_command
    mock_setLastRun = mocker.patch.object(demisto, 'setLastRun')

    result = reset_last_run_command()

    mock_setLastRun.assert_called_once_with([])
    assert result == 'fetch-incidents was reset successfully.'


def test_reset_last_run_command_failure(mocker):
    import demistomock as demisto
    from CommonServerPython import DemistoException
    from CortexXpanse import reset_last_run_command

    mocker.patch.object(demisto, 'setLastRun', side_effect=DemistoException('Test error'))

    with pytest.raises(DemistoException, match='Error: fetch-incidents was not reset. Reason: Test error'):
        reset_last_run_command()


if __name__ == "__main__":
    pytest.main()
