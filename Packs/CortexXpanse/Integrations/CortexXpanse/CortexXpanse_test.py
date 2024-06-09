"""
Tests module for Cortex Xpanse integration.
"""


def test_format_asm_id_func(requests_mock):
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
    from CortexXpanse import Client, list_external_service_command

    from test_data.raw_response import EXTERNAL_SERVICES_RESPONSE
    from test_data.expected_results import EXTERNAL_SERVICES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_services/',
                       json=EXTERNAL_SERVICES_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

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
    from CortexXpanse import Client, get_external_service_command

    from test_data.raw_response import EXTERNAL_SERVICE_RESPONSE
    from test_data.expected_results import EXTERNAL_SERVICE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_service',
                       json=EXTERNAL_SERVICE_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

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
    from CortexXpanse import Client, list_external_ip_address_range_command

    from test_data.raw_response import EXTERNAL_RANGES_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_ip_address_ranges/',
                       json=EXTERNAL_RANGES_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, get_external_ip_address_range_command

    from test_data.raw_response import EXTERNAL_RANGE_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_ip_address_range/',
                       json=EXTERNAL_RANGE_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'range_id': '1093124c-ce26-33ba-8fb8-937fecb4c7b6'
    }

    response = get_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGE_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalIpAddressRange'
    assert response.outputs_key_field == 'range_id'


def test_list_asset_internet_exposure_command(requests_mock):
    """Tests list_asset_internet_exposure_command function.

        Given:
            - requests_mock instance to generate the appropriate list_asset_internet_exposure_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'list_asset_internet_exposure_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import Client, list_asset_internet_exposure_command

    from test_data.raw_response import EXTERNAL_EXPOSURES_RESPONSE
    from test_data.expected_results import EXTERNAL_EXPOSURES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_assets_internet_exposure/',
                       json=EXTERNAL_EXPOSURES_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {'name': 'testdomain.com'}
    args_externally_inferred_cves = {"externally_inferred_cves": ["CVE-2020-15778"]}
    args_ipv6s = {"ipv6s": ["2600:1900:4000:9664:0:7::"]}
    args_asm_id_list = {"asm_ids": ["3c176460-8735-333c-b618-8262e2fb660c"]}
    args_aws_cloud_tags = {"aws_cloud_tags": ["Name:AD Lab"]}
    args_gcp_cloud_tags = {"gcp_cloud_tags": ["Name:gcp Lab"]}
    args_azure_cloud_tags = {"azure_cloud_tags": ["Name:azure Lab"]}
    args_has_xdr_agent = {"has_xdr_agent": "NO"}
    args_externally_detected_providers = {"externally_detected_providers": ["Amazon Web Services"]}
    args_has_bu_overrides = {"has_bu_overrides": False}
    args_business_units_list = {"business_units": ["Acme"]}
    args_mac_address = {"mac_address": ["00:11:22:33:44:55"]}

    response = list_asset_internet_exposure_command(client, args)
    response_externally_inferred_cves = list_asset_internet_exposure_command(args=args_externally_inferred_cves, client=client)
    response_ipv6s = list_asset_internet_exposure_command(args=args_ipv6s, client=client)
    response_asm_id_list = list_asset_internet_exposure_command(args=args_asm_id_list, client=client)
    response_aws_cloud_tags = list_asset_internet_exposure_command(args=args_aws_cloud_tags, client=client)
    response_gcp_cloud_tags = list_asset_internet_exposure_command(args=args_gcp_cloud_tags, client=client)
    response_azure_cloud_tags = list_asset_internet_exposure_command(args=args_azure_cloud_tags, client=client)
    response_has_xdr_agent = list_asset_internet_exposure_command(args=args_has_xdr_agent, client=client)
    response_externally_detected_providers = list_asset_internet_exposure_command(
        args=args_externally_detected_providers, client=client)
    response_has_bu_overrides = list_asset_internet_exposure_command(args=args_has_bu_overrides, client=client)
    response_business_units_list = list_asset_internet_exposure_command(args=args_business_units_list, client=client)
    response_mac_address = list_asset_internet_exposure_command(args=args_mac_address, client=client)

    assert response.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response.outputs_prefix == 'ASM.AssetInternetExposure'
    assert response.outputs_key_field == 'asm_ids'

    assert response_externally_inferred_cves.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_externally_inferred_cves.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_externally_inferred_cves.outputs_key_field == "asm_ids"

    assert response_ipv6s.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_ipv6s.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_ipv6s.outputs_key_field == "asm_ids"

    assert response_asm_id_list.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_asm_id_list.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_asm_id_list.outputs_key_field == "asm_ids"

    assert response_aws_cloud_tags.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_aws_cloud_tags.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_aws_cloud_tags.outputs_key_field == "asm_ids"

    assert response_gcp_cloud_tags.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_gcp_cloud_tags.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_gcp_cloud_tags.outputs_key_field == "asm_ids"

    assert response_azure_cloud_tags.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_azure_cloud_tags.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_azure_cloud_tags.outputs_key_field == "asm_ids"

    assert response_has_xdr_agent.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_has_xdr_agent.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_has_xdr_agent.outputs_key_field == "asm_ids"

    assert response_externally_detected_providers.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_externally_detected_providers.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_externally_detected_providers.outputs_key_field == "asm_ids"

    assert response_has_bu_overrides.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_has_bu_overrides.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_has_bu_overrides.outputs_key_field == "asm_ids"

    assert response_business_units_list.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_business_units_list.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_business_units_list.outputs_key_field == "asm_ids"

    assert response_mac_address.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_mac_address.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_mac_address.outputs_key_field == "asm_ids"


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
    from CortexXpanse import Client, get_asset_internet_exposure_command

    from test_data.raw_response import EXTERNAL_EXPOSURE_RESPONSE
    from test_data.expected_results import EXTERNAL_EXPOSURE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_asset_internet_exposure/',
                       json=EXTERNAL_EXPOSURE_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, list_alerts_command

    from test_data.raw_response import LIST_ALERTS_RESPONSE
    from test_data.expected_results import LIST_ALERTS_RESULTS
    requests_mock.post('https://test.com/public_api/v2/alerts/get_alerts_multi_events/',
                       json=LIST_ALERTS_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'limit': '3',
        'sort_by_creation_time': 'asc'
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
    from CortexXpanse import Client, list_attack_surface_rules_command

    from test_data.raw_response import ATTACK_SURFACE_RULES_RAW
    from test_data.expected_results import ATTACK_SURFACE_RULES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/get_attack_surface_rules/',
                       json=ATTACK_SURFACE_RULES_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, assign_tag_to_assets_command

    from test_data.raw_response import TAG_APPLY_RAW
    from test_data.expected_results import TAG_APPLY_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/assets_internet_exposure/assign/',
                       json=TAG_APPLY_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, remove_tag_to_assets_command

    from test_data.raw_response import TAG_REMOVE_RAW
    from test_data.expected_results import TAG_REMOVE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/assets_internet_exposure/remove/',
                       json=TAG_REMOVE_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, assign_tag_to_ranges_command

    from test_data.raw_response import TAG_APPLY_RAW
    from test_data.expected_results import TAG_APPLY_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/external_ip_address_ranges/assign/',
                       json=TAG_APPLY_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, remove_tag_to_ranges_command

    from test_data.raw_response import TAG_REMOVE_RAW
    from test_data.expected_results import TAG_REMOVE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/tags/external_ip_address_ranges/remove/',
                       json=TAG_REMOVE_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, list_incidents_command

    from test_data.raw_response import LIST_INCIDENTS_RAW
    from test_data.expected_results import LIST_INCIDENTS_RESULTS
    requests_mock.post('https://test.com/public_api/v1/incidents/get_incidents/',
                       json=LIST_INCIDENTS_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'limit': 1,
        'status': 'new'
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
    from CortexXpanse import Client, get_incident_command

    from test_data.raw_response import INCIDENT_GET_RAW
    from test_data.expected_results import INCIDENT_GET_RESULTS
    requests_mock.post('https://test.com/public_api/v1/incidents/get_incident_extra_data/',
                       json=INCIDENT_GET_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, update_incident_command

    from test_data.raw_response import INCIDENT_UPDATE_RAW
    from test_data.expected_results import INCIDENT_UPDATE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/incidents/update_incident/',
                       json=INCIDENT_UPDATE_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
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
    from CortexXpanse import Client, update_alert_command

    from test_data.raw_response import ALERT_UPDATE_RAW
    from test_data.expected_results import ALERT_UPDATE_RESULTS
    requests_mock.post('https://test.com/public_api/v1/alerts/update_alerts/',
                       json=ALERT_UPDATE_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'alert_id_list': 602,
        'status': 'new'
    }

    response = update_alert_command(client, args)

    assert response.outputs == ALERT_UPDATE_RESULTS
    assert response.outputs_prefix == 'ASM.UpdatedAlerts'


def test_ip_command(requests_mock):
    """Tests ip_command function.

        Given:
            - requests_mock instance to generate the appropriate ip_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'ip_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import Client, ip_command

    from test_data.raw_response import IP_DOMAIN_RAW
    from test_data.expected_results import IP_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_assets_internet_exposure/',
                       json=IP_DOMAIN_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'ip': "1.1.1.1"
    }

    responses = ip_command(client, args)
    assert len(responses) == 2
    for response in responses:
        if response.outputs_prefix == 'ASM.IP':
            assert response.outputs == IP_RESULTS
        elif response.outputs_prefix == 'DBotScore':
            assert response.outputs.get("Score") == 0


def test_domain_command(requests_mock):
    """Tests domain_command function.

        Given:
            - requests_mock instance to generate the appropriate domain_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'domain_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import Client, domain_command

    from test_data.raw_response import IP_DOMAIN_RAW
    from test_data.expected_results import IP_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_assets_internet_exposure/',
                       json=IP_DOMAIN_RAW)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'domain': "*.acme.com"
    }
    del IP_RESULTS[0]['ip']
    responses = domain_command(client, args)

    assert len(responses) == 2
    for response in responses:
        if response.outputs_prefix == 'ASM.Domain':
            assert response.outputs == IP_RESULTS
        elif response.outputs_prefix == 'DBotScore':
            assert response.outputs.get("Score") == 0


def test_fetch_incidents(requests_mock, mocker):
    """Tests fetch_incidents function.

        Given:
            - requests_mock instance to generate the appropriate fetch_incidents( API response,
              loaded from a local JSON file.
        When:
            - Running the 'fetch_incidents' command.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexXpanse import Client, fetch_incidents
    import json

    from test_data.raw_response import LIST_ALERTS_RESPONSE
    requests_mock.post('https://test.com/public_api/v2/alerts/get_alerts_multi_events/',
                       json=LIST_ALERTS_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

    last_run = {'last_fetch': 1659452708759}
    next_run, incidents = fetch_incidents(
        client=client,
        max_fetch=2,
        last_run=last_run,
        first_fetch_time=1658452708759,
        severity=None,
        status=None,
        tags=None)

    assert len(incidents) == 3
    assert incidents[0]['name'] == "Networking Infrastructure"
    assert json.loads(incidents[0]['rawJSON']).pop('local_insert_ts')
    assert next_run == {'last_fetch': 1659455267908}


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
    from CortexXpanse import Client, list_external_websites_command

    from test_data.raw_response import EXTERNAL_WEBSITES_RESPONSE
    from test_data.expected_results import EXTERNAL_WEBSITES_RESULTS
    requests_mock.post('https://test.com/public_api/v1/assets/get_external_websites/',
                       json=EXTERNAL_WEBSITES_RESPONSE)

    client = Client(
        base_url='https://test.com',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

    args = {
        'authentication': 'Form',
        'limit': 5
    }

    response = list_external_websites_command(client, args)

    assert response.outputs == EXTERNAL_WEBSITES_RESULTS.get('ExternalWebsite', {}).get('websites')
    assert response.outputs_prefix == 'ASM.ExternalWebsite'
    # assert response.outputs_key_field == ''
