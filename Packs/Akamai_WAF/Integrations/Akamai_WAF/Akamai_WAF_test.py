import json
import pytest
from Akamai_WAF import Client
from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_txt(path: str):
    """
    Utility to load text data from a local folder.
    """
    with open(path, encoding='utf-8') as file:
        return file.read()


@pytest.fixture(scope='module')
def akamai_waf_client():
    return Client(base_url="https://hostname/",
                  verify=False,
                  proxy=False)


environments = ['production', 'staging']


@pytest.mark.parametrize('environment', environments)
def test_get_cps_enrollment_deployment_command(environment, mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_id and environment
    When:
        - running the command get-cps-enrollment-deployment
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import get_cps_enrollment_deployment_command

    enrollment_id = 111111

    test_data = util_load_json('test_data/get_cps_enrollment_deployment_test.json')
    expected_response = test_data.get(environment)
    expected_human_readable = test_data.get(f'{environment}_human_readable')
    expected_context_entry = test_data.get(f'{environment}_context_entry')

    mocker.patch.object(akamai_waf_client, 'get_cps_enrollment_deployment', return_value=expected_response)

    human_readable, context_entry, raw_response = get_cps_enrollment_deployment_command(akamai_waf_client,
                                                                                        enrollment_id,
                                                                                        environment)
    assert expected_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_cidr_blocks_command(mocker, akamai_waf_client):
    """
    Given:
        - A last_action and an effective_date_gt
    When:
        - running the command list-cidr-blocks
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import list_cidr_blocks_command

    last_action = 'add'
    effective_date_gt = '2021-02-21'

    test_data = util_load_json('test_data/list_cidr_blocks_test.json')
    expected_raw_response = test_data.get('raw_response')
    expected_human_readable = test_data.get('human_readable')
    expected_context_entry = test_data.get('context_entry')

    mocker.patch.object(akamai_waf_client, 'list_cidr_blocks', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = list_cidr_blocks_command(akamai_waf_client, last_action, effective_date_gt)

    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_update_cps_enrollment_command(mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_id, updates, deploy_not_after, deploy_not_before.
    When:
        - running the command update_cps_enrollment.
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import update_cps_enrollment_command

    enrollment_id = "11111"
    updates = {
        "thirdParty": {
            "excludeSans": False
        }
    }
    deploy_not_after = "2023-11-30T00:00:00Z"
    deploy_not_before = "2023-11-23T00:00:00Z"
    test_data = util_load_json('test_data/update-cps-enrollment_test.json')
    enrollment = test_data.get('enrollment')

    expected_raw_response = test_data.get('raw_response')
    expected_human_readable = test_data.get('human_readable')
    expected_context_entry = test_data.get('context_entry')

    mocker.patch.object(akamai_waf_client, 'update_cps_enrollment', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = update_cps_enrollment_command(client=akamai_waf_client,
                                                                                enrollment_id=enrollment_id,
                                                                                updates=updates,
                                                                                deploy_not_before=deploy_not_before,
                                                                                deploy_not_after=deploy_not_after,
                                                                                enrollment=enrollment)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_update_cps_enrollment_schedule_command(mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_id, change_id, deploy_not_after, deploy_not_before.
    When:
        - running the command update_cps_enrollment_schedule.
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import update_cps_enrollment_schedule_command

    enrollment_id = '111111'
    change_id = '1111111'
    deploy_not_before = "2023-11-30T00:00:00Z"

    test_data = util_load_json('test_data/update-cps-enrollment-schedule_test.json')
    expected_raw_response = test_data.get('raw_response')
    expected_human_readable = test_data.get('human_readable')
    expected_context_entry = test_data.get('context_entry')

    mocker.patch.object(akamai_waf_client, 'update_cps_enrollment_schedule', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = update_cps_enrollment_schedule_command(client=akamai_waf_client,
                                                                                         enrollment_id=enrollment_id,
                                                                                         change_id=change_id,
                                                                                         deploy_not_before=deploy_not_before)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_get_cps_change_status_command(mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_path.
    When:
        - running the command get_cps_change_status.
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import get_cps_change_status_command
    enrollment_path = "/cps/v2/enrollments/111111/changes/1111111"

    test_data = util_load_json('test_data/get_cps_change_status_test.json')
    expected_raw_response = test_data.get('raw_response')
    expected_human_readable = test_data.get('human_readable')
    expected_context_entry = test_data.get('context_entry')

    mocker.patch.object(akamai_waf_client, 'get_cps_change_status', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = get_cps_change_status_command(client=akamai_waf_client,
                                                                                enrollment_path=enrollment_path)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_try_parsing_date():
    """
    Given:
        - An arr contains the allowed date formats and dates.
    When:
        - Running every command that has a date validation.
    Then:
        - date1-3 pass, date4 fails.
    """
    from Akamai_WAF import try_parsing_date
    arr_fmt = ['%Y-%m-%d', '%m-%d-%Y', '%Y-%m-%dT%H:%M:%SZ']
    date1 = '2020-10-31'
    date2 = '10-31-2020'
    date3 = '2020-10-31T00:00:00Z'
    date4 = '31 oct 2020'
    value_error = f'The date you provided does not match the wanted format {arr_fmt}'

    assert try_parsing_date(date1, arr_fmt)
    assert try_parsing_date(date2, arr_fmt)
    assert try_parsing_date(date3, arr_fmt)
    with pytest.raises(ValueError) as e:
        try_parsing_date(date4, arr_fmt)
        assert value_error == str(e.value)


def test_list_siteshield_maps_command(mocker, akamai_waf_client):
    """
    When:
        - running the command list_siteshield_maps_command.
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import list_siteshield_maps_command

    test_data = util_load_json('test_data/list_siteshild_maps_test.json')
    expected_raw_response = test_data.get('raw_response')
    expected_human_readable = test_data.get('human_readable')
    expected_context_entry = test_data.get('context_entry')

    mocker.patch.object(akamai_waf_client, 'list_siteshield_maps', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = list_siteshield_maps_command(client=akamai_waf_client)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_acknowledge_warning_command(mocker, akamai_waf_client):
    """
    Given:
        - An enrollment_path.
    When:
        - running the command get_cps_change_status.
    Then:
        - The returned value is correct.
    """
    from Akamai_WAF import acknowledge_warning_command

    change_path = "/cps/v2/enrollments/10002/changes/10002"
    expected_raw_response = {
        "change": "/cps/v2/enrollments/10002/changes/10002"
    }
    expected_human_readable = "Akamai WAF - Acknowledge_warning"
    expected_context_entry = {
        'Akamai.Acknowledge':
            {
                'change': '/cps/v2/enrollments/10002/changes/10002'
            }
    }

    mocker.patch.object(akamai_waf_client, 'acknowledge_warning', return_value=expected_raw_response)

    human_readable, context_entry, raw_response = acknowledge_warning_command(client=akamai_waf_client,
                                                                              change_path=change_path)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_cancel_cps_change_command(mocker, akamai_waf_client):
    """
    Given:
        - enrollment ID and change ID.
    When:
        - running the command cancel_cps_change_command.
    Then:
        - enrollment ID is cancelled correctly.
    """
    from Akamai_WAF import cancel_cps_change_command
    expected_raw_response = {
        "change": "/cps/v2/enrollments/193622/changes/3914270"
    }
    expected_human_readable = "### Akamai WAF - cps cancel change\n|change|\n|---|\n|\
 /cps/v2/enrollments/193622/changes/3914270 |\n"
    expected_context_entry = {
        'Akamai.Cps.Change.Canceled': {
            'change': '/cps/v2/enrollments/193622/changes/3914270'
        }
    }
    mocker.patch.object(akamai_waf_client, 'cancel_cps_change', return_value=expected_raw_response)
    human_readable, context_entry, raw_response = cancel_cps_change_command(client=akamai_waf_client,
                                                                            enrollment_id="193622",
                                                                            change_id="3914270")
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_get_cps_enrollment_by_id_command(mocker, akamai_waf_client):
    """
    Given:
        - enrollment ID.
    When:
        - running the command get_cps_enrollment_by_id_command.
    Then:
        - we get details of enrollment.
    """
    from Akamai_WAF import get_cps_enrollment_by_id_command
    test_data = util_load_json('test_data/get_cps_enrollment_by_id_test.json')
    expected_raw_response = test_data
    expected_context_entry = util_load_json('test_data/get_cps_enrollment_by_id_context.json')

    mocker.patch.object(akamai_waf_client, 'get_cps_enrollment_by_id', return_value=expected_raw_response)
    _, context_entry, raw_response = get_cps_enrollment_by_id_command(client=akamai_waf_client, enrollment_id=193622)
    assert expected_raw_response == raw_response
    assert expected_context_entry == context_entry


def test_list_appsec_config_command(mocker, akamai_waf_client):
    """
    When:
        - running the command list_appsec_config_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_appsec_config_command

    test_data = util_load_json("test_data/list_appsec_config_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(
        akamai_waf_client, "list_appsec_config", return_value=expected_raw_response
    )

    human_readable, context_entry, raw_response = list_appsec_config_command(
        client=akamai_waf_client
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_dns_zones_command(mocker, akamai_waf_client):
    """
    When:
        - running the command list_dns_zones_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_dns_zones_command

    test_data = util_load_json("test_data/list_dns_zones_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(
        akamai_waf_client, "list_dns_zones", return_value=expected_raw_response
    )

    human_readable, context_entry, raw_response = list_dns_zones_command(
        client=akamai_waf_client
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_dns_zone_recordsets_command(mocker, akamai_waf_client):
    """
    When:
        - running the command list_dns_zone_recordsets_command with a specific zone.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_dns_zone_recordsets_command

    zone = "example.com"
    test_data = util_load_json("test_data/list_dns_zone_recordsets_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(
        akamai_waf_client,
        "list_dns_zone_recordsets",
        return_value=expected_raw_response,
    )

    human_readable, context_entry, raw_response = list_dns_zone_recordsets_command(
        client=akamai_waf_client, zone=zone
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_cps_active_certificates_command(mocker, akamai_waf_client):
    """
    When:
        - running the command list_cps_active_certificates_command with a specific contract_id.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_cps_active_certificates_command

    contract_id = "contract123"
    test_data = util_load_json("test_data/list_cps_active_certificates_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(
        akamai_waf_client,
        "list_cps_active_certificates",
        return_value=expected_raw_response,
    )

    human_readable, context_entry, raw_response = list_cps_active_certificates_command(
        client=akamai_waf_client, contract_id=contract_id
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry
