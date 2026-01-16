import json

import demistomock as demisto  # noqa: F401
import pytest

from Akamai_WAF import Client
from CommonServerPython import *  # noqa: F401


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_txt(path: str):
    """
    Utility to load text data from a local folder.
    """
    with open(path, encoding="utf-8") as file:
        return file.read()


@pytest.fixture(scope="module")
def akamai_waf_client():
    return Client(base_url="https://hostname/", verify=False, proxy=False)


environments = ["production", "staging"]


@pytest.mark.parametrize("environment", environments)
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

    test_data = util_load_json("test_data/get_cps_enrollment_deployment_test.json")
    expected_response = test_data.get(environment)
    expected_human_readable = test_data.get(f"{environment}_human_readable")
    expected_context_entry = test_data.get(f"{environment}_context_entry")

    mocker.patch.object(akamai_waf_client, "get_cps_enrollment_deployment", return_value=expected_response)

    human_readable, context_entry, raw_response = get_cps_enrollment_deployment_command(
        akamai_waf_client, enrollment_id, environment
    )
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

    last_action = "add"
    effective_date_gt = "2021-02-21"

    test_data = util_load_json("test_data/list_cidr_blocks_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "list_cidr_blocks", return_value=expected_raw_response)

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
    updates = {"thirdParty": {"excludeSans": False}}
    deploy_not_after = "2023-11-30T00:00:00Z"
    deploy_not_before = "2023-11-23T00:00:00Z"
    test_data = util_load_json("test_data/update-cps-enrollment_test.json")
    enrollment = test_data.get("enrollment")

    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "update_cps_enrollment", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = update_cps_enrollment_command(
        client=akamai_waf_client,
        enrollment_id=enrollment_id,
        updates=updates,
        deploy_not_before=deploy_not_before,
        deploy_not_after=deploy_not_after,
        enrollment=enrollment,
    )
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

    enrollment_id = "111111"
    change_id = "1111111"
    deploy_not_before = "2023-11-30T00:00:00Z"

    test_data = util_load_json("test_data/update-cps-enrollment-schedule_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "update_cps_enrollment_schedule", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = update_cps_enrollment_schedule_command(
        client=akamai_waf_client, enrollment_id=enrollment_id, change_id=change_id, deploy_not_before=deploy_not_before
    )
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

    test_data = util_load_json("test_data/get_cps_change_status_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "get_cps_change_status", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = get_cps_change_status_command(
        client=akamai_waf_client, enrollment_path=enrollment_path
    )
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

    arr_fmt = ["%Y-%m-%d", "%m-%d-%Y", "%Y-%m-%dT%H:%M:%SZ"]
    date1 = "2020-10-31"
    date2 = "10-31-2020"
    date3 = "2020-10-31T00:00:00Z"
    date4 = "31 oct 2020"
    value_error = f"The date you provided does not match the wanted format {arr_fmt}"

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

    test_data = util_load_json("test_data/list_siteshild_maps_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "list_siteshield_maps", return_value=expected_raw_response)

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
    expected_raw_response = {"change": "/cps/v2/enrollments/10002/changes/10002"}
    expected_human_readable = "Akamai WAF - Acknowledge_warning"
    expected_context_entry = {"Akamai.Acknowledge": {"change": "/cps/v2/enrollments/10002/changes/10002"}}

    mocker.patch.object(akamai_waf_client, "acknowledge_warning", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = acknowledge_warning_command(client=akamai_waf_client, change_path=change_path)
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

    expected_raw_response = {"change": "/cps/v2/enrollments/193622/changes/3914270"}
    expected_human_readable = "### Akamai WAF - cps cancel change\n|change|\n|---|\n|\
 /cps/v2/enrollments/193622/changes/3914270 |\n"
    expected_context_entry = {"Akamai.Cps.Change.Canceled": {"change": "/cps/v2/enrollments/193622/changes/3914270"}}
    mocker.patch.object(akamai_waf_client, "cancel_cps_change", return_value=expected_raw_response)
    human_readable, context_entry, raw_response = cancel_cps_change_command(
        client=akamai_waf_client, enrollment_id="193622", change_id="3914270"
    )
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

    test_data = util_load_json("test_data/get_cps_enrollment_by_id_test.json")
    expected_raw_response = test_data
    expected_context_entry = util_load_json("test_data/get_cps_enrollment_by_id_context.json")

    mocker.patch.object(akamai_waf_client, "get_cps_enrollment_by_id", return_value=expected_raw_response)
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

    mocker.patch.object(akamai_waf_client, "list_appsec_config", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = list_appsec_config_command(client=akamai_waf_client)
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

    mocker.patch.object(akamai_waf_client, "list_dns_zones", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = list_dns_zones_command(client=akamai_waf_client)
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

    human_readable, context_entry, raw_response = list_dns_zone_recordsets_command(client=akamai_waf_client, zone=zone)
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


def test_list_datastream_groups_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A client.
    When:
        - running the command list_datastream_groups_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_datastream_groups_command

    test_data = util_load_json("test_data/list_datastream_groups_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get("https://hostname/datastream-config-api/v2/log/groups", json=expected_raw_response)

    human_readable, context_entry, raw_response = list_datastream_groups_command(client=akamai_waf_client)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_get_client_lists_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A client.
    When:
        - running the command get_client_lists_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import get_client_lists_command

    test_data = util_load_json("test_data/get_client_lists_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get("https://hostname/client-list/v1/lists", json=expected_raw_response)

    human_readable, context_entry, raw_response = get_client_lists_command(client=akamai_waf_client)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_patch_datastream_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A stream_id, a path, a value, and a value_to_json flag.
    When:
        - running the command patch_datastream_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import patch_datastream_command

    stream_id = 12345
    path = "/streamName"
    value = "New Stream Name"
    value_to_json = "no"

    test_data = util_load_json("test_data/patch_datastream_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.patch(
        f"https://hostname/datastream-config-api/v2/log/streams/{stream_id}?activate=true",
        json=expected_raw_response,
    )

    human_readable, context_entry, raw_response = patch_datastream_command(
        client=akamai_waf_client,
        stream_id=stream_id,
        path=path,
        value=value,
        value_to_json=value_to_json,
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_delete_datastream_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A stream_id.
    When:
        - running the command delete_datastream_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import delete_datastream_command

    stream_id = 12345

    test_data = util_load_json("test_data/delete_datastream_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.delete(f"https://hostname/datastream-config-api/v2/log/streams/{stream_id}", status_code=204)

    human_readable, context_entry, raw_response = delete_datastream_command(client=akamai_waf_client, stream_id=stream_id)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_datastreams_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A group_id.
    When:
        - running the command list_datastreams_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_datastreams_command

    group_id = 12345

    test_data = util_load_json("test_data/list_datastreams_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get("https://hostname/datastream-config-api/v2/log/streams", json=expected_raw_response)

    human_readable, context_entry, raw_response = list_datastreams_command(client=akamai_waf_client, group_id=group_id)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_generic_api_call_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A url_suffix and a method.
    When:
        - running the command generic_api_call_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import generic_api_call_command

    url_suffix = "/test"
    method = "GET"

    test_data = util_load_json("test_data/generic_api_call_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get(f"https://hostname/{url_suffix.strip('/')}", json=expected_raw_response)

    human_readable, context_entry, raw_response = generic_api_call_command(
        client=akamai_waf_client, url_suffix=url_suffix, method=method
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_idam_properties_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A client.
    When:
        - running the command list_idam_properties_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_idam_properties_command

    test_data = util_load_json("test_data/list_idam_properties_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get("https://hostname/identity-management/v3/user-admin/properties", json=expected_raw_response)

    human_readable, context_entry, raw_response = list_idam_properties_command(client=akamai_waf_client)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_datastream_properties_bygroup_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A group_id.
    When:
        - running the command list_datastream_properties_bygroup_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_datastream_properties_bygroup_command

    group_id = 12345

    test_data = util_load_json("test_data/list_datastream_properties_bygroup_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get(f"https://hostname/datastream-config-api/v2/log/groups/{group_id}/properties", json=expected_raw_response)

    human_readable, context_entry, raw_response = list_datastream_properties_bygroup_command(
        client=akamai_waf_client, group_id=group_id
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_toggle_datastream_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A stream_id and an option.
    When:
        - running the command toggle_datastream_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import toggle_datastream_command

    stream_id = 12345
    option = "deactivate"

    test_data = util_load_json("test_data/toggle_datastream_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.post(f"https://hostname/datastream-config-api/v2/log/streams/{stream_id}/{option}", json=expected_raw_response)

    human_readable, context_entry, raw_response = toggle_datastream_command(
        client=akamai_waf_client, stream_id=stream_id, option=option
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_get_client_list_command(mocker, akamai_waf_client):
    """
    Given:
        - A client.
    When:
        - running the command get_client_list_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import get_client_list_command

    test_data = util_load_json("test_data/get_client_list_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "get_client_list", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = get_client_list_command(client=akamai_waf_client)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_create_client_list_command(mocker, akamai_waf_client):
    """
    Given:
        - A client and arguments for creating a client list.
    When:
        - running the command create_client_list_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import create_client_list_command

    test_data = util_load_json("test_data/create_client_list_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "create_client_list", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = create_client_list_command(
        client=akamai_waf_client,
        name="Test Client List",
        type="IP",
        contract_id="ctr_1-23456",
        group_id=12345,
        notes="Test notes",
        tags=["tag1", "tag2"],
        entry_value="1.2.3.4",
        entry_description="Test entry",
        entry_tags=["entry_tag"],
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_deprecate_client_list_command(mocker, akamai_waf_client):
    """
    Given:
        - A client and a client_list_id.
    When:
        - running the command deprecate_client_list_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import deprecate_client_list_command
    import requests

    test_data = util_load_json("test_data/deprecate_client_list_test.json")
    expected_human_readable = test_data.get("human_readable")

    mock_response = requests.Response()
    mock_response.status_code = 204
    mocker.patch.object(akamai_waf_client, "deprecate_client_list", return_value=mock_response)

    human_readable, _, _ = deprecate_client_list_command(client=akamai_waf_client, client_list_id="12345")
    assert expected_human_readable == human_readable


def test_add_client_list_entry_command(mocker, akamai_waf_client):
    """
    Given:
        - A client and arguments for adding an entry to a client list.
    When:
        - running the command add_client_list_entry_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import add_client_list_entry_command

    test_data = util_load_json("test_data/add_client_list_entry_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")

    mocker.patch.object(akamai_waf_client, "add_client_list_entry", return_value=expected_raw_response)

    human_readable, _, raw_response = add_client_list_entry_command(
        client=akamai_waf_client, list_id="12345", value="1.2.3.4", description="Test entry", tags=["test_tag"]
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable


def test_remove_client_list_entry_command(mocker, akamai_waf_client):
    """
    Given:
        - A client and arguments for removing an entry from a client list.
    When:
        - running the command remove_client_list_entry_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import remove_client_list_entry_command

    test_data = util_load_json("test_data/remove_client_list_entry_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")

    mocker.patch.object(akamai_waf_client, "remove_client_list_entry", return_value=expected_raw_response)

    human_readable, _, raw_response = remove_client_list_entry_command(
        client=akamai_waf_client, list_id="12345", value=["1.2.3.4"]
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable


def test_get_contract_group_command(mocker, akamai_waf_client):
    """
    Given:
        - A client.
    When:
        - running the command get_contract_group_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import get_contract_group_command

    test_data = util_load_json("test_data/get_contract_group_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "get_contract_group", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = get_contract_group_command(client=akamai_waf_client)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_update_client_list_command(mocker, akamai_waf_client):
    """
    Given:
        - A client, list_id, and arguments for updating a client list.
    When:
        - running the command update_client_list_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import update_client_list_command

    test_data = util_load_json("test_data/update_client_list_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "update_client_list", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = update_client_list_command(
        client=akamai_waf_client,
        list_id="12345",
        name="New Test Client List",
        notes="New test notes",
        tags=["new_tag1", "new_tag2"],
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_update_client_list_entry_command(mocker, akamai_waf_client):
    """
    Given:
        - A client, list_id, and arguments for updating a client list entry.
    When:
        - running the command update_client_list_entry_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import update_client_list_entry_command

    test_data = util_load_json("test_data/update_client_list_entry_test.json")
    existing_list = test_data.get("existing_list")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    mocker.patch.object(akamai_waf_client, "get_client_list", return_value=existing_list)
    mocker.patch.object(akamai_waf_client, "update_client_list_entry", return_value=expected_raw_response)

    human_readable, context_entry, raw_response = update_client_list_entry_command(
        client=akamai_waf_client, list_id="12345", value="1.2.3.4", description="New description", tags="new_tag"
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_get_datastream_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A stream_id.
    When:
        - running the command get_datastream_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import get_datastream_command

    stream_id = 12345

    test_data = util_load_json("test_data/get_datastream_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get(f"https://hostname/datastream-config-api/v2/log/streams/{stream_id}", json=expected_raw_response)

    human_readable, context_entry, raw_response = get_datastream_command(client=akamai_waf_client, stream_id=stream_id)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_list_edgehostname_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A contract_id.
    When:
        - running the command list_edgehostname_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import list_edgehostname_command

    contract_id = "ctr_1-23456"

    test_data = util_load_json("test_data/list_edgehostname_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.get(f"https://hostname/papi/v1/edgehostnames?contractId={contract_id}", json=expected_raw_response)

    human_readable, context_entry, raw_response = list_edgehostname_command(client=akamai_waf_client, contract_id=contract_id)
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry


def test_new_datastream_command(requests_mock, akamai_waf_client):
    """
    Given:
        - A stream_name, group_id, contract_id, properties, and dataset_fields.
    When:
        - running the command new_datastream_command.
    Then:
        - The returned values (human_readable, context_entry, raw_response) are correct.
    """
    from Akamai_WAF import new_datastream_command

    group_id = 12345
    contract_id = "ctr_1-23456"
    properties = "67890"
    stream_name = "Test Stream"
    dataset_fields = "1,2,3"

    test_data = util_load_json("test_data/new_datastream_test.json")
    expected_raw_response = test_data.get("raw_response")
    expected_human_readable = test_data.get("human_readable")
    expected_context_entry = test_data.get("context_entry")

    requests_mock.post("https://hostname/datastream-config-api/v2/log/streams", json=expected_raw_response)

    human_readable, context_entry, raw_response = new_datastream_command(
        client=akamai_waf_client,
        stream_name=stream_name,
        group_id=group_id,
        contract_id=contract_id,
        properties=properties,
        dataset_fields=dataset_fields,
    )
    assert expected_raw_response == raw_response
    assert expected_human_readable == human_readable
    assert expected_context_entry == context_entry
