import json
import time

import pytest
from Tenable_sc import (
    Client,
    convert_unix_to_iso,
    create_asset_command,
    create_get_device_request_params_and_path,
    create_policy_request_body,
    create_scan_command,
    create_user_request_body,
    delete_asset_command,
    delete_scan_command,
    delete_user_command,
    fetch_assets_page,
    fetch_vulnerabilities_page,
    generate_snapshot_id,
    get_alert_command,
    get_all_scan_results_command,
    get_asset_command,
    get_device_command,
    get_organization_command,
    get_query,
    get_scan_report_command,
    get_scan_status_command,
    get_system_information_command,
    get_system_licensing_command,
    is_assets_fetch_in_progress,
    is_vulns_fetch_in_progress,
    launch_scan,
    list_alerts_command,
    list_assets_command,
    list_credentials_command,
    list_groups_command,
    list_plugin_family_command,
    list_policies_command,
    list_queries,
    list_query_command,
    list_report_definitions_command,
    list_repositories_command,
    list_scans_command,
    list_users_command,
    list_zones_command,
    parse_vulnerabilities,
    skip_fetch_assets,
    transform_record_timestamps,
    update_asset_command,
    validate_create_scan_inputs,
    validate_user_body_params,
)

client_mocker = Client(
    verify_ssl=False, proxy=True, access_key="access_key", secret_key="secret_key", url="www.tenable_sc_url_mock.com"
)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_update_asset_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, and expected hr.
    - Case 1: args with asset_id, name, and description to update.

    When:
    - Running update_asset_command.

    Then:
    - Ensure that the response was parsed correctly and right HR is returned.
    - Case 1: Should include the right asset_id in the hr.
    """
    test_data = load_json("./test_data/test_update_asset_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = update_asset_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3"])
def test_list_zones_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      response mock, expected hr and ec outputs.
    - Case 1: A response with empty response field
    - Case 2: A response with 2 zones, where the zones also have the same scanners.
    - Case 3: A response with 3 zones, where the zones also have different scanners.

    When:
    - Running list_zones_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC outputs are returned.
    - Case 1: Should create only scan zones table in HR, and include one zone with ID = 0 and name = all zones in EC.
    - Case 2: Should create both tables in HR, the second table should have only one entry.
              Should include two zones in the EC and each zone should have a scanner.
    - Case 3: Should create both tables in HR, the second table should have two entries.
              Should include two zones in the EC and each zone should have a scanner.
    """
    test_data = load_json("./test_data/test_list_zones_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_zones_command(client_mocker, {})
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3"])
def test_list_groups_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr and ec outputs.
    - Case 1: Args with limit=1 and show_users=True, and a response with 2 groups where each have users.
    - Case 2: Args without limit (default is 50) and show_users=False, and a response with 2 groups where each have users.
    - Case 3: Args without limit, and show_users=True, and a response with 2 groups where each have users.

    When:
    - Running list_groups_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC outputs are returned.
    - Case 1: Should return information about only 1 group in the HR and EC and include the users table.
    - Case 2: Should return information about both groups in the HR and EC,
              and exclude the users table and users field from EC.
    - Case 3: Should return information about both groups in the HR where each group has its own users table.
              And EC where each group include a user field.
    """
    test_data = load_json("./test_data/test_list_groups_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_groups_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3", "test_case_4"])
def test_list_plugin_family_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr and ec outputs.
    - Case 1: Args with limit=1 and is_active=true, and a response with 2 plugin families.
    - Case 2: Empty args, and a response with 2 plugins.
    - Case 3: Args with plugin_id, and a response with the plugin family information where the plugin type is malware.
    - Case 4: Args with plugin_id, and a response with the plugin family information where the plugin type is active.

    When:
    - Running list_plugin_family_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC outputs are returned.
    - Case 1: Should return a table with is_active column in the HR, and EC that include only the first plugin family.
    - Case 2: Should return a table with name column in the HR, and EC that include both plugin families.
    - Case 3: Should return a table with only id and name columns, and EC with plugin type in it.
    - Case 4: Should return a table with all columns (id, name, and is_active), and EC with plugin type in it.
    """
    test_data = load_json("./test_data/test_list_plugin_family_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_plugin_family_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3", "test_case_4", "test_case_5", "test_case_6"])
def test_validate_user_body_params(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, command_type flag and the expected error message.
    - Case 1: Args with group_id which is not a number, and a command_type flag that point to create.
    - Case 2: Args with invalid time_zone, and a command_type flag that point to create.
    - Case 3: Args with only password, and a command_type flag that point to update.
    - Case 4: Args with password string of length = 1, and a command_type flag that point to create.
    - Case 5: Args with invalid email address, and a command_type flag that point to create.
    - Case 6: Args with email_notice but no email field, and a command_type flag that point to create.

    When:
    - Running validate_user_body_params.

    Then:
    - Ensure that the right error was thrown.
    - Case 1: Should throw an error for none-number argument.
    - Case 2: Should throw an error for invalid time_zone.
    - Case 3: Should throw an error for missing current_password field.
    - Case 4: Should throw an error for too short password string.
    - Case 5: Should throw an error for invalid email address.
    - Case 6: Should throw an error for missing email field.
    """
    test_data = load_json("./test_data/test_validate_user_body_params.json").get(test_case, {})
    args = test_data.get("args")
    command_type = test_data.get("command_type")

    with pytest.raises(Exception) as e:
        validate_user_body_params(args, command_type)

    assert test_data.get("expected_error_msg") in str(e.value)


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_create_user_request_body(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, and expected body.
    - Case 1: Args with first_name, role_id, managed_users_groups, and time_zone fields.

    When:
    - Running create_user_request_body.

    Then:
    - Ensure that the body was created correctly.
    - Case 1: Should create a body with all the given fields, first_name should be at the root,
    role_id should be translated to the correspondence number, managed_users_groups should be a list of ID dicts,
    and time_zone should be a list of one dict with name, value, and tags.
    """
    test_data = load_json("./test_data/test_create_user_request_body.json").get(test_case, {})
    args = test_data.get("args")
    body = create_user_request_body(args)
    assert test_data.get("expected_body") == body


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3"])
def test_validate_create_scan_inputs(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, and the expected error message.
    - Case 1: Args with invalid time_zone.
    - Case 2: Empty args.
    - Case 3: args with ip_list and schedule = 'schedule'.

    When:
    - Running validate_create_scan_inputs.

    Then:
    - Ensure that the right error was thrown.
    - Case 1: Should throw an error for invalid time_zone.
    - Case 2: Should throw an error for missing ip_list and assets.
    - Case 3: Should throw an error for missing dependent scan ID.
    """
    test_data = load_json("./test_data/test_validate_create_scan_inputs.json").get(test_case, {})
    args = test_data.get("args")

    with pytest.raises(Exception) as e:
        validate_create_scan_inputs(args)

    assert test_data.get("expected_error_msg") in str(e.value)


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3", "test_case_4"])
def test_validate_credentials(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, and the expected error message.
    - Case 1: Only access key filled.
    - Case 2: Only username filled.
    - Case 3: No argument filled.
    - Case 4: args with access key and username filled.

    When:
    - Running Client creator.

    Then:
    - Ensure that an error for missing credentials pair is thrown.
    """
    test_data = load_json("./test_data/test_validate_credentials.json").get(test_case, {})
    access_key = test_data.get("access_key")
    secret_key = test_data.get("secret_key")
    user_name = test_data.get("user_name")
    password = test_data.get("password")

    with pytest.raises(Exception) as e:
        Client(proxy=True, access_key=access_key, secret_key=secret_key, user_name=user_name, password=password)

    assert "Please provide either user_name and password or secret_key and access_key" in str(e.value)


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_create_policy_request_body(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, and expected body.
    - Case 1: Args with policy_description, policy_template_id, family_id,and plugins_id.

    When:
    - Running create_policy_request_body.

    Then:
    - Ensure that the body was created correctly.
    - Case 1: Should create a body with all the given fields, and include default none-included (preference and context).
    """
    test_data = load_json("./test_data/test_create_policy_request_body.json").get(test_case, {})
    args = test_data.get("args")
    body = create_policy_request_body(args)
    assert test_data.get("expected_body") == body


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3"])
def test_create_scan_body(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, mock_response (for some test cases) and expected body.
    - Case 1: Args with scan_type, scan_name saved under "name", repository_id, asset_ids set to "AllManageable",
    schedule set to "rollover", and dependent_id. Also, a mock_response to get asses with two manageable assets.
    - Case 2: Args with policy_id, scan_name saved under "scan_name", credentials with few credentials, max_scan_time,
    schedule set to "ical", time_zone, start_time, repeat_rule_freq, repeat_rule_interval, and repeat_rule_by_day.
    - Case 3: Args with plugins_id, zone_id and a comma separated list of report_ids.

    When:
    - Running create_scan_body.

    Then:
    - Ensure that the body was created correctly.
    - Case 1: Should set type to be scan_type value, configure scan_name, add repository_id under repository dict,
              send a get_assets request and include the two assets from the response in the request body,
              set max_scan_time to 3600, and include dependent_id under schedule.
    - Case 2: Should set type to be policy, configure scan_name, create a list of credentials id dicts,
              calculate max_scan_time, and include time_zone, start_time, repeat_rule_freq, repeat_rule_interval,
              and repeat_rule_by_day under schedule.
    - Case 3: Should set type to be plugin, create a zone dict, a list of report ids dicts and set max_scan_time to 3600.
    """
    test_data = load_json("./test_data/test_create_scan_body.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response", {}))
    body = client_mocker.create_scan_body(args)
    assert test_data.get("expected_body") == body


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3"])
def test_create_get_device_request_params_and_path(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      function args (uuid, ip, dns_name, repo), expected path and params, and expected body.
    - Case 1: repo, uuid and dns_name.
    - Case 2: ip.
    - Case 3: ip and dns_name.

    When:
    - Running create_get_device_request_params_and_path.

    Then:
    - Ensure that the body was created correctly.
    - Case 1: Path should include repo, params should include uuid and ignore dns_name.
    - Case 2: Path should be deviceInfo, params should include ip.
    - Case 3: Path should be deviceInfo, params should include ip and dns_name.
    """
    test_data = load_json("./test_data/test_create_get_device_request_params_and_path.json").get(test_case, {})
    uuid = test_data.get("uuid")
    ip = test_data.get("ip")
    dns_name = test_data.get("dns_name")
    repo = test_data.get("repo")
    path, params = create_get_device_request_params_and_path(uuid, ip, dns_name, repo)
    assert test_data.get("expected_path") == path
    assert test_data.get("expected_params") == params


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_create_get_vulnerability_request_body(test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, query, scan_results_id, calling_command, and expected body.
    - Case 1: Args with scan_results_id, vulnerability_id, sort_field, and sort_direction.
              Empty query, scan_results_id, and calling_command.
    - Case 2: Args with scan_results_id, vulnerability_id, query_id, source_type and limit higher than 200.
              Empty query, scan_results_id, and calling_command.

    When:
    - Running create_get_vulnerability_request_body.

    Then:
    - Ensure that the body was created correctly.
    - Case 1: Should complete all the none-given fields, count source_type as individual, and add related fields.
    - Case 2: Should lower limit to 200, ignore scan_results_id and vulnerability_id.
    """
    test_data = load_json("./test_data/test_create_get_vulnerability_request_body.json").get(test_case, {})
    args = test_data.get("args", {})
    body = client_mocker.create_get_vulnerability_request_body(args)
    assert test_data.get("expected_body") == body


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_query(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      query_id, response mock, expected hr, and expected_ec.
    - Case 1: response mock that misses filters section.

    When:
    - Running get_query.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should exclude the filters section from the HR but not from the EC.
    """
    test_data = load_json("./test_data/test_get_query.json").get(test_case, {})
    query_id = test_data.get("query_id")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    _, hr, query = get_query(client_mocker, query_id)
    assert test_data.get("expected_hr") == hr
    assert test_data.get("expected_ec") == query


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_list_queries(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      response mock, expected hr, and expected_ec.
    - Case 1: response mock with 2 manageable and 2 usable queries, one of the queries appears in both lists,
              some queries with filters and some don't.

    When:
    - Running list_queries.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should Include the filters section in the HR,
    should have "True" in both manageable and usable columns for the mutual query and fill False in the none-mutual queries.
    """
    test_data = load_json("./test_data/test_list_queries.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    _, hr, query = list_queries(client_mocker, "")
    assert test_data.get("expected_hr") == hr
    assert test_data.get("expected_ec") == query


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_query_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, function to mock, response mock, expected hr, and expected_ec.
    - Case 1: empty args, mocked_function = list_queries, response mock with 2 manageable and 2 usable queries,
              one of the queries appears in both lists, some queries with filters and some don't.
    - Case 2: args with query_id, mocked_function = get_query, response mock that misses filters section.

    When:
    - Running list_query_command.

    Then:
    - Ensure that the right function is mocked and the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should call list_queries, Include the filters section in the HR,
    should have "True" in both manageable and usable columns for the mutual query and fill False in the none-mutual queries.
    - Case 2: Should call get_query, exclude the filters section from the HR and EC.
    """
    test_data = load_json("./test_data/test_list_query_command.json").get(test_case, {})
    mocked_function = test_data.get("mocked_function")
    args = test_data.get("args")
    mocker.patch(f"Tenable_sc.Client.{mocked_function}", return_value=test_data.get("mock_response"))
    command_results = list_query_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3"])
def test_list_users_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with id and email pointing to an email different from the email in the response,
              response of a get user request.
    - Case 2: args with email and username, response of a list users request with 3 users.
    - Case 2: Empty args, response of a list users request with 3 users.

    When:
    - Running list_users_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should include the retrieved user in the response.
    - Case 2: Should filter out the user with un matched username and ignore the email argument.
    - Case 2: Should retrieve HR and EC including all 3 users.
    """
    test_data = load_json("./test_data/test_list_users_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_users_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2", "test_case_3", "test_case_4", "test_case_5"])
def test_launch_scan_errors(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, command_type flag and the expected error message.
    - Case 1: Args with diagnostic_target but no diagnostic_password.
    - Case 2: Args with diagnostic_password but no diagnostic_target.
    - Case 3: Args with both diagnostic_password and diagnostic_target, and an empty mock response.
    - Case 4: Args without both diagnostic_password and diagnostic_target,
    and an empty mock response with empty response section.
    - Case 5: Args with both diagnostic_password and diagnostic_target,
    and a response with missing scanResult from response section.

    When:
    - Running launch_scan.

    Then:
    - Ensure that the right error was thrown.
    - Case 1: Should throw an error for none-number argument.
    - Case 2: Should throw an error for invalid time_zone.
    - Case 3: Should throw aCould not retrieve the scans error.
    - Case 4: Should throw aCould not retrieve the scans error.
    - Case 5: Should throw aCould not retrieve the scans error.
    """
    test_data = load_json("./test_data/test_launch_scan_errors.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response", {}))

    with pytest.raises(Exception) as e:
        launch_scan(client_mocker, args)

    assert test_data.get("expected_error_msg") in str(e.value)


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_list_report_definitions_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 2 report definitions with the same name,
              where one report is later than the second.

    When:
    - Running list_report_definitions_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only one report definition, the one that occurred later.
    """
    test_data = load_json("./test_data/test_list_report_definitions_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_report_definitions_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


def test_delete_asset_command(mocker):
    """
    Given:
    - Args with asset_id to delete.

    When:
    - Running delete_asset_command.

    Then:
    - Ensure that the response was parsed correctly and right HR is returned.
    """
    args = {"asset_id": "test_id"}
    mocker.patch.object(client_mocker, "send_request", return_value={"code": 200})
    command_results = delete_asset_command(client_mocker, args)
    assert command_results.readable_output == "Asset test_id was deleted successfully."


def test_delete_scan_command(mocker):
    """
    Given:
    - Args with scan_id to delete.

    When:
    - Running delete_scan_command.

    Then:
    - Ensure that the response was parsed correctly and right HR is returned.
    """
    args = {"scan_id": "test_id"}
    mocker.patch.object(client_mocker, "send_request", return_value={"code": 200})
    command_results = delete_scan_command(client_mocker, args)
    assert command_results.readable_output == "Scan test_id was deleted successfully."


def test_delete_user_command(mocker):
    """
    Given:
    - Args with user_id to delete.

    When:
    - Running delete_user_command.

    Then:
    - Ensure that the response was parsed correctly and right HR is returned.
    """
    args = {"user_id": "test_id"}
    mocker.patch.object(client_mocker, "send_request", return_value={"code": 200})
    command_results = delete_user_command(client_mocker, args)
    assert command_results.readable_output == "User test_id was deleted successfully."


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_scans_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 2 usable and 2 manageable scans.
    - Case 2: Empty args, and mock response to response with 2 usable and 2 manageable scans.

    When:
    - Running test_list_scans_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only the manageable scans.
    - Case 2: Should return only the usable scans.
    """
    test_data = load_json("./test_data/test_list_scans_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_scans_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_get_scan_status_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 2 usable and 2 manageable scans.
    - Case 2: Empty args, and mock response to response with 2 usable and 2 manageable scans.

    When:
    - Running get_scan_status_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only the manageable scans.
    - Case 2: Should return only the usable scans.
    """
    test_data = load_json("./test_data/test_get_scan_status_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = get_scan_status_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_device_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with ip, repo_id, dns_name, and uuid.

    When:
    - Running get_device_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should Include 2 Commands results objects, 1 for endpoint and 1 for device.
    """
    test_data = load_json("./test_data/test_get_device_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = get_device_command(client_mocker, args)
    for i in range(2):
        assert test_data.get("expected_hr")[i] == command_results[i].readable_output
        assert test_data.get("expected_ec")[i] == command_results[i].outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_policies_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 2 usable and 2 manageable policies.
    - Case 2: Empty args, and mock response to response with 2 usable and 2 manageable policies.

    When:
    - Running list_policies_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only the manageable policies.
    - Case 2: Should return only the usable policies.
    """
    test_data = load_json("./test_data/test_list_policies_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_policies_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_credentials_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 1 usable and 1 manageable credentials.
    - Case 2: Empty args, and mock response to response with 1 usable and 1 manageable credentials.

    When:
    - Running list_credentials_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only the manageable credentials.
    - Case 2: Should return only the usable credentials.
    """
    test_data = load_json("./test_data/test_list_credentials_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_credentials_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_create_asset_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with name, description, and ip_list and a successful response.

    When:
    - Running create_asset_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return the created asset info.
    """
    test_data = load_json("./test_data/test_create_asset_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = create_asset_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_create_scan_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with multiple scan args and a successful response.

    When:
    - Running create_scan_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return the created scan info.
    """
    test_data = load_json("./test_data/test_create_scan_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = create_scan_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_scan_report_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with scan results id and a mock response.

    When:
    - Running get_scan_report_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return the parsed HR and EC.
    """
    test_data = load_json("./test_data/test_get_scan_report_command.json").get(test_case, {})
    args = test_data.get("args")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = get_scan_report_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_system_information_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      response mock, and expected hr.
    - Case 1: A mock response.

    When:
    - Running get_system_information_command.

    Then:
    - Ensure that the response was parsed correctly and right HR is returned.
    - Case 1: Should return the parsed hr.
    """
    test_data = load_json("./test_data/test_get_system_information_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = get_system_information_command(client_mocker, {})
    assert test_data.get("expected_hr") == command_results.readable_output


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_system_licensing_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      response mock, and expected hr.
    - Case 1: A mock response.

    When:
    - Running get_system_licensing_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and ec are returned.
    - Case 1: Should return the parsed hr and ec.
    """
    test_data = load_json("./test_data/test_get_system_licensing_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = get_system_licensing_command(client_mocker, {})
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_all_scan_results_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with limit=1, and a mock response with 2 results.

    When:
    - Running get_all_scan_results_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and ec are returned.
    - Case 1: Should return only the first scan result.
    """
    test_data = load_json("./test_data/test_get_all_scan_results_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    args = test_data.get("args")
    command_results = get_all_scan_results_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_alerts_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 1 usable and 1 manageable alerts.
    - Case 2: Empty args, and mock response to response with 1 usable and 1 manageable alerts.

    When:
    - Running list_alerts_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only the manageable alerts.
    - Case 2: Should return only the usable alerts.
    """
    test_data = load_json("./test_data/test_list_alerts_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    args = test_data.get("args")
    command_results = list_alerts_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_list_repositories_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      response mock, expected hr, and expected_ec.
    - Case 1: Mock response with 1 repo.

    When:
    - Running list_repositories_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    """
    test_data = load_json("./test_data/test_list_repositories_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    command_results = list_repositories_command(client_mocker, {})
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_list_assets_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with manageable = true, and mock response to response with 1 usable and 1 manageable assets.
    - Case 2: Empty args, and mock response to response with 1 usable and 1 manageable assets.

    When:
    - Running list_assets_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return only the manageable assets.
    - Case 2: Should return only the usable assets.
    """
    test_data = load_json("./test_data/test_list_assets_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    args = test_data.get("args")
    command_results = list_assets_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_asset_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with asset id, and a mock response.

    When:
    - Running get_asset_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should parse all the ips and return both HR and EC.
    """
    test_data = load_json("./test_data/test_get_asset_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    args = test_data.get("args")
    command_results = get_asset_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_alert_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with alert id, and a mock response.

    When:
    - Running get_alert_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return all tables with parsed response.
    """
    test_data = load_json("./test_data/test_get_alert_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    args = test_data.get("args")
    command_results = get_alert_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


@pytest.mark.parametrize("test_case", ["test_case_1"])
def test_get_organization_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr, and expected_ec.
    - Case 1: args with fields vulnScoreMedium, repositories, restrictedIPs and a mock response.

    When:
    - Running get_organization_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC is returned.
    - Case 1: Should return all tables with parsed response.
    """
    test_data = load_json("./test_data/test_get_organization_command.json").get(test_case, {})
    mocker.patch.object(client_mocker, "send_request", return_value=test_data.get("mock_response"))
    args = test_data.get("args")
    command_results = get_organization_command(client_mocker, args)
    assert test_data.get("expected_hr") == command_results.readable_output
    assert test_data.get("expected_ec") == command_results.outputs


""" FETCH ASSETS TESTS """


def test_generate_snapshot_id():
    """
    Given:
    - Nothing.

    When:
    - Calling generate_snapshot_id.

    Then:
    - Ensure a string of digits is returned representing milliseconds timestamp.
    """
    snapshot_id = generate_snapshot_id()
    assert isinstance(snapshot_id, str)
    assert snapshot_id.isdigit()
    assert len(snapshot_id) >= 13  # millisecond timestamp


def test_is_assets_fetch_in_progress_true():
    """
    Given:
    - A last_run dict with current_offset set.

    When:
    - Calling is_assets_fetch_in_progress.

    Then:
    - Should return True.
    """
    last_run = {"current_offset": 500, "snapshot_id": "123456"}
    assert is_assets_fetch_in_progress(last_run) is True


def test_is_assets_fetch_in_progress_false():
    """
    Given:
    - A last_run dict without current_offset.

    When:
    - Calling is_assets_fetch_in_progress.

    Then:
    - Should return False.
    """
    last_run = {"assets_last_fetch": 1709500000.0}
    assert is_assets_fetch_in_progress(last_run) is False


def test_skip_fetch_assets_no_previous_fetch():
    """
    Given:
    - A last_run dict with no assets_last_fetch timestamp.

    When:
    - Calling skip_fetch_assets.

    Then:
    - Should return False (don't skip, this is the first fetch).
    """
    last_run = {}
    assert skip_fetch_assets(last_run) is False


def test_skip_fetch_assets_too_soon():
    """
    Given:
    - A last_run dict with assets_last_fetch set to 10 minutes ago.

    When:
    - Calling skip_fetch_assets.

    Then:
    - Should return True (skip, not enough time has passed).
    """
    last_run = {"assets_last_fetch": time.time() - (10 * 60)}  # 10 minutes ago
    assert skip_fetch_assets(last_run) is True


def test_skip_fetch_assets_enough_time():
    """
    Given:
    - A last_run dict with assets_last_fetch set to 2 hours ago.

    When:
    - Calling skip_fetch_assets.

    Then:
    - Should return False (don't skip, enough time has passed).
    """
    last_run = {"assets_last_fetch": time.time() - (120 * 60)}  # 2 hours ago
    assert skip_fetch_assets(last_run) is False


def test_skip_fetch_assets_in_progress():
    """
    Given:
    - A last_run dict with assets_last_fetch set to 10 minutes ago but fetch is in progress.

    When:
    - Calling skip_fetch_assets.

    Then:
    - Should return False (don't skip, there's an ongoing fetch).
    """
    last_run = {
        "assets_last_fetch": time.time() - (10 * 60),
        "current_offset": 500,
    }
    assert skip_fetch_assets(last_run) is False


def test_fetch_assets_page_first_page(mocker):
    """
    Given:
    - A mock response with 2 results out of 3 total (first page).

    When:
    - Calling fetch_assets_page with offset 0.

    Then:
    - Should return 2 assets.
    - Should set current_offset to 2 in last_run (more pages to fetch).
    - Should set nextTrigger to "30".
    """
    test_data = load_json("./test_data/test_search_hosts.json")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data["first_page"])

    last_run = {"current_offset": 0, "total_assets_fetched": 0, "snapshot_id": "123456"}
    assets = fetch_assets_page(client_mocker, last_run)

    assert len(assets) == 2
    assert last_run["current_offset"] == 2
    assert last_run["total_assets_fetched"] == 2
    assert last_run["nextTrigger"] == "30"
    assert assets[0]["name"] == "TestHost1"
    assert assets[1]["name"] == "TestHost2"


def test_fetch_assets_page_last_page(mocker):
    """
    Given:
    - A mock response with 1 result out of 3 total (last page, offset=2).

    When:
    - Calling fetch_assets_page with offset 2.

    Then:
    - Should return 1 asset.
    - Should clear current_offset from last_run (no more pages).
    - Should clear total_records from last_run.
    """
    test_data = load_json("./test_data/test_search_hosts.json")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data["last_page"])

    last_run = {"current_offset": 2, "total_assets_fetched": 2, "snapshot_id": "123456"}
    assets = fetch_assets_page(client_mocker, last_run)

    assert len(assets) == 1
    assert "current_offset" not in last_run
    assert "total_records" not in last_run
    assert last_run["total_assets_fetched"] == 3
    assert assets[0]["name"] == "TestHost3"


def test_fetch_assets_page_empty_response(mocker):
    """
    Given:
    - A mock response with 0 results.

    When:
    - Calling fetch_assets_page.

    Then:
    - Should return empty list.
    - Should clear pagination state from last_run.
    """
    test_data = load_json("./test_data/test_search_hosts.json")
    mocker.patch.object(client_mocker, "send_request", return_value=test_data["empty_response"])

    last_run = {"current_offset": 0, "total_assets_fetched": 0, "snapshot_id": "123456"}
    assets = fetch_assets_page(client_mocker, last_run)

    assert len(assets) == 0
    assert "current_offset" not in last_run
    assert "total_records" not in last_run


def test_fetch_assets_page_no_response(mocker):
    """
    Given:
    - A None response from the API.

    When:
    - Calling fetch_assets_page.

    Then:
    - Should return empty list.
    - Should clear pagination state from last_run.
    """
    mocker.patch.object(client_mocker, "send_request", return_value=None)

    last_run = {"current_offset": 0, "total_assets_fetched": 0, "snapshot_id": "123456"}
    assets = fetch_assets_page(client_mocker, last_run)

    assert len(assets) == 0
    assert "current_offset" not in last_run


def test_search_hosts_client_method(mocker):
    """
    Given:
    - A client with search_hosts method.

    When:
    - Calling search_hosts with fields, offsets, and no filters.

    Then:
    - Should call send_request with correct path, method, params, and body.
    """
    test_data = load_json("./test_data/test_search_hosts.json")
    mock_send = mocker.patch.object(client_mocker, "send_request", return_value=test_data["first_page"])

    result = client_mocker.search_hosts(
        fields="id,uuid,name",
        start_offset=0,
        end_offset=500,
    )

    mock_send.assert_called_once_with(
        path="hosts/search",
        method="POST",
        body={},
        params={
            "fields": "id,uuid,name",
            "startOffset": "0",
            "endOffset": "500",
            "pagination": "true",
        },
    )
    assert result == test_data["first_page"]


""" VULNERABILITY FETCH TESTS """


def test_is_vulns_fetch_in_progress_true():
    """
    Given:
    - A last_run dict with vuln_current_offset set.

    When:
    - Calling is_vulns_fetch_in_progress.

    Then:
    - Should return True (vulnerability fetch is in progress).
    """
    last_run = {"vuln_current_offset": 500}
    assert is_vulns_fetch_in_progress(last_run) is True


def test_is_vulns_fetch_in_progress_false():
    """
    Given:
    - A last_run dict without vuln_current_offset.

    When:
    - Calling is_vulns_fetch_in_progress.

    Then:
    - Should return False (no vulnerability fetch in progress).
    """
    last_run = {"assets_last_fetch": time.time()}
    assert is_vulns_fetch_in_progress(last_run) is False


def test_skip_fetch_assets_vulns_in_progress():
    """
    Given:
    - A last_run dict with assets_last_fetch set to 10 minutes ago and vulns fetch in progress.

    When:
    - Calling skip_fetch_assets.

    Then:
    - Should return False (don't skip, there's an ongoing vulnerability fetch).
    """
    last_run = {
        "assets_last_fetch": time.time() - (10 * 60),
        "vuln_current_offset": 500,
    }
    assert skip_fetch_assets(last_run) is False


def test_fetch_vulnerabilities_page_first_page(mocker):
    """
    Given:
    - A mock response with 2 vulnerability results out of 3 total (first page).

    When:
    - Calling fetch_vulnerabilities_page with offset 0.

    Then:
    - Should return 2 vulnerabilities.
    - Should set vuln_current_offset to 2 in last_run (more pages to fetch).
    - Should set nextTrigger to "30".
    """
    mock_response = {
        "response": {
            "totalRecords": "3",
            "returnedRecords": 2,
            "results": [
                {
                    "pluginID": "10001",
                    "name": "Test Vuln 1",
                    "severity": {"id": "3", "name": "High"},
                    "family": {"name": "General"},
                    "lastSeen": "1709654400",
                    "firstSeen": "1709568000",
                    "pluginDescription": "Test description 1",
                },
                {
                    "pluginID": "10002",
                    "name": "Test Vuln 2",
                    "severity": {"id": "2", "name": "Medium"},
                    "family": {"name": "Web Servers"},
                    "lastSeen": "1709654400",
                    "firstSeen": "1709568000",
                    "pluginDescription": "Test description 2",
                },
            ],
        }
    }
    mocker.patch.object(client_mocker, "send_request", return_value=mock_response)

    last_run = {"vuln_current_offset": 0, "total_vulns_fetched": 0}
    vulns = fetch_vulnerabilities_page(client_mocker, last_run)

    assert len(vulns) == 2
    assert last_run["vuln_current_offset"] == 2
    assert last_run["total_vulns_fetched"] == 2
    assert last_run["nextTrigger"] == "30"
    assert vulns[0]["pluginID"] == "10001"
    assert vulns[1]["pluginID"] == "10002"


def test_fetch_vulnerabilities_page_last_page(mocker):
    """
    Given:
    - A mock response with 1 vulnerability result out of 3 total (last page, offset=2).

    When:
    - Calling fetch_vulnerabilities_page with offset 2.

    Then:
    - Should return 1 vulnerability.
    - Should clear vuln_current_offset from last_run (no more pages).
    """
    mock_response = {
        "response": {
            "totalRecords": "3",
            "returnedRecords": 1,
            "results": [
                {
                    "pluginID": "10003",
                    "name": "Test Vuln 3",
                    "severity": {"id": "1", "name": "Low"},
                    "family": {"name": "DNS"},
                    "lastSeen": "1709654400",
                    "firstSeen": "1709568000",
                    "pluginDescription": "Test description 3",
                },
            ],
        }
    }
    mocker.patch.object(client_mocker, "send_request", return_value=mock_response)

    last_run = {"vuln_current_offset": 2, "total_vulns_fetched": 2}
    vulns = fetch_vulnerabilities_page(client_mocker, last_run)

    assert len(vulns) == 1
    assert "vuln_current_offset" not in last_run
    assert last_run["total_vulns_fetched"] == 3
    assert vulns[0]["pluginID"] == "10003"


def test_fetch_vulnerabilities_page_empty_response(mocker):
    """
    Given:
    - A mock response with 0 vulnerability results.

    When:
    - Calling fetch_vulnerabilities_page.

    Then:
    - Should return empty list.
    - Should clear vuln pagination state from last_run.
    """
    mock_response = {
        "response": {
            "totalRecords": "0",
            "returnedRecords": 0,
            "results": [],
        }
    }
    mocker.patch.object(client_mocker, "send_request", return_value=mock_response)

    last_run = {"vuln_current_offset": 0, "total_vulns_fetched": 0}
    vulns = fetch_vulnerabilities_page(client_mocker, last_run)

    assert len(vulns) == 0
    assert "vuln_current_offset" not in last_run


def test_fetch_vulnerabilities_page_no_response(mocker):
    """
    Given:
    - A None response from the API.

    When:
    - Calling fetch_vulnerabilities_page.

    Then:
    - Should return empty list.
    - Should clear vuln pagination state from last_run.
    """
    mocker.patch.object(client_mocker, "send_request", return_value=None)

    last_run = {"vuln_current_offset": 0, "total_vulns_fetched": 0}
    vulns = fetch_vulnerabilities_page(client_mocker, last_run)

    assert len(vulns) == 0
    assert "vuln_current_offset" not in last_run
    assert "total_vulns_fetched" not in last_run


def test_parse_vulnerabilities_normal():
    """
    Given:
    - A list of vulnerability records with lastSeen and firstSeen fields.

    When:
    - Calling parse_vulnerabilities.

    Then:
    - Should add _time field from lastSeen (converted to ISO 8601).
    - Should convert firstSeen and lastSeen to ISO 8601 format.
    - Should set isTruncated to False for normal-sized entries.
    """
    vulns = [
        {
            "pluginID": "10001",
            "name": "Test Vuln",
            "lastSeen": "1709654400",
            "firstSeen": "1709568000",
            "pluginDescription": "Short description",
        },
        {
            "pluginID": "10002",
            "name": "Test Vuln 2",
            "lastSeen": "1709654400",
            "firstSeen": "1709568000",
            "pluginDescription": "Another description",
        },
    ]
    result = parse_vulnerabilities(vulns)

    assert len(result) == 2
    assert result[0]["_time"] == "2024-03-05T16:00:00.000Z"
    assert result[0]["lastSeen"] == "2024-03-05T16:00:00.000Z"
    assert result[0]["firstSeen"] == "2024-03-04T16:00:00.000Z"
    assert result[0]["isTruncated"] is False
    assert result[1]["_time"] == "2024-03-05T16:00:00.000Z"
    assert result[1]["lastSeen"] == "2024-03-05T16:00:00.000Z"
    assert result[1]["firstSeen"] == "2024-03-04T16:00:00.000Z"
    assert result[1]["isTruncated"] is False


def test_parse_vulnerabilities_uses_firstseen_fallback():
    """
    Given:
    - A vulnerability record without lastSeen but with firstSeen.

    When:
    - Calling parse_vulnerabilities.

    Then:
    - Should use firstSeen (converted to ISO 8601) as the _time field.
    """
    vulns = [
        {
            "pluginID": "10001",
            "name": "Test Vuln",
            "firstSeen": "1709568000",
            "pluginDescription": "Description",
        },
    ]
    result = parse_vulnerabilities(vulns)

    assert result[0]["_time"] == "2024-03-04T16:00:00.000Z"
    assert result[0]["firstSeen"] == "2024-03-04T16:00:00.000Z"


def test_fetch_vulnerabilities_analysis_client_method(mocker):
    """
    Given:
    - A client with fetch_vulnerabilities_analysis method.

    When:
    - Calling fetch_vulnerabilities_analysis with start_offset and end_offset.

    Then:
    - Should call send_request with correct path, method, and body.
    """
    mock_response = {
        "response": {
            "totalRecords": "0",
            "returnedRecords": 0,
            "results": [],
        }
    }
    mock_send = mocker.patch.object(client_mocker, "send_request", return_value=mock_response)

    result = client_mocker.fetch_vulnerabilities_analysis(
        start_offset=0,
        end_offset=500,
    )

    mock_send.assert_called_once_with(
        path="analysis",
        method="POST",
        body={
            "type": "vuln",
            "sourceType": "cumulative",
            "view": "all",
            "wasVuln": "excludeWas",
            "startOffset": 0,
            "endOffset": 500,
            "sortField": "severity",
            "sortDir": "DESC",
            "tool": "vulndetails",
            "query": {
                "type": "vuln",
                "tool": "vulndetails",
                "filters": [],
            },
        },
    )
    assert result == mock_response


def test_convert_unix_to_iso_valid():
    """
    Given:
    - A valid unix timestamp string.

    When:
    - Calling convert_unix_to_iso.

    Then:
    - Should return the timestamp in ISO 8601 format with milliseconds.
    """
    assert convert_unix_to_iso("1709654400") == "2024-03-05T16:00:00.000Z"
    assert convert_unix_to_iso("1709568000") == "2024-03-04T16:00:00.000Z"
    assert convert_unix_to_iso("0") is None
    assert convert_unix_to_iso("-1") is None
    assert convert_unix_to_iso(None) is None
    assert convert_unix_to_iso("") is None


def test_transform_record_timestamps():
    """
    Given:
    - A record dict with unix timestamp fields (firstSeen, lastSeen, createdTime, modifiedTime).

    When:
    - Calling transform_record_timestamps.

    Then:
    - Should convert all timestamp fields to ISO 8601 format.
    - Should leave non-timestamp fields unchanged.
    """
    record = {
        "id": "12345",
        "name": "Test Host",
        "firstSeen": "1709568000",
        "lastSeen": "1709654400",
        "createdTime": "1709568000",
        "modifiedTime": "1709654400",
        "ipAddress": "10.0.0.1",
    }
    result = transform_record_timestamps(record)

    assert result["firstSeen"] == "2024-03-04T16:00:00.000Z"
    assert result["lastSeen"] == "2024-03-05T16:00:00.000Z"
    assert result["createdTime"] == "2024-03-04T16:00:00.000Z"
    assert result["modifiedTime"] == "2024-03-05T16:00:00.000Z"
    assert result["id"] == "12345"
    assert result["name"] == "Test Host"
    assert result["ipAddress"] == "10.0.0.1"


def test_transform_record_timestamps_partial_fields():
    """
    Given:
    - A record dict with only some timestamp fields present.

    When:
    - Calling transform_record_timestamps.

    Then:
    - Should convert only the present timestamp fields.
    - Should not add missing fields.
    """
    record = {
        "id": "12345",
        "firstSeen": "1709568000",
        "lastSeen": "1709654400",
    }
    result = transform_record_timestamps(record)

    assert result["firstSeen"] == "2024-03-04T16:00:00.000Z"
    assert result["lastSeen"] == "2024-03-05T16:00:00.000Z"
    assert "createdTime" not in result
    assert "modifiedTime" not in result


def test_transform_record_timestamps_empty_values():
    """
    Given:
    - A record dict with empty or zero timestamp values.

    When:
    - Calling transform_record_timestamps.

    Then:
    - Should not convert empty or zero values.
    """
    record = {
        "firstSeen": "",
        "lastSeen": "0",
        "createdTime": "-1",
    }
    result = transform_record_timestamps(record)

    assert result["firstSeen"] == ""
    assert result["lastSeen"] == "0"
    assert result["createdTime"] == "-1"
