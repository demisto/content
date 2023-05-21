import pytest
import json
from Tenable_sc import *
import io

client_mocker = Client(verify_ssl=False, proxy=True, access_key="access_key", secret_key="secret_key",
                       url="www.tenable_sc_url_mock.com")


def load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    args = test_data.get('args')
    mocker.patch.object(client_mocker, 'send_request', return_value=test_data.get('mock_response'))
    command_results = update_asset_command(client_mocker, args)
    assert test_data.get('expected_hr') == command_results.readable_output


# @pytest.mark.parametrize("test_case", ["test_case_1"])
# def test_get_vulnerability_command(mocker, test_case):
#     test_data = load_json("./test_data/test_update_asset_command.json").get(test_case, {})
#     args = test_data.get('args')
#     mocker.patch.object(client_mocker, 'send_request', return_value=test_data.get('mock_response'))
#     command_results = get_vulnerability_command(client_mocker, args)
#     assert test_data.get('expected_hr') == command_results.readable_output


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
    mocker.patch.object(client_mocker, 'send_request', return_value=test_data.get('mock_response'))
    command_results = list_zones_command(client_mocker, {})
    assert test_data.get('expected_hr') == command_results.readable_output
    assert test_data.get('expected_ec') == command_results.outputs


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
    args = test_data.get('args')
    mocker.patch.object(client_mocker, 'send_request', return_value=test_data.get('mock_response'))
    command_results = list_groups_command(client_mocker, args)
    a = test_data.get('expected_hr')
    b = command_results.readable_output
    assert test_data.get('expected_hr') == command_results.readable_output
    assert test_data.get('expected_ec') == command_results.outputs
