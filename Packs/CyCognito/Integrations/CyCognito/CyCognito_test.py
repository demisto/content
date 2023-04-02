"""Test file for CyCognito Integration."""

import io
import json
import os.path
from unittest import mock
import pytest
from CommonServerPython import DemistoException
from CyCognito import BASE_URL, ERRORS, VALID_INVESTIGATION_STATUS, VALID_ASSET_TYPES, VALID_OPERATORS, VALID_SEVERITY, \
    VALID_ISSUE_TYPES, AVAILABLE_STATUS_TYPES, AVAILABLE_SECURITY_GRADE, ISSUE_OUTPUT_PREFIX, ASSET_OUTPUT_PREFIX

DUMMY_ISSUE_INSTANCE_ID = "127.0.0.1-test"
DUMMY_ORG_NAME = "Acme Interior Design"
DUMMY_TIMESTAMP = "2020-07-25T16:57:01.565Z"


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    from CyCognito import CyCognitoClient
    headers = {
        "Authorization": 'dummy_key'
    }

    client = CyCognitoClient(base_url=BASE_URL,
                             verify=False,
                             headers=headers,
                             proxy=False,
                             ok_codes=(404, 200))
    return client


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock, mock_client):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns an ok message
    """
    from CyCognito import test_module
    requests_mock.post(f"{BASE_URL}/issues", json=[], status_code=200)
    assert test_module(mock_client) == 'ok'


def test_test_module_when_is_fetch_is_true(requests_mock, mock_client):
    """
    Test case scenario for successful execution of test_module when isFetch is true.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns an ok message
    """
    from CyCognito import test_module

    requests_mock.post(f"{BASE_URL}/issues", json=[], status_code=200)
    with mock.patch("demistomock.params", return_value={"isFetch": True, 'max_fetch': 1}):
        assert test_module(mock_client) == 'ok'


def test_get_issue_command_status_404(requests_mock, mock_client):
    """
    Test case scenario for execution of cycognito_issue_get_command function when status code is 404.

    Given:
        - command arguments for cycognito_issue_get_command
    When:
        - Calling `cycognito_issue_get_command` function
    Then:
        - Returns a valid message
    """
    from CyCognito import cycognito_issue_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_issue_status_404_response.json"))

    requests_mock.get(f"{BASE_URL}/issues/issue/dummy", json=mock_response, status_code=404)
    with pytest.raises(DemistoException) as err:
        cycognito_issue_get_command(mock_client, args={"issue_instance_id": "dummy"})

    assert str(err.value) == ERRORS['NO_RECORDS']


def test_get_issue_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_issue_get_command function.

    Given:
        - command arguments for cycognito_issue_get_command
    When:
        - Calling `cycognito_issue_get_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_issue_get_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_issue_success_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/get_issue_success_hr.md")) as file:
        hr_output = file.read()

    requests_mock.get(f"{BASE_URL}/issues/issue/127.0.0.1-test", json=mock_response["raw_response"], status_code=200)

    actual = cycognito_issue_get_command(mock_client, args={"issue_instance_id": DUMMY_ISSUE_INSTANCE_ID})

    assert actual.outputs_prefix == "CyCognito.Issue"
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response["raw_response"]
    assert actual.outputs == mock_response["outputs"]
    assert actual.readable_output == hr_output


@pytest.mark.parametrize("args, err_msg", [
    ({"asset_id": "", "asset_type": "ip"}, ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_id')),
    ({"asset_id": "dummy", "asset_type": ""}, ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type')),
    ({"asset_id": "dummy", "asset_type": "incorrect-type"},
     ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('incorrect-type', 'asset_type', VALID_ASSET_TYPES)),
])
def test_get_asset_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cycognito_asset_get_command when invalid argument provided.

    Given:
        - command arguments for cycognito_asset_get_command
    When:
        - Calling `cycognito_asset_get_command` function
    Then:
        - Returns a valid error message
    """
    from CyCognito import cycognito_asset_get_command
    with pytest.raises(ValueError) as err:
        cycognito_asset_get_command(mock_client, args)
    assert str(err.value) == err_msg


def test_cycognito_asset_get_status_404(requests_mock, mock_client):
    """
    Test case scenario for invalid arguments for cycognito_asset_get_command function.

    Given:
        - command arguments for cycognito_asset_get_command
    When:
        - Calling `cycognito_asset_get_command` function
    Then:
        - Returns an error
    """
    from CyCognito import cycognito_asset_get_command

    json_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/get_asset_status_404_response.json"))

    requests_mock.get(f'{BASE_URL}/assets/ip/-', json=json_data, status_code=404, reason='not found')

    with pytest.raises(DemistoException) as e:
        cycognito_asset_get_command(mock_client, args={"asset_type": "ip", "asset_id": "-"})
    assert str(e.value) == ERRORS['NO_RECORDS']


def test_cycognito_asset_get_success_ip(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_asset_get_command function for IP.

    Given:
        - command arguments for cycognito_asset_get_command
    When:
        - Calling `cycognito_asset_get_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_asset_get_command

    json_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/get_asset_success_response_ip.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/get_asset_success_hr_ip.md")) as file:
        hr_output = file.read()

    requests_mock.get(f'{BASE_URL}/assets/ip/0.0.0.0', json=json_data, status_code=200)
    response = cycognito_asset_get_command(mock_client, args={'asset_type': 'ip', 'asset_id': '0.0.0.0'})

    assert response.outputs_prefix == "CyCognito.Asset"
    assert response.raw_response == json_data
    assert response.outputs == json_data
    assert response.outputs_key_field == 'id'
    assert response.readable_output == hr_output


def test_cycognito_asset_get_success_iprange(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_asset_get_command function for iprange.

    Given:
        - command arguments for cycognito_asset_get_command
    When:
        - Calling `cycognito_asset_get_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_asset_get_command

    json_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/get_asset_success_response_iprange.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/get_asset_success_hr_iprange.md")) as file:
        hr_output = file.read()

    requests_mock.get(f'{BASE_URL}/assets/iprange/0.0.0.1-1.0.0.0', json=json_data,
                      status_code=200)
    response = cycognito_asset_get_command(mock_client,
                                           args={'asset_type': 'iprange', 'asset_id': '0.0.0.1-1.0.0.0'})

    assert response.outputs_prefix == 'CyCognito.Asset'
    assert response.raw_response == json_data
    assert response.outputs == json_data
    assert response.outputs_key_field == 'id'
    assert response.readable_output == hr_output


def test_cycognito_asset_get_success_cert(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_asset_get_command function for certificate.

    Given:
        - command arguments for cycognito_asset_get_command
    When:
        - Calling `cycognito_asset_get_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_asset_get_command

    json_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/get_asset_success_response_cert.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/get_asset_success_hr_cert.md")) as file:
        hr_output = file.read()

    requests_mock.get(f'{BASE_URL}/assets/cert/test_cert',
                      json=json_data,
                      status_code=200)
    response = cycognito_asset_get_command(mock_client,
                                           args={'asset_type': 'cert',
                                                 'asset_id': 'test_cert'})

    assert response.outputs_prefix == ASSET_OUTPUT_PREFIX
    assert response.raw_response == json_data
    assert response.outputs == json_data
    assert response.outputs_key_field == 'id'
    assert response.readable_output == hr_output


def test_issue_investigation_status_change_with_invalid_args(mock_client):
    """
    Test case scenario for execution of issue_investigation_status_change when invalid argument provided.

    Given:
        - command arguments for cycognito_issue_change_investigation_status_command
    When:
        - Calling `cycognito_issue_change_investigation_status_command` function
    Then:
        - Returns a valid message
    """
    from CyCognito import cycognito_issue_investigation_status_change_command
    args = {"issue_instance_id": DUMMY_ISSUE_INSTANCE_ID, "investigation_status": "incorrect-status"}

    with pytest.raises(ValueError) as err:
        cycognito_issue_investigation_status_change_command(mock_client, args)

    assert str(err.value) == ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('incorrect-status', 'investigation_status',
                                                                          VALID_INVESTIGATION_STATUS)


def test_issue_investigation_status_change_command_success(requests_mock, mock_client):
    """
    Test case scenario for execution of issue_investigation_status_change with success.

    Given:
        - command arguments for cycognito_issue_change_investigation_status_command
    When:
        - Calling `cycognito_issue_change_investigation_status_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_issue_investigation_status_change_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/change_issue_investigation_status_success_response.json"))
    context_output = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "test_data/change_issue_investigation_status_success_context.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/change_issue_investigation_status_success_hr.md")) as file:
        hr_output = file.read()

    requests_mock.put(f"{BASE_URL}/issues/issue/127.0.0.1-test/investigation-status", json=mock_response,
                      status_code=200)

    args = {"issue_instance_id": DUMMY_ISSUE_INSTANCE_ID, "investigation_status": "investigating"}

    actual = cycognito_issue_investigation_status_change_command(mock_client, args)

    assert actual.outputs_prefix == ISSUE_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == context_output
    assert actual.readable_output == hr_output


def test_issue_investigation_status_change_command_failure(requests_mock, mock_client):
    """
    Test case scenario for execution of issue_investigation_status_change with failure.

    Given:
        - command arguments for cycognito_issue_change_investigation_status_command
    When:
        - Calling `cycognito_issue_change_investigation_status_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_issue_investigation_status_change_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/change_issue_investigation_status_failure_response.json"))
    context_output = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "test_data/change_issue_investigation_status_failure_context.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/change_issue_investigation_status_failure_hr.md")) as file:
        hr_output = file.read()

    requests_mock.put(f"{BASE_URL}/issues/issue/127.0.0.1-test/investigation-status", json=mock_response,
                      status_code=200)

    args = {"issue_instance_id": DUMMY_ISSUE_INSTANCE_ID, "investigation_status": "investigating"}

    actual = cycognito_issue_investigation_status_change_command(mock_client, args)

    assert actual.outputs_prefix == ISSUE_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == context_output
    assert actual.readable_output == hr_output


def test_asset_investigation_status_change_with_invalid_args(mock_client):
    """
    Test case scenario for execution of asset_investigation_status_change when invalid argument provided.

    Given:
        - command arguments for cycognito_asset_investigation_status_change_command
    When:
        - Calling `cycognito_asset_investigation_status_change_command` function
    Then:
        - Returns a valid message
    """
    from CyCognito import cycognito_asset_investigation_status_change_command
    args = {'asset_id': '0.0.0-dummy', 'asset_type': 'ip', 'investigation_status': 'dummy'}

    with pytest.raises(ValueError) as e:
        cycognito_asset_investigation_status_change_command(mock_client, args)

    assert str(e.value) == ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('dummy', 'investigation_status',
                                                                        VALID_INVESTIGATION_STATUS)


def test_asset_investigation_status_change_command_success(requests_mock, mock_client):
    """
    Test case scenario for execution of asset_investigation_status_change with success.

    Given:
      - command arguments for cycognito_asset_investigation_status_change_command
    When:
      - Calling `cycognito_asset_investigation_status_change_command` function
    Then:
      - Returns a valid output
    """
    from CyCognito import cycognito_asset_investigation_status_change_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/change_asset_investigation_status_success_response.json"))
    context_output = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "test_data/change_asset_investigation_status_success_context.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/change_asset_investigation_status_success_hr.md")) as file:
        hr_output = file.read()

    requests_mock.put(f"{BASE_URL}/assets/ip/0.0.0.0/investigation-status", json=mock_response, status_code=200)

    args = {'asset_id': '0.0.0.0', 'asset_type': "ip", 'investigation_status': 'investigating'}
    actual = cycognito_asset_investigation_status_change_command(mock_client, args)

    assert actual.outputs_prefix == ASSET_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == context_output
    assert actual.readable_output == hr_output


def test_asset_investigation_status_change_command_failure(requests_mock, mock_client):
    """
    Test case scenario for execution of asset_investigation_status_change with failure.

    Given:
       - command arguments for cycognito_asset_investigation_status_change_command
    When:
       - Calling `cycognito_asset_investigation_status_change_command` function
    Then:
       - Returns a valid output
    """
    from CyCognito import cycognito_asset_investigation_status_change_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/change_asset_investigation_status_failure_response.json"))
    context_output = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "test_data/change_asset_investigation_status_failure_context.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/change_asset_investigation_status_failure_hr.md")) as file:
        hr_output = file.read()

    requests_mock.put(f"{BASE_URL}/assets/ip/0.0.0.0/investigation-status", json=mock_response,
                      status_code=200)

    args = {"asset_id": "0.0.0.0", 'asset_type': 'ip', "investigation_status": "investigating"}

    actual = cycognito_asset_investigation_status_change_command(mock_client, args)

    assert actual.outputs_prefix == ASSET_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == context_output
    assert actual.readable_output == hr_output


@pytest.mark.parametrize("args, err_msg", [
    ({'asset_id': ' '}, ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_id')),
    ({'asset_type': ' '}, ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type')),
    ({'asset_type': 'dummy'},
     ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('dummy', 'asset_type',
                                                  ["ip", "domain", "cert", "iprange", 'webapp'])),
    ({'investigation_status': 'dummy'},
     ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('dummy', 'investigation_status',
                                                  ['investigated', 'investigating', 'uninvestigated'])),
    ({'investigation_status': ' '}, ERRORS['INVALID_REQUIRED_PARAMETER'].format('investigation_status'))
])
def test_asset_investigation_status_change_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of asset_change_investigation_status when invalid argument provided.

    Given:
        - command arguments for cycognito_asset_investigation_status_Change
    When:
        - Calling `cycognito_asset_investigation_status_change_command` function
    Then:
        - Returns a valid error message
    """
    from CyCognito import cycognito_asset_investigation_status_change_command

    with pytest.raises(ValueError) as err:
        cycognito_asset_investigation_status_change_command(mock_client, args)

        assert str(err.value) == err_msg


@pytest.mark.parametrize("args, err_msg", [
    ({"count": -1}, ERRORS['INVALID_PAGE_SIZE'].format(-1)),
    ({"sort_order": "incorrect_order"},
     ERRORS['INVALID_SINGLE_SELECT_PARAM'].format("incorrect_order", 'sort_order', ["asc", "desc"])),
    ({"first_detected": "20-20-2022"}, 'Invalid date: "first_detected"="20-20-2022"'),
    ({"last_detected": "20-20-2022"}, 'Invalid date: "last_detected"="20-20-2022"'),
    ({"count": "incorrect_count"}, 'Invalid number: "count"="incorrect_count"'),
    ({"offset": "incorrect_offset"}, 'Invalid number: "offset"="incorrect_offset"'),
    ({"advanced_filter": '{"field":"dummy", "op":"incorrect", "value":"dummy"}'},
     ERRORS['INVALID_OPERATOR'].format('incorrect', VALID_OPERATORS)),
    ({"advanced_filter": "incorrect_json"}, ERRORS['INVALID_ADVANCED_FILTER'].format('incorrect_json'))])
def test_list_issues_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of list_issues when invalid argument provided.

    Given:
        - command arguments for cycognito_issues_list_command
    When:
        - Calling `cycognito_issues_list_command` function
    Then:
        - Returns a valid error message
    """
    from CyCognito import cycognito_issues_list_command

    with pytest.raises(ValueError) as err:
        cycognito_issues_list_command(mock_client, args)

    assert str(err.value) == err_msg


def test_list_issues_command_when_empty_body_params(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_issues_list_command function with no args.

    Given:
        - command arguments for cycognito_issues_list_command
    When:
        - Calling `cycognito_issues_list_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_issues_list_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/list_issues_empty_request_body_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/list_issues_empty_request_body_hr.md")) as file:
        hr_output = file.read()

    requests_mock.post(f"{BASE_URL}/issues", json=mock_response["raw_response"], status_code=200)

    actual = cycognito_issues_list_command(mock_client, args={'count': 2})

    assert actual.outputs_prefix == ISSUE_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response["raw_response"]
    assert actual.outputs == mock_response["outputs"]
    assert actual.readable_output == hr_output


def test_list_issues_command_with_body_params(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_issues_list_command function with body params.

    Given:
        - command arguments for cycognito_issues_list_command
    When:
        - Calling `cycognito_issues_list_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_issues_list_command
    args = {
        "count": "2",
        "offset": "-1",
        "search": DUMMY_ORG_NAME,
        "first_detected": "2021-07-25T16:57:01.565Z",
        "last_detected": "2021-07-25T16:57:01.565Z",
        "organizations": DUMMY_ORG_NAME,
        "locations": "IND",
        "issue_type": "Exposed Data",
        "advanced_filter": "[{\"field\":\"severity\",\"op\": \"in\",\"values\": [\"High\"]}]"
    }

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/list_issues_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/list_issues_hr.md")) as file:
        hr_output = file.read()

    requests_mock.post(f"{BASE_URL}/issues", json=mock_response["raw_response"], status_code=200)

    actual = cycognito_issues_list_command(mock_client, args=args)

    assert actual.outputs_prefix == ISSUE_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response["raw_response"]
    assert actual.outputs == mock_response["outputs"]
    assert actual.readable_output == hr_output


def test_list_issues_command_with_empty_response(requests_mock, mock_client):
    """
    Test case scenario for execution of cycognito_issues_list_command when response in empty.

    Given:
        - command arguments for cycognito_issues_list_command
    When:
        - Calling `cycognito_issues_list_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_issues_list_command
    args = {"organizations": "Invalid_owner_name"}

    requests_mock.post(f"{BASE_URL}/issues", json=[], status_code=200)

    actual = cycognito_issues_list_command(mock_client, args=args)

    assert actual.outputs_prefix == ISSUE_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == []
    assert actual.outputs == []
    assert actual.readable_output == '### Issues:\n**No entries.**\n'


@pytest.mark.parametrize("args, err_msg", [
    ({'asset_type': 'dummy'}, ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('dummy', 'asset_type', VALID_ASSET_TYPES)),
    ({"count": -1, 'asset_type': 'ip'}, ERRORS['INVALID_PAGE_SIZE'].format('-1')),
    ({"sort_order": "incorrect_order", 'asset_type': 'ip'},
     ERRORS['INVALID_SINGLE_SELECT_PARAM'].format("incorrect_order", 'sort_order', ["asc", "desc"])),
    ({"first_seen": "20-20-2022", 'asset_type': 'ip'}, 'Invalid date: "first_seen"="20-20-2022"'),
    ({"last_seen": "20-20-2022", 'asset_type': 'ip'}, 'Invalid date: "last_seen"="20-20-2022"'),
    ({'security_grade': 'dummy', 'asset_type': 'ip'},
     ERRORS['INVALID_MULTI_SELECT_PARAM'].format('security_grade', list(
         map(lambda x: x.upper(), AVAILABLE_SECURITY_GRADE)))),
    ({'status': 'dummy', 'asset_type': 'ip'},
     ERRORS['INVALID_MULTI_SELECT_PARAM'].format('status', AVAILABLE_STATUS_TYPES)),
    ({"count": "incorrect_count", 'asset_type': 'ip'}, 'Invalid number: "count"="incorrect_count"'),
    ({"offset": "incorrect_offset", 'asset_type': 'ip'}, 'Invalid number: "offset"="incorrect_offset"'),
    ({"advanced_filter": "incorrect_json", 'asset_type': 'ip'},
     ERRORS['INVALID_ADVANCED_FILTER'].format('incorrect_json'))])
def test_list_asset_command_when_invalid_argument_provided(args, err_msg, mock_client):
    """
    Test case scenario for execution of cycognito_assets_list_command when invalid argument provided.

    Given:
        - command arguments for cycognito_assets_list_command
    When:
        - Calling `cycognito_assets_list_command` function
    Then:
        - Returns a valid error message
    """
    from CyCognito import cycognito_assets_list_command

    with pytest.raises(ValueError) as err:
        cycognito_assets_list_command(mock_client, args)

    assert str(err.value) == err_msg


def test_list_assets_command_when_empty_body_params(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_assets_list_command function with no args.

    Given:
        - command arguments for cycognito_assets_list_command
    When:
        - Calling `cycognito_assets_list_command` function
    Then:
        - Returns a valid output
    """
    from CyCognito import cycognito_assets_list_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/list_assets_empty_request_body_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "test_data/list_assets_empty_request_body_hr.md")) as file:
        hr_output = file.read()

    requests_mock.post(f"{BASE_URL}/assets/domain", json=mock_response, status_code=200)

    actual = cycognito_assets_list_command(mock_client, args={'asset_type': 'domain', 'count': 2})

    assert actual.outputs_prefix == ASSET_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == mock_response
    assert actual.readable_output == hr_output


def test_list_assets_command_with_body_params(requests_mock, mock_client):
    """
    Test case scenario for successful execution of cycognito_assets_list_command function with body params.

    Given:
       - command arguments for cycognito_assets_list_command
    When:
       - Calling `cycognito_assets_list_command` function
    Then:
       - Returns a valid output
    """
    from CyCognito import cycognito_assets_list_command

    args = {
        "asset_type": "ip",
        "count": "2",
        "offset": "-1",
        "search": DUMMY_ORG_NAME,
        "first_seen": "2022-03-17T03:11:02.882Z",
        "last_seen": "2022-03-24T04:26:03.296Z",
        "organizations": DUMMY_ORG_NAME,
        "locations": "IND",
        "security_grade": "A",
        "status": "new",
        "advance_filter": "[{\"field\":\"status\",\"op\": \"in\",\"values\": [\"new\"]}]"
    }

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/list_assets_response.json"))

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           "./test_data/list_assets_hr.md")) as file:
        hr_output = file.read()

    requests_mock.post(f"{BASE_URL}/assets/ip", json=mock_response, status_code=200)

    actual = cycognito_assets_list_command(mock_client, args=args)

    assert actual.outputs_prefix == ASSET_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == mock_response
    assert actual.outputs == mock_response
    assert actual.readable_output == hr_output


def test_list_asset_command_with_empty_response(requests_mock, mock_client):
    """
    Test case scenario for execution of cycognito_assets_list_command when response in empty.

    Given:
       - command arguments for cycognito_assets_list_command
    When:
       - Calling `cycognito_assets_list_command` function
    Then:
       - Returns a valid output
    """
    from CyCognito import cycognito_assets_list_command
    args = {'asset_type': 'iprange',
            'advanced_filter': "[{\"field\":\"locations\",\"op\": \"in\",\"values\": [\"USA\"]}]"}

    requests_mock.post(f"{BASE_URL}/assets/iprange", json=[], status_code=200)

    actual = cycognito_assets_list_command(mock_client, args=args)

    assert actual.outputs_prefix == ASSET_OUTPUT_PREFIX
    assert actual.outputs_key_field == "id"
    assert actual.raw_response == []
    assert actual.outputs == []
    assert actual.readable_output == '### Asset List:\n Assets Type: Iprange\n**No entries.**\n'


@pytest.mark.parametrize("args, err_msg", [
    ({}, ERRORS['INVALID_REQUIRED_PARAMETER'].format('Max Fetch')),
    ({"max_fetch": -1}, ERRORS['INVALID_PAGE_SIZE'].format(-1)),
    ({'max_fetch': 1, "first_fetch": "20-20-2022"}, 'Invalid date: "First Fetch"="20-20-2022"'),
    ({"max_fetch": "incorrect_number"}, 'Invalid number: "Max Fetch"="incorrect_number"'),
    ({'max_fetch': 1, "severity_filter": "incorrect_severity"},
     ERRORS['INVALID_MULTI_SELECT_PARAM'].format('Severity', VALID_SEVERITY)),
    ({'max_fetch': 1, "issue_type": "incorrect_type"},
     ERRORS['INVALID_MULTI_SELECT_PARAM'].format('Issue Type', VALID_ISSUE_TYPES)),
    ({'max_fetch': 1, "investigation_status": "incorrect_status"},
     ERRORS['INVALID_SINGLE_SELECT_PARAM'].format('incorrect_status', 'Investigation Status',
                                                  VALID_INVESTIGATION_STATUS)),
    ({'max_fetch': 1, "advanced_filter": "incorrect_json"}, ERRORS['INVALID_ADVANCED_FILTER'].format('incorrect_json')),
    ({'max_fetch': 1, "advanced_filter": '{"field":"dummy", "op":"incorrect", "value":"dummy"}'},
     ERRORS['INVALID_OPERATOR'].format('incorrect', VALID_OPERATORS)),
    ({'max_fetch': 1, "locations": ['incorrect_country_name']},
     ERRORS['INVALID_COUNTRY_ERROR'].format('incorrect_country_name'))
])
def test_fetch_incident_when_invalid_arguments_provided(args, err_msg, mock_client, capfd):
    """
    Test case scenario for execution of fetch_incident when invalid arguments are provided.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid error message.
    """
    from CyCognito import fetch_incidents

    with pytest.raises(ValueError) as err:
        capfd.close()
        fetch_incidents(mock_client, {}, args)

    assert str(err.value) == err_msg


def test_fetch_incident_success_with_last_run(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch_incident when last_run is given.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from CyCognito import fetch_incidents

    last_run = {'last_fetch': '2020-07-25T16:57:01.565Z', 'offset': 2}

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/fetch_incident_response.json"))
    incidents = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/fetch_incident_incidents.json"))

    requests_mock.post(f"{BASE_URL}/issues", json=mock_response, status_code=200)

    next_run, actual_incidents = fetch_incidents(mock_client, last_run, {'max_fetch': 50})

    assert next_run == {'last_fetch': '2021-07-25T16:57:01.566000Z', 'offset': 0}
    assert actual_incidents == incidents


def test_fetch_incident_success_with_args(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch_incident when args are provided.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from CyCognito import fetch_incidents

    last_run = {'last_fetch': DUMMY_TIMESTAMP, 'offset': 2}
    args = {'max_fetch': 10, 'issue_type': 'Exposed Data', 'severity_filter': 'high',
            'investigation_status': 'uninvestigated', 'locations': ['India', 'United States'],
            'advance_filter': '{"field": "organizations", "op": "in", "values": "Acme Interior Design"}'}

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/fetch_incident_response.json"))
    incidents = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "test_data/fetch_incident_incidents.json"))

    requests_mock.post(f"{BASE_URL}/issues", json=mock_response, status_code=200)

    next_run, actual_incidents = fetch_incidents(mock_client, last_run, args)

    assert next_run == {'last_fetch': DUMMY_TIMESTAMP, 'offset': 3}
    assert actual_incidents == incidents


def test_fetch_incident_empty_response_with_last_run(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch_incident when response in empty and last_run is given.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from CyCognito import fetch_incidents

    last_run = {'last_fetch': DUMMY_TIMESTAMP, 'offset': 2}
    args = {'locations': 'ABW', 'max_fetch': 1}

    requests_mock.post(f"{BASE_URL}/issues", json=[], status_code=200)

    next_run, actual_incidents = fetch_incidents(mock_client, last_run, args)

    assert next_run == {'last_fetch': DUMMY_TIMESTAMP, 'offset': 2}
    assert actual_incidents == []


def test_fetch_incident_empty_response_without_last_run(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch_incident when response in empty and last_run is not given.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from CyCognito import fetch_incidents

    args = {'locations': 'ABW', 'max_fetch': 1}

    requests_mock.post(f"{BASE_URL}/issues", json=[], status_code=200)

    next_run, actual_incidents = fetch_incidents(mock_client, {}, args)

    assert next_run == {}
    assert actual_incidents == []


def test_update_remote_data_command(requests_mock, mock_client):
    """
    Test case scenario for successful execution of update_remote_data_command

    Given:
        - arguments for update_remote_data command.
    When:
        - Calling `update_remote_system_command` function.
    Then:
        - Returns ID of incident.
    """
    from CyCognito import update_remote_system_command

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/change_issue_investigation_status_success_response.json"))

    data = {'cycognitoinvestigationstatus': 'uninvestigated'}

    requests_mock.put(f"{BASE_URL}/issues/issue/127.0.0.1-test/investigation-status", json=mock_response,
                      status_code=200)

    args = {'remoteId': DUMMY_ISSUE_INSTANCE_ID, 'data': data, 'entries': [], 'incidentChanged': True,
            'delta': {'cycognitoinvestigationstatus': 'investigating'},
            'status': 2}

    assert update_remote_system_command(mock_client, args) == DUMMY_ISSUE_INSTANCE_ID


def test_get_remote_data_command(requests_mock, mock_client):
    """
    Test case scenario for successful execution of get_remote_data_command.

    Given:
        - arguments for get_remote_data_command.
    When:
        - Calling `get_remote_data_command` function.
    Then:
        - Returns a valid output.
    """
    from CyCognito import get_remote_data_command

    args = {'id': DUMMY_ISSUE_INSTANCE_ID, 'lastUpdate': '2022-03-17T03:11:02.882Z'}

    mock_response = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                "test_data/get_issue_success_response.json"))

    requests_mock.get(f"{BASE_URL}/issues/issue/127.0.0.1-test", json=mock_response["raw_response"], status_code=200)

    assert get_remote_data_command(mock_client, args).mirrored_object == mock_response["raw_response"]
