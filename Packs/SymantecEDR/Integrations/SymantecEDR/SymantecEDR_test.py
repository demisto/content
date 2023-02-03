"""
Symantec EDR (On-prem) Integration - Unit Tests file
"""
# type: ignore
import pytest
import json
import time
import datetime
import os
from CommonServerPython import DemistoException
from SymantecEDR import Client, get_file_instance_command, get_domain_instance_command, get_endpoint_instance_command, \
    get_endpoint_file_association_list_command, get_domain_file_association_list_command, \
    get_endpoint_domain_association_list_command, get_deny_list_command, get_allow_list_command, \
    get_event_list_command, get_audit_event_command, get_system_activity_command, get_incident_list_command, \
    get_event_for_incident_list_command, pagination, PAGE_NUMBER_ERROR_MSG, PAGE_SIZE_ERROR_MSG, \
    compile_command_title_string, get_access_token_from_context, check_valid_indicator_value,\
    get_endpoint_status_command, get_endpoint_command, get_incident_uuid


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


client = Client(
    base_url="http://<host:port>:port",
    verify=False,
    proxy=False,
    client_id="test_123",
    client_secret="test@12345"
)

FILE_INSTANCE_RESPONSE = util_load_json('test_data/file_instance_data.json')
DOMAIN_INSTANCE_RESPONSE = util_load_json('test_data/domain_instance_data.json')
ENDPOINT_INSTANCE_RESPONSE = util_load_json('test_data/endpoint_instance.json')
ENDPOINT_FILE_ASSOCIATION_RESPONSE = util_load_json('test_data/endpoint_file_association.json')
DOMAIN_FILE_ASSOCIATION_RESPONSE = util_load_json('test_data/domain_file_association.json')
ENDPOINT_DOMAIN_ASSOCIATION_RESPONSE = util_load_json('test_data/endpoint_domain_association.json')
DENY_LIST_RESPONSE = util_load_json('test_data/deny_list.json')
ALLOW_LIST_RESPONSE = util_load_json('test_data/deny_list.json')
EVENT_LIST_RESPONSE = util_load_json('test_data/event_list_data.json')
AUDIT_EVENT_RESPONSE = util_load_json('test_data/audit_event_data.json')
SYSTEM_ACTIVITY_RESPONSE = util_load_json('test_data/system_activity.json')
INCIDENT_LIST_RESPONSE = util_load_json('test_data/incident_list_data.json')
INCIDENT_COMMENT_RESPONSE = util_load_json('test_data/incident_comment_data.json')
INCIDENT_EVENT_FOR_INCIDENT = util_load_json('test_data/incident_event_data.json')
ENDPOINT_COMMAND_STATUS = util_load_json('test_data/endpoint_command_status.json')
ENDPOINT_COMMAND_ISOLATE = util_load_json('test_data/endpoint_command_isolate_endpoint.json')
ENDPOINT_COMMAND_REJOIN = util_load_json('test_data/endpoint_command_rejoin.json')
ENDPOINT_COMMAND_CANCEL = util_load_json('test_data/endpoint_command_cancel.json')
ENDPOINT_COMMAND_DELETE = util_load_json('test_data/endpoint_command_delete_endpoint_file.json')


today = datetime.datetime.now(datetime.timezone.utc)
now_iso = today.isoformat()[:23] + "Z"


@pytest.mark.parametrize('raw_response, expected', [(FILE_INSTANCE_RESPONSE, FILE_INSTANCE_RESPONSE)])
def test_get_file_instance_command(mocker, raw_response, expected):
    """
    Tests get_get_file_instance_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_file_instance_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    with open(os.path.join("test_data", "command_readable_output/file_instance_command_readable_output.md"), 'r') as f:
        readable_output = f.read()
    command_results = get_file_instance_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(DOMAIN_INSTANCE_RESPONSE, DOMAIN_INSTANCE_RESPONSE)])
def test_get_domain_instance_command(mocker, raw_response, expected):
    """
    Tests get_domain_instance_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_domain_instance_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_domain_instance_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_INSTANCE_RESPONSE, ENDPOINT_INSTANCE_RESPONSE)])
def test_get_endpoint_instance_command(mocker, raw_response, expected):
    """
    Tests get_endpoint_instance_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_instance_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_instance_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_FILE_ASSOCIATION_RESPONSE,
                                                     ENDPOINT_FILE_ASSOCIATION_RESPONSE)])
def test_get_endpoint_file_association_list_command(mocker, raw_response, expected):
    """
    Tests get_endpoint_file_association_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_file_association_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_file_association_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(DOMAIN_FILE_ASSOCIATION_RESPONSE,
                                                     DOMAIN_FILE_ASSOCIATION_RESPONSE)])
def test_get_domain_file_association_list_command(mocker, raw_response, expected):
    """
    Tests get_domain_file_association_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_domain_file_association_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_domain_file_association_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_DOMAIN_ASSOCIATION_RESPONSE,
                                                     ENDPOINT_DOMAIN_ASSOCIATION_RESPONSE)])
def test_get_endpoint_domain_association_list_command(mocker, raw_response, expected):
    """
    Tests get_endpoint_domain_association_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_domain_association_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_domain_association_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(DENY_LIST_RESPONSE, DENY_LIST_RESPONSE)])
def test_get_deny_list_command(mocker, raw_response, expected):
    """
    Tests get_deny_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_deny_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 10}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_deny_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(ALLOW_LIST_RESPONSE, ALLOW_LIST_RESPONSE)])
def test_get_allow_list_command(mocker, raw_response, expected):
    """
    Tests get_allow_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_allow_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 10}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_allow_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(EVENT_LIST_RESPONSE, EVENT_LIST_RESPONSE)])
def test_get_event_list_command(mocker, raw_response, expected):
    """
    Tests get_event_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_event_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_event_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(AUDIT_EVENT_RESPONSE, AUDIT_EVENT_RESPONSE)])
def test_get_audit_event_command(mocker, raw_response, expected):
    """
    Tests get_audit_event_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_audit_event_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_audit_event_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(SYSTEM_ACTIVITY_RESPONSE, SYSTEM_ACTIVITY_RESPONSE)])
def test_get_system_activity_command(mocker, raw_response, expected):
    """
    Tests get_system_activity_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_system_activity_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_system_activity_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(INCIDENT_LIST_RESPONSE, INCIDENT_LIST_RESPONSE)])
def test_get_incident_list_command(mocker, raw_response, expected):
    """
    Tests get_incident_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_incident_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_incident_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(INCIDENT_LIST_RESPONSE, '9d6f2100-7158-11ed-da26-000000000001')])
def test_get_incident_uuid(mocker, raw_response, expected):
    args = {
        "incident_id": 100010
    }
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    uuid = get_incident_uuid(client, args)

    # results is CommandResults list
    assert uuid == expected


@pytest.mark.parametrize('raw_response, expected', [(INCIDENT_EVENT_FOR_INCIDENT, INCIDENT_EVENT_FOR_INCIDENT)])
def test_get_event_for_incident_list_command(mocker, raw_response, expected):
    """
    Tests get_event_for_incident_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_event_for_incident_list_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_event_for_incident_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_COMMAND_STATUS, ENDPOINT_COMMAND_STATUS)])
def test_get_endpoint_status_command(mocker, raw_response, expected):
    """
    Tests get_endpoint_status_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_status_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"command_id": '35fcb7c144764188b810799a120b26eb-2022-12-09'}
    with open(os.path.join("test_data", "command_readable_output/endpoint_command_status_readable_output.md"), 'r') as f:
        readable_output = f.read()
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_status_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["status"]
    assert context_detail == expected.get("status")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_COMMAND_ISOLATE, ENDPOINT_COMMAND_ISOLATE)])
def test_get_endpoint_command_isolate(mocker, raw_response, expected):
    """
    Tests get_endpoint_command isolate endpoint function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"device_id": '"393b8e82-fe40-429f-8e5e-c6b79a0f2b1c'}
    with open(os.path.join("test_data", "command_readable_output/endpoint_command_isolate_readable_output.md"), 'r') as f:
        readable_output = f.read()
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_command(client, args, 'symantec-edr-endpoint-isolate')

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_COMMAND_REJOIN, ENDPOINT_COMMAND_REJOIN)])
def test_get_endpoint_command_rejoin(mocker, raw_response, expected):
    """
    Tests get_endpoint_command rejoin function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"device_id": '"393b8e82-fe40-429f-8e5e-c6b79a0f2b1c'}
    with open(os.path.join("test_data", "command_readable_output/endpoint_command_rejoin_readable_output.md"), 'r') as f:
        readable_output = f.read()
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_command(client, args, 'symantec-edr-endpoint-rejoin')

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_COMMAND_DELETE, ENDPOINT_COMMAND_DELETE)])
def test_get_endpoint_command_delete(mocker, raw_response, expected):
    """
    Tests get_endpoint_command delete function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {
        'device_id': '393b8e82-fe40-429f-8e5e-c6b79a0f2b1c',
        'sha2': '0ce49dc9f71360bf9dd21b8e3af4641834f85eed7d80a7de0940508437e68970'
    }
    with open(os.path.join("test_data", "command_readable_output/endpoint_command_delete_readable_output.md"), 'r') as f:
        readable_output = f.read()
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_command(client, args, 'symantec-edr-endpoint-delete-file')

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_COMMAND_CANCEL, ENDPOINT_COMMAND_CANCEL)])
def test_get_endpoint_command_cancel(mocker, raw_response, expected):
    """
    Tests get_endpoint_command cancel function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_endpoint_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"device_id": '"393b8e82-fe40-429f-8e5e-c6b79a0f2b1c'}
    with open(os.path.join("test_data", "command_readable_output/endpoint_command_cancel_readable_output.md"), 'r') as f:
        readable_output = f.read()
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_endpoint_command(client, args, 'symantec-edr-endpoint-cancel-command')

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('page, page_size, expected_result', [
    (2, 5, (5, 5)),
    (None, 5, (5, 0)),
    (2, None, (50, 50)),
    (3, None, (50, 100)),
    (1, 1, (1, 0)),
    (None, None, (50, 0))
])
def test_pagination(page, page_size, expected_result):
    """
    Tests the pagination function.

        Given:
            - page and page size arguments.

        When:
            - Running the 'pagination function'.

        Then:
            - Checks that the limit and offset are calculated as expected.
    """
    actual_result = pagination(page, page_size)
    assert actual_result == expected_result


@pytest.mark.parametrize('page, page_size, expected_err_msg', [
    (0, 5, PAGE_NUMBER_ERROR_MSG),
    (1, 0, PAGE_SIZE_ERROR_MSG),
    (-1, 5, PAGE_NUMBER_ERROR_MSG),
    (1, -2, PAGE_SIZE_ERROR_MSG),
])
def test_pagination_wrong_input(page, page_size, expected_err_msg):
    """
    Tests the pagination function.

        Given:
            1+2 -  page and page size arguments with 0 value.
            3+4 -  page and page size arguments with < 0 value.

        When:
            - Running the 'pagination function'.

        Then:
            - Checks that the expected err message is raised.
    """
    with pytest.raises(DemistoException) as e:
        pagination(page, page_size)
    assert e.value.args[0] == expected_err_msg


@pytest.mark.parametrize('sub_context, page, page_size, total_record, expected_title', [
    ('File Endpoint', 1, 10, 100, 'File Endpoint List\nShowing page 1\nShowing 10 out of 100 Record(s) Found.'),
    ('File Endpoint', 0, 0, 0, 'File Endpoint List'),
    ('File Endpoint', None, 10, 10, 'File Endpoint List'),
    ('File Endpoint', 1, None, 10, 'File Endpoint List'),
])
def test_compile_command_title_string(sub_context, page, page_size, total_record, expected_title):
    """
        Tests the compile_command_title_string function

            Given:
                1. a sub context, page, page size and total records arguments.
                2. a sub context, 0 values for page, page size and total records arguments.
                3. a sub context, page = None.
                4. a sub context, page size = None.

            When:
                - Running the 'compile_command_title_string function'.

            Then:
                - Checks the output of the command function with the expected output.
    """

    actual_title = compile_command_title_string(sub_context, page, page_size, total_record)
    assert actual_title == expected_title


@pytest.mark.parametrize('context_dict, expected_result', [
    ({'access_token_timestamp': int(time.time()), 'access_token': '12345'}, '12345'),
    ({'access_token_timestamp': int(time.time() - 300), 'access_token': '12345'}, '12345'),
    ({'access_token_timestamp': int(time.time() - 3660), 'access_token': '12345'}, None),
    ({}, None),
])
def test_get_access_token_from_context(context_dict, expected_result):
    actual_result = get_access_token_from_context(context_dict)
    assert actual_result == expected_result


@pytest.mark.parametrize('indicator_type, indicator_value, expected_result', [
    ('urls', 'https://www.facebook.com', True),
    ('ip', '1.1.1.1', True),
    ('sha256', '1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164', True),  # File sha256
    ('md5', 'eb67bdf0eaac6ea0ca18667f6cacd5fb', True)
])
def test_check_valid_indicator_value(indicator_type, indicator_value, expected_result):
    """
        Tests the check_valid_indicator_value function.

            Given:
                indicator_type - type of indicator
                indicator_value - Value of indicator

            When:
                - Running the 'check_valid_indicator_value function'.

            Then:
                - Checks the output of the command function with the expected result.
    """
    actual_result = check_valid_indicator_value(indicator_type, indicator_value)
    assert actual_result == expected_result


@pytest.mark.parametrize('indicator_type, indicator_value, expected_err_msg', [
    ('domains', 'abcd123', 'Indicator domains type does not support'),
    ('urls', '123245', '123245 is not a valid urls'),
    ('ip', 'google.1234', '"google.1234" is not a valid IP'),
    ('sha256', 'abcde34', 'abcde34 is not a valid sha256'),
    ('md5', 'eb67bdf0eaac6e', 'eb67bdf0eaac6e is not a valid md5')
])
def test_check_valid_indicator_value_wrong_input(indicator_type, indicator_value, expected_err_msg):
    """
        Tests the check_valid_indicator_value function.

            Given:
                indicator_type - type of indicator.
                indicator_value - Value of indicator massage.

            When:
                - Running the 'check_valid_indicator_value function'.

            Then:
                - Checks the output of the command function with the expected error message.
    """
    with pytest.raises(ValueError) as e:
        check_valid_indicator_value(indicator_type, indicator_value)
    assert e.value.args[0] == expected_err_msg
