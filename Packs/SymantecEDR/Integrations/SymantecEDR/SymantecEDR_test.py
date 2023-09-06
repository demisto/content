"""
Symantec EDR (On-prem) Integration - Unit Tests file
"""
import pytest
import CommonServerPython
from SymantecEDR import *


def util_load_json(path):
    """
    Utility Json Load Method
    """
    with open(path) as f:
        return json.loads(f.read())


CommonServerPython.demisto.setIntegrationContext(
    CommonServerPython.demisto.getIntegrationContext() | {
        'access_token': '12345678', 'access_token_timestamp': int(time.time())}
)

client = Client(
    base_url="http://test.com",
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
EVENT_8001_DATA = util_load_json('test_data/event_typeid_8001_data.json')
EVENT_8007_DATA = util_load_json('test_data/event_typeid_8007_data.json')
EVENT_8015_DATA = util_load_json('test_data/event_typeid_8015_data.json')
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
HEADER_LIST = util_load_json('test_data/header_list.json')
SANDBOX_ISSUE_COMMAND = util_load_json('test_data/sandbox_issue_command.json')
SANDBOX_STATUS_COMMAND = util_load_json('test_data/sandbox_status_command.json')
SANDBOX_VERDICT_COMMAND = util_load_json('test_data/sandbox_verdict_command.json')
DEFAULT_RELIABILITY = 'B - Usually reliable'


@pytest.mark.parametrize('expected_result', ['12345678'])
def test_get_access_token_from_context(expected_result):
    actual_result = client.get_access_token_from_context()
    assert actual_result == expected_result


def test_get_access_token_or_login(requests_mock):
    """
        Tests the get_access_token_or_login function.
            Given:
                - requests_mock object.
            When:
                - Running the 'get_access_token_or_login function'.
            Then:
                -  Checks the output of the command function with the expected output.
    """
    post_req_url = f'{client._base_url}/atpapi/oauth2/tokens'
    # before login, access_token is not present
    # requests_mock.post(post_req_url, json={'access_token': '12345678'})
    # assert client.headers == {'Content-Type': 'application/json'}
    requests_mock.post(post_req_url, json={})
    access_token = client.get_access_token_or_login()
    assert client.access_token == access_token
    # after login, access_token is present
    assert client.headers == {'Authorization': f'Bearer {client.access_token}', 'Content-Type': 'application/json'}


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
    mocker.patch.object(client, 'get_file_instance', side_effect=[raw_response])
    with open(os.path.join("test_data", "command_readable_output/file_instance_command_readable_output.md")) as f:
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
    mocker.patch.object(client, 'get_domain_instance', side_effect=[raw_response])
    with open(os.path.join("test_data", "command_readable_output/endpoint_domain_instance_readable_output.md")) \
            as f:
        readable_output = f.read()
    command_results = get_domain_instance_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


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
    mocker.patch.object(client, 'get_endpoint_instance', side_effect=[raw_response])
    with open(os.path.join("test_data",
                           "command_readable_output/endpoint_instance_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_endpoint_instance_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


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
    mocker.patch.object(client, 'list_endpoint_file', side_effect=[raw_response])
    with open(os.path.join(
            "test_data", "command_readable_output/endpoint_file_association_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_endpoint_file_association_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


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
    mocker.patch.object(client, 'list_domain_file', side_effect=[raw_response])
    with open(os.path.join(
            "test_data", "command_readable_output/domain_file_association_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_domain_file_association_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


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
    mocker.patch.object(client, 'list_endpoint_domain', side_effect=[raw_response])
    with open(os.path.join(
            "test_data", "command_readable_output/endpoint_domain_association_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_endpoint_domain_association_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


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
    mocker.patch.object(client, 'get_deny_list', side_effect=[raw_response])
    with open(os.path.join(
            "test_data", "command_readable_output/deny_list_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_deny_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")
    assert command_results.readable_output == readable_output


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
    mocker.patch.object(client, 'get_allow_list', side_effect=[raw_response])
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
    mocker.patch.object(client, 'get_event_list', side_effect=[raw_response])
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
    mocker.patch.object(client, 'get_audit_event', side_effect=[raw_response])
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
    mocker.patch.object(client, 'get_system_activity', side_effect=[raw_response])
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
    mocker.patch.object(client, 'get_incident', side_effect=[raw_response])
    command_results = get_incident_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


@pytest.mark.parametrize('raw_response, expected', [(INCIDENT_LIST_RESPONSE, '9d6f2100-7158-11ed-da26-000000000001')])
def test_get_incident_uuid(mocker, raw_response, expected):
    """
    Tests get_incident_uuid function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_incident_uuid'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {
        "incident_id": 100010
    }
    mocker.patch.object(client, 'get_incident', side_effect=[raw_response])
    uuid = get_incident_uuid(client, args)

    # results is CommandResults list
    assert uuid == expected


@pytest.mark.parametrize('raw_incident, uuid_result',
                         [(INCIDENT_LIST_RESPONSE, '9d6f2100-7158-11ed-da26-000000000001')])
@pytest.mark.parametrize('raw_response, expected', [(INCIDENT_COMMENT_RESPONSE, INCIDENT_COMMENT_RESPONSE)])
def test_get_incident_comments_command(mocker, raw_incident, uuid_result, raw_response, expected):
    """
    Tests get_incident_comments_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_incident_comments_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {
        "incident_id": 100010
    }
    mocker.patch.object(client, 'get_incident', side_effect=[raw_incident])
    mocker.patch.object(client, 'get_incident_comment', side_effect=[raw_response])
    command_results = get_incident_comments_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']["result"]
    assert context_detail == expected.get("result")


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
    mocker.patch.object(client, 'get_event_for_incident', side_effect=[raw_response])
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
    with open(os.path.join(
            "test_data",
            "command_readable_output/endpoint_command_status_readable_output.md"
    )) as f:
        readable_output = f.read()
    mocker.patch.object(client, 'get_status_endpoint', side_effect=[raw_response])
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
    with open(os.path.join(
            "test_data",
            "command_readable_output/endpoint_command_isolate_readable_output.md"
    )) as f:
        readable_output = f.read()
    mocker.patch.object(client, 'get_isolate_endpoint', side_effect=[raw_response])
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
    with open(os.path.join(
            "test_data",
            "command_readable_output/endpoint_command_rejoin_readable_output.md"
    )) as f:
        readable_output = f.read()
    mocker.patch.object(client, 'get_rejoin_endpoint', side_effect=[raw_response])
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
    with open(os.path.join(
            "test_data",
            "command_readable_output/endpoint_command_delete_readable_output.md"
    )) as f:
        readable_output = f.read()
    mocker.patch.object(client, 'get_delete_endpoint', side_effect=[raw_response])
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
    with open(os.path.join(
            "test_data",
            "command_readable_output/endpoint_command_cancel_readable_output.md"
    )) as f:
        readable_output = f.read()
    mocker.patch.object(client, 'get_cancel_endpoint', side_effect=[raw_response])
    command_results = get_endpoint_command(client, args, 'symantec-edr-endpoint-cancel-command')

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize('sub_context, params, total_record, expected_title', [
    ('File Endpoint', {'page': 1, 'page_size': 10}, 100,
     'File Endpoint List\nShowing page 1\nShowing 10 out of 100 Record(s) Found.'),
    ('File Endpoint', {'page': 0, 'page_size': 0}, 0, 'File Endpoint List'),
    ('File Endpoint', {'limit': 5, 'page': None, 'page_size': 10}, 10,
     'File Endpoint List\nShowing page 1\nShowing 10 out of 10 Record(s) Found.'),
    ('File Endpoint', {'limit': 5, 'page': 1, 'page_size': None}, 10,
     'File Endpoint List\nShowing page 1\nShowing 10 out of 10 Record(s) Found.'),
    ('File Endpoint', {'limit': 5}, 10, 'File Endpoint List'),
])
def test_compile_command_title_string(sub_context, params, total_record, expected_title):
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

    actual_title = compile_command_title_string(sub_context, params, total_record)
    assert actual_title == expected_title


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
    ('domains', 'abcd123', 'Indicator type domains is not supported'),
    ('urls', '123245', '123245 is not a valid urls'),
    ('ip', 'google.1234', 'google.1234 is not a valid IP'),
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


@pytest.mark.parametrize('raw_response, expected', [(INCIDENT_LIST_RESPONSE, 'ok')])
def test_test_module(mocker, raw_response, expected):
    """
        Tests the test_module function.
            Given:
                - no argument required.
            When:
                - Running the 'test_module function'.
            Then:
                - Check weather the given credentials are correct or not.
    """
    # from SymantecEDR import test_module
    mocker.patch.object(client, 'get_incident', side_effect=[raw_response])
    output = client.test_module()
    # results
    assert output == expected


@pytest.mark.parametrize('response_code', [401, 500])
def test_test_module__invalid(mocker, response_code):
    """
        Tests the test_module handle exception.
            Given:
                - no argument required.
            When:
                - Running the 'test_module function'.
            Then:
                - Check weather the given credentials are correct or not.
    """
    with pytest.raises(Exception) as e:
        mocker.patch.object(client, 'get_incident', side_effect=[response_code])
        client.test_module()
        assert e.res.status_code == response_code


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
now = str(datetime.today())
now_iso = dateparser.parse(now, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)[:-3]
week_before = str(datetime.today() - timedelta(days=7))
iso_datatime_week_before = dateparser.parse(week_before, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)[:-3]


@pytest.mark.parametrize('date_string, expected_result', [
    (now, f'{now_iso}Z'),
    (week_before, f'{iso_datatime_week_before}Z')
])
def test_convert_to_iso8601(date_string, expected_result):
    """
        Tests the convert timestamp to iso8601 formate.

            Given:
                date_string - Datetime.
            When:
                - Running the 'test_convert_to_iso8601 function'.

            Then:
                - Checks the output of the command function with the expected ISO Date format .
    """
    actual_result = convert_to_iso8601(date_string)
    assert actual_result == str(expected_result)


@pytest.mark.parametrize('args, key, expected_result', [
    ({'start_time': '2023-02-26 10:01:11'}, 'start_time', '2023-02-26T10:01:11.000Z'),
    ({'end_time': '2023-02-26 00:00:00'}, 'end_time', '2023-02-26T00:00:00.000Z')
])
def test_create_content_query(args, key, expected_result):
    """
        Tests Create content request body.

            Given:
                args - command argument.
            When:
                - Running the 'create_content_query function'.

            Then:
                - Checks the output of the content request body function with the start_time, end_time.
    """
    payload = create_content_query(args)
    assert payload.get(key) == str(expected_result)


@pytest.mark.parametrize('args, key, expected_result', [
    ({'denylist_id': 123}, 'id', 123),
    ({'allowlist_id': 234}, 'id', 234),
    ({'ip': '127.0.0.1'}, 'ip', '127.0.0.1'),
    ({'url': 'https://google.com'}, 'url', 'https://google.com'),
    ({'domain': 'windowsupdate.com'}, 'domain', 'windowsupdate.com'),
    ({'md5': '4dd18f001ac31d5f48f50f99e4aa1761'}, 'md5', '4dd18f001ac31d5f48f50f99e4aa1761'),
    ({'sha256': '2b105fb153b1bcd619b95028612b3a93c60b953eef6837d3bb0099e4207aaf6b'},
     'sha256', '2b105fb153b1bcd619b95028612b3a93c60b953eef6837d3bb0099e4207aaf6b')
])
def test_create_params_query(args, key, expected_result):
    """
        Tests Create param query.

            Given:
                args - demisto argument.
            When:
                - Running the 'create_params_query function'.

            Then:
                - Checks the output of the demisto params query with different indicators.
    """
    payload = create_params_query(args)
    assert payload.get(key) == expected_result


@pytest.mark.parametrize('args, expected_result', [
    ({'type_id': 12345}, 'type_id: 12345'),
    ({'severity': 'info'}, 'severity_id: 1'),
    ({'status': 'Success'}, 'status_id: 1'),
    ({'query': "original_name: svchost.exe"}, 'original_name: svchost.exe'),
])
def test_get_event_filter_query(args, expected_result):
    """
        Tests event query condition.

            Given:
                args - demisto argument.
                expected_result - query condition
            When:
                - Running the 'get_event_filter_query function'.

            Then:
                - Checks the output of the demisto args for create query condition.
    """
    condition = get_event_filter_query(args)
    assert condition == expected_result


@pytest.mark.parametrize('args, expected_error', [
    ({'query': "name: svchost.exe", 'type_id': 12345},
     'Invalid query arguments. Either use any optional filter in lieu of "query" '
     'or explicitly use only "query" argument')])
def test_get_event_filter_query_wrong_input(args, expected_error):
    """
    Tests get_event_filter_query  function.
        Given:
            - event_data test data.
            - expected output.
        When:
            - Running the 'get_event_filter_query '.
        Then:
            - Checks expected error message is being raised.
    """
    with pytest.raises(DemistoException) as e:
        get_event_filter_query(args)
    assert e.value.args[0] == expected_error


@pytest.mark.parametrize('args, expected_result', [
    ({'incident_id': 12345}, 'atp_incident_id: 12345'),
    ({'priority': 'High'}, 'priority_level: 3'),
    ({'status': 'Open'}, 'state: 1'),
    ({'query': "name: svchost.exe"}, 'name: svchost.exe'),
])
def test_get_incident_filter_query(args, expected_result):
    """
        Tests incident query condition.

            Given:
                args - demisto argument.
                expected_result - query condition
            When:
                - Running the 'get_incident_filter_query function'.

            Then:
                - Checks the output of the demisto args for incident query condition.
    """
    condition = get_incident_filter_query(args)
    assert condition == expected_result


@pytest.mark.parametrize('raw_response, expected', [(HEADER_LIST, 'Id')])
def test_extract_headers_for_readable_output(raw_response, expected):
    """
    Tests extract_headers_for_readable_output function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'extract_headers_for_readable_output'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    actual_result = extract_headers_for_readable_output(raw_response)
    assert actual_result[0] == expected


@pytest.mark.parametrize('raw_response, offset, limit, expected', [(HEADER_LIST, 0, 3, HEADER_LIST[:3]),
                                                                   (HEADER_LIST, 2, 3, HEADER_LIST[2:2 + 3])])
def test_get_data_of_current_page(raw_response, offset, limit, expected):
    """
    Tests get_data_of_current_page function.
        Given:
            - raw_response test data.
            - offset Page Offset.
            - limit Max rows to fetches
            - expected output.
        When:
            - Running the 'get_data_of_current_page'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    actual_result = get_data_of_current_page(raw_response, offset, limit)
    assert actual_result == expected


@pytest.mark.parametrize('raw_event_data', [EVENT_LIST_RESPONSE])
def test_parse_event_object_data(raw_event_data):
    """
    Tests parse_event_object_data function.
        Given:
            - raw_response test data.
            - expected output.
        When:
            - Running the 'parse_event_object_data'.
        Then:
            -  Checks the output of parse event object with the expected output.
    """
    results = parse_event_object_data(raw_event_data.get('result')[0])
    assert results.get('file_file_sha2') == 'c4e078607db2784be7761c86048dffa6f3ef04b551354a32fcdec3b6a3450905'
    assert results.get('uuid') == '6a79a590-84a9-11ed-f4c8-000000032af2'


@pytest.mark.parametrize('raw_event_data', [EVENT_8001_DATA])
def test_parse_attacks_sub_object(raw_event_data):
    """
    Tests parse_attacks_sub_object function.
        Given:
            - raw_response test data.
            - expected output.
        When:
            - Running the 'parse_attacks_sub_object'.
        Then:
            -  Checks the output of parse event attacks sub object and with expected output.
    """
    results = parse_attacks_sub_object(raw_event_data.get('result')[0].get('attacks'))
    assert results.get('attacks_technique_uid') == 'T1021'
    assert results.get('attacks_tactic_ids_0') == '8,5'
    assert results.get('attacks_tactic_uids_0') == 'TA0008,TA0004'


@pytest.mark.parametrize('raw_event_data', [EVENT_8001_DATA])
def test_parse_enriched_data_sub_object(raw_event_data):
    """
    Tests parse_enriched_data_sub_object function.
        Given:
            - raw_response test data.
            - expected output.
        When:
            - Running the 'parse_enriched_data_sub_object'.
        Then:
            -  Checks the output of parse event enriched sub object and with expected output.
    """
    results = parse_enriched_data_sub_object(raw_event_data.get('result')[0].get('enriched_data'))
    assert results.get('enriched_data_suspicion_score') == 50
    assert results.get('enriched_data_category_id') == 201


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8007_DATA, 'xattributes_symc_injected', False), (EVENT_8007_DATA, 'xattributes_is_trusted', False)])
def test_parse_xattributes_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_xattributes_sub_object function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_xattributes_sub_object'.
        Then:
            -  Checks the output of parse event actor xattributes sub object expected output.
    """
    results = parse_xattributes_sub_object(event_data.get('result')[0].get('event_actor').get('xattributes'), None)
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8007_DATA, 'user_sid', 'S-1-5-20'), (EVENT_8007_DATA, 'user_name', 'NETWORK SERVICE')])
def test_parse_user_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_user_sub_object function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_user_sub_object'.
        Then:
            -  Checks the output of parse event actor user sub object output.
    """
    results = parse_user_sub_object(event_data.get('result')[0].get('event_actor').get('user'), None)
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8007_DATA, 'file_md5', '4dd18f001ac31d5f48f50f99e4aa1761'), (EVENT_8007_DATA, 'file_name', 'svchost.exe')])
def test_parse_file_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_file_sub_object function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_file_sub_object'.
        Then:
            -  Checks the output of parse event actor file sub object output.
    """
    results = parse_file_sub_object(event_data.get('result')[0].get('event_actor').get('file'), None)
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8007_DATA, 'event_actor_pid', 2888),
    (EVENT_8007_DATA, 'event_actor_uid', '52D97C3B-A235-F1ED-821C-98261F32744E')])
def test_parse_event_actor_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_event_actor_sub_object function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_event_actor_sub_object'.
        Then:
            -  Checks the output of parse event actor sub object output.
    """
    results = parse_event_actor_sub_object(event_data.get('result')[0].get('event_actor'))
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8007_DATA, 'connection_bytes_download', 8228),
    (EVENT_8007_DATA, 'connection_uid', '4000486770828200160')])
def test_parse_connection_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_connection_sub_object function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_connection_sub_object'.
        Then:
            - Checks the output of parse connection sub object output.
    """
    results = parse_connection_sub_object(event_data.get('result')[0].get('connection'))
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8001_DATA, 'pid', 7260),
    (EVENT_8001_DATA, 'uid', '346CA85F-B35B-F1ED-821C-98261F32744E')])
def test_parse_process_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_process_sub_object  function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_process_sub_object '.
        Then:
            - Checks the output of parse process sub object output.
    """
    results = parse_process_sub_object(event_data.get('result')[0].get('process'))
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (EVENT_8015_DATA, 'monitor_source_type_id', 5),
    (EVENT_8015_DATA, 'monitor_source_facility', 'Microsoft-Windows-Security-Auditing')])
def test_parse_monitor_source_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_monitor_source_sub_object  function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_monitor_source_sub_object '.
        Then:
            - Checks the output of parse monitor source sub object output.
    """
    results = parse_monitor_source_sub_object(event_data.get('result')[0].get('monitor_source'))
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, event_key, expected_output', [
    (SYSTEM_ACTIVITY_RESPONSE, 'sepm_server_db_type', 'MSSQL'),
    (SYSTEM_ACTIVITY_RESPONSE, 'sepm_server_status', 'healthy'),
    (SYSTEM_ACTIVITY_RESPONSE, 'search_config_cmd_type', 'edr_search'),
    (SYSTEM_ACTIVITY_RESPONSE, 'atp_service_service', 'microservice_host')])
def test_parse_event_data_sub_object(event_data, event_key, expected_output):
    """
    Tests parse_event_data_sub_object  function.
        Given:
            - event_data test data.
            - event_key attribute
            - expected output.
        When:
            - Running the 'parse_event_data_sub_object'.
        Then:
            - Checks the output of parse system Activity data object output.
    """
    results = parse_event_data_sub_object(event_data.get('result')[0].get('data'))
    assert results.get(event_key) == expected_output


@pytest.mark.parametrize('event_data, expected_error', [
    ('hello', 'Unexpected data type <class \'str\'>:: must be either a list or dict.\ndata=hello')])
def test_extract_raw_data_wrong_input(event_data, expected_error):
    """
    Tests extract_raw_data  function.
        Given:
            - event_data test data.
            - expected output.
        When:
            - Running the 'extract_raw_data '.
        Then:
            - Checks expected error message is being raised.
    """
    with pytest.raises(ValueError) as e:
        extract_raw_data(event_data, [], None)
    assert e.value.args[0] == expected_error


@pytest.mark.parametrize('raw_response, expected', [(SANDBOX_ISSUE_COMMAND, SANDBOX_ISSUE_COMMAND)])
def test_issue_sandbox_command(mocker, raw_response, expected):
    """
    Tests issue_sandbox_command Issue function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'issue_sandbox_command('.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"file": '1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164'}
    mocker.patch.object(client, 'submit_file_to_sandbox_analyze', side_effect=[raw_response])
    command_results = issue_sandbox_command(client, args,)

    # results is CommandResults list
    context_detail = command_results.raw_response
    assert context_detail == expected


@pytest.mark.parametrize('raw_response, expected', [(SANDBOX_STATUS_COMMAND, SANDBOX_STATUS_COMMAND)])
def test_check_sandbox_status(mocker, raw_response, expected):
    """
    Tests check_sandbox_status status function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'check_sandbox_status'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"command_id": 'a4277ce5ebd84fe18c30fa67a05b42c9-2023-02-06'}
    mocker.patch.object(client, 'get_sandbox_status', side_effect=[raw_response])
    command_results = check_sandbox_status(client, args,)

    # results is CommandResults list
    context_detail = command_results.raw_response
    assert context_detail == expected


BAD_SANDBOX_VERDICT = SANDBOX_VERDICT_COMMAND.copy()
BAD_SANDBOX_VERDICT["verdict"] = "malware"
SUSPICIOUS_SANDBOX_VERDICT = SANDBOX_VERDICT_COMMAND.copy()
SUSPICIOUS_SANDBOX_VERDICT["verdict"] = "file_type_unrecognized"


@pytest.mark.parametrize('raw_response, expected, expected_dbot_score', [(SANDBOX_VERDICT_COMMAND,
                                                                          SANDBOX_VERDICT_COMMAND,
                                                                          Common.DBotScore.GOOD),
                                                                         (BAD_SANDBOX_VERDICT,
                                                                          BAD_SANDBOX_VERDICT,
                                                                          Common.DBotScore.BAD),
                                                                         (SUSPICIOUS_SANDBOX_VERDICT,
                                                                          SUSPICIOUS_SANDBOX_VERDICT,
                                                                          Common.DBotScore.SUSPICIOUS)])
def test_get_sandbox_verdict(mocker, raw_response, expected, expected_dbot_score):
    """
    Tests get_sandbox_verdict status function.
        Given:
            - mocker object.
            - raw_response test data.
            - expected output.
            - different verdicts.
            - expected DBot score.
        When:
            - Running the 'get_sandbox_verdict'.
        Then:
            - Checks the output of the command function with the expected output.
            - Assert the DBotScore returned is as expected.
    """
    args = {"sha2": '1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164',
            "integration_reliability": DEFAULT_RELIABILITY}
    mocker.patch.object(client, 'get_sandbox_verdict_for_file', side_effect=[raw_response])
    mocker.patch.object(client, 'get_file_entity', side_effect=[raw_response])
    command_results = get_sandbox_verdict(client, args)

    # results is CommandResults list
    context_detail = command_results.raw_response
    assert context_detail == expected
    assert command_results.indicator.dbot_score.score == expected_dbot_score
    assert command_results.indicator.dbot_score.indicator_type == DBotScoreType.FILE
    assert command_results.indicator.dbot_score.integration_name == INTEGRATION_CONTEXT_NAME
    assert command_results.indicator.dbot_score.reliability == DEFAULT_RELIABILITY


@pytest.mark.parametrize("reliability",
                         ["A+ - 3rd party enrichment",
                          "A - Completely reliable",
                          "B - Usually reliable",
                          "C - Fairly reliable",
                          "D - Not usually reliable",
                          "E - Unreliable",
                          "F - Reliability cannot be judged"])
def test_email_different_reliability(mocker, reliability):
    """
    Given:
        - Different source reliability param
    When:
        - Running file command
    Then:
        - Ensure the reliability specified is returned.
    """
    args = {"sha2": '1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164',
            "integration_reliability": reliability}
    mocker.patch.object(client, 'get_sandbox_verdict_for_file', side_effect=[SANDBOX_VERDICT_COMMAND])
    mocker.patch.object(client, 'get_file_entity', side_effect=[SANDBOX_VERDICT_COMMAND])
    command_results = get_sandbox_verdict(client, args)

    assert command_results.indicator.dbot_score.reliability == reliability


@pytest.mark.parametrize('query_type, query_value, expected_result', [
    ('sha256', '1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164',
     'sha2: (1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164)'),
    ('device_uid', '393b8e82-fe40-429f-8e5e-c6b79a0f2b1c',
     'device_uid: (393b8e82-fe40-429f-8e5e-c6b79a0f2b1c)')
])
def test_get_association_filter_query(query_type, query_value, expected_result):
    """
        Tests the get_association_filter_query function.

            Given:
                query_type - Indicator search obj
                query_value - Indicator search value
            When:
                - Running the 'get_association_filter_query function'.

            Then:
                - Checks the output of the command function with the expected result.
    """
    args = {'search_object': query_type, 'search_value': query_value}
    result = get_association_filter_query(args)
    assert result == expected_result


@pytest.mark.parametrize('list_data, expected_result', [
    ([1, 2, 3, 4], "1,2,3,4"),
])
def test_convert_list_to_str(list_data, expected_result):
    """
        Tests the convert_list_to_str function.

            Given:
                list_data - Lists data
            When:
                - Running the 'convert_list_to_str function'.

            Then:
                - Checks the output of the command function with the expected result.
    """
    result = convert_list_to_str(list_data)
    assert result == expected_result


@pytest.mark.parametrize('page, page_size, expected_result', [
    # page, page_size, (page_limit, offset)
    (2, 5, (10, 5)),
    (None, 5, (5, 0)),
    (2, None, (100, 50)),
    (3, None, (150, 100)),
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


@pytest.mark.parametrize('param, expected_result', [
    ({'limit': 5, 'page_size': None}, (5, 0)),  #
    ({'limit': 5, 'page_size': 15}, (15, 0)),
    ({'limit': 5, 'page': 1}, (50, 0)),
    ({'limit': 5, 'page': 1, 'page_size': 10}, (10, 0)),
    ({'limit': 5, 'page': 2, 'page_size': 10}, (20, 10)),
])
def test_get_query_limit(param, expected_result):
    """
        Tests the get_query_limit function.

            Given:
                param - parameter data
            When:
                - Running the 'get_query_limit function'.

            Then:
                - Checks the output of the command function with the expected result.
    """
    (limit, offset) = get_query_limit(param)
    assert limit == expected_result[0], f"Validate limit {limit} == {expected_result[0]}"
    assert offset == expected_result[1], f"Validate offset {offset} == {expected_result[1]}"


@pytest.mark.parametrize('raw_data, expected', [(INCIDENT_LIST_RESPONSE, 'SEDR Incident 100010')])
def test_fetch_incidents(mocker, raw_data, expected):
    """
    Tests fetch incidents function.

        Given:
            - mocker object.
            - raw_data test data.
            - expected output.

        When:
            - Running the 'fetch_incidents'.

        Then:
            -  Checks the output of the fetch_incidents.
    """
    client.fetch_priority = ['High', 'Low', 'Medium']
    client.fetch_status = ['Open', 'Closed']
    client.fetch_limit = 1
    mocker.patch.object(client, 'get_incident', side_effect=[raw_data])
    incident_list = fetch_incidents(client)

    # results incident list
    assert incident_list[0].get('name') == expected
