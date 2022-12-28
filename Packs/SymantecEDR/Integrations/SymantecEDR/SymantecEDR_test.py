"""
Symantec EDR (On-prem) Integration - Unit Tests file
"""
# type: ignore
import pytest
import json
import io
# import os
# from CommonServerPython import DemistoException
from SymantecEDR import Client, get_file_instance_command, get_domain_instance_command, get_endpoint_instance_command, \
    get_endpoint_file_association_list_command, get_domain_file_association_list_command, \
    get_endpoint_domain_association_list_command, get_deny_list_command, get_allow_list_command, \
    get_event_list_command, get_audit_event_command, get_system_activity_command, get_incident_list_command, \
    get_event_for_incident_list_command


def util_load_json(path):
    with io.open(path, mode='r') as f:
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
    # with open(os.path.join("test_data", "file_instance_readable_output.md"), 'r') as f:
    #     readable_output = f.read()
    command_results = get_file_instance_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']['result']
    assert context_detail == expected.get("result")
    # assert command_results.readable_output == readable_output


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


# @pytest.mark.parametrize('raw_response, expected', [(ENDPOINT_INSTANCE_RESPONSE, ENDPOINT_INSTANCE_RESPONSE)])
# def test_get_endpoint_instance_command(mocker, raw_response, expected):
#     """
#     Tests get_endpoint_instance_command function.
#
#         Given:
#             - mocker object.
#             - raw_response test data.
#             - expected output.
#
#         When:
#             - Running the 'get_endpoint_instance_command'.
#
#         Then:
#             -  Checks the output of the command function with the expected output.
#     """
#     args = {"limit": 1}
#     mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
#     command_results = get_endpoint_instance_command(client, args)
#
#     # results is CommandResults list
#     context_detail = command_results.to_context()['Contents']['result']
#     assert context_detail == expected.get("result")


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


# @pytest.mark.parametrize('raw_response, expected', [(INCIDENT_COMMENT_RESPONSE, INCIDENT_COMMENT_RESPONSE)])
# def test_get_incident_comments_command(mocker, raw_response, expected):
#     """
#     Tests get_incident_comments_command function.
#
#         Given:
#             - mocker object.
#             - raw_response test data.
#             - expected output.
#
#         When:
#             - Running the 'get_incident_comments_command'.
#
#         Then:
#             -  Checks the output of the command function with the expected output.
#     """
#     args = {
#         "limit": 1,
#         "incident_id": 100011
#     }
#     mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
#     command_results = get_incident_comments_command(client, args)
#
#     # results is CommandResults list
#     context_detail = command_results.to_context()['Contents']["result"]
#     assert context_detail == expected.get("result")


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
