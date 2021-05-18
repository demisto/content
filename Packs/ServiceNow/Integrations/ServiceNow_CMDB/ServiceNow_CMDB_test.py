import pytest
from ServiceNow_CMDB import Client, records_list_command, get_record_command, create_record_command, \
    update_record_command, add_relation_command, delete_relation_command
from test_data.result_constants import EXPECTED_RECORDS_LIST_NO_RECORDS, \
    EXPECTED_RECORDS_LIST_WITH_RECORDS, EXPECTED_GET_RECORD, EXPECTED_CREATE_RECORD, EXPECTED_UPDATE_RECORD, \
    EXPECTED_ADD_RELATION, EXPECTED_DELETE_RELATION
from test_data.response_constants import RECORDS_LIST_EMPTY_RESPONSE, RECORDS_LIST_RESPONSE_WITH_RECORDS, \
    GET_RECORD_RESPONSE, CREATE_RECORD_RESPONSE, UPDATE_RECORD_RESPONSE, \
    ADD_RELATION_RESPONSE, DELETE_RELATION_RESPONSE
from ServiceNowApiModule import ServiceNowClient


@pytest.mark.parametrize('response, expected_result', [
    (RECORDS_LIST_RESPONSE_WITH_RECORDS, EXPECTED_RECORDS_LIST_WITH_RECORDS),
    (RECORDS_LIST_EMPTY_RESPONSE, EXPECTED_RECORDS_LIST_NO_RECORDS)
])
def test_records_list_command(response, expected_result, mocker):
    """
    Given:
        - The records list command.
    When:
        - Mocking the response from the http request once to a response containing records, and once to a response with
        no records.
    Then:
        - Validate that in the first case when the response contains records, the context has both `Class` and `Records`
         keys. In the second case, when no records are in the response, validate the context has only the `Class` key.
    """
    client = Client({})
    mocker.patch.object(ServiceNowClient, 'http_request', return_value=response)
    result = records_list_command(client, args={'class': 'test_class'})
    assert expected_result == result[1]


def test_get_record_command(mocker):
    """
    Given:
        - The get record by id command.
    When:
        - Mocking the response from the http request to a response containing several attributes, inbound and outbound
        relations of the record.
    Then:
        - Validate that the output context of the command contains all attributes and relations that were returned.
    """
    client = Client(credentials={})
    mocker.patch.object(ServiceNowClient, 'http_request', return_value=GET_RECORD_RESPONSE)
    result = get_record_command(client, args={'class': 'test_class', 'sys_id': 'record_id'})
    assert EXPECTED_GET_RECORD == result[1]


def test_create_record_command(mocker):
    """
    Given:
        - The create record command.
    When:
        - Mocking the response from the http request to a response containing the attributes of the new record with no
        inbound or outbound relations.
    Then:
        - Validate that the context output contains the `Class`, `SysId` and `Attributes` keys according to the mocked
        response, and that the inbound and outbound relations lists are empty.
    """
    client = Client(credentials={})
    mocker.patch.object(ServiceNowClient, 'http_request', return_value=CREATE_RECORD_RESPONSE)
    result = create_record_command(client, args={'class': 'test_class', 'attributes': 'name=Test Create Record'})
    assert EXPECTED_CREATE_RECORD == result[1]


def test_update_record_command(mocker):
    """
    Given:
        - The update record command.
    When:
        - Mocking the response from the http request to a response containing the attributes of the updated record.
    Then:
        - Validate that the context output was changed according to the new attributes.
    """
    client = Client(credentials={})
    mocker.patch.object(ServiceNowClient, 'http_request', return_value=UPDATE_RECORD_RESPONSE)
    result = update_record_command(client, args={'class': 'test_class', 'sys_id': 'record_id',
                                                 'attributes': 'name=Test Create Record'})
    assert EXPECTED_UPDATE_RECORD == result[1]


def test_add_relation_command(mocker):
    """
    Given:
        - The add relation command.
    When:
        - Mocking the response from the http request to a response containing the attributes and the relations of the
        record.
    Then:
        - Validate that the `InboundRelations` key in the context output contains the added relation.
    """
    client = Client(credentials={})
    mocker.patch.object(ServiceNowClient, 'http_request', return_value=ADD_RELATION_RESPONSE)
    result = add_relation_command(client, args={
        'class': 'test_class',
        'sys_id': 'record_id',
        'inbound_relations': "[{'type': 'relation_type', 'target':'target', 'sys_class_name':'class_name'}]"
    })
    assert EXPECTED_ADD_RELATION == result[1]


def test_delete_relation_command(mocker):
    """
    Given:
        - The delete relation command.
    When:
        - Mocking the response from the http request to a response containing the attributes and the relations of the
        record.
    Then:
        - Validate that the `InboundRelations` key in the context output is empty.
    """
    client = Client(credentials={})
    mocker.patch.object(ServiceNowClient, 'http_request', return_value=DELETE_RELATION_RESPONSE)
    result = delete_relation_command(client, args={'class': 'test_class', 'sys_id': 'record_id',
                                                   'relation_sys_id': 'rel_id'})
    assert EXPECTED_DELETE_RELATION == result[1]
