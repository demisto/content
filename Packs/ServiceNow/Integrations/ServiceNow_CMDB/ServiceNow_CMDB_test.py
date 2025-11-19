import pytest
from ServiceNow_CMDB import (
    Client,
    add_relation_command,
    create_record_command,
    delete_relation_command,
    get_record_command,
    records_list_command,
    update_record_command,
)
from ServiceNowApiModule import ServiceNowClient
from test_data.response_constants import (
    ADD_RELATION_RESPONSE,
    CREATE_RECORD_RESPONSE,
    DELETE_RELATION_RESPONSE,
    GET_RECORD_RESPONSE,
    RECORDS_LIST_EMPTY_RESPONSE,
    RECORDS_LIST_RESPONSE_WITH_RECORDS,
    UPDATE_RECORD_RESPONSE,
)
from test_data.result_constants import (
    EXPECTED_ADD_RELATION,
    EXPECTED_CREATE_RECORD,
    EXPECTED_DELETE_RELATION,
    EXPECTED_GET_RECORD,
    EXPECTED_RECORDS_LIST_NO_RECORDS,
    EXPECTED_RECORDS_LIST_WITH_RECORDS,
    EXPECTED_UPDATE_RECORD,
)


@pytest.mark.parametrize(
    "response, expected_result",
    [
        (RECORDS_LIST_RESPONSE_WITH_RECORDS, EXPECTED_RECORDS_LIST_WITH_RECORDS),
        (RECORDS_LIST_EMPTY_RESPONSE, EXPECTED_RECORDS_LIST_NO_RECORDS),
    ],
)
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
    mocker.patch.object(ServiceNowClient, "http_request", return_value=response)
    result = records_list_command(client, args={"class": "test_class"})
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
    mocker.patch.object(ServiceNowClient, "http_request", return_value=GET_RECORD_RESPONSE)
    result = get_record_command(client, args={"class": "test_class", "sys_id": "record_id"})
    assert result[1] == EXPECTED_GET_RECORD


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
    mocker.patch.object(ServiceNowClient, "http_request", return_value=CREATE_RECORD_RESPONSE)
    result = create_record_command(client, args={"class": "test_class", "attributes": "name=Test Create Record"})
    assert result[1] == EXPECTED_CREATE_RECORD


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
    mocker.patch.object(ServiceNowClient, "http_request", return_value=UPDATE_RECORD_RESPONSE)
    result = update_record_command(
        client, args={"class": "test_class", "sys_id": "record_id", "attributes": "name=Test Create Record"}
    )
    assert result[1] == EXPECTED_UPDATE_RECORD


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
    mocker.patch.object(ServiceNowClient, "http_request", return_value=ADD_RELATION_RESPONSE)
    result = add_relation_command(
        client,
        args={
            "class": "test_class",
            "sys_id": "record_id",
            "inbound_relations": "[{'type': 'relation_type', 'target':'target', 'sys_class_name':'class_name'}]",
        },
    )
    assert result[1] == EXPECTED_ADD_RELATION


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
    mocker.patch.object(ServiceNowClient, "http_request", return_value=DELETE_RELATION_RESPONSE)
    result = delete_relation_command(client, args={"class": "test_class", "sys_id": "record_id", "relation_sys_id": "rel_id"})
    assert result[1] == EXPECTED_DELETE_RELATION


def test_client_jwt_param_usage(mocker):
    """
    Given:
    - JWT params provided to the ServiceNow CMDB Client
    When:
    - Initializing the Client with jwt_params
    Then:
    - ServiceNowClient is instantiated with the same jwt_params
    - The jwt attribute is set on the inner ServiceNowClient
    """
    jwt_params = {
        "private_key": "-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----",
        "kid": "test_kid",
        "sub": "test_sub",
        "aud": "test_aud",
        "iss": "test_iss",
    }
    mocker.patch("ServiceNowApiModule.jwt.encode", return_value="jwt_token_stub")
    client = Client(
        credentials={"identifier": "user", "password": "pw"},
        use_oauth=True,
        client_id="client_id",
        client_secret="client_secret",
        url="https://example.com",
        verify=True,
        proxy=False,
        jwt_params=jwt_params,
    )
    assert hasattr(client.snow_client, "jwt")
    assert client.snow_client.jwt == "jwt_token_stub"


def test_client_empty_jwt_param_usage(mocker):
    """
    Given:
    - no JWT params provided to the ServiceNow CMDB Client
    When:
    - Initializing the Client
    Then:
    - ServiceNowClient is instantiated with the same jwt_params
    - The jwt attribute is set to None on the inner ServiceNowClient
    """
    jwt_params = {}
    client = Client(
        credentials={"identifier": "user", "password": "pw"},
        use_oauth=True,
        client_id="client_id",
        client_secret="client_secret",
        url="https://example.com",
        verify=True,
        proxy=False,
        jwt_params=jwt_params,
    )
    assert hasattr(client.snow_client, "jwt")
    assert client.snow_client.jwt is None
