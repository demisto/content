import pytest
from TrendMicroVisionOne import (
    Client,
    add_or_remove_from_block_list,
    quarantine_or_delete_email_message,
    isolate_or_restore_connection,
    terminate_process,
    add_or_delete_from_exception_list,
    add_to_suspicious_list,
    delete_from_suspicious_list,
    get_file_analysis_status,
    get_file_analysis_report,
    collect_file,
    download_information_collected_file,
    submit_file_to_sandbox,
)


# Provide valid API KEY
api_key = "test api key"


# Mock function for add to block list and remove from block list
def add_remove_blocklist_mock_response(*args, **kwargs):
    return_value = {
        "actionId": "88139521",
        "taskStatus": "pending",
        "data": {
            "createdTime": 1589525651,
            "executedTime": 1589525725,
            "finishedTime": 1589525725,
            "taskStatus": "success",
            "error": {}
        }
    }
    return return_value


# Test cases for add to block list
def test_add_blocklist(mocker):
    """Test add to block list with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_remove_blocklist_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-add-to-block-list", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "action_id"


def test_add_blocklist_missing_optional_data(mocker):
    """Test add to block list with missing optional data."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_remove_blocklist_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": None,
        "description": None,
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-add-to-block-list", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "action_id"


def test_add_block_list_wrong_api_key():
    """Test add block list with wrong API key."""
    api_key = "wrong key"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        add_or_remove_from_block_list(
            client, "trendmicro-visionone-add-to-block-list", args
        )


def test_add_blocklist_wrong_value_type():
    """Test add to block list with wrong value type."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "valueType": "file",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": None,
        "description": None,
    }
    with pytest.raises(SystemExit):
        add_or_remove_from_block_list(
            client, "trendmicro-visionone-add-to-block-list", args
        )


# Test cases for remove from block list
def test_remove_block_list(mocker):
    """Test remove block list positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_remove_blocklist_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-remove-from-block-list", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "action_id"


def test_remove_block_list_missing_optional_data(mocker):
    """Test remove block list with missing optional data"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_remove_blocklist_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": None,
        "description": None,
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-remove-from-block-list", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "action_id"


def test_remove_from_blocklist_wrong_api_key():
    """Test remove from block list with wrong API key."""
    api_key = "adswe"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        add_or_remove_from_block_list(
            client, "trendmicro-visionone-remove-from-block-list", args
        )


def test_remove_block_list_wrong_value_type():
    """Test remove block list with wrong value type."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "valueType": "file",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": None,
        "description": None,
    }
    with pytest.raises(SystemExit):
        add_or_remove_from_block_list(
            client, "trendmicro-visionone-remove-from-block-list", args
        )


# Mock function for quarantine and delete email message
def quarantine_delete_email_mock_response(*args, **kwargs):
    return_value = {
        "actionId": "88139521",
        "taskStatus": "pending",
        "data": {
            "createdTime": 1589525651,
            "executedTime": 1589525725,
            "finishedTime": 1589525725,
            "taskStatus": "success",
            "error": {},
        },
    }
    return return_value


# Test cases for quarantine email message
def test_quarantine_email_wrong_api_key():
    """Test quarantine email with wrong API."""
    api_key = "adswe"
    args = {
        "messageId": (
            "<CANUJTKRiUHNyx1VKQ19G6xi_Lmho"
            "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:01:53.000Z",
        "productId": "sca",
        "description": "quarantine info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        quarantine_or_delete_email_message(
            client, "trendmicro-visionone-quarantine-email-message", args
        )


def test_quarantine_email_message(mocker):
    """Test quarantine email message positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        quarantine_delete_email_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "messageId": (
            "<CANUJTKTjto9GAHTr9V=TFqMZhRXqVn="
            "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:00:12.000Z",
        "productId": "sca",
        "description": "quarantine info",
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-quarantine-email-message", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "action_id"


def test_quarantine_email_message_optional_missing_data(mocker):
    """Test delete email message with missing optional data"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        quarantine_delete_email_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "messageId": (
            "<CANUJTKQSYNp+jDHAP-+=2Uw=2ij7cjj-"
            "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:00:34.000Z",
        "productId": None,
        "description": None,
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-quarantine-email-message", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "action_id"


# Test cases for delete email message
def test_delete_email_wrong_api_key():
    """Test delete email message with wrong API."""
    api_key = "adswe"
    args = {
        "messageId": (
            "<CANUJTKRiUHNyx1VKQ19G6xi_LmhoMfS"
            "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:01:53.000Z",
        "productId": "sca",
        "description": "quarantine info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        quarantine_or_delete_email_message(
            client, "trendmicro-visionone-delete-email-message", args
        )


def test_delete_email_message(mocker):
    """Test delete email message with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        quarantine_delete_email_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "messageId": (
            "<CANUJTKTqmuCT12v7mpbxZih_crrP"
            "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:00:55.000Z",
        "productId": "sca",
        "description": "quarantine info",
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-delete-email-message", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "action_id"


def test_delete_email_message_optional_missing_data(mocker):
    """Test delete email with optional data missing"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        quarantine_delete_email_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "messageId": (
            "<CANUJTKQHxGoMvU7K=7Di64WM"
            "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:00:46.000Z",
        "productId": None,
        "description": None,
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-delete-email-message", args
    )
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "action_id"


# Mock function for isolate and restore endpoint
def isolate_restore_mock_response(*args, **kwargs):
    return_value = {
        "status": "string",
        "actionId": "88139521",
        "taskStatus": "pending",
        "result": {
            "computerId": "string",
        },
        "data": {
            "createdTime": 1589525651,
            "executedTime": 1589525725,
            "finishedTime": 1589525725,
            "taskStatus": "success",
            "error": {},
        },
    }
    return return_value


# Test cases for isolate endpoint
def test_isolate_endpoint_wrong_api_key():
    """Test isolate endpoint with wrong API."""
    api_key = "adswe"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        isolate_or_restore_connection(
            client, "trendmicro-visionone-isolate-endpoint", args
        )


def test_isolate_endpoint(mocker):
    """Test isolate endpoint postive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        isolate_restore_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "CLIENT2",
        "productId": "sao",
        "description": "isolate endpoint info",
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-isolate-endpoint", args
    )
    assert result.outputs["task_status"] == "success"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "action_id"


def test_isolate_endpoint_missing_optional_data(mocker):
    """Test isolate endpoint with optional data missing."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        isolate_restore_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "CLIENT2",
        "productId": "sao",
        "description": None,
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-isolate-endpoint", args
    )
    assert result.outputs["task_status"] == "success"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "action_id"


def test_isolate_endpoint_wrong_field():
    """Test isolate endpoint with missing field data."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostnameing",
        "value": "CLIENT2",
        "productId": "sao",
        "description": None,
    }
    with pytest.raises(SystemExit):
        isolate_or_restore_connection(
            client, "trendmicro-visionone-isolate-endpoint", args
        )


# Test cases for restore endpoint
def test_retore_endpoint_wrong_api_key():
    """Test restore endpoint with wrong API key."""
    api_key = "adswe"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        isolate_or_restore_connection(
            client, "trendmicro-visionone-restore-endpoint-connection", args
        )


def test_restore_endpoint(mocker):
    """Test restore endpoint positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        isolate_restore_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "CLIENT2",
        "productId": "sao",
        "description": "restore endpoint info",
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-restore-endpoint-connection", args
    )
    assert result.outputs["task_status"] == "success"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "action_id"


def test_restore_endpoint_missing_optional_data(mocker):
    """Test restore endpoint with missing optional data."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        isolate_restore_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "CLIENT2",
        "productId": "sao",
        "description": None,
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-restore-endpoint-connection", args
    )
    assert result.outputs["task_status"] == "success"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "action_id"


def test_restore_endpoint_wrong_field():
    """Test restore endpoint with wrong field."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostnimg",
        "value": "CLIENT2",
        "productId": "sao",
        "description": "restore endpoint info",
    }
    with pytest.raises(SystemExit):
        isolate_or_restore_connection(
            client, "trendmicro-visionone-restore-endpoint-connection", args
        )


# Test cases for terminate process endpoint
def test_terminate_endpoint_wrong_api_key():
    """Test terminate process with wrong API."""
    api_key = "adswe"
    args = {
        "computerId": "cb9c8412-1f64-4fa0-a36b-76bf41a07ede",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "productId": "sao",
        "description": "terminate info",
        "filename": ["testfile"],
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        terminate_process(client, args)


def test_terminate_process_endpoint(mocker):
    """Test terminate process positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        isolate_restore_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "macaddr",
        "value": "00:50:56:81:87:A8",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "productId": "sao",
        "description": "terminate info",
        "filename": "testfile",
    }
    result = terminate_process(client, args)
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Terminate_Process"
    assert result.outputs_key_field == "action_id"


def test_terminate_process_endpoint_optional_data(mocker):
    """Test terminate process with optional data missing."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        isolate_restore_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "macaddr",
        "value": "00:50:56:81:87:A8",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "productId": "sao",
        "description": None,
        "filename": None,
    }
    result = terminate_process(client, args)
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Terminate_Process"
    assert result.outputs_key_field == "action_id"


def test_terminate_process_endpoint_wrong_productid():
    """Test terminate process with wrong product id."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "macaddr",
        "value": "00:50:56:81:87:A8",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "productId": "ssd",
        "description": None,
        "filename": None,
    }
    with pytest.raises(SystemExit):
        terminate_process(client, args)


def test_invalid_field_value():
    """Test terminate process with wrong field."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "macaddr",
        "value": "test",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "productId": "sao",
        "description": None,
        "filename": None,
    }
    with pytest.raises(SystemExit):
        terminate_process(client, args)


# Mock function for add and delete exception list
def add_delete_exception_mock_response(*args, **kwargs):
    return_value = 20
    return return_value


# Test cases for add exception list endpoint.
def test_add_exception_wrong_api_key():
    """Test add exception list with wrong API key."""
    api_key = "adswe"
    args = {"type": "domain", "value": "1.alisiosanguera.com.cn"}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        add_or_delete_from_exception_list(
            client, "trendmicro-visionone-add-objects-to-exception-list", args
        )


def test_add_object_to_exception_list(mocker):
    """Test add to exception list with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_exception_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.exception_list_count",
        add_delete_exception_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "type": "domain",
        "value": "1.alisiosanguera.com",
        "description": "new key"
    }
    result = add_or_delete_from_exception_list(
        client,
        "trendmicro-visionone-add-objects-to-exception-list",
        args
    )
    assert result.outputs["status_code"] is None
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_key_field == "message"


def test_add_object_to_exception_list_missing_data(mocker):
    """Test add to exception with missing data."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_exception_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.exception_list_count",
        add_delete_exception_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "type": "domain",
        "value": "1.some_value.com.cn",
        "description": None
    }
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-add-objects-to-exception-list", args
    )
    assert result.outputs["status_code"] is None
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_key_field == "message"


# Test cases for delete exception list.
def test_delete_exception_list_wrong_api_key():
    """Test delete exception list with wrong API key."""
    api_key = "adswe"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        add_or_delete_from_exception_list(
            client,
            "trendmicro-visionone-delete-objects-from-exception-list",
            args
        )


def test_delete_object_to_exception_list(mocker):
    """Test delete exception list positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_exception_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.exception_list_count",
        add_delete_exception_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "type": "domain",
        "value": "1.alisiosanguera.com.cn",
        "description": "testing exception",
    }
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-delete-objects-from-exception-list", args
    )
    assert result.outputs["status_code"] is None
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "message"


def test_delete_object_to_exception_list_missing_optional_data(mocker):
    """Test delete object from exception list with missing optional data"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_exception_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.exception_list_count",
        add_delete_exception_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {"type": "domain", "value": "1.alisiosanguera.com.cn"}
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-delete-objects-from-exception-list", args
    )
    assert result.outputs["status_code"] is None
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "message"


def test_delete_object_wrong_type():
    """Test delete exception list with wrong type."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {"type": "domain123", "value": "1.alisiosanguera.com.cn"}
    with pytest.raises(SystemExit):
        add_or_delete_from_exception_list(
            client,
            "trendmicro-visionone-delete-objects-from-exception-list",
            args
        )


# Mock response for add and delete suspicious list
def add_delete_suspicious_mock_response(*args, **kwargs):
    return_value = 20
    return return_value


# Test cases for add suspicious object list
def test_add_suspicious_wrong_api_key():
    """Test add suspicious object with wrong API key."""
    api_key = "adswe"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        add_to_suspicious_list(client, args)


def test_add_object_to_suspicious_list(mocker):
    """Test add to suspicious list with poistive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_suspicious_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.suspicious_list_count",
        add_delete_suspicious_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "type": "domain",
        "value": "1.alisiosanguera.com.cn",
        "description": "Example Suspicious Object.",
        "scanAction": "log",
        "riskLevel": "high",
        "expiredDay": 15,
    }
    result = add_to_suspicious_list(client, args)
    assert result.outputs["status_code"] is None
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "message"


def test_add_object_to_suspicious_list_no_description(mocker):
    """Test add to suspicious list with no description."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_suspicious_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.suspicious_list_count",
        add_delete_suspicious_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "type": "domain",
        "value": "1.alisiosanguera.com.cn",
        "description": None,
        "scanAction": "log",
        "riskLevel": "high",
        "expiredDay": "1.0",
    }
    result = add_to_suspicious_list(client, args)
    assert result.outputs["status_code"] is None
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "message"


def test_add_object_to_suspicious_list_invalid_scanaction(mocker):
    """Test add to suspicious list with invalid scan action data."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "type": "domain",
        "value": "1.alisiosanguera.com.cn",
        "description": None,
        "scanAction": "Log",
        "riskLevel": "high",
        "expiredDay": 15,
    }
    with pytest.raises(SystemExit):
        add_to_suspicious_list(client, args)


# Test cases for delete suspicious object list
def test_delete_suspicious_wrong_api_key():
    """Test delete suspicious list with wrong API."""
    api_key = "adswe"
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        delete_from_suspicious_list(client, args)


def test_delete_object_from_suspicious_list(mocker):
    """Test delete object from suspicious list."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        add_delete_suspicious_mock_response)
    mocker.patch(
        "TrendMicroVisionOne.Client.suspicious_list_count",
        add_delete_suspicious_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {"type": "domain", "value": "1.alisiosanguera.com.cn"}
    result = delete_from_suspicious_list(client, args)
    assert result.outputs["status_code"] is None
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "message"


# Mock response for Get file analysis status
def mock_file_status_response(*args, **kwargs):
    return_response = {
        "code": "Success",
        "message": "Success",
        "data": {
            "taskId": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
            "taskStatus": "finished",
            "digest": {
                "md5": "4ac174730d4143a119037d9fda81c7a9",
                "sha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
                "sha256": (
                    "65b0f656e79ab84ca17807158e3ea"
                    "c206bd58be6689ddeb95956a48748d138f9"
                ),
            },
            "analysisSummary": {
                "analysisCompletionTime": "2021-05-07T03:08:40Z",
                "riskLevel": "high",
                "description": "",
                "detectionNameList": [],
                "threatTypeList": [],
                "trueFileType": "exe",
            },
            "reportId": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
        },
    }
    return return_response


# Test Cases for Get file analysis status
def test_wrong_api_key():
    """Test collect file with wrong API."""
    api_key = "adswe"
    args = {"taskID": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        get_file_analysis_status(client, args)


def test_get_file_status(mocker):
    """Test to get status of file"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_file_status_response)
    args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    result = get_file_analysis_status(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert result.outputs["task_id"] == "012e4eac-9bd9-4e89-95db-77e02f75a6f3"
    assert result.outputs["task_status"] == "finished"
    assert result.outputs["report_id"] == (
        "012e4eac-9bd9-4e89-95db-77e02f75a6f3")
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "message"


def test_get_report_id(mocker):
    """Test to get status of file with report id"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_file_status_response)
    args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    result = get_file_analysis_status(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert result.outputs["report_id"] == (
        "012e4eac-9bd9-4e89-95db-77e02f75a6f3")
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "message"


def test_empty_task_id():
    """Test empty task id"""
    args = {"taskId": ""}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        get_file_analysis_status(client, args)


# Mock response for Get file analysis report
def mock_file_report_response(*args, **kwargs):
    return_response = {
        "code": "Success",
        "message": "Success",
        "data": [
            {
                "type": "ip",
                "value": "6.6.6.6",
                "riskLevel": "high",
                "analysisCompletionTime": "2021-05-07T03:08:40Z",
                "expiredTime": "2021-06-07T03:08:40Z",
                "rootFileSha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
            }
        ],
    }
    return return_response


# Test cases for get file analysis report
def test_get_file_report_wrong_api_key():
    """Test get file analysis report with wrong API key."""
    api_key = "adswe"
    args = {
        "reportId": "800f908d-9578-4333-91e5-822794ed5483",
        "type": "suspiciousObject",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        get_file_analysis_report(client, args)


def test_get_file_analysis_report(mocker):
    """Test get file analysis report data."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_file_report_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "reportId": "800f908d-9578-4333-91e5-822794ed5483",
        "type": "suspiciousObject",
    }
    result = get_file_analysis_report(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert isinstance(result.outputs["data"][0]["type"], str)
    assert isinstance(result.outputs["data"][0]["value"], str)
    assert isinstance(result.outputs["data"][0]["risk_level"], str)
    assert isinstance(result.outputs["data"][0]["analysis_completion_time"], str)
    assert isinstance(result.outputs["data"][0]["expired_time"], str)
    assert isinstance(result.outputs["data"][0]["root_file_sha1"], str)


def test_get_file_analysis_report_1(mocker):
    """Test get file analysis report data."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_file_report_response)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "reportId": "800f908d-9578-4333-91e5-822794ed5483",
        "type": "suspiciousObject",
    }
    result = get_file_analysis_report(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert len(result.outputs["data"]) > 0


# Mock function for isolate and restore endpoint
def mock_collect_file(*args, **kwargs):
    return_value = {
        "status": "string",
        "actionId": "88139521",
        "taskStatus": "pending",
        "result": {
            "computerId": "string",
        },
        "data": {
            "createdTime": 1589525651,
            "executedTime": 1589525725,
            "finishedTime": 1589525725,
            "taskStatus": "success",
            "error": {},
        },
    }
    return return_value


# Test cases for collect forensic file.
def test_collect_file_wrong_api_key():
    """Test collect file with wrong API."""
    api_key = "adswe"
    args = {
        "description": "collect file",
        "productId": "sao",
        "computerId": "bcee207f-21d6-4794-8e62-78d72ee82ed3",
        "filePath": "/file_path/sample.log",
        "os": "linux",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        collect_file(client, args)


def test_collect_forensic_file(mocker):
    """Test collect file with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_collect_file)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "sacumen-Vostro-3500",
        "description": "collect file",
        "productId": "sao",
        "filePath": (
            "/file_path/sample.txt"
        ),
        "os": "linux",
    }
    result = collect_file(client, args)
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Collect_Forensic_File"
    assert result.outputs_key_field == "action_id"


def test_missing_optional_field(mocker):
    """Test collect file with missing optional field."""
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_collect_file)
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "sacumen-Vostro-3500",
        "description": "",
        "productId": "sao",
        "filePath": (
            "/file_path/sample.txt"
        ),
        "os": "linux",
    }
    result = collect_file(client, args)
    assert result.outputs["task_status"] == "success"
    assert isinstance(result.outputs["action_id"], str)
    assert result.outputs_prefix == "VisionOne.Collect_Forensic_File"
    assert result.outputs_key_field == "action_id"


def test_wrong_os_type():
    """Test wrong os type passed to data."""
    client = Client("https://api.xdr.trendmicro.com", api_key)
    args = {
        "field": "hostname",
        "value": "sacumen-Vostro-3500",
        "description": "",
        "productId": "sao",
        "filePath": (
            "/file_path/sample.txt"
        ),
        "os": "linuxs",
    }
    with pytest.raises(SystemExit):
        collect_file(client, args)


# Mock for downloaded file information
def mock_download_collected_file_info_response(*args, **kwargs):
    return_response = {
        "data": {
            "url": "string",
            "expires": "2011-10-05T14:48:00.000Z",
            "password": "string",
            "filename": "string",
        }
    }
    return return_response


# Test Cases for Collected downloaded file information.
def test_downloded_file_infowrong_api_key():
    """Test endpoint with with wrong API key.."""
    api_key = "wrong key"
    args = {"actionId": "00000700"}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        download_information_collected_file(client, args)


def test_get_fornesic_file_information(mocker):
    """Test endpoint to get collected file infomation based on action id"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_download_collected_file_info_response
    )
    args = {"actionId": "00000700"}
    client = Client("https://api.xdr.trendmicro.com", api_key)
    result = download_information_collected_file(client, args)
    assert isinstance(result.outputs["url"], str)
    assert isinstance(result.outputs["expires"], str)
    assert isinstance(result.outputs["password"], str)
    assert isinstance(result.outputs["filename"], str)


# Mock response for submit file to sandbox.
def mock_submit_file_to_sandbox_reponse(*args, **kwargs):
    return_response = {
        "code": "Success",
        "message": "Success",
        "data": {
            "taskId": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
            "digest": {
                "md5": "4ac174730d4143a119037d9fda81c7a9",
                "sha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
                "sha256": (
                    "65b0f656e79ab84ca17807158e3ea"
                    "c206bd58be6689ddeb95956a48748d138f9"
                )
            },
        },
    }
    return return_response


# Test cases for submit file to sandbox.
def test_submit_file_wrong_api_key():
    """Test endpoint with with wrong API key.."""
    api_key = "wrong key"
    args = {
        "fileUrl": (
            "https://upload.xdr.trendmicro.com/arp/"
        ),
        "fileName": (
            "XDR_ResponseApp_CollectFile_ID00000700_20211206T134158Z.7z"
        ),
        "archivePassword": "6hn467c8",
        "documentPassword": "",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key)
    with pytest.raises(SystemExit):
        submit_file_to_sandbox(client, args)
