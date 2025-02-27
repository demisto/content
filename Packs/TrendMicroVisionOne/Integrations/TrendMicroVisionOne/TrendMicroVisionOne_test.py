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
    submit_file_entry_to_sandbox,
    get_sandbox_submission_status,
    get_task_status,
    get_endpoint_info,
    add_note,
    update_status,
)
import demistomock as demisto

# Provide valid API KEY
api_key = "test api key"
proxy = "false"
verify = "true"


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
            "error": {},
        },
    }
    return return_value


# Test cases for add to block list
def test_add_blocklist(mocker):
    """Test add to block list with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", add_remove_blocklist_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-add-to-block-list", args
    )
    assert result.outputs["taskStatus"] == "pending"
    assert isinstance(result.outputs["actionId"], str)
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "actionId"


# Test cases for remove from block list
def test_remove_block_list(mocker):
    """Test remove block list positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", add_remove_blocklist_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "valueType": "file_sha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "productId": "sao",
        "description": "block info",
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-remove-from-block-list", args
    )
    assert result.outputs["taskStatus"] == "pending"
    assert isinstance(result.outputs["actionId"], str)
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "actionId"


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
def test_quarantine_email_message(mocker):
    """Test quarantine email message positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", quarantine_delete_email_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "messageId": (
            "<CANUJTKTjto9GAHTr9V=TFqMZhRXqVn=" + "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:00:12.000Z",
        "productId": "sca",
        "description": "quarantine info",
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-quarantine-email-message", args
    )
    assert result.outputs["taskStatus"] == "pending"
    assert isinstance(result.outputs["actionId"], str)
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "actionId"


# Test cases for delete email message
def test_delete_email_message(mocker):
    """Test delete email message with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", quarantine_delete_email_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "messageId": (
            "<CANUJTKTqmuCT12v7mpbxZih_crrP" + "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
        ),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "messageDeliveryTime": "2021-12-09T14:00:55.000Z",
        "productId": "sca",
        "description": "quarantine info",
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-delete-email-message", args
    )
    assert result.outputs["taskStatus"] == "pending"
    assert isinstance(result.outputs["actionId"], str)
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "actionId"


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
def test_isolate_endpoint(mocker):
    """Test isolate endpoint postive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", isolate_restore_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "hostname",
        "productId": "sao",
        "description": "isolate endpoint info",
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-isolate-endpoint", args
    )
    assert result.outputs["taskStatus"] == "pending"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "actionId"


# Test cases for restore endpoint
def test_restore_endpoint(mocker):
    """Test restore endpoint positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", isolate_restore_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "hostname",
        "productId": "sao",
        "description": "restore endpoint info",
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-restore-endpoint-connection", args
    )
    assert result.outputs["taskStatus"] == "pending"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "actionId"


# Test cases for terminate process endpoint
def test_terminate_process_endpoint(mocker):
    """Test terminate process positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", isolate_restore_mock_response
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "00:50:56:81:87:A8",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "productId": "sao",
        "description": "terminate info",
        "filename": "testfile",
    }
    result = terminate_process(client, args)
    assert result.outputs["taskStatus"] == "pending"
    assert isinstance(result.outputs["actionId"], str)
    assert result.outputs_prefix == "VisionOne.Terminate_Process"
    assert result.outputs_key_field == "actionId"


# Mock function for add and delete exception list
def add_delete_exception_mock_response(*args, **kwargs):
    return_value = 20
    return return_value


# Test cases for add exception list endpoint.
def test_add_object_to_exception_list(mocker):
    """Test add to exception list with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", add_delete_exception_mock_response
    )
    mocker.patch(
        "TrendMicroVisionOne.Client.exception_list_count",
        add_delete_exception_mock_response,
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {"type": "domain", "value": "1.alisiosanguera.com", "description": "new key"}
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-add-objects-to-exception-list", args
    )
    assert result.outputs["status_code"] is None
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_key_field == "message"


# Test cases for delete exception list.
def test_delete_object_to_exception_list(mocker):
    """Test delete exception list positive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", add_delete_exception_mock_response
    )
    mocker.patch(
        "TrendMicroVisionOne.Client.exception_list_count",
        add_delete_exception_mock_response,
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
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


# Mock response for add and delete suspicious list
def add_delete_suspicious_mock_response(*args, **kwargs):
    return_value = 20
    return return_value


# Test cases for add suspicious object list
def test_add_object_to_suspicious_list(mocker):
    """Test add to suspicious list with poistive scenario."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", add_delete_suspicious_mock_response
    )
    mocker.patch(
        "TrendMicroVisionOne.Client.suspicious_list_count",
        add_delete_suspicious_mock_response,
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
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


# Test cases for delete suspicious object list
def test_delete_object_from_suspicious_list(mocker):
    """Test delete object from suspicious list."""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", add_delete_suspicious_mock_response
    )
    mocker.patch(
        "TrendMicroVisionOne.Client.suspicious_list_count",
        add_delete_suspicious_mock_response,
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
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
def test_get_file_status(mocker):
    """Test to get status of file"""
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_file_status_response)
    args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    result = get_file_analysis_status(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert result.outputs["task_id"] == "012e4eac-9bd9-4e89-95db-77e02f75a6f3"
    assert result.outputs["taskStatus"] == "finished"
    assert result.outputs["report_id"] == ("012e4eac-9bd9-4e89-95db-77e02f75a6f3")
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "message"


def test_get_report_id(mocker):
    """Test to get status of file with report id"""
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_file_status_response)
    args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    result = get_file_analysis_status(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert result.outputs["report_id"] == ("012e4eac-9bd9-4e89-95db-77e02f75a6f3")
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "message"


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
def test_get_file_analysis_report(mocker):
    """Test get file analysis report data."""
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_file_report_response)
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
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
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_file_report_response)
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
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
def test_collect_forensic_file(mocker):
    """Test collect file with positive scenario."""
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_collect_file)
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "hostname",
        "description": "collect file",
        "productId": "sao",
        "filePath": ("/file_path/sample.txt"),
        "os": "linux",
    }
    result = collect_file(client, args)
    assert result.outputs["taskStatus"] == "pending"
    assert isinstance(result.outputs["actionId"], str)
    assert result.outputs_prefix == "VisionOne.Collect_Forensic_File"
    assert result.outputs_key_field == "actionId"


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
def test_get_forensic_file_information(mocker):
    """Test endpoint to get collected file infomation based on action id"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request",
        mock_download_collected_file_info_response,
    )
    args = {"actionId": "00000700"}
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
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
                ),
            },
        },
    }
    return return_response


# Mock response for submit file to sandbox.
def mocked_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code, content):
            self.json_data = json_data
            self.status_code = status_code
            self.content = content

        def json(self):
            return self.json_data

    if args[0] == "http://someurl.com/test.json":
        return MockResponse({"key1": "value1"}, 200, "response")
    elif args[0] == "http://someotherurl.com/anothertest.json":
        return MockResponse({"key2": "value2"}, 200, "response")

    return MockResponse(None, 404, None)


# Mock response for submit file to sandbox.
def mocked_requests_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code, content):
            self.json_data = json_data
            self.status_code = status_code
            self.content = content

        def json(self):
            return {
                "code": "Success",
                "message": "Success",
                "data": {
                    "taskId": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
                    "digest": {
                        "md5": "4ac174730d4143a119037d9fda81c7a9",
                        "sha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
                        "sha256": (
                            "65b0f656e79ab84ca17807158e3ea",
                            "c206bd58be6689ddeb95956a48748d138f9",
                        ),
                    },
                },
            }

        def raise_for_status(self):
            return True

    if args[0] == "http://someurl.com/test.json":
        return MockResponse({"key1": "value1"}, 200, "response")
    elif args[0] == "http://someotherurl.com/anothertest.json":
        return MockResponse({"key2": "value2"}, 200, "response")

    return MockResponse(None, 404, None)


def test_submit_file_to_sandbox(mocker):
    mocker.patch("TrendMicroVisionOne.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOne.requests.post", mocked_requests_post)
    args = {
        "fileUrl": "http://adsd.com",
        "fileName": "XDR_ResponseApp_CollectFile_ID00000700_20211206T134158Z.7z",
        "archivePassword": "6hn467c8",
        "documentPassword": "",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    result = submit_file_to_sandbox(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"


# Test Cases for Submit file entry to sandbox.
def test_submit_file_entry_to_sandbox(mocker):
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"id": id, "path": "README.md", "name": "test.txt"},
    )
    mocker.patch("TrendMicroVisionOne.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOne.requests.post", mocked_requests_post)
    args = {
        "entry_id": "123@1221",
        "archivePassword": "6hn467c8",
        "documentPassword": "",
    }
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    result = submit_file_entry_to_sandbox(client, args)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"


# Test Cases for Sandbox submission polling
def test_sandbox_submission_polling(mocker):
    """Test to get status of sandbox submission"""
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={'version': '6.2.0', 'buildNumber': '12345'},
    )
    mocker.patch("TrendMicroVisionOne.Client.http_request", mock_file_status_response)
    args = {"task_id": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    result = get_sandbox_submission_status(args, client)
    assert result.outputs["message"] == "Success"
    assert result.outputs["code"] == "Success"
    assert result.outputs["task_id"] == "012e4eac-9bd9-4e89-95db-77e02f75a6f3"
    assert result.outputs["taskStatus"] == "finished"
    assert result.outputs["report_id"] == ("012e4eac-9bd9-4e89-95db-77e02f75a6f3")
    assert result.outputs_prefix == "VisionOne.Sandbox_Submission_Polling"
    assert result.outputs_key_field == "report_id"


# Mock function for check task status
def check_task_status_mock_response(*args, **kwargs):
    return_value = {
        "data": {
            "createdTime": 1589525651,
            "executedTime": 1589525725,
            "finishedTime": 1589525725,
            "taskStatus": "success",
            "error": {},
        }
    }
    return return_value


def test_check_task_status(mocker):
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", check_task_status_mock_response
    )
    mocker.patch(
        "CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None
    )
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {"actionId": "00001108"}
    result = get_task_status(args, client)
    assert result.outputs["taskStatus"] == "success"


# Mock for downloaded file information
def mock_get_endpoint_info_response(*args, **kwargs):
    return_response = {
        "status": "SUCCESS",
        "errorCode": 0,
        "message": "message",
        "result": {
            "logonAccount": {"value": ["DOMAIN\\username"], "updateAt": 0},
            "hostname": {"value": "hostname", "updateAt": 0},
            "macAddr": {"value": "00:11:22:33:44:55", "updateAt": 0},
            "ip": {"value": "192.168.1.1", "updateAt": 0},
            "osName": "Windows",
            "osVersion": "10.0.19042",
            "osDescription": "Windows 10 Pro (64 bit) build 19042",
            "productCode": "xes",
        },
    }
    return return_response


# Test case for get endpoint information.
def test_get_endpoint_information(mocker):
    """Test get information from endpoint based on computerid"""
    mocker.patch(
        "TrendMicroVisionOne.Client.http_request", mock_get_endpoint_info_response
    )
    args = {"endpoint": "hostname"}
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    result = get_endpoint_info(client, args)
    assert result.outputs["status"] == "SUCCESS"
    assert isinstance(result.outputs["message"], str)
    assert isinstance(result.outputs["hostname"], str)
    assert isinstance(result.outputs["ip"], str)
    assert isinstance(result.outputs["macAddr"], str)
    assert isinstance(result.outputs["osDescription"], str)
    assert isinstance(result.outputs["osName"], str)
    assert isinstance(result.outputs["osVersion"], str)
    assert isinstance(result.outputs["productCode"], str)


# Mock function for add note.
def add_note_mock_response(*args, **kwargs):
    return_value = {
        "data": {"id": 123},
        "info": {"code": 3021000, "msg": "Alert notes added successfully."},
    }
    return return_value


# Test case for add note
def test_add_note(mocker):
    mocker.patch("TrendMicroVisionOne.Client.http_request", add_note_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {"workbench_id": "WB-20837-20220418-00000", "content": "This is a new note."}
    result = add_note(client, args)
    assert result.outputs["response_msg"] == "Alert notes added successfully."
    assert isinstance(result.outputs["Workbench_Id"], str)
    assert isinstance(result.outputs["noteId"], int)
    assert isinstance(result.outputs["response_code"], int)


# Mock function for update alert status
def update_status_mock_response(*args, **kwargs):
    return_value = {
        "data": {},
        "info": {"code": 3006000, "msg": "Alert status changed successfully."},
    }
    return return_value


# Test case for update alert status
def test_update_status(mocker):
    mocker.patch("TrendMicroVisionOne.Client.http_request", update_status_mock_response)
    client = Client("https://api.xdr.trendmicro.com", api_key, proxy, verify)
    args = {"workbench_id": "WB-20837-20220418-00000", "status": "in_progress"}
    result = update_status(client, args)
    assert result.outputs["response_msg"] == "Alert status changed successfully."
    assert isinstance(result.outputs["Workbench_Id"], str)
    assert isinstance(result.outputs["response_code"], int)
