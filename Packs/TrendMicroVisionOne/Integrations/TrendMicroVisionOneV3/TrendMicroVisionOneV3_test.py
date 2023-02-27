from TrendMicroVisionOneV3 import (
    Client,
    add_note,
    collect_file,
    update_status,
    force_sign_out,
    get_task_status,
    get_endpoint_info,
    terminate_process,
    force_password_reset,
    add_to_suspicious_list,
    submit_file_to_sandbox,
    get_file_analysis_status,
    get_file_analysis_result,
    download_analysis_report,
    delete_from_suspicious_list,
    submit_file_entry_to_sandbox,
    get_sandbox_submission_status,
    add_or_remove_from_block_list,
    isolate_or_restore_connection,
    download_investigation_package,
    enable_or_disable_user_account,
    download_suspicious_object_list,
    add_or_delete_from_exception_list,
    quarantine_or_delete_email_message,
    download_information_collected_file,
)
import demistomock as demisto

# Provide valid API KEY
api_key = "test api key"
proxy = "false"
verify = "true"


# Mock response for enabling or disabling user account
def enable_disable_user_account_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


def test_enable_user_account(mocker):
    """Test enable user account success response."""
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        enable_disable_user_account_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "accountName": "ghost@trendmicro.com",
        "description": "Enabling user account.",
    }
    result = enable_or_disable_user_account(
        client, "trendmicro-visionone-enable-user-account", args
    )
    assert result.outputs["status_code"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.User_Account"
    assert result.outputs_key_field == "taskId"


def test_disable_user_account(mocker):
    """Test disable user account success response."""
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        enable_disable_user_account_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "accountName": "ghost@trendmicro.com",
        "description": "Disabling user account.",
    }
    result = enable_or_disable_user_account(
        client, "trendmicro-visionone-disable-user-account", args
    )
    assert result.outputs["status_code"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.User_Account"
    assert result.outputs_key_field == "taskId"


# Mock response for force sign out
def force_signout_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


def test_force_signout(mocker):
    """Test to force sign out user account with successful result."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", force_signout_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "accountName": "ghost@trendmicro.com",
        "description": "Signing out user account.",
    }
    result = force_sign_out(client, args)
    assert result.outputs["status_code"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Force_Sign_Out"
    assert result.outputs_key_field == "taskId"


# Mock response for force password reset
def force_password_reset_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


def test_force_password_reset(mocker):
    """Test to force sign out user account with successful result."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", force_password_reset_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "accountName": "ghost@trendmicro.com",
        "description": "Forcing a password reset for user account.",
    }
    result = force_password_reset(client, args)
    assert result.outputs["status_code"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Force_Password_Reset"
    assert result.outputs_key_field == "taskId"


# Mock function for add to block list and remove from block list
def add_remove_blocklist_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location.",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


# Test cases for add to block list
def test_add_blocklist(mocker):
    """Test add to block list with positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", add_remove_blocklist_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "valueType": "fileSha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "description": "block info",
    }
    result = add_or_remove_from_block_list(client, "trendmicro-visionone-add-to-block-list", args)
    assert result.outputs["status"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "taskId"


# Test cases for remove from block list
def test_remove_block_list(mocker):
    """Test remove block list positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", add_remove_blocklist_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "valueType": "fileSha1",
        "targetValue": "2de5c1125d5f991842727ed8ea8b5fda0ffa249b",
        "description": "block info",
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-remove-from-block-list", args
    )
    assert result.outputs["status"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "taskId"


# Mock function for quarantine and delete email message
def quarantine_delete_email_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


# Test cases for quarantine email message
def test_quarantine_email_message(mocker):
    """Test quarantine email message positive scenario."""
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        quarantine_delete_email_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "messageId": ("<CANUJTKTjto9GAHTr9V=TFqMZhRXqVn=" "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "description": "quarantine info",
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-quarantine-email-message", args
    )
    assert result.outputs["status"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "taskId"


# Test cases for delete email message
def test_delete_email_message(mocker):
    """Test delete email message with positive scenario."""
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        quarantine_delete_email_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "messageId": ("<CANUJTKTqmuCT12v7mpbxZih_crrP" "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"),
        "mailBox": "kjshdfjksahd@trendenablement.com",
        "description": "quarantine info",
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-delete-email-message", args
    )
    assert result.outputs["status"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "taskId"


# Mock function for isolate and restore endpoint
def isolate_restore_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
            "body": {
                "error": {"code": "TaskError", "message": "Task duplication."},
            },
        }
    ]
    return return_value


# Test cases for isolate endpoint
def test_isolate_endpoint(mocker):
    """Test isolate endpoint positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", isolate_restore_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "client1",
        "description": "isolate endpoint info",
    }
    result = isolate_or_restore_connection(client, "trendmicro-visionone-isolate-endpoint", args)
    assert result.outputs["taskStatus"] == 202
    assert isinstance(result.outputs["taskId"], str)
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "taskId"


# Test cases for restore endpoint
def test_restore_endpoint(mocker):
    """Test restore endpoint positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", isolate_restore_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "client1",
        "description": "restore endpoint info",
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-restore-endpoint-connection", args
    )
    assert result.outputs["taskStatus"] == 202
    assert isinstance(result.outputs["taskId"], str)
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "taskId"


# Mock function for terminate process
def terminate_process_mock_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


# Test cases for terminate process endpoint
def test_terminate_process_endpoint(mocker):
    """Test terminate process positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", terminate_process_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "035f6286-2414-4cb4-8d05-e67d2d32c944",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "description": "terminate info",
        "fileName": "testfile.txt",
    }
    result = terminate_process(client, args)
    assert result.outputs["taskStatus"] == 202
    assert result.outputs["taskId"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Terminate_Process"
    assert result.outputs_key_field == "taskId"


# Mock function for add and delete exception list
def add_delete_exception_mock_response(*args, **kwargs):
    return_value = [{"status": 201}]
    return return_value


# Test cases for add exception list endpoint.
def test_add_object_to_exception_list(mocker):
    """Test add to exception list with positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", add_delete_exception_mock_response)
    mocker.patch(
        "TrendMicroVisionOneV3.Client.exception_list_count",
        add_delete_exception_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"type": "domain", "value": "1.alisiosanguera.com", "description": "new key"}
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-add-objects-to-exception-list", args
    )
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["status_code"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "message"


# Test cases for delete exception list.
def test_delete_object_to_exception_list(mocker):
    """Test delete exception list positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", add_delete_exception_mock_response)
    mocker.patch(
        "TrendMicroVisionOneV3.Client.exception_list_count",
        add_delete_exception_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"type": "domain", "value": "1.alisiosanguera.com.cn"}
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-delete-objects-from-exception-list", args
    )
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["status_code"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "message"


# Mock response for add and delete suspicious list
def add_delete_suspicious_mock_response(*args, **kwargs):
    return_value = [{"total_items": 20, "status": 201}]
    return return_value


# Test cases for add suspicious object list
def test_add_object_to_suspicious_list(mocker):
    """Test add to suspicious list with poistive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", add_delete_suspicious_mock_response)
    mocker.patch(
        "TrendMicroVisionOneV3.Client.suspicious_list_count",
        add_delete_suspicious_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "type": "domain",
        "value": "1.alisiosanguera.com.cn",
        "description": "Example Suspicious Object.",
        "scanAction": "log",
        "riskLevel": "high",
        "daysToExpiration": 15,
    }
    result = add_to_suspicious_list(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["status_code"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "message"


# Test cases for delete suspicious object list
def test_delete_object_from_suspicious_list(mocker):
    """Test delete object from suspicious list."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", add_delete_suspicious_mock_response)
    mocker.patch(
        "TrendMicroVisionOneV3.Client.suspicious_list_count",
        add_delete_suspicious_mock_response,
    )
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"type": "domain", "value": "1.alisiosanguera.com.cn"}
    result = delete_from_suspicious_list(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["status_code"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "message"


# Mock response for Get file analysis status
def mock_file_status_response(*args, **kwargs):
    return_response = {
        "status_code": 200,
        "id": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
        "action": "analyzeFile",
        "status": "succeeded",
        "error": {},
        "createdDateTime": "2021-05-07T03:07:40Z",
        "lastActionDateTime": "2021-05-07T03:08:40Z",
        "resourceLocation": """"https://apimock-dev.trendmicro.com/v3.0/sandbox/analysisResults/
                                012e4eac-9bd9-4e89-95db-77e02f75a6f3""",
        "isCached": True,
        "digest": {},
        "arguments": "LS10ZXN0IA==",
    }
    return return_response


# Test Cases for Get file analysis status
def test_get_file_status(mocker):
    """Test to get status of file"""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_file_status_response)
    args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = get_file_analysis_status(client, args)
    assert result.outputs["isCached"] is not None
    assert result.outputs["status"] == "succeeded"
    assert isinstance(result.outputs["action"], str)
    assert result.outputs["arguments"] == "LS10ZXN0IA=="
    assert result.outputs["id"] == "012e4eac-9bd9-4e89-95db-77e02f75a6f3"
    assert isinstance(result.outputs["digest"], dict)
    assert isinstance(result.outputs["error"], dict)
    assert isinstance(result.outputs.get("resourceLocation"), str)
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "message"


def test_get_report_id(mocker):
    """Test to get status of file with report id"""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_file_status_response)
    args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = get_file_analysis_status(client, args)
    assert result.outputs["status"] == "succeeded"
    assert result.outputs["action"] == "analyzeFile"
    assert result.outputs["id"] == "012e4eac-9bd9-4e89-95db-77e02f75a6f3"
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "message"


# Mock response for Get file analysis report
def mock_file_result_response(*args, **kwargs):
    return_response = {
        "id": "8559a7ce-2b85-451b-8742-4b943ad76a22",
        "type": "file",
        "digest": {},
        "arguments": "LS10ZXN0IA==",
        "analysisCompletionDateTime": "2021-05-07T03:08:40Z",
        "riskLevel": "high",
        "detectionNames": [],
        "threatTypes": [],
        "trueFileType": "exe",
    }
    return return_response


# Test cases for get file analysis report
def test_get_file_analysis_result(mocker):
    """Test get file analysis report data."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_file_result_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"reportId": "800f908d-9578-4333-91e5-822794ed5483"}
    result = get_file_analysis_result(client, args)
    assert result.outputs["report_id"] == "8559a7ce-2b85-451b-8742-4b943ad76a22"
    assert isinstance(result.outputs["type"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert isinstance(result.outputs["arguments"], str)
    assert isinstance(result.outputs["analysisCompletionDateTime"], str)
    assert isinstance(result.outputs["riskLevel"], str)
    assert isinstance(result.outputs["detectionNames"], list)
    assert isinstance(result.outputs["threatTypes"], list)
    assert isinstance(result.outputs["trueFileType"], str)


def test_get_file_analysis_result_1(mocker):
    """Test get file analysis report data."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_file_result_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"reportId": "800f908d-9578-4333-91e5-822794ed5483"}
    result = get_file_analysis_result(client, args)
    assert len(result.outputs) > 0


# Mock response for collect file
def mock_collect_file_response(*args, **kwargs):
    return_value = [
        {
            "status": 202,
            "headers": [
                {
                    "name": "Operation-Location",
                    "value": "https://apimock-dev.trendmicro.com/v3.0/xdr/response/tasks/00000001",
                }
            ],
        }
    ]
    return return_value


# Test cases for collect forensic file.
def test_collect_forensic_file(mocker):
    """Test collect file with positive scenario."""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_collect_file_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {
        "endpoint": "client1",
        "description": "collect file",
        "filePath": ("/file_path/sample.txt"),
    }
    result = collect_file(client, args)
    assert result.outputs["taskStatus"] == 202
    assert isinstance(result.outputs["taskId"], str)
    assert result.outputs_prefix == "VisionOne.Collect_Forensic_File"
    assert result.outputs_key_field == "taskId"


# Mock for downloaded file information
def mock_download_collected_file_info_response(*args, **kwargs):
    return_response = {
        "id": "00000012",
        "status": "running",
        "createdDateTime": "2021-04-05T08:22:37Z",
        "lastActionDateTime": "2021-04-06T08:22:37Z",
        "description": "task description",
        "action": "isolate",
        "account": "test",
        "agentGuid": "cb9c8412-1f64-4fa0-a36b-76bf41a07ede",
        "endpointName": "trend-host-1",
        "filePath": "string",
        "fileSha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
        "fileSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "fileSize": 102400,
        "resourceLocation": "htttps://api.xdr.trendmicro.com/...",
        "expiredDateTime": "string",
        "password": "xns9ns",
    }
    return return_response


# Test Cases for Collected downloaded file information.
def test_get_forensic_file_information(mocker):
    """Test endpoint to get collected file information based on task id"""
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        mock_download_collected_file_info_response,
    )
    args = {"task_id": "00000012"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = download_information_collected_file(client, args)
    assert result.outputs["taskId"] == "00000012"
    assert result.outputs["status"] == "running"
    assert result.outputs["action"] == "isolate"
    assert result.outputs["agentGuid"] == "cb9c8412-1f64-4fa0-a36b-76bf41a07ede"
    assert result.outputs["endpointName"] == "trend-host-1"
    assert result.outputs["fileSha1"] == "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b"
    assert result.outputs["fileSize"] == 102400
    assert isinstance(result.outputs["filePath"], str)
    assert isinstance(result.outputs["resourceLocation"], str)
    assert isinstance(result.outputs["expiredDateTime"], str)
    assert isinstance(result.outputs["password"], str)


# Mock response for Download analysis results
def mock_download_analysis_report_response(*args, **kwargs):
    class Response:
        content = ""
        status_code = 200

    return_value = Response()
    return return_value


# Test Case for Download analysis report
def test_download_analysis_report(mocker):
    """
    Test to download analysis report (PDF) of file submitted
    to sandbox based on submission ID returned by get
    file analysis status.
    """
    mocker.patch(
        "requests.get",
        mock_download_analysis_report_response,
    )
    args = {"submission_id": "8559a7ce-2b85-451b-8742-4b943ad76a22"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = download_analysis_report(client, args)
    assert isinstance(result[1].outputs["code"], int)
    assert result[1].outputs["message"] == "Please select download to start download"
    assert result[1].outputs["submissionId"] == "8559a7ce-2b85-451b-8742-4b943ad76a22"
    assert result[1].outputs_prefix == "VisionOne.Download_Analysis_Report"
    assert result[1].outputs_key_field == "submissionId"


# Mock response for download investigation package
def mock_download_investigation_package_response(*args, **kwargs):
    class Response:
        content = ""
        status_code = 200

    return_value = Response()
    return return_value


# Test case for Download analysis package
def test_download_analysis_package(mocker):
    """
    Test to download investigation package for file
    submitted to sandbox based on submission ID returned
    by get file analysis status.
    """
    mocker.patch(
        "requests.get",
        mock_download_investigation_package_response,
    )
    args = {"submission_id": "8559a7ce-2b85-451b-8742-4b943ad76a22"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = download_investigation_package(client, args)
    assert isinstance(result[1].outputs["code"], int)
    assert result[1].outputs["message"] == "Please select download to start download"
    assert result[1].outputs["submissionId"] == "8559a7ce-2b85-451b-8742-4b943ad76a22"
    assert result[1].outputs_prefix == "VisionOne.Download_Investigation_Package"
    assert result[1].outputs_key_field == "submissionId"


# Mock response for download suspicious object list
def mock_download_suspicious_object_list_response(*args, **kwargs):
    return_value = {
        "code": 200,
        "items": [
            {
                "riskLevel": "high",
                "analysisCompletionDateTime": "2021-05-07T03:08:40Z",
                "expiredDateTime": "2021-06-07T03:08:40Z",
                "rootSha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
                "ip": "6.6.6.6",
            }
        ],
    }
    return return_value


# Test case for download suspicious object list
def test_download_suspicious_object_list(mocker):
    """
    Test to download suspicious object list
    based on submission ID returned by download
    file analysis report. Only items classified as
    High will be populated in the list. If no items
    exist, a 404 not found error will be returned.
    """
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        mock_download_suspicious_object_list_response,
    )
    args = {"submission_id": "8559a7ce-2b85-451b-8742-4b943ad76a22"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = download_suspicious_object_list(client, args)
    assert result.outputs["riskLevel"] == "high"
    assert result.outputs["analysisCompletionDateTime"] == "2021-05-07T03:08:40Z"
    assert result.outputs["expiredDateTime"] == "2021-06-07T03:08:40Z"
    assert result.outputs["rootSha1"] == "fb5608fa03de204a12fe1e9e5275e4a682107471"
    assert result.outputs["ip"] == "6.6.6.6"
    assert result.outputs_prefix == "VisionOne.Download_Suspicious_Object_list"
    assert result.outputs_key_field == "riskLevel"


# Mock response for submit file to sandbox.
def mock_submit_file_to_sandbox_response(*args, **kwargs):
    return_response = {
        "id": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
        "digest": {
            "md5": "4ac174730d4143a119037d9fda81c7a9",
            "sha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
            "sha256": "65b0f656e79ab84ca17807158e3eac206bd58be6689ddeb95956a48748d138f9",
        },
        "arguments": "LS10ZXN0IA==",
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
                "id": "012e4eac-9bd9-4e89-95db-77e02f75a6f3",
                "digest": {
                    "md5": "4ac174730d4143a119037d9fda81c7a9",
                    "sha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
                    "sha256": "65b0f656e79ab84ca17807158e3eac206bd58be6689ddeb95956a48748d138f9",
                },
                "arguments": "LS10ZXN0IA==",
            }

        def raise_for_status(self):
            return True

    if args[0] == "http://someurl.com/test.json":
        return MockResponse({"key1": "value1"}, 200, "response")
    elif args[0] == "http://someotherurl.com/anothertest.json":
        return MockResponse({"key2": "value2"}, 200, "response")

    return MockResponse(None, 404, None)


def test_submit_file_to_sandbox(mocker):
    mocker.patch("TrendMicroVisionOneV3.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOneV3.requests.post", mocked_requests_post)
    args = {
        "file_path": "http://adsd.com",
        "filename": "XDR_ResponseApp_CollectFile.7z",
        "archive_password": "6hn467c8",
        "document_password": "",
    }
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = submit_file_to_sandbox(client, args)
    assert isinstance(result.outputs["task_id"], str)
    assert isinstance(result.outputs["digest"], dict)


def test_submit_file_entry_to_sandbox(mocker):
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"id": id, "path": "README.md", "name": "test.txt"},
    )
    mocker.patch("TrendMicroVisionOneV3.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOneV3.requests.post", mocked_requests_post)
    args = {
        "entry_id": "12@1221",
        "archive_password": "6hn467c8",
        "document_password": "",
    }
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = submit_file_entry_to_sandbox(client, args)
    assert isinstance(result.outputs["task_id"], str)
    assert isinstance(result.outputs["digest"], dict)


# Mock response for Get file analysis report
def mock_sandbox_submission_polling_response(*args, **kwargs):
    return_response = {
        "id": "8559a7ce-2b85-451b-8742-4b943ad76a22",
        "action": "analyzeFile",
        "status": "succeeded",
        "error": {"code": "", "message": ""},
        "createdDateTime": "2021-05-07T03:07:40Z",
        "lastActionDateTime": "2021-05-07T03:08:40Z",
        "resourceLocation": """https://apimock-dev.trendmicro.com/v3.0/sandbox/analysisResults/
                               012e4eac-9bd9-4e89-95db-77e02f75a6f3""",
        "isCached": "true",
        "digest": {
            "md5": "4ac174730d4143a119037d9fda81c7a9",
            "sha1": "fb5608fa03de204a12fe1e9e5275e4a682107471",
            "sha256": "65b0f656e79ab84ca17807158e3eac206bd58be6689ddeb95956a48748d138f9",
        },
        "arguments": "LS10ZXN0IA==",
        "type": "file",
        "analysisCompletionDateTime": "2021-05-07T03:08:40Z",
        "riskLevel": "high",
        "detectionNames": ["VAN_DROPPER.UMXX"],
        "threatTypes": ["Dropper"],
        "trueFileType": "exe",
    }
    return return_response


def test_sandbox_submission_polling(mocker):
    """Test sandbox submission polling."""
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.2.0", "buildNumber": "12345"},
    )
    mocker.patch(
        "TrendMicroVisionOneV3.Client.http_request",
        mock_sandbox_submission_polling_response,
    )
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"task_id": "8559a7ce-2b85-451b-8742-4b943ad76a22"}
    result = get_sandbox_submission_status(args, client)
    assert result.outputs["report_id"] == "8559a7ce-2b85-451b-8742-4b943ad76a22"
    assert isinstance(result.outputs["type"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert isinstance(result.outputs["arguments"], str)
    assert isinstance(result.outputs["analysis_completion_time"], str)
    assert isinstance(result.outputs["risk_level"], str)
    assert isinstance(result.outputs["detection_name_list"], list)
    assert isinstance(result.outputs["threat_type_list"], list)
    assert isinstance(result.outputs["file_type"], str)


# Mock function for check task status
def check_task_status_mock_response(*args, **kwargs):
    return_value = {
        "id": "00001824",
        "status": "succeeded",
        "createdDateTime": "2021-04-05T08:22:37Z",
        "lastActionDateTime": "2021-04-06T08:22:37Z",
        "description": "task description",
        "action": "isolate",
        "account": "test",
        "agentGuid": "cb9c8412-1f64-4fa0-a36b-76bf41a07ede",
        "endpointName": "client1",
    }
    return return_value


def test_check_task_status(mocker):
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", check_task_status_mock_response)
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"task_id": "00001824"}
    result = get_task_status(args, client)
    assert result.outputs["taskId"] == "00001824"
    assert result.outputs["taskStatus"] == "succeeded"
    assert isinstance(result.outputs["action"], str)
    assert isinstance(result.outputs["createdDateTime"], str)
    assert isinstance(result.outputs["account"], str)


# Mock for downloaded file information
def mock_get_endpoint_info_response(*args, **kwargs):
    return_response = {
        "items": [
            {
                "agentGuid": "35fa11da-a24e-40cf-8b56-baf8828cc151",
                "loginAccount": {
                    "value": ["MSEDGEWIN10\\\\IEUser"],
                    "updatedDateTime": "2020-06-01T02:12:56Z",
                },
                "endpointName": {
                    "value": "MSEDGEWIN10",
                    "updatedDateTime": "2020-06-01T02:12:56Z",
                },
                "macAddress": {
                    "value": ["00:1c:42:be:22:5f"],
                    "updatedDateTime": "2020-06-01T02:12:56Z",
                },
                "ip": {
                    "value": ["10.211.55.36"],
                    "updatedDateTime": "2020-06-01T02:12:56Z",
                },
                "osName": "Linux",
                "osVersion": "10.0.17763",
                "osDescription": "Windows 10 Enterprise Evaluation (64 bit) build 17763",
                "productCode": "sao",
                "installedProductCodes": ["xes"],
            }
        ]
    }
    return return_response


# Test case for get endpoint information.
def test_get_endpoint_information(mocker):
    """Test get information from endpoint based on endpointName or agentGuid"""
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_get_endpoint_info_response)
    args = {"endpoint": "hostname"}
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    result = get_endpoint_info(client, args)
    assert result.outputs["status"] == "success"
    assert isinstance(result.outputs["agentGuid"], str)
    assert isinstance(result.outputs["logonAccount"], list)
    assert isinstance(result.outputs["hostname"], str)
    assert isinstance(result.outputs["macAddr"], list)
    assert isinstance(result.outputs["ip"], str)
    assert isinstance(result.outputs["osName"], str)
    assert isinstance(result.outputs["osVersion"], str)
    assert isinstance(result.outputs["osDescription"], str)
    assert isinstance(result.outputs["productCode"], str)
    assert isinstance(result.outputs["installedProductCodes"], str)


# Mock function for add note.
def add_note_mock_response(*args, **kwargs):
    class Response:
        headers = {}
        status_code = 200

    return_value = Response()
    return return_value


# Test case for add note
def test_add_note(mocker):
    mocker.patch("TrendMicroVisionOneV3.requests.post", add_note_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"workbench_id": "WB-14-20190709-00003", "content": "This is a new note."}
    result = add_note(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["code"], int)
    assert isinstance(result.outputs["note_id"], str)
    assert isinstance(result.outputs["Workbench_Id"], str)


# Mock function for update alert status
def update_status_mock_response(*args, **kwargs):
    return_value = {
        "message": "Alert status changed successfully",
        "Workbench_Id": "WB-20837-20220418-00000",
    }
    return return_value


# Test case for update alert status
def test_update_status(mocker):
    mocker.patch("TrendMicroVisionOneV3.Client.http_request", update_status_mock_response)
    client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
    args = {"workbench_id": "WB-20837-20220418-00000", "status": "In Progress"}
    result = update_status(client, args)
    assert result.outputs["message"] == "Alert status changed successfully"
    assert isinstance(result.outputs["Workbench_Id"], str)
