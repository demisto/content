from TrendMicroVisionOneV3 import (
    Client,
    add_note,
    collect_file,
    update_status,
    force_sign_out,
    get_task_status,
    get_endpoint_info,
    get_alert_details,
    terminate_process,
    force_password_reset,
    restore_email_message,
    submit_urls_to_sandbox,
    add_to_suspicious_list,
    submit_file_to_sandbox,
    get_email_activity_data,
    get_file_analysis_status,
    get_file_analysis_result,
    download_analysis_report,
    get_endpoint_activity_data,
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
import json
import TrendMicroVisionOneV3

# Provide valid API KEY
api_key = "test api key"
proxy = True
verify = True


# Mock response for enabling or disabling user account
def enable_user_account_mock_response(*args, **kwargs):
    with open("./test_data/enable_user_account.json") as f:
        return_value = json.load(f)
    return return_value


def test_enable_user_account(mocker):
    """Test enable user account success response."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch(
        "TrendMicroVisionOneV3.enable_or_disable_user_account",
        enable_user_account_mock_response,
    )
    args = {
        "account_identifiers": [
            {
                "account_name": "ghost@trendmicro.com",
                "description": "Signing out user account.",
            }
        ]
    }

    result = enable_or_disable_user_account(
        client, "trendmicro-visionone-enable-user-account", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000010"
    assert result.outputs_prefix == "VisionOne.User_Account"
    assert result.outputs_key_field == "task_id"


def disable_user_account_mock_response(*args, **kwargs):
    with open("./test_data/disable_user_account.json") as f:
        return_value = json.load(f)
    return return_value


def test_disable_user_account(mocker):
    """Test disable user account success response."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "enable_or_disable_user_account",
        disable_user_account_mock_response,
    )
    args = {
        "account_identifiers": [
            {
                "account_name": "ghost@trendmicro.com",
                "description": "Signing out user account.",
            }
        ]
    }
    result = enable_or_disable_user_account(
        client, "trendmicro-visionone-disable-user-account", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000009"
    assert result.outputs_prefix == "VisionOne.User_Account"
    assert result.outputs_key_field == "task_id"


# Mock response for force sign out
def force_signout_mock_response(*args, **kwargs):
    with open("./test_data/force_signout.json") as f:
        return_value = json.load(f)
    return return_value


def test_force_signout(mocker):
    """Test to force sign out user account with successful result."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3, "force_sign_out", force_signout_mock_response
    )
    args = {
        "account_identifiers": [
            {
                "account_name": "ghost@trendmicro.com",
                "description": "Signing out user account.",
            }
        ]
    }

    result = force_sign_out(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000012"
    assert result.outputs_prefix == "VisionOne.Force_Sign_Out"
    assert result.outputs_key_field == "task_id"


# Mock response for force password reset
def force_password_reset_mock_response(*args, **kwargs):
    with open("./test_data/force_password_reset.json") as f:
        return_value = json.load(f)
    return return_value


def test_force_password_reset(mocker):
    """Test to force sign out user account with successful result."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "force_password_reset",
        force_password_reset_mock_response,
    )
    args = {
        "account_identifiers": [
            {
                "account_name": "ghost@trendmicro.com",
                "description": "Signing out user account.",
            }
        ]
    }
    result = force_password_reset(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000011"
    assert result.outputs_prefix == "VisionOne.Force_Password_Reset"
    assert result.outputs_key_field == "task_id"


# Mock function for add to block list
def add_blocklist_mock_response(*args, **kwargs):
    with open("./test_data/add_blocklist.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for add to block list
def test_add_blocklist(mocker):
    """Test add to block list with positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "add_or_remove_from_block_list",
        add_blocklist_mock_response,
    )
    args = {
        "block_objects": [
            {
                "object_type": "file_sha1",
                "object_value": "2de5c1125d5f991842727ed8eca8b5fda0ffa249b",
                "description": "Add to blocklist.",
            }
        ]
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-add-to-block-list", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000007"
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "task_id"


# Mock function for remove from block list
def remove_blocklist_mock_response(*args, **kwargs):
    with open("./test_data/remove_blocklist.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for remove from block list
def test_remove_blocklist(mocker):
    """Test remove block list positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "add_or_remove_from_block_list",
        remove_blocklist_mock_response,
    )
    args = {
        "block_objects": [
            {
                "object_type": "domain",
                "object_value": "www.test.com",
                "description": "Remove from block list",
            }
        ]
    }
    result = add_or_remove_from_block_list(
        client, "trendmicro-visionone-remove-from-block-list", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000008"
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "task_id"


# Mock function for quarantine and delete email message
def quarantine_email_mock_response(*args, **kwargs):
    with open("./test_data/quarantine_email.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for quarantine email message
def test_quarantine_email_message(mocker):
    """Test quarantine email message positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "quarantine_or_delete_email_message",
        quarantine_email_mock_response,
    )
    args = {
        "email_identifiers": [
            {
                "message_id": (
                    "<CANUJTKTjto9GAHTr9V=TFqMZhRXqVn="
                    "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"
                ),
                "mailbox": "kjshdfjksahd@trendenablement.com",
                "description": "quarantine email",
            }
        ]
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-quarantine-email-message", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000002"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "task_id"


def delete_email_mock_response(*args, **kwargs):
    with open("./test_data/delete_email.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for delete email message
def test_delete_email_message(mocker):
    """Test delete email message with positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "quarantine_or_delete_email_message",
        delete_email_mock_response,
    )
    args = {
        "email_identifiers": [
            {
                "unique_id": (
                    "CANUJTKTjto9GAHTr9V=TFqMZhRXqVn="
                    "MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com"
                ),
                "description": "delete email",
            }
        ]
    }
    result = quarantine_or_delete_email_message(
        client, "trendmicro-visionone-delete-email-message", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "task_id"


# Mock response for restore email message
def restore_email_mock_response(*args, **kwargs):
    with open("./test_data/restore_email_message.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for restore email
def test_restore_email_message(mocker):
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "restore_email_message",
        restore_email_mock_response,
    )
    args = {
        "email_identifiers": [
            {
                "unique_id": "CANUJTKTjto9GAHTr9V=TFqMZhRXqVnMfSqmTdAMyv9PDX3k",
                "description": "Restore email.",
            }
        ]
    }
    result = restore_email_message(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000003"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "task_id"


# Mock response for isolate endpoint
def isolate_mock_response(*args, **kwargs):
    with open("./test_data/isolate_endpoint.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for isolate endpoint
def test_isolate_endpoint(mocker):
    """Test isolate endpoint positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "isolate_or_restore_connection",
        isolate_mock_response,
    )
    args = {
        "endpoint_identifiers": [
            {
                "endpoint": "client782",
                "description": "Add to blocklist.",
            }
        ]
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-isolate-endpoint", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000004"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "task_id"


# Mock response for restore endpoint
def restore_endpoint_mock_response(*args, **kwargs):
    with open("./test_data/restore_endpoint.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for restore endpoint
def test_restore_endpoint(mocker):
    """Test restore endpoint positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "isolate_or_restore_connection",
        restore_endpoint_mock_response,
    )
    args = {
        "endpoint_identifiers": [
            {
                "agent_guid": "cb9c8412-1f64-4fa0-a36b-76bf41a07ede",
                "description": "Remove from blocklist.",
            }
        ]
    }
    result = isolate_or_restore_connection(
        client, "trendmicro-visionone-restore-endpoint-connection", args
    )
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000005"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "task_id"


# Mock response for terminate process
def terminate_process_mock_response(*args, **kwargs):
    with open("./test_data/terminate_process.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for terminate process endpoint
def test_terminate_process(mocker):
    """Test terminate process positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "terminate_process",
        terminate_process_mock_response,
    )
    args = {
        "process_identifiers": [
            {
                "endpoint": "035f6286-2414-4cb4-8d05-e67d2d32c944",
                "file_sha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
                "description": "terminate info",
                "filename": "testfile.txt",
            }
        ]
    }
    result = terminate_process(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000006"
    assert result.outputs_prefix == "VisionOne.Terminate_Process"
    assert result.outputs_key_field == "task_id"


# Mock response for add to exception list
def add_exception_mock_response(*args, **kwargs):
    with open("./test_data/add_exception.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for add exception list.
def test_add_object_to_exception_list(mocker):
    """Test add to exception list with positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "add_or_delete_from_exception_list",
        add_exception_mock_response,
    )
    args = {
        "block_objects": [
            {
                "object_type": "domain",
                "object_value": "1.alisiosanguera.com",
                "description": "new key",
            }
        ]
    }
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-add-objects-to-exception-list", args
    )
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for remove from exception list
def delete_exception_mock_response(*args, **kwargs):
    with open("./test_data/remove_exception.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for delete exception list.
def test_delete_object_from_exception_list(mocker):
    """Test delete exception list positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "add_or_delete_from_exception_list",
        delete_exception_mock_response,
    )
    args = {
        "block_objects": [
            {
                "object_type": "ip",
                "object_value": "7.7.7.7",
                "description": "Remove IP from exception list",
            }
        ]
    }
    result = add_or_delete_from_exception_list(
        client, "trendmicro-visionone-delete-objects-from-exception-list", args
    )
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for add to suspicious list
def add_suspicious_mock_response(*args, **kwargs):
    with open("./test_data/add_suspicious_list.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for add suspicious object list
def test_add_object_to_suspicious_list(mocker):
    """Test add to suspicious list with poistive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "add_to_suspicious_list",
        delete_exception_mock_response,
    )
    args = {
        "block_objects": [
            {
                "object_type": "domain",
                "object_value": "1.alisiosanguera.com.cn",
                "description": "Example Suspicious Object.",
                "scan_action": "log",
                "risk_level": "high",
                "expiry_days": 15,
            }
        ]
    }
    result = add_to_suspicious_list(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for delete from suspicious list
def delete_suspicious_mock_response(*args, **kwargs):
    with open("./test_data/delete_suspicious_list.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for delete suspicious object list
def test_delete_object_from_suspicious_list(mocker):
    """Test delete object from suspicious list."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "add_to_suspicious_list",
        delete_suspicious_mock_response,
    )
    args = {
        "block_objects": [
            {
                "object_type": "domain",
                "object_value": "1.alisiosanguera.com.cn",
                "description": "Delete from suspicious list",
            }
        ]
    }
    result = delete_from_suspicious_list(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for Get file analysis status
def mock_file_analysis_status_response(*args, **kwargs):
    with open("./test_data/get_file_analysis_status.json") as f:
        return_value = json.load(f)
    return return_value


# Test Cases for Get file analysis status
def test_get_file_analysis_status(mocker):
    """Test to get status of file"""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "get_file_analysis_status",
        mock_file_analysis_status_response,
    )
    args = {"task_id": "921674d0-9735-4f79-b7de-c852e00a003d"}
    result = get_file_analysis_status(client, args)
    assert isinstance(result.outputs["is_cached"], bool)
    assert result.outputs["status"] == "succeeded"
    assert isinstance(result.outputs["action"], str)
    assert isinstance(result.outputs["arguments"], str)
    assert result.outputs["id"] == "921674d0-9735-4f79-b7de-c852e00a003d"
    assert isinstance(result.outputs["digest"], dict)
    assert isinstance(result.outputs["resource_location"], str)
    assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
    assert result.outputs_key_field == "id"


# def test_get_report_id(mocker):
#     """Test to get status of file with report id"""
#     mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_file_status_response)
#     args = {"taskId": "921674d0-9735-4f79-b7de-c852e00a003d"}
#     client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
#     result = get_file_analysis_status(client, args)
#     assert result.outputs["status"] == "succeeded"
#     assert result.outputs["action"] == "analyzeFile"
#     assert result.outputs["id"] == "012e4eac-9bd9-4e89-95db-77e02f75a6f3"
#     assert result.outputs_prefix == "VisionOne.File_Analysis_Status"
#     assert result.outputs_key_field == "message"


# Mock response for Get file analysis report
def mock_file_result_response(*args, **kwargs):
    with open("./test_data/get_file_analysis_result.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for get file analysis report
def test_get_file_analysis_result(mocker):
    """Test get file analysis report data."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "get_file_analysis_result",
        mock_file_result_response,
    )
    args = {
        "report_id": "800f908d-9578-4333-91e5-822794ed5483",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = get_file_analysis_result(client, args)
    assert result.outputs["id"] == "800f908d-9578-4333-91e5-822794ed5483"
    assert isinstance(result.outputs["type"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert isinstance(result.outputs["arguments"], str)
    assert isinstance(result.outputs["analysis_completion_date_time"], str)
    assert result.outputs["risk_level"] == "high"
    assert isinstance(result.outputs["detection_names"], list)
    assert isinstance(result.outputs["threat_types"], list)
    assert isinstance(result.outputs["true_file_type"], str)
    assert result.outputs_key_field == "id"


# def test_get_file_analysis_result_1(mocker):
#     """Test get file analysis report data."""
#     mocker.patch("TrendMicroVisionOneV3.Client.http_request", mock_file_result_response)
#     client = Client("https://apimock-dev.trendmicro.com", api_key, proxy, verify)
#     args = {"reportId": "800f908d-9578-4333-91e5-822794ed5483"}
#     result = get_file_analysis_result(client, args)
#     assert len(result.outputs) > 0


# Mock response for collect file
def mock_collect_file_response(*args, **kwargs):
    with open("./test_data/collect_forensic_file.json") as f:
        return_value = json.load(f)
    return return_value


# Test cases for collect forensic file.
def test_collect_forensic_file(mocker):
    """Test collect file with positive scenario."""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "collect_file",
        mock_collect_file_response,
    )
    args = {
        "collect_files": [
            {
                "endpoint": "client95c3",
                "file_path": "C/file_path/sample.txt",
                "description": "collect file",
            }
        ]
    }
    result = collect_file(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000003"
    assert result.outputs_prefix == "VisionOne.Collect_Forensic_File"
    assert result.outputs_key_field == "task_id"


# Mock for downloaded file information
def mock_download_collected_file_info_response(*args, **kwargs):
    with open("./test_data/download_information_collected_file.json") as f:
        return_value = json.load(f)
    return return_value


# Test Cases for Collected downloaded file information.
def test_get_forensic_file_information(mocker):
    """Test endpoint to get collected file information based on task id"""
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "download_information_collected_file",
        mock_download_collected_file_info_response,
    )
    args = {
        "task_id": "collect_file",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = download_information_collected_file(client, args)
    assert result.outputs["id"] == "00000003"
    assert result.outputs["action"] == "collectFile"
    assert result.outputs["status"] == "succeeded"
    assert result.outputs["agent_guid"] == "cb9c8412-1f64-4fa0-a36b-76bf41a07ede"
    assert result.outputs["endpoint_name"] == "trend-host-1"
    assert result.outputs["file_sha1"] == "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b"
    assert result.outputs["file_size"] == 102400
    assert isinstance(result.outputs["file_path"], str)
    assert isinstance(result.outputs["resource_location"], str)
    assert isinstance(result.outputs["expired_date_time"], str)
    assert isinstance(result.outputs["created_date_time"], str)
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
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "download_analysis_report",
        mock_download_analysis_report_response,
    )
    args = {
        "submission_id": "8559a7ce-2b85-451b-8742-4b943ad76a22",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = download_analysis_report(client, args)
    assert result[1].outputs["result_code"] == "SUCCESS"
    assert result[1].outputs["submission_id"] == "8559a7ce-2b85-451b-8742-4b943ad76a22"
    assert result[1].outputs_prefix == "VisionOne.Download_Analysis_Report"
    assert result[1].outputs_key_field == "submission_id"


# Mock response for download investigation package
def mock_download_investigation_package_response(*args, **kwargs):
    class Response:
        content = ""
        status_code = 200

    return_value = Response()
    return return_value


# Test case for Download analysis package
def test_download_investigation_package(mocker):
    """
    Test to download investigation package for file
    submitted to sandbox based on submission ID returned
    by get file analysis status.
    """
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "download_investigation_package",
        mock_download_investigation_package_response,
    )
    args = {
        "submission_id": "8559a7ce-2b85-451b-8742-4b943ad76a22",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = download_investigation_package(client, args)
    assert result[1].outputs["result_code"] == "SUCCESS"
    assert result[1].outputs["submission_id"] == "8559a7ce-2b85-451b-8742-4b943ad76a22"
    assert result[1].outputs_prefix == "VisionOne.Download_Investigation_Package"
    assert result[1].outputs_key_field == "submission_id"


# Mock response for download suspicious object list
def mock_download_suspicious_object_list_response(*args, **kwargs):
    with open("./test_data/download_suspicious_object_list.json") as f:
        return_value = json.load(f)
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
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "download_suspicious_object_list",
        mock_download_suspicious_object_list_response,
    )
    args = {
        "submission_id": "8559a7ce-2b85-451b-8742-4b943ad76a22",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = download_suspicious_object_list(client, args)
    assert result.outputs[0]["risk_level"] == "high"
    assert isinstance(result.outputs[0]["analysis_completion_date_time"], str)
    assert isinstance(result.outputs[0]["expired_date_time"], str)
    assert isinstance(result.outputs[0]["root_sha1"], str)
    assert isinstance(result.outputs[0]["type"], str)
    assert isinstance(result.outputs[0]["value"], str)
    assert result.outputs_prefix == "VisionOne.Download_Suspicious_Object_list"
    assert result.outputs_key_field == "risk_level"


# Mock response for submit file to sandbox.
def mock_submit_file_to_sandbox_response(*args, **kwargs):
    with open("./test_data/submit_file_to_sandbox.json") as f:
        return_value = json.load(f)
    return return_value


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
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "submit_file_to_sandbox",
        mock_submit_file_to_sandbox_response,
    )
    args = {
        "file_path": "https://docs.docker.com/get-started/docker_cheatsheet.pdf",
        "filename": "cheat_sheet.pdf",
        "archive_password": "6hn467c8",
        "document_password": "",
        "arguments": "",
    }
    result = submit_file_to_sandbox(client, args)
    assert isinstance(result.outputs["task_id"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert result.outputs["code"] == 202
    assert isinstance(result.outputs["arguments"], str)
    assert result.outputs["message"] == "SUCCESS"
    assert result.outputs_key_field == "task_id"


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
        "arguments": "",
    }
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    result = submit_file_entry_to_sandbox(client, args)
    assert result.outputs["entry_id"] == "12@1221"
    assert isinstance(result.outputs["task_id"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert result.outputs_key_field == "entry_id"


# Mock response for submit urls to sandbox
def mock_urls_to_sandbox(*args, **kwargs):
    with open("./test_data/submit_urls_sandbox.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for submit urls to sandbox
def test_submit_urls_to_sandbox(mocker):
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "submit_urls_to_sandbox",
        mock_submit_file_to_sandbox_response,
    )
    args = {
        "urls": [
            "http://www.shadywebsite.com",
            "http://www.virus2.com",
            "https://testurl.com",
        ]
    }
    result = submit_urls_to_sandbox(client, args)
    assert isinstance(result.outputs[0]["url"], str)
    assert isinstance(result.outputs[0]["id"], str)
    assert isinstance(result.outputs[0]["digest"], dict)
    assert result.outputs_key_field == "id"


# Mock response for Get file analysis report
def mock_sandbox_submission_polling_response(*args, **kwargs):
    with open("./test_data/sandbox_submission_polling.json") as f:
        return_value = json.load(f)
    return return_value


def test_sandbox_submission_polling(mocker):
    """Test sandbox submission polling."""
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.2.0", "buildNumber": "12345"},
    )
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "get_sandbox_submission_status",
        mock_sandbox_submission_polling_response,
    )
    mocker.patch(
        "CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None
    )
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
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
    with open("./test_data/check_task_status.json") as f:
        return_value = json.load(f)
    return return_value


def test_check_task_status(mocker):
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "get_task_status",
        mock_sandbox_submission_polling_response,
    )
    mocker.patch(
        "CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None
    )
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    args = {
        "task_id": "00000004",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = get_task_status(args, client)
    assert result.outputs["id"] == "00000004"
    assert result.outputs["status"] == "succeeded"
    assert isinstance(result.outputs["action"], str)
    assert isinstance(result.outputs["created_date_time"], str)
    assert isinstance(result.outputs["description"], str)
    assert isinstance(result.outputs["last_action_date_time"], str)


# Mock for downloaded file information
def mock_get_endpoint_info_response(*args, **kwargs):
    with open("./test_data/get_endpoint_info.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for get endpoint information.
def test_get_endpoint_information(mocker):
    """Test get information from endpoint based on endpointName or agentGuid"""
    mocker.patch(
        "TrendMicroVisionOneV3.get_endpoint_info",
        mock_get_endpoint_info_response,
    )
    args = {"endpoint": "hostname", "query_op": "or"}
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    result = get_endpoint_info(client, args)
    assert isinstance(result.outputs[0]["agent_guid"], str)
    assert isinstance(result.outputs[0]["login_account"], dict)
    assert isinstance(result.outputs[0]["endpoint_name"], dict)
    assert isinstance(result.outputs[0]["mac_address"], dict)
    assert isinstance(result.outputs[0]["ip"], dict)
    assert isinstance(result.outputs[0]["os_name"], str)
    assert isinstance(result.outputs[0]["os_version"], str)
    assert isinstance(result.outputs[0]["os_description"], str)
    assert isinstance(result.outputs[0]["product_code"], str)
    assert isinstance(result.outputs[0]["installed_product_codes"], list)


# Mock response for get endpoint activity data
def get_endpoint_activity_data_mock_response(*args, **kwargs):
    with open("./test_data/get_endpoint_activity_data.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for get alert details
def test_get_endpoint_activity_data(mocker):
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "get_endpoint_activity_data",
        get_endpoint_activity_data_mock_response,
    )
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    args = {
        "start": "2022-10-04T08:22:37Z",
        "end": "2023-10-04T08:22:37Z",
        "top": 50,
        "query_op": "or",
        "select": "dpt,dst,endpointHostName",
        "get_activity_data_count": "true",
        "fields": {"dpt": "443", "endpointHostName": "client1"},
    }
    result = get_endpoint_activity_data(client, args)
    assert isinstance(result.outputs[0]["total_count"], int)
    assert isinstance(result.outputs[1], dict)


# Mock response for get endpoint activity data
def get_email_activity_data_mock_response(*args, **kwargs):
    with open("./test_data/get_email_activity_data.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for get alert details
def test_get_email_activity_data(mocker):
    mocker.patch.object(
        TrendMicroVisionOneV3,
        "get_email_activity_data",
        get_email_activity_data_mock_response,
    )
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    args = {
        "start": "2022-10-04T08:22:37Z",
        "end": "2023-10-04T08:22:37Z",
        "top": 50,
        "query_op": "or",
        "select": "mailFromAddresses,mailToAddresses",
        "get_activity_data_count": "true",
        "fields": {"mailToAddresses": "testemail@gmail.com", "mailMsgSubject": "spam"},
    }
    result = get_email_activity_data(client, args)
    assert isinstance(result.outputs[0]["total_count"], int)
    assert isinstance(result.outputs[1], dict)


# Mock response for get alert details
def get_alert_details_mock_response(*args, **kwargs):
    with open("./test_data/get_alert_details.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for get alert details
def test_get_alert_details(mocker):
    mocker.patch.object(
        TrendMicroVisionOneV3, "get_alert_details", get_alert_details_mock_response
    )
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    args = {"workbench_id": "WB-14-20190709-00003"}
    result = get_alert_details(client, args)
    assert result.outputs["etag"] == "33a64df551425fcc55e4d42a148795d9f25f89d4"
    assert isinstance(result.outputs["alert"], dict)
    assert result.outputs_key_field == "etag"


# Mock response for add note.
def add_note_mock_response(*args, **kwargs):
    with open("./test_data/add_note.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for add note
def test_add_note(mocker):
    mocker.patch("TrendMicroVisionOneV3.add_note", add_note_mock_response)
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    args = {"workbench_id": "WB-14-20190709-00003", "content": "This is a new note."}
    result = add_note(client, args)
    assert isinstance(result.outputs["message"], str)
    assert isinstance(result.outputs["code"], int)
    assert result.outputs["note_id"] == "1"
    assert result.outputs_key_field == "note_id"


# Mock function for update alert status
def update_status_mock_response(*args, **kwargs):
    with open("./test_data/add_note.json") as f:
        return_value = json.load(f)
    return return_value


# Test case for update alert status
def test_update_status(mocker):
    mocker.patch("TrendMicroVisionOneV3.update_status", update_status_mock_response)
    client = Client("https://tmv1-mock.trendmicro.com", api_key, proxy, verify)
    args = {
        "workbench_id": "WB-20837-20220418-00000",
        "if_match": "d41d8cd98f00b204e9800998ecf8427e",
        "status": "in_progress",
    }
    result = update_status(client, args)
    assert isinstance(result.outputs["message"], str)
    assert result.outputs["code"] == 204
    assert result.outputs["Workbench_Id"] == "WB-20837-20220418-00000"
