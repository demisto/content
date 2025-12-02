import json
from typing import Any

# import unittest
from unittest.mock import Mock

import demistomock as demisto
import TrendMicroVisionOneV3
from pytmv1 import (
    Account,
    AccountTaskResp,
    AddAlertNoteResp,
    AddCustomScriptResp,
    BaseTaskResp,
    BytesResp,
    CollectFileTaskResp,
    Digest,
    EmailActivity,
    Endpoint,
    EndpointActivity,
    GetAlertResp,
    GetEmailActivitiesCountResp,
    Iam,
    ListCustomScriptsResp,
    ListEmailActivityResp,
    ListEndpointActivityResp,
    ListOatsResp,
    ListSandboxSuspiciousResp,
    MsData,
    MsDataUrl,
    MultiResp,
    MultiResult,
    MultiUrlResp,
    NoContentResp,
    OatEvent,
    ObjectType,
    OperatingSystem,
    ProductCode,
    QueryOp,
    Result,
    ResultCode,
    RiskLevel,
    SandboxAction,
    SandboxAnalysisResultResp,
    SandboxObjectType,
    SandboxSubmissionStatusResp,
    SandboxSuspiciousObject,
    ScriptType,
    Status,
    SubmitFileToSandboxResp,
    TaskAction,
    TextResp,
    Value,
    ValueList,
)
from pytmv1.model.common import Script
from TrendMicroVisionOneV3 import (
    add_custom_script,
    add_note,
    add_or_delete_from_exception_list,
    add_or_remove_from_block_list,
    add_to_suspicious_list,
    collect_file,
    delete_custom_script,
    delete_from_suspicious_list,
    download_analysis_report,
    download_custom_script,
    download_information_collected_file,
    download_investigation_package,
    download_suspicious_object_list,
    enable_or_disable_user_account,
    force_password_reset,
    force_sign_out,
    get_alert_details,
    get_custom_script_list,
    get_email_activity_data,
    get_email_activity_data_count,
    get_endpoint_activity_data,
    get_endpoint_activity_data_count,
    get_endpoint_info,
    get_file_analysis_result,
    get_file_analysis_status,
    get_mapping_fields_command,
    get_modified_remote_data_command,
    get_observed_attack_techniques,
    get_remote_data_command,
    get_sandbox_submission_status,
    get_task_status,
    isolate_or_restore_connection,
    quarantine_or_delete_email_message,
    restore_email_message,
    run_custom_script,
    submit_file_entry_to_sandbox,
    submit_file_to_sandbox,
    submit_urls_to_sandbox,
    terminate_process,
    update_custom_script,
    update_remote_system_command,
    update_status,
    vision_one_status_to_xsoar,
    xsoar_status_to_vision_one,
)

# Provide valid API KEY
api_key = "test api key"
proxy = True
verify = True


# Mock response for enabling or disabling user account
def enable_user_account_mock_response(*args, **kwargs) -> MultiResult[MultiResp]:
    with open("./test_data/enable_user_account.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


def test_enable_user_account(mocker):
    """Test enable user account success response."""
    client = Mock()
    client.account.enable = Mock(return_value=enable_user_account_mock_response())
    args = {
        "account_identifiers": json.dumps(
            [
                {
                    "account_name": "ghost@trendmicro.com",
                    "description": "Enable user account.",
                }
            ]
        )
    }
    result = TrendMicroVisionOneV3.enable_or_disable_user_account(client, "trendmicro-visionone-enable-user-account", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000010"
    assert result.outputs_prefix == "VisionOne.User_Account"
    assert result.outputs_key_field == "task_id"


def disable_user_account_mock_response(*args, **kwargs):
    with open("./test_data/disable_user_account.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


def test_disable_user_account(mocker):
    """Test disable user account success response."""
    client = Mock()
    client.account.disable = Mock(return_value=disable_user_account_mock_response())
    args = {
        "account_identifiers": json.dumps(
            [
                {
                    "account_name": "ghost@trendmicro.com",
                    "description": "Disable user account.",
                }
            ]
        )
    }
    result = enable_or_disable_user_account(client, "trendmicro-visionone-disable-user-account", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000009"
    assert result.outputs_prefix == "VisionOne.User_Account"
    assert result.outputs_key_field == "task_id"


# Mock response for force sign out
def force_signout_mock_response(*args, **kwargs):
    with open("./test_data/force_signout.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


def test_force_signout(mocker):
    """Test to force sign out user account with successful result."""
    client = Mock()
    client.account.sign_out = Mock(return_value=force_signout_mock_response())
    args = {
        "account_identifiers": json.dumps(
            [
                {
                    "account_name": "ghost@trendmicro.com",
                    "description": "Signing out user account.",
                }
            ]
        )
    }

    result = force_sign_out(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000012"
    assert result.outputs_prefix == "VisionOne.Force_Sign_Out"
    assert result.outputs_key_field == "task_id"


# Mock response for force password reset
def force_password_reset_mock_response(*args, **kwargs):
    with open("./test_data/force_password_reset.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


def test_force_password_reset(mocker):
    """Test to force sign out user account with successful result."""
    client = Mock()
    client.account.reset = Mock(return_value=force_password_reset_mock_response())
    args = {
        "account_identifiers": json.dumps(
            [
                {
                    "account_name": "ghost@trendmicro.com",
                    "description": "Signing out user account.",
                }
            ]
        )
    }
    result = force_password_reset(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000011"
    assert result.outputs_prefix == "VisionOne.Force_Password_Reset"
    assert result.outputs_key_field == "task_id"


# Mock function for add to block list
def add_blocklist_mock_response(*args, **kwargs):
    with open("./test_data/add_blocklist.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for add to block list
def test_add_blocklist(mocker):
    """Test add to block list with positive scenario."""
    client = Mock()
    client.object.add_block = Mock(return_value=add_blocklist_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "object_type": "file_sha1",
                    "object_value": "2de5c1125d5f991842727ed8eca8b5fda0ffa249b",
                    "description": "Add to blocklist.",
                }
            ]
        )
    }
    result = add_or_remove_from_block_list(client, "trendmicro-visionone-add-to-block-list", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000007"
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "task_id"


# Mock function for remove from block list
def remove_blocklist_mock_response(*args, **kwargs):
    with open("./test_data/remove_blocklist.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for remove from block list
def test_remove_blocklist(mocker):
    """Test remove block list positive scenario."""
    client = Mock()
    client.object.delete_block = Mock(return_value=remove_blocklist_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "object_type": "domain",
                    "object_value": "www.test.com",
                    "description": "Remove from block list",
                }
            ]
        )
    }
    result = add_or_remove_from_block_list(client, "trendmicro-visionone-remove-from-block-list", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000008"
    assert result.outputs_prefix == "VisionOne.BlockList"
    assert result.outputs_key_field == "task_id"


# Mock function for quarantine and delete email message
def quarantine_email_mock_response(*args, **kwargs):
    with open("./test_data/quarantine_email.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for quarantine email message
def test_quarantine_email_message(mocker):
    """Test quarantine email message positive scenario."""
    client = Mock()
    client.email.quarantine = Mock(return_value=quarantine_email_mock_response())
    args = {
        "email_identifiers": json.dumps(
            [
                {
                    "message_id": ("<CANUJTKTjto9GAHTr9V=TFqMZhRXqVn=MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com>"),
                    "mailbox": "kjshdfjksahd@trendenablement.com",
                    "description": "quarantine email",
                }
            ]
        )
    }
    result = quarantine_or_delete_email_message(client, "trendmicro-visionone-quarantine-email-message", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000002"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "task_id"


def delete_email_mock_response(*args, **kwargs):
    with open("./test_data/delete_email.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for delete email message
def test_delete_email_message(mocker):
    """Test delete email message with positive scenario."""
    client = Mock()
    client.email.delete = Mock(return_value=delete_email_mock_response())
    args = {
        "email_identifiers": json.dumps(
            [
                {
                    "unique_id": ("CANUJTKTjto9GAHTr9V=TFqMZhRXqVn=MfSqmTdAMyv9PDX3k+vQ0w@mail.gmail.com"),
                    "description": "delete email",
                }
            ]
        )
    }
    result = quarantine_or_delete_email_message(client, "trendmicro-visionone-delete-email-message", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000001"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "task_id"


# Mock response for restore email message
def restore_email_mock_response(*args, **kwargs):
    with open("./test_data/restore_email_message.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test case for restore email
def test_restore_email_message(mocker):
    client = Mock()
    client.email.restore = Mock(return_value=restore_email_mock_response())
    args = {
        "email_identifiers": json.dumps(
            [
                {
                    "unique_id": "CANUJTKTjto9GAHTr9V=TFqMZhRXqVnMfSqmTdAMyv9PDX3k",
                    "description": "Restore email.",
                }
            ]
        )
    }
    result = restore_email_message(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000003"
    assert result.outputs_prefix == "VisionOne.Email"
    assert result.outputs_key_field == "task_id"


# Mock response for isolate endpoint
def isolate_mock_response(*args, **kwargs):
    with open("./test_data/isolate_endpoint.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for isolate endpoint
def test_isolate_endpoint(mocker):
    """Test isolate endpoint positive scenario."""
    client = Mock()
    client.endpoint.isolate = Mock(return_value=isolate_mock_response())
    args = {
        "endpoint_identifiers": json.dumps(
            [
                {
                    "endpoint": "client782",
                    "description": "Add to blocklist.",
                }
            ]
        )
    }
    result = isolate_or_restore_connection(client, "trendmicro-visionone-isolate-endpoint", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000004"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "task_id"


# Mock response for restore endpoint
def restore_endpoint_mock_response(*args, **kwargs):
    with open("./test_data/restore_endpoint.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for restore endpoint
def test_restore_endpoint(mocker):
    """Test restore endpoint positive scenario."""
    client = Mock()
    client.endpoint.restore = Mock(return_value=restore_endpoint_mock_response())
    args = {
        "endpoint_identifiers": json.dumps(
            [
                {
                    "agent_guid": "cb9c8412-1f64-4fa0-a36b-76bf41a07ede",
                    "description": "Remove from blocklist.",
                }
            ]
        )
    }
    result = isolate_or_restore_connection(client, "trendmicro-visionone-restore-endpoint-connection", args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000005"
    assert result.outputs_prefix == "VisionOne.Endpoint_Connection"
    assert result.outputs_key_field == "task_id"


# Mock response for terminate process
def terminate_process_mock_response(*args, **kwargs):
    with open("./test_data/terminate_process.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for terminate process endpoint
def test_terminate_process(mocker):
    """Test terminate process positive scenario."""
    client = Mock()
    client.endpoint.terminate_process = Mock(return_value=terminate_process_mock_response())
    args = {
        "process_identifiers": json.dumps(
            [
                {
                    "endpoint": "035f6286-2414-4cb4-8d05-e67d2d32c944",
                    "file_sha1": "12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
                    "description": "terminate info",
                    "filename": "testfile.txt",
                }
            ]
        )
    }
    result = terminate_process(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000006"
    assert result.outputs_prefix == "VisionOne.Terminate_Process"
    assert result.outputs_key_field == "task_id"


# Mock response for add to exception list
def add_exception_mock_response(*args, **kwargs):
    with open("./test_data/add_exception.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for add exception list.
def test_add_object_to_exception_list(mocker):
    """Test add to exception list with positive scenario."""
    client = Mock()
    client.object.add_exception = Mock(return_value=add_exception_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "object_type": "domain",
                    "object_value": "1.alisiosanguera.com",
                    "description": "new key",
                }
            ]
        )
    }
    result = add_or_delete_from_exception_list(client, "trendmicro-visionone-add-objects-to-exception-list", args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for remove from exception list
def delete_exception_mock_response(*args, **kwargs):
    with open("./test_data/remove_exception.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for delete exception list.
def test_delete_object_from_exception_list(mocker):
    """Test delete exception list positive scenario."""
    client = Mock()
    client.object.delete_exception = Mock(return_value=delete_exception_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "object_type": "ip",
                    "object_value": "7.7.7.7",
                    "description": "Remove IP from exception list",
                }
            ]
        )
    }
    result = add_or_delete_from_exception_list(client, "trendmicro-visionone-delete-objects-from-exception-list", args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Exception_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for add to suspicious list
def add_suspicious_mock_response(*args, **kwargs):
    with open("./test_data/add_suspicious_list.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for add suspicious object list
def test_add_object_to_suspicious_list(mocker):
    """Test add to suspicious list with poistive scenario."""
    client = Mock()
    client.object.add_suspicious = Mock(return_value=add_suspicious_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "object_type": "domain",
                    "object_value": "1.alisiosanguera.com.cn",
                    "description": "Example Suspicious Object.",
                    "scan_action": "log",
                    "risk_level": "high",
                    "expiry_days": 15,
                }
            ]
        )
    }
    result = add_to_suspicious_list(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for delete from suspicious list
def delete_suspicious_mock_response(*args, **kwargs):
    with open("./test_data/delete_suspicious_list.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for delete suspicious object list
def test_delete_object_from_suspicious_list(mocker):
    """Test delete object from suspicious list."""
    client = Mock()
    client.object.delete_suspicious = Mock(return_value=delete_suspicious_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "object_type": "domain",
                    "object_value": "1.alisiosanguera.com.cn",
                    "description": "Delete from suspicious list",
                }
            ]
        )
    }
    result = delete_from_suspicious_list(client, args)
    assert result.outputs["message"] == "success"
    assert isinstance(result.outputs["total_items"], int)
    assert result.outputs_prefix == "VisionOne.Suspicious_List"
    assert result.outputs_key_field == "multi_response"


# Mock response for Get file analysis status
def mock_file_analysis_status_response(*args, **kwargs):
    # with open("./test_data/get_file_analysis_status.json") as f:
    #     return_value: list[dict[str, Any]] = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=SandboxSubmissionStatusResp(
            id="921674d0-9735-4f79-b7de-c852e00a003d",
            status=Status.SUCCEEDED,
            created_date_time="2021-11-17T12:00:00Z",
            last_action_date_time="2021-12-17T12:00:00Z",
            action=SandboxAction.ANALYZE_FILE,
            resource_location="https://api.xdr.trendmicro.com/...",
            is_cached=False,
            arguments="LS10ZXN0IA==",
            digest=Digest(
                md5="4ac174730d4143a119037d9fda81c7a9",
                sha1="fb5608fa03de204a12fe1e9e5275e4a682107471",
                sha256="65b0f656e79ab84ca17807158e3eac206bd58be6689ddeb95956a48748d138f9",
            ),
        ),
    )


# Test Cases for Get file analysis status
def test_get_file_analysis_status(mocker):
    """Test to get status of file"""
    client = Mock()
    client.sandbox.get_submission_status = Mock(return_value=mock_file_analysis_status_response())
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


# Mock response for Get file analysis report
def mock_file_result_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=SandboxAnalysisResultResp(
            id="800f908d-9578-4333-91e5-822794ed5483",
            type=SandboxObjectType.FILE,
            analysis_completion_date_time="2021-11-17T12:00:00Z",
            risk_level=RiskLevel.HIGH,
            true_file_type="exe",
            digest=Digest(
                md5="4ac174730d4143a119037d9fda81c7a9",
                sha1="fb5608fa03de204a12fe1e9e5275e4a682107471",
                sha256="65b0f656e79ab84ca17807158e3eac206bd58be6689ddeb95956a48748d138f9",
            ),
            arguments="LS10ZXN0IA==",
            detection_names=["VAN_DROPPER.UMXX"],
            threat_types=["Dropper"],
        ),
    )


# Test cases for get file analysis report
def test_get_file_analysis_result(mocker):
    """Test get file analysis report data."""
    client = Mock()
    client.sandbox.get_analysis_result = Mock(return_value=mock_file_result_response())
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


# Mock response for collect file
def mock_collect_file_response(*args, **kwargs):
    with open("./test_data/collect_forensic_file.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test cases for collect forensic file.
def test_collect_forensic_file(mocker):
    """Test collect file with positive scenario."""
    client = Mock()
    client.endpoint.collect_file = Mock(return_value=mock_collect_file_response())
    args = {
        "collect_files": json.dumps(
            [
                {
                    "endpoint": "client95c3",
                    "file_path": "C/file_path/sample.txt",
                    "description": "collect file",
                }
            ]
        )
    }
    result = collect_file(client, args)
    assert result.outputs[0]["status"] == 202
    assert result.outputs[0]["task_id"] == "00000003"
    assert result.outputs_prefix == "VisionOne.Collect_Forensic_File"
    assert result.outputs_key_field == "task_id"


# Mock for downloaded file information
def mock_download_collected_file_info_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=CollectFileTaskResp(
            id="00000003",
            status=Status.SUCCEEDED,
            action=TaskAction.COLLECT_FILE,
            created_date_time="2023-11-12T12:00:00Z",
            last_action_date_time="2023-11-16T12:00:00Z",
            description="Test",
            account="API",
            agent_guid="cb9c8412-1f64-4fa0-a36b-76bf41a07ede",
            endpoint_name="trend-host-1",
            file_path="string",
            file_sha1="12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
            file_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size=102400,
            resource_location="htttps://api.xdr.trendmicro.com/...",
            expired_date_time="2023-11-17T12:00:00Z",
            password="LS10ZXN0IA==",
        ),
    )


# Test Cases for Collected downloaded file information.
def test_get_forensic_file_information(mocker):
    """Test endpoint to get collected file information based on task id"""
    client = Mock()
    client.task.get_result_class = Mock(return_value=mock_download_collected_file_info_response())
    args = {
        "task_id": "00000003",
        "poll": "true",
        "poll_time_sec": 30,
    }
    result = download_information_collected_file(client, args)
    assert result.outputs["id"] == "00000003"
    # assert result.outputs["action"] == "collectFile"
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
    return Result(
        result_code=ResultCode.SUCCESS,
        response=BytesResp(content=b"JVBERi0xLjQKJcCnN0cmVhbQp4nD2OywoCMQxF9=="),
    )


# Test Case for Download analysis report
def test_download_analysis_report(mocker):
    """
    Test to download analysis report (PDF) of file submitted
    to sandbox based on submission ID returned by get
    file analysis status.
    """
    client = Mock()
    client.sandbox.download_analysis_result = Mock(return_value=mock_download_analysis_report_response())
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
    return Result(
        result_code=ResultCode.SUCCESS,
        response=BytesResp(content=b"JVBERi0xLjQKJcCnN0cmVhbQp4nD2OywoCMQxF9=="),
    )


# Test case for Download analysis package
def test_download_investigation_package(mocker):
    """
    Test to download investigation package for file
    submitted to sandbox based on submission ID returned
    by get file analysis status.
    """
    client = Mock()
    client.sandbox.download_investigation_package = Mock(return_value=mock_download_investigation_package_response())
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
    return Result(
        result_code=ResultCode.SUCCESS,
        response=ListSandboxSuspiciousResp(
            items=[
                SandboxSuspiciousObject(
                    risk_level=RiskLevel.HIGH,
                    analysis_completion_date_time="2021-11-17T12:00:00Z",
                    expired_date_time="2022-12-17T12:00:00Z",
                    root_sha1="12a08b7a3c5a10b64700c0aca1a47941b50a4f8b",
                    value="https://someurl.com",
                    type=ObjectType.URL,
                )
            ],
        ),
    )


# Test case for download suspicious object list
def test_download_suspicious_object_list(mocker):
    """
    Test to download suspicious object list
    based on submission ID returned by download
    file analysis report. Only items classified as
    High will be populated in the list. If no items
    exist, a 404 not found error will be returned.
    """
    client = Mock()
    client.sandbox.list_suspicious = Mock(return_value=mock_download_suspicious_object_list_response())
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
    return Result(
        result_code=ResultCode.SUCCESS,
        response=SubmitFileToSandboxResp(
            id="012e4eac-9bd9-4e89-95db-77e02f75a6f3",
            digest=Digest(
                md5="4ac174730d4143a119037d9fda81c7a9",
                sha1="fb5608fa03de204a12fe1e9e5275e4a682107471",
                sha256="65b0f656e79ab84ca17807158e3eac206bd58be6689ddeb95956a48748d138f9",
            ),
            arguments="LS10ZXN0IA==",
        ),
    )


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
    client = Mock()
    client.sandbox.submit_file = Mock(return_value=mock_submit_file_to_sandbox_response())
    args = {
        "file_path": "https://someurl.com/test.json",
        "filename": "dummy.pdf",
        "archive_password": "6hn467c8",
        "document_password": "",
        "arguments": "LS10ZXN0IA==",
    }
    mocker.patch("TrendMicroVisionOneV3.requests.get", mocked_requests_get)
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
    client = Mock()
    client.sandbox.submit_file = Mock(return_value=mock_submit_file_to_sandbox_response())
    mocker.patch("TrendMicroVisionOneV3.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOneV3.requests.post", mocked_requests_post)
    args = {
        "entry_id": "12@1221",
        "archive_password": "6hn467c8",
        "document_password": "",
        "arguments": "LS10ZXN0IA==",
    }

    result = submit_file_entry_to_sandbox(client, args)
    assert result.outputs["entry_id"] == "12@1221"
    assert isinstance(result.outputs["task_id"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert result.outputs_key_field == "entry_id"


# Mock response for submit urls to sandbox
def mock_urls_to_sandbox_response(*args, **kwargs):
    with open("./test_data/submit_urls_sandbox.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiUrlResp(items=[MsDataUrl(**data) for data in return_value]),
    )


# Test case for submit urls to sandbox
def test_submit_urls_to_sandbox(mocker):
    client = Mock()
    client.sandbox.submit_url = Mock(return_value=mock_urls_to_sandbox_response())
    args = {
        "urls": json.dumps(
            [
                "http://www.shadywebsite.com",
                "http://www.virus2.com",
                "https://testurl.com",
            ]
        )
    }
    result = submit_urls_to_sandbox(client, args)
    assert isinstance(result.outputs[0]["url"], str)
    assert isinstance(result.outputs[0]["id"], str)
    assert isinstance(result.outputs[0]["digest"], dict)
    assert result.outputs_key_field == "id"


def test_sandbox_submission_polling(mocker):
    """Test sandbox submission polling."""
    client = Mock()
    client.sandbox.get_submission_status = Mock(return_value=mock_file_analysis_status_response())
    client.sandbox.get_analysis_result = Mock(return_value=mock_file_result_response())
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.2.0", "buildNumber": "12345"},
    )
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None)

    args = {"task_id": "800f908d-9578-4333-91e5-822794ed5483"}
    result = get_sandbox_submission_status(args, client)
    assert result.outputs["report_id"] == "800f908d-9578-4333-91e5-822794ed5483"
    assert isinstance(result.outputs["type"], str)
    assert isinstance(result.outputs["digest"], dict)
    assert isinstance(result.outputs["arguments"], str)
    assert isinstance(result.outputs["analysis_completion_time"], str)
    assert isinstance(result.outputs["risk_level"], str)
    assert isinstance(result.outputs["detection_name_list"], list)
    assert isinstance(result.outputs["threat_type_list"], list)
    assert isinstance(result.outputs["file_type"], str)


# Mock function for check task status
def get_base_task_result_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=BaseTaskResp(
            id="00000004",
            status=Status.SUCCEEDED,
            created_date_time="2021-11-17T12:00:00Z",
            last_action_date_time="2021-12-17T12:00:00Z",
            action=TaskAction.ENABLE_ACCOUNT,
            description="something",
            account="API",
        ),
    )


# Mock function for check task status
def check_task_status_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=AccountTaskResp(
            id="00000004",
            status=Status.SUCCEEDED,
            created_date_time="2021-11-17T12:00:00Z",
            last_action_date_time="2021-12-17T12:00:00Z",
            action=TaskAction.ENABLE_ACCOUNT,
            description="something",
            account="API",
            tasks=[
                Account(
                    iam=Iam.AAD,
                    account_name="jdoe@trendenablement.com",
                    status=Status.SUCCEEDED,
                    last_action_date_time="2023-11-16T21:51:19Z",
                )
            ],
        ),
    )


def test_check_task_status(mocker):
    client = Mock()
    client.task.get_result = Mock(return_value=get_base_task_result_mock_response())
    client.task.get_result_class = Mock(return_value=check_task_status_mock_response())
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", lambda: None)
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
    return Endpoint(
        agent_guid="35fa11da-a24e-40cf-8b56-baf8828cc151",
        login_account=ValueList(
            value=["MSEDGEWIN10\\\\IEUser"],
            updated_date_time="2020-06-01T02:12:56Z",
        ),
        endpoint_name=Value(value="MSEDGEWIN10", updated_date_time="2020-06-01T02:12:56Z"),
        mac_address=ValueList(
            updated_date_time="2020-06-01T02:12:56Z",
            value=["00:1c:42:be:22:5f"],
        ),
        ip=ValueList(value=["10.211.55.36"], updated_date_time="2020-06-01T02:12:56Z"),
        os_name=OperatingSystem.WINDOWS,
        os_version="10.0 (Build 19045)",
        os_description="Windows 10 10.0 (Build 19045)",
        product_code=ProductCode.SAO,
        installed_product_codes=[ProductCode.SAO, ProductCode.XES],
    )


def side_effect(lambda_func, *args2, **args3):
    lambda_func(mock_get_endpoint_info_response())


# Test case for get endpoint information.
def test_get_endpoint_information(mocker):
    """Test get information from endpoint based on endpointName or agentGuid"""
    args = {
        "query_op": "and",
        "endpoint": json.dumps({"dpt": "443", "endpointName": "MSEDGEWIN10"}),
    }
    client = Mock()
    my_list = []
    client.endpoint.consume_data = Mock(side_effect=side_effect)
    client.endpoint.consume_data(lambda cons: my_list.append(cons), QueryOp.AND, **json.loads(args["endpoint"]))
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
    assert result.outputs_key_field == "endpoint_name"


# Mock response for get endpoint activity data
def get_endpoint_activity_data_mock_response(*args, **kwargs):
    with open("./test_data/get_endpoint_activity_data.json") as f:
        endpoint_activity: dict[str, Any] = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=ListEndpointActivityResp(
            next_link="https://somelink.com",
            items=[EndpointActivity(**endpoint_activity)],
            progress_rate=30,
        ),
    )


# Test case for get alert details
def test_get_endpoint_activity_data(mocker):
    client = Mock()
    client.endpoint.get_activity_count = Mock(return_value=get_endpoint_activity_data_count_mock_response())
    client.endpoint.list_activity = Mock(return_value=get_endpoint_activity_data_mock_response())
    args = {
        "start": "2022-10-04T08:22:37Z",
        "end": "2023-10-04T08:22:37Z",
        "top": 500,
        "query_op": "or",
        "select": "dpt,dst,endpointHostName",
        "get_activity_data_count": "true",
        "fetch_all": "false",
        "fetch_max_count": "50",
        "fields": json.dumps({"dpt": "443", "endpointHostName": "MSEDGEWIN10"}),
    }
    result = get_endpoint_activity_data(client, args)
    assert isinstance(result.outputs[0]["endpoint_host_name"], str)
    assert result.outputs_key_field == "endpoint_host_name"


# Mock response for get endpoint activity data count
def get_endpoint_activity_data_count_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=GetEmailActivitiesCountResp(total_count=10),
    )


# Test case for get alert details
def test_get_endpoint_activity_data_count(mocker):
    client = Mock()
    client.endpoint.get_activity_count = Mock(return_value=get_endpoint_activity_data_count_mock_response())
    args = {
        "start": "2022-10-04T08:22:37Z",
        "end": "2023-10-04T08:22:37Z",
        "query_op": "or",
        "select": "dpt,dst,endpointHostName",
        "get_activity_data_count": "true",
        "fields": json.dumps({"dpt": "443", "endpointHostName": "MSEDGEWIN10"}),
    }
    result = get_endpoint_activity_data_count(client, args)
    assert isinstance(result.outputs["endpoint_activity_count"], int)
    assert result.outputs_key_field == "endpoint_activity_count"


# Mock response for get endpoint activity data
def get_email_activity_data_mock_response(*args, **kwargs):
    with open("./test_data/get_email_activity_data.json") as f:
        email_activity: dict[str, Any] = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=ListEmailActivityResp(
            next_link="https://somelink.com",
            items=[EmailActivity(**email_activity)],
            progress_rate=30,
        ),
    )


# Test case for get alert details
def test_get_email_activity_data(mocker):
    client = Mock()
    client.email.get_activity_count = Mock(return_value=get_email_activity_data_count_mock_response())
    client.email.list_activity = Mock(return_value=get_email_activity_data_mock_response())
    args = {
        "start": "2022-10-04T08:22:37Z",
        "end": "2023-10-04T08:22:37Z",
        "top": 50,
        "query_op": "or",
        "select": "mailFromAddresses,mailToAddresses",
        "fetch_all": "false",
        "fetch_max_count": "50",
        "fields": json.dumps({"mailToAddresses": "testemail@gmail.com", "mailMsgSubject": "spam"}),
    }
    result = get_email_activity_data(client, args)
    assert isinstance(result.outputs[0]["mail_msg_id"], str)
    assert result.outputs_key_field == "mail_to_addresses"


# Mock response for get email activity data count
def get_email_activity_data_count_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=GetEmailActivitiesCountResp(total_count=10),
    )


# Test case for get email activity data count
def test_get_email_activity_data_count(mocker):
    client = Mock()
    client.email.get_activity_count = Mock(return_value=get_email_activity_data_count_mock_response())
    args = {
        "start": "2022-10-04T08:22:37Z",
        "end": "2023-10-04T08:22:37Z",
        "query_op": "or",
        "select": "mailFromAddresses,mailToAddresses",
        "fields": json.dumps({"mailToAddresses": "testemail@gmail.com", "mailMsgSubject": "spam"}),
    }
    result = get_email_activity_data_count(client, args)
    assert isinstance(result.outputs["email_activity_count"], int)
    assert result.outputs_key_field == "email_activity_count"


# Mock response for get alert details
def get_alert_details_mock_response(*args, **kwargs):
    with open("./test_data/get_alert_details.json") as f:
        alert = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=GetAlertResp(etag="33a64df551425fcc55e4d42a148795d9f25f89d4", data=alert),
    )


# Test case for get alert details
def test_get_alert_details(mocker):
    client = Mock()
    client.alert.get = Mock(return_value=get_alert_details_mock_response())

    args = {"workbench_id": "WB-9002-20220909-00111"}
    result = get_alert_details(client, args)
    assert result.outputs["etag"] == "33a64df551425fcc55e4d42a148795d9f25f89d4"
    assert isinstance(result.outputs["alert"], dict)
    assert result.outputs_key_field == "etag"


# Mock response for add note.
def add_note_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=AddAlertNoteResp(note_id="1"),
    )


# Test case for add note
def test_add_note(mocker):
    client = Mock()
    client.note.create = Mock(return_value=add_note_mock_response())
    args = {"workbench_id": "WB-14-20190709-00003", "content": "This is a new note."}
    result = add_note(client, args)
    assert isinstance(result.outputs["message"], str)
    assert isinstance(result.outputs["code"], int)
    assert result.outputs["note_id"] == "1"
    assert result.outputs_key_field == "note_id"


# Mock function for update alert status
def update_status_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=NoContentResp(),
    )


# Test case for update alert status
def test_update_status(mocker):
    client = Mock()
    client.alert.update_status = Mock(return_value=update_status_mock_response())
    args = {
        "workbench_id": "WB-20837-20220418-00000",
        "if_match": "d41d8cd98f00b204e9800998ecf8427e",
        "status": "in_progress",
        "inv_result": "no_findings",
    }
    result = update_status(client, args)
    assert result.outputs["code"] == 204
    assert isinstance(result.outputs["message"], str)
    assert result.outputs["Workbench_Id"] == "WB-20837-20220418-00000"


# Mock function for run custom script
def run_custom_script_mock_response(*args, **kwargs):
    with open("./test_data/run_custom_script.json") as f:
        return_value: list[dict[str, Any]] = json.load(f)
    return MultiResult(
        result_code=ResultCode.SUCCESS,
        response=MultiResp(items=[MsData(**data) for data in return_value]),
    )


# Test case to run a custom script
def test_run_custom_script(mocker):
    """
    Given:
        - block_objects -> A dictionary object containing endpoint or agent_guid,
            optional description and optional parameter.
    When:
        - Execute run_custom_script command
    Then:
        - validate a success response and a task_id is generated
    """
    client = Mock()
    client.script.run = Mock(return_value=run_custom_script_mock_response())
    args = {
        "block_objects": json.dumps(
            [
                {
                    "filename": "test.ps1",
                    "endpoint": "custom-endpoint1",
                    "parameter": "string",
                    "description": "Run custom script.",
                }
            ]
        )
    }
    result = run_custom_script(client, args)
    assert result.outputs[0]["status"] == 202
    assert isinstance(result.outputs[0]["task_id"], str)
    assert result.outputs_prefix == "VisionOne.Run_Custom_Script"
    assert result.outputs_key_field == "task_id"


# Mock function to get custom script list
def get_custom_script_list_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=ListCustomScriptsResp(
            items=[
                Script(
                    id="cb044c99-8fc5-2418-f5a5-2f15dbe62133",
                    file_name="string",
                    file_type=ScriptType.BASH,
                    description="Script to update some values",
                ),
                Script(
                    id="44c99cb0-8c5f-4182-af55-62135dbe32f1",
                    file_name="string",
                    file_type=ScriptType.POWERSHELL,
                    description="Script to delete duplicate values",
                ),
            ]
        ),
    )


# Test case to fetch custom script list
def test_get_custom_script_list(mocker):
    """
    Given:
        - fields -> A dictionary object containing fileName and/or fileType
        - query_op -> Operator used to build the query string, possible values are and/or
    When:
        - Execute get_custom_script_list command
    Then:
        - validate an id, filename and filetype are returned
    """
    client = Mock()
    client.script.list = Mock(return_value=get_custom_script_list_mock_response())
    args = {"filename": "test-script.sh", "filetype": "bash", "query_op": "or"}
    result = get_custom_script_list(client, args)
    assert isinstance(result.outputs[0]["id"], str)
    assert isinstance(result.outputs[0]["filename"], str)
    assert isinstance(result.outputs[0]["filetype"], str)
    assert result.outputs_prefix == "VisionOne.Get_Custom_Script_List"
    assert result.outputs_key_field == "id"


# Mock function to download custom script
def download_custom_script_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=TextResp(text="#!/bin/sh echo 'Download script'"),
    )


# Test case to download a custom script
def test_download_custom_script(mocker):
    """
    Given:
        - script_id -> The ID for a custom script to download
    When:
        - Execute download_custom_script command
    Then:
        - validate text response for downloaded script
    """
    client = Mock()
    client.script.download = Mock(return_value=download_custom_script_mock_response())
    args = {"script_id": "44c99cb0-8c5f-4182-af55-62135dbe32f1"}
    result = download_custom_script(client, args)
    assert result.outputs["text"] == "#!/bin/sh echo 'Download script'"
    assert result.outputs_prefix == "VisionOne.Download_Custom_Script"
    assert result.outputs_key_field == "text"


# Mock function to delete custom script
def delete_custom_script_mock_response(*args, **kwargs):
    with open("./test_data/delete_custom_script.json") as f:
        return_value: dict[str, str] = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=NoContentResp(**return_value),
    )


# Test case to delete a custom script
def test_delete_custom_script(mocker):
    """
    Given:
        - script_id -> The ID of a custom script to delete
    When:
        - Execute delete_custom_script command
    Then:
        - validate a success response
    """
    client = Mock()
    client.script.delete = Mock(return_value=delete_custom_script_mock_response())
    args = {"script_id": "44c99cb0-8c5f-4182-af55-62135dbe32f1"}
    result = delete_custom_script(client, args)
    assert isinstance(result.outputs["status"], str)
    assert result.outputs_prefix == "VisionOne.Delete_Custom_Script"
    assert result.outputs_key_field == "status"


# Mock function to add custom script
def add_custom_script_mock_response(*args, **kwargs):
    return Result(
        result_code=ResultCode.SUCCESS,
        response=AddCustomScriptResp(script_id="44c99cb0-8c5f-4182-af55-62135dbe32f1"),
    )


# Test case to add a custom script
def test_add_custom_script(mocker):
    """
    Given:
        - filename -> Name of the custom script
        - filetype -> Filetype of the custom script
        - description -> Optional description for the custom script
        - script_contents -> Contents of the custom script
    When:
        - Execute add_custom_script command
    Then:
        - validate an ID is returned after successful action completion
    """
    client = Mock()
    client.script.create = Mock(return_value=add_custom_script_mock_response())
    args = {
        "file_url": "http://someurl.com/testscript.sh",
        "filename": "test_script.sh",
        "filetype": "bash",
        "description": "Script to delete duplicates.",
    }
    mocker.patch("TrendMicroVisionOneV3.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOneV3.requests.post", mocked_requests_post)
    result = add_custom_script(client, args)
    assert result.outputs["id"] == "44c99cb0-8c5f-4182-af55-62135dbe32f1"
    assert result.outputs_prefix == "VisionOne.Add_Custom_Script"
    assert result.outputs_key_field == "id"


# Mock function to update custom script
def update_custom_script_mock_response(*args, **kwargs):
    with open("./test_data/update_custom_script.json") as f:
        return_value: dict[str, str] = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=NoContentResp(**return_value),
    )


# Test case to update a custom script
def test_update_custom_script(mocker):
    """
    Given:
        - filename -> Name of the custom script
        - filetype -> Filetype of the custom script
        - script_id -> ID of the custom script to update
        - script_contents -> New contents of the custom script
        - description -> Optional description for the custom script
    When:
        - Execute update_custom_script command
    Then:
        - validate a success response
    """
    client = Mock()
    client.script.update = Mock(return_value=update_custom_script_mock_response())
    mocker.patch("TrendMicroVisionOneV3.requests.get", mocked_requests_get)
    mocker.patch("TrendMicroVisionOneV3.requests.post", mocked_requests_post)
    args = {
        "filetype": "bash",
        "filename": "test_script.sh",
        "script_id": "44c99cb0-8c5f-4182-af55-62135dbe32f1",
        "file_url": "http://someurl.com/test1script.sh",
        "description": "Script to update values.",
    }
    result = update_custom_script(client, args)
    assert result.outputs["status"] == "SUCCESS"
    assert result.outputs_prefix == "VisionOne.Update_Custom_Script"
    assert result.outputs_key_field == "status"


# Mock response for get observed attack techniques events
def get_observed_attack_techniques_mock_response(*args, **kwargs):
    with open("./test_data/get_observed_attack_techniques.json") as f:
        attack_techniques: dict[str, Any] = json.load(f)
    return Result(
        result_code=ResultCode.SUCCESS,
        response=ListOatsResp(
            next_link="https://somelink.com",
            items=[OatEvent(**attack_techniques)],
            total_count=30,
            count=10,
        ),
    )


# Test case for fetching observed attack techniques
def test_get_observed_attack_techniques(mocker):
    """
    Given:
        - detected_start -> Detection start date time
        - detected_end -> Detection end date time
        - ingested_start -> Ingestion start date time
        - ingested_end -> Ingestion end date time
        - top -> Number of records displayed on a page.
        - query_op -> Conditional operator used to build request that allows
            user to retrieve a subset of the collected Observed Attack Techniques events
        - fields -> Required filter (A dictionary object with key/value used to create a query string) for
            retrieving a subset of the collected Observed Attack Techniques events
    When:
        - Execute get_observed_attack_techniques command
    Then:
        - validate a string id response
    """
    client = Mock()
    client.oat.list = Mock(return_value=get_observed_attack_techniques_mock_response())
    args = {
        "detected_start": "2024-01-15T10:00:00Z",
        "detected_end": "2024-05-15T10:00:00Z",
        "ingested_start": "2024-01-15T10:00:00Z",
        "ingested_end": "2024-05-15T10:00:00Z",
        "top": 10,
        "query_op": "or",
        "fields": json.dumps({"endpointName": "sample-host", "riskLevel": "low"}),
    }
    result = get_observed_attack_techniques(client, args)
    assert isinstance(result.outputs[0]["id"], str)
    assert result.outputs_prefix == "VisionOne.Get_Observed_Attack_Techniques"
    assert result.outputs_key_field == "id"


def test_xsoar_status_to_vision_one():
    """
    Test the xsoar_status_to_vision_one helper function that maps XSOAR incident statuses
    to Vision One alert statuses.

    Given:
        - incident_status: XSOAR IncidentStatus value (0=Pending, 1=Active, 2=Closed, or unknown)
    When:
        - Execute xsoar_status_to_vision_one function
    Then:
        - Validate correct mapping to Vision One status
    """
    # Test Pending (0) -> "open"
    status = xsoar_status_to_vision_one(0)
    assert status == "open"

    # Test Active (1) -> "in_progress"
    status = xsoar_status_to_vision_one(1)
    assert status == "in_progress"

    # Test Closed (2) -> "closed"
    status = xsoar_status_to_vision_one(2)
    assert status == "closed"

    # Test Unknown status (999) -> defaults to "open"
    status = xsoar_status_to_vision_one(999)
    assert status == "open"


# ========== Outgoing Mirroring Tests (update-remote-system) ==========


def test_update_remote_system_no_remote_id(mocker):
    """
    Test update_remote_system when no remote ID is provided.

    Given:
        - No remote incident ID (empty string)
    When:
        - Execute update_remote_system command
    Then:
        - Should return empty string without making API calls
    """
    client = Mock()
    mocker.patch.object(demisto, "error")

    args = {
        "remoteId": "",
        "data": {"status": 2},
        "entries": [],
        "incidentChanged": True,
    }

    result = update_remote_system_command(client, args)

    # Should return empty string without any API calls
    assert result == ""
    client.alert.get.assert_not_called()


def test_update_remote_system_incident_not_changed(mocker):
    """
    Test update_remote_system when incident has not changed.

    Given:
        - Remote incident ID
        - incidentChanged is False
    When:
        - Execute update_remote_system command
    Then:
        - Should return remote ID without making API calls
    """
    client = Mock()
    mocker.patch.object(demisto, "error")

    args = {
        "remoteId": "WB-14-20190709-00003",
        "data": {"status": 1},
        "entries": [],
        "incidentChanged": False,
    }

    result = update_remote_system_command(client, args)

    # Should return remote ID without calling API
    assert result == "WB-14-20190709-00003"
    client.alert.get.assert_not_called()


def test_update_remote_system_status_update_success(mocker):
    """
    Test update_remote_system when incident status changes successfully.

    Given:
        - Incident status changed to Closed (2)
        - Close reason "Resolved"
    When:
        - Execute update_remote_system command
    Then:
        - Should retrieve alert to get ETag
        - Should update Vision One alert status to "closed" with investigation result TRUE_POSITIVE
    """
    from pytmv1 import AlertStatus, InvestigationResult, GetAlertResp, Result, ResultCode, MultiResp

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.get() response - return success with etag
    mock_alert_resp = Mock(spec=GetAlertResp)
    mock_alert_resp.etag = "test-etag-123"

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.SUCCESS
    mock_get_result.response = mock_alert_resp
    mock_get_result.error = None

    client.alert.get.return_value = mock_get_result

    # Mock alert.update_status() response - return success
    mock_update_result = Mock(spec=MultiResp)
    mock_update_result.result_code = ResultCode.SUCCESS
    mock_update_result.error = None

    client.alert.update_status.return_value = mock_update_result

    args = {
        "remoteId": "WB-14-20190709-00003",
        "data": {"status": 2, "closeReason": "Resolved"},
        "entries": [],
        "incidentChanged": True,
    }

    result = update_remote_system_command(client, args)

    # Should return remote ID
    assert result == "WB-14-20190709-00003"

    # Verify alert.get was called
    client.alert.get.assert_called_once_with(alert_id="WB-14-20190709-00003")

    # Verify alert.update_status was called with correct parameters
    client.alert.update_status.assert_called_once()
    call_args = client.alert.update_status.call_args
    assert call_args.kwargs["alert_id"] == "WB-14-20190709-00003"
    assert call_args.kwargs["status"] == AlertStatus.CLOSED
    assert call_args.kwargs["etag"] == "test-etag-123"
    assert call_args.kwargs["inv_result"] == InvestigationResult.TRUE_POSITIVE


def test_update_remote_system_with_close_notes(mocker):
    """
    Test update_remote_system when incident is closed with close notes.

    Given:
        - Incident closed with closeNotes
    When:
        - Execute update_remote_system command
    Then:
        - Should update status
        - Should add closing note to Vision One alert
    """
    from pytmv1 import AlertStatus, InvestigationResult, GetAlertResp, Result, ResultCode, MultiResp

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.get() response
    mock_alert_resp = Mock(spec=GetAlertResp)
    mock_alert_resp.etag = "test-etag-456"

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.SUCCESS
    mock_get_result.response = mock_alert_resp
    mock_get_result.error = None

    client.alert.get.return_value = mock_get_result

    # Mock alert.update_status() response
    mock_update_result = Mock(spec=MultiResp)
    mock_update_result.result_code = ResultCode.SUCCESS
    mock_update_result.error = None

    client.alert.update_status.return_value = mock_update_result

    # Mock note.create() response
    mock_note_result = Mock(spec=Result)
    mock_note_result.result_code = ResultCode.SUCCESS
    mock_note_result.error = None

    client.note.create.return_value = mock_note_result

    args = {
        "remoteId": "WB-14-20190709-00003",
        "data": {
            "status": 2,
            "closeReason": "Resolved",
            "closeNotes": "Confirmed false positive after investigation",
            "closingUserId": "analyst@example.com",
            "id": "12345",
        },
        "entries": [],
        "incidentChanged": True,
    }

    result = update_remote_system_command(client, args)

    # Should return remote ID
    assert result == "WB-14-20190709-00003"

    # Verify note.create was called
    client.note.create.assert_called_once()
    call_args = client.note.create.call_args
    assert call_args.kwargs["alert_id"] == "WB-14-20190709-00003"
    assert "XSOAR Incident ID: 12345" in call_args.kwargs["note_content"]
    assert "Close Reason: Resolved" in call_args.kwargs["note_content"]
    assert "analyst@example.com" in call_args.kwargs["note_content"]
    assert "Confirmed false positive after investigation" in call_args.kwargs["note_content"]


def test_update_remote_system_close_reason_mapping(mocker):
    """
    Test update_remote_system close reason to investigation result mapping.

    Given:
        - Incident closed with different close reasons
    When:
        - Execute update_remote_system command
    Then:
        - Should map close reasons correctly to investigation results
    """
    from pytmv1 import AlertStatus, InvestigationResult, GetAlertResp, Result, ResultCode, MultiResp

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock responses
    mock_alert_resp = Mock(spec=GetAlertResp)
    mock_alert_resp.etag = "test-etag"

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.SUCCESS
    mock_get_result.response = mock_alert_resp
    mock_get_result.error = None

    client.alert.get.return_value = mock_get_result

    mock_update_result = Mock(spec=MultiResp)
    mock_update_result.result_code = ResultCode.SUCCESS
    mock_update_result.error = None

    client.alert.update_status.return_value = mock_update_result

    # Test case 1: "False Positive" -> FALSE_POSITIVE
    args_fp = {
        "remoteId": "WB-TEST",
        "data": {"status": 2, "closeReason": "False Positive"},
        "entries": [],
        "incidentChanged": True,
    }
    update_remote_system_command(client, args_fp)
    call_args = client.alert.update_status.call_args
    assert call_args.kwargs["inv_result"] == InvestigationResult.FALSE_POSITIVE

    # Reset mock
    client.alert.update_status.reset_mock()

    # Test case 2: "Resolved" -> TRUE_POSITIVE
    args_resolved = {
        "remoteId": "WB-TEST",
        "data": {"status": 2, "closeReason": "Resolved"},
        "entries": [],
        "incidentChanged": True,
    }
    update_remote_system_command(client, args_resolved)
    call_args = client.alert.update_status.call_args
    assert call_args.kwargs["inv_result"] == InvestigationResult.TRUE_POSITIVE

    # Reset mock
    client.alert.update_status.reset_mock()

    # Test case 3: "Duplicate" -> NO_FINDINGS
    args_duplicate = {
        "remoteId": "WB-TEST",
        "data": {"status": 2, "closeReason": "Duplicate"},
        "entries": [],
        "incidentChanged": True,
    }
    update_remote_system_command(client, args_duplicate)
    call_args = client.alert.update_status.call_args
    assert call_args.kwargs["inv_result"] == InvestigationResult.NO_FINDINGS

    # Reset mock
    client.alert.update_status.reset_mock()

    # Test case 4: "Other" -> NOTEWORTHY
    args_other = {
        "remoteId": "WB-TEST",
        "data": {"status": 2, "closeReason": "Other"},
        "entries": [],
        "incidentChanged": True,
    }
    update_remote_system_command(client, args_other)
    call_args = client.alert.update_status.call_args
    assert call_args.kwargs["inv_result"] == InvestigationResult.NOTEWORTHY


def test_update_remote_system_api_error(mocker):
    """
    Test update_remote_system when API returns an error.

    Given:
        - Vision One API returns error when getting alert
    When:
        - Execute update_remote_system command
    Then:
        - Should log error and return remote ID without updating
    """
    from pytmv1 import Result, ResultCode, Error

    client = Mock()
    mock_error_logger = mocker.patch.object(demisto, "error")

    # Mock alert.get() to return error
    mock_error = Mock(spec=Error)
    mock_error.message = "Alert not found"

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.ERROR
    mock_get_result.response = None
    mock_get_result.error = mock_error

    client.alert.get.return_value = mock_get_result

    args = {
        "remoteId": "WB-INVALID",
        "data": {"status": 2},
        "entries": [],
        "incidentChanged": True,
    }

    result = update_remote_system_command(client, args)

    # Should return remote ID even on error
    assert result == "WB-INVALID"

    # Should have logged error
    assert mock_error_logger.called
    error_msg = mock_error_logger.call_args[0][0]
    assert "Error fetching alert" in error_msg
    assert "WB-INVALID" in error_msg

    # Should not call update_status
    client.alert.update_status.assert_not_called()


# ========== Incoming Mirroring Tests (get-modified-remote-data) ==========


def test_vision_one_status_to_xsoar():
    """
    Test the vision_one_status_to_xsoar helper function that maps Vision One alert statuses
    to XSOAR incident statuses.

    Given:
        - v1_status: Vision One alert status string
    When:
        - Execute vision_one_status_to_xsoar function
    Then:
        - Validate correct mapping to XSOAR IncidentStatus values
    """
    # Test "Open" -> 0 (Pending) - Vision One API format
    status = vision_one_status_to_xsoar("Open")
    assert status == 0

    # Test "In Progress" -> 1 (Active) - Vision One API format
    status = vision_one_status_to_xsoar("In Progress")
    assert status == 1

    # Test "Closed" -> 2 (Closed) - Vision One API format
    status = vision_one_status_to_xsoar("Closed")
    assert status == 2

    # Test unknown status -> defaults to 0 (Pending)
    status = vision_one_status_to_xsoar("unknown_status")
    assert status == 0


def test_get_modified_remote_data_success(mocker):
    """
    Test get_modified_remote_data returns modified alert IDs.

    Given:
        - last_update timestamp
    When:
        - Execute get_modified_remote_data command
        - Vision One returns alerts updated since last_update
    Then:
        - Should return list of modified alert IDs
    """
    from pytmv1 import SaeAlert
    from datetime import datetime, UTC

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.consume to call callback with test alerts
    def mock_consume(callback, **kwargs):
        # Create mock alerts
        alert1 = Mock(spec=SaeAlert)
        alert1.id = "WB-ALERT-001"

        alert2 = Mock(spec=SaeAlert)
        alert2.id = "WB-ALERT-002"

        # Call the callback for each alert
        callback(alert1)
        callback(alert2)

    client.alert.consume = mock_consume

    args = {
        "lastUpdate": "2025-01-01T00:00:00Z",
    }

    result = get_modified_remote_data_command(client, args)

    # Should return list of modified alert IDs
    assert len(result.modified_incident_ids) == 2
    assert "WB-ALERT-001" in result.modified_incident_ids
    assert "WB-ALERT-002" in result.modified_incident_ids


def test_get_modified_remote_data_no_last_update(mocker):
    """
    Test get_modified_remote_data when no last_update provided.

    Given:
        - No last_update timestamp
    When:
        - Execute get_modified_remote_data command
    Then:
        - Should default to 1 hour ago
        - Should return modified alerts
    """
    from pytmv1 import SaeAlert

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.consume
    def mock_consume(callback, **kwargs):
        alert = Mock(spec=SaeAlert)
        alert.id = "WB-ALERT-003"
        callback(alert)

    client.alert.consume = mock_consume

    args = {}

    result = get_modified_remote_data_command(client, args)

    # Should return results even without last_update
    assert len(result.modified_incident_ids) == 1
    assert "WB-ALERT-003" in result.modified_incident_ids


def test_get_modified_remote_data_invalid_timestamp(mocker):
    """
    Test get_modified_remote_data with invalid timestamp format.

    Given:
        - Invalid last_update timestamp format
    When:
        - Execute get_modified_remote_data command
    Then:
        - Should log error
        - Should default to 1 hour ago
        - Should still return results
    """
    from pytmv1 import SaeAlert

    client = Mock()
    mock_error_logger = mocker.patch.object(demisto, "error")

    # Mock alert.consume
    def mock_consume(callback, **kwargs):
        alert = Mock(spec=SaeAlert)
        alert.id = "WB-ALERT-004"
        callback(alert)

    client.alert.consume = mock_consume

    args = {
        "lastUpdate": "invalid-timestamp-format",
    }

    result = get_modified_remote_data_command(client, args)

    # Should log error about invalid format
    assert mock_error_logger.called
    error_msg = mock_error_logger.call_args[0][0]
    assert "Invalid last_update format" in error_msg

    # Should still return results
    assert len(result.modified_incident_ids) == 1


def test_get_modified_remote_data_api_error(mocker):
    """
    Test get_modified_remote_data when API throws exception.

    Given:
        - Vision One API throws exception
    When:
        - Execute get_modified_remote_data command
    Then:
        - Should log error
        - Should return empty list
    """
    client = Mock()
    mock_error_logger = mocker.patch.object(demisto, "error")

    # Mock alert.consume to raise exception
    client.alert.consume.side_effect = Exception("API connection error")

    args = {
        "lastUpdate": "2025-01-01T00:00:00Z",
    }

    result = get_modified_remote_data_command(client, args)

    # Should log error
    assert mock_error_logger.called

    # Should return empty list
    assert len(result.modified_incident_ids) == 0


# ========== Incoming Mirroring Tests (get-remote-data) ==========


def test_get_remote_data_no_alert_id(mocker):
    """
    Test get_remote_data when no alert ID is provided.

    Given:
        - Empty or missing alert ID
    When:
        - Execute get_remote_data command
    Then:
        - Should return empty response
    """
    client = Mock()
    mocker.patch.object(demisto, "error")

    args = {
        "id": "",
        "lastUpdate": "2025-01-01T00:00:00Z",
    }

    result = get_remote_data_command(client, args)

    # Should return empty response
    assert result.mirrored_object == {}
    assert len(result.entries) == 0

    # Should not call API
    client.alert.get.assert_not_called()


def test_get_remote_data_alert_not_modified(mocker):
    """
    Test get_remote_data when alert was not modified since last_update.

    Given:
        - Alert updated time is before last_update
    When:
        - Execute get_remote_data command
    Then:
        - Should return empty response (optimization)
    """
    from pytmv1 import GetAlertResp, Result, ResultCode

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.get() to return alert with old update time
    mock_alert_data = Mock()
    mock_alert_data.model_dump.return_value = {
        "id": "WB-ALERT-OLD",
        "status": "Open",
        "severity": "medium",
        "updated_date_time": "2025-01-01T00:00:00Z",  # Before last_update
    }

    mock_alert_resp = Mock(spec=GetAlertResp)
    mock_alert_resp.data = mock_alert_data

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.SUCCESS
    mock_get_result.response = mock_alert_resp
    mock_get_result.error = None

    client.alert.get.return_value = mock_get_result

    args = {
        "id": "WB-ALERT-OLD",
        "lastUpdate": "2025-01-02T00:00:00Z",  # After alert update time
    }

    result = get_remote_data_command(client, args)

    # Should return empty response (not modified)
    assert result.mirrored_object == {}
    assert len(result.entries) == 0


def test_get_remote_data_success_closed_alert(mocker):
    """
    Test get_remote_data when alert status is closed.

    Given:
        - Alert with status "Closed" (realistic Vision One data structure)
    When:
        - Execute get_remote_data command
    Then:
        - Should return incident data with status 2 (Closed)
        - Should add close entry
        - Should preserve impact_scope and indicators fields
    """
    from pytmv1 import GetAlertResp, Result, ResultCode

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.get() to return closed alert with realistic Vision One structure
    mock_alert_data = Mock()
    mock_alert_data.model_dump.return_value = {
        "schema_version": "1.12",
        "id": "WB-ALERT-CLOSED",
        "status": "Closed",
        "severity": "high",
        "investigation_status": "Closed",
        "investigation_result": "True Positive",
        "updated_date_time": "2025-01-03T00:00:00Z",
        "created_date_time": "2025-01-01T00:00:00Z",
        "model": "Privilege Escalation via UAC Bypass",
        "score": 64,
        "workbench_link": "https://portal.xdr.trendmicro.com/...",
        "impact_scope": {
            "desktop_count": 1,
            "server_count": 0,
            "account_count": 1,
            "entities": [
                {
                    "entity_type": "account",
                    "entity_value": "domain\\user",
                    "entity_id": "domain\\user",
                    "related_entities": ["HOST-GUID"],
                    "provenance": ["Alert"]
                },
                {
                    "entity_type": "host",
                    "entity_value": {
                        "guid": "HOST-GUID",
                        "name": "test-host",
                        "ips": ["10.0.0.1"]
                    },
                    "entity_id": "HOST-GUID",
                    "related_entities": ["domain\\user"],
                    "related_indicator_ids": [1, 2],
                    "provenance": ["Alert"]
                }
            ]
        },
        "indicators": [
            {
                "id": 1,
                "type": "command_line",
                "field": "processCmd",
                "value": "powershell.exe -enc ...",
                "related_entities": ["HOST-GUID"],
                "provenance": ["Alert"]
            },
            {
                "id": 2,
                "type": "registry_key",
                "field": "objectRegistryKeyHandle",
                "value": "hkcr\\ms-settings\\shell\\open\\command",
                "related_entities": ["HOST-GUID"],
                "provenance": ["Alert"]
            }
        ],
        "matched_rules": [
            {
                "id": "rule-id",
                "name": "UAC Bypass Rule",
                "matched_filters": []
            }
        ]
    }

    mock_alert_resp = Mock(spec=GetAlertResp)
    mock_alert_resp.data = mock_alert_data

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.SUCCESS
    mock_get_result.response = mock_alert_resp
    mock_get_result.error = None

    client.alert.get.return_value = mock_get_result

    args = {
        "id": "WB-ALERT-CLOSED",
        "lastUpdate": "2025-01-01T00:00:00Z",
    }

    result = get_remote_data_command(client, args)

    # Should return incident data with closed status
    assert result.mirrored_object["id"] == "WB-ALERT-CLOSED"
    assert result.mirrored_object["status"] == 2  # Closed

    # Should have close entry
    assert len(result.entries) == 1
    close_entry = result.entries[0]
    assert close_entry["Type"] == 1  # Note
    assert "closed" in close_entry["Contents"].lower()


def test_get_remote_data_success_open_alert(mocker):
    """
    Test get_remote_data when alert status is open or in progress.

    Given:
        - Alert with status "In Progress" (realistic Vision One data structure)
    When:
        - Execute get_remote_data command
    Then:
        - Should return incident data with status 1 (Active)
        - Should not add any entries (XSOAR handles status update automatically)
        - Should preserve impact_scope and indicators fields
    """
    from pytmv1 import GetAlertResp, Result, ResultCode

    client = Mock()
    mocker.patch.object(demisto, "error")

    # Mock alert.get() to return in-progress alert with realistic Vision One structure
    mock_alert_data = Mock()
    mock_alert_data.model_dump.return_value = {
        "schema_version": "1.12",
        "id": "WB-ALERT-ACTIVE",
        "status": "In Progress",
        "severity": "medium",
        "investigation_status": "In Progress",
        "updated_date_time": "2025-01-03T00:00:00Z",
        "created_date_time": "2025-01-01T00:00:00Z",
        "model": "Suspicious Network Activity",
        "score": 45,
        "workbench_link": "https://portal.xdr.trendmicro.com/...",
        "impact_scope": {
            "desktop_count": 1,
            "server_count": 0,
            "account_count": 1,
            "entities": [
                {
                    "entity_type": "host",
                    "entity_value": {
                        "guid": "HOST-GUID-123",
                        "name": "workstation-01",
                        "ips": ["192.168.1.100"]
                    },
                    "entity_id": "HOST-GUID-123",
                    "related_entities": ["user@domain.com"],
                    "related_indicator_ids": [1],
                    "provenance": ["Alert"]
                }
            ]
        },
        "indicators": [
            {
                "id": 1,
                "type": "ip",
                "field": "dst",
                "value": "203.0.113.10",
                "related_entities": ["HOST-GUID-123"],
                "provenance": ["Alert"]
            }
        ],
        "matched_rules": [
            {
                "id": "rule-id-456",
                "name": "Outbound Connection to Known Bad IP",
                "matched_filters": []
            }
        ]
    }

    mock_alert_resp = Mock(spec=GetAlertResp)
    mock_alert_resp.data = mock_alert_data

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.SUCCESS
    mock_get_result.response = mock_alert_resp
    mock_get_result.error = None

    client.alert.get.return_value = mock_get_result

    args = {
        "id": "WB-ALERT-ACTIVE",
        "lastUpdate": "2025-01-01T00:00:00Z",
    }

    result = get_remote_data_command(client, args)

    # Should return incident data with active status
    assert result.mirrored_object["id"] == "WB-ALERT-ACTIVE"
    assert result.mirrored_object["status"] == 1  # Active

    # Should not have any entries (no reopen needed, XSOAR handles status update via status field)
    assert len(result.entries) == 0


def test_get_remote_data_alert_not_found(mocker):
    """
    Test get_remote_data when alert is not found.

    Given:
        - Vision One API returns error (alert not found)
    When:
        - Execute get_remote_data command
    Then:
        - Should log error
        - Should return empty response
    """
    from pytmv1 import Result, ResultCode, Error

    client = Mock()
    mock_error_logger = mocker.patch.object(demisto, "error")

    # Mock alert.get() to return error
    mock_error = Mock(spec=Error)
    mock_error.message = "Alert not found"

    mock_get_result = Mock(spec=Result)
    mock_get_result.result_code = ResultCode.ERROR
    mock_get_result.response = None
    mock_get_result.error = mock_error

    client.alert.get.return_value = mock_get_result

    args = {
        "id": "WB-NONEXISTENT",
        "lastUpdate": "2025-01-01T00:00:00Z",
    }

    result = get_remote_data_command(client, args)

    # Should log error
    assert mock_error_logger.called
    error_msg = mock_error_logger.call_args[0][0]
    assert "Error fetching alert" in error_msg

    # Should return empty response
    assert result.mirrored_object == {}
    assert len(result.entries) == 0


# ========== Mapping Fields Tests ==========


def test_get_mapping_fields(mocker):
    """
    Test get_mapping_fields returns correct field mappings.

    Given:
        - No arguments (function takes no parameters)
    When:
        - Execute get_mapping_fields command
    Then:
        - Should return GetMappingFieldsResponse with SchemeTypeMapping
        - Should include mirrored Vision One alert fields
    """
    mocker.patch.object(demisto, "error")

    # get_mapping_fields() takes no parameters
    result = get_mapping_fields_command()

    # Should return GetMappingFieldsResponse
    assert result is not None
    assert len(result.scheme_types_mappings) > 0

    # Verify incident type name
    scheme_type = result.scheme_types_mappings[0]
    assert scheme_type.type_name == "Trend Micro Vision One XDR Incident"

    # Verify mirrored fields are present
    field_names = [field.name for field in scheme_type.fields]
    assert "status" in field_names
    assert "severity" in field_names
    assert "investigation_result" in field_names
